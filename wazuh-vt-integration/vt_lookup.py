#!/usr/bin/env python3
"""
vt_lookup.py
Query VirusTotal v3 for a file hash and print a concise result.
Reads API key from the `VT_API_KEY` environment variable or
from `/var/ossec/etc/vt_api.key` when run on the Wazuh Manager.
"""

import os
import sys
import argparse
import json
from typing import Optional

try:
    import requests
except ImportError:
    requests = None

VT_KEY_FILE = "/var/ossec/etc/vt_api.key"
VT_API_URL = "https://www.virustotal.com/api/v3/files/{}"


def get_api_key() -> Optional[str]:
    key = os.environ.get("VT_API_KEY")
    if key:
        return key.strip()
    try:
        with open(VT_KEY_FILE, "r") as f:
            return f.read().strip()
    except Exception:
        return None


def query_vt(file_hash: str, api_key: str) -> dict:
    if requests is None:
        raise RuntimeError("Missing dependency: install 'requests'.")
    url = VT_API_URL.format(file_hash)
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def summarize(resp: dict) -> dict:
    data = resp.get("data", {})
    attributes = data.get("attributes", {})
    last_analysis = attributes.get("last_analysis_stats", {})
    malicious = last_analysis.get("malicious", 0)
    suspicious = last_analysis.get("suspicious", 0)
    undetected = last_analysis.get("undetected", 0)
    total = sum([v for v in last_analysis.values() if isinstance(v, int)])
    engine_results = attributes.get("last_analysis_results", {})
    positives = [(e, r.get("result")) for e, r in engine_results.items() if r.get("category") in ("malicious", "suspicious")]
    return {
        "hash": data.get("id"),
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "total_engines": total,
        "positives": positives,
        "vt_data_url": attributes.get("last_submission_date") and f"https://www.virustotal.com/gui/file/{data.get('id')}/detection"
    }


def main():
    p = argparse.ArgumentParser(description="Query VirusTotal for a file hash")
    p.add_argument("hash", help="File hash (md5/sha1/sha256)")
    p.add_argument("--json", action="store_true", help="Print full JSON response")
    p.add_argument("--short", action="store_true", help="Print a short one-line summary")
    args = p.parse_args()

    api_key = get_api_key()
    if not api_key:
        print("Error: VirusTotal API key not found. Set VT_API_KEY or create /var/ossec/etc/vt_api.key", file=sys.stderr)
        sys.exit(2)

    try:
        resp = query_vt(args.hash, api_key)
    except Exception as e:
        print(f"Error querying VirusTotal: {e}", file=sys.stderr)
        sys.exit(3)

    if args.json:
        print(json.dumps(resp))
        return

    summary = summarize(resp)
    if args.short:
        print(f"{summary['hash']}: {summary['malicious']} malicious / {summary['total_engines']} engines")
        return

    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
