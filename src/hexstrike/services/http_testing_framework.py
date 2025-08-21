"""
HTTP testing framework service (Burp Suite alternative).

This module changes when HTTP testing capabilities or proxy features change.
"""

from typing import Dict, Any, List, Optional
import requests
import logging
from datetime import datetime
from ..interfaces.visual_engine import ModernVisualEngine

logger = logging.getLogger(__name__)

class HTTPTestingFramework:
    """Advanced HTTP testing framework as Burp Suite alternative"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)'
        })
        self.proxy_history = []
        self.vulnerabilities = []
        self.match_replace_rules = []
        self.scope = None
        self._req_id = 0
        
    def setup_proxy(self, proxy_port: int = 8080):
        """Setup HTTP proxy for request interception"""
        self.session.proxies = {
            'http': f'http://127.0.0.1:{proxy_port}',
            'https': f'http://127.0.0.1:{proxy_port}'
        }
        
    def intercept_request(self, url: str, method: str = 'GET', data: dict = None, 
                         headers: dict = None, cookies: dict = None) -> dict:
        """Intercept and analyze HTTP requests"""
        try:
            if headers:
                self.session.headers.update(headers)
            if cookies:
                self.session.cookies.update(cookies)

            url, data, send_headers = self._apply_match_replace(url, data, dict(self.session.headers))
            if headers:
                send_headers.update(headers)
                
            if method.upper() == 'GET':
                response = self.session.get(url, params=data, headers=send_headers, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'PUT':
                response = self.session.put(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=send_headers, timeout=30)
            else:
                response = self.session.request(method, url, data=data, headers=send_headers, timeout=30)
            
            self._req_id += 1
            request_data = {
                'id': self._req_id,
                'url': url,
                'method': method,
                'headers': dict(response.request.headers),
                'data': data,
                'timestamp': datetime.now().isoformat()
            }
            
            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:10000],
                'size': len(response.content),
                'time': response.elapsed.total_seconds()
            }
            
            self.proxy_history.append({
                'request': request_data,
                'response': response_data
            })
            
            self._analyze_response_for_vulns(url, response)
            
            return {
                'success': True,
                'request': request_data,
                'response': response_data,
                'vulnerabilities': self._get_recent_vulns()
            }
            
        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
            return {'success': False, 'error': str(e)}

    def set_match_replace_rules(self, rules: list):
        """Set match/replace rules"""
        self.match_replace_rules = rules or []

    def set_scope(self, host: str, include_subdomains: bool = True):
        self.scope = {'host': host, 'include_subdomains': include_subdomains}

    def _in_scope(self, url: str) -> bool:
        """Check if URL is in scope"""
        if not self.scope:
            return True
        
        host = self.scope['host']
        if self.scope['include_subdomains']:
            return host in url or url.endswith(f".{host}")
        else:
            return host in url

    def _apply_match_replace(self, url: str, data: dict, headers: dict) -> tuple:
        """Apply match/replace rules"""
        modified_url = url
        modified_data = data or {}
        modified_headers = headers or {}
        
        for rule in self.match_replace_rules:
            where = rule.get('where', 'url')
            pattern = rule.get('pattern', '')
            replacement = rule.get('replacement', '')
            
            if where == 'url':
                modified_url = modified_url.replace(pattern, replacement)
            elif where == 'headers' and pattern in str(modified_headers):
                for key, value in modified_headers.items():
                    if pattern in str(value):
                        modified_headers[key] = str(value).replace(pattern, replacement)
            elif where == 'body' and pattern in str(modified_data):
                for key, value in modified_data.items():
                    if pattern in str(value):
                        modified_data[key] = str(value).replace(pattern, replacement)
        
        return modified_url, modified_data, modified_headers

    def _analyze_response_for_vulns(self, url: str, response):
        """Analyze response for potential vulnerabilities"""
        vulns = []
        
        if response.status_code == 500:
            vulns.append({
                'type': 'error_disclosure',
                'severity': 'low',
                'url': url,
                'description': 'Server error may disclose sensitive information'
            })
        
        if 'sql' in response.text.lower() and 'error' in response.text.lower():
            vulns.append({
                'type': 'sql_injection',
                'severity': 'high',
                'url': url,
                'description': 'Potential SQL injection vulnerability detected'
            })
        
        if '<script>' in response.text.lower():
            vulns.append({
                'type': 'xss',
                'severity': 'medium',
                'url': url,
                'description': 'Potential XSS vulnerability detected'
            })
        
        self.vulnerabilities.extend(vulns)

    def _get_recent_vulns(self) -> List[Dict[str, Any]]:
        """Get recent vulnerabilities"""
        return self.vulnerabilities[-5:]

    def get_proxy_history(self) -> List[Dict[str, Any]]:
        """Get proxy history"""
        return self.proxy_history

    def clear_history(self):
        """Clear proxy history"""
        self.proxy_history.clear()
        self.vulnerabilities.clear()

    def export_session(self) -> Dict[str, Any]:
        """Export session data"""
        return {
            'proxy_history': self.proxy_history,
            'vulnerabilities': self.vulnerabilities,
            'scope': self.scope,
            'match_replace_rules': self.match_replace_rules
        }

    def import_session(self, session_data: Dict[str, Any]):
        """Import session data"""
        self.proxy_history = session_data.get('proxy_history', [])
        self.vulnerabilities = session_data.get('vulnerabilities', [])
        self.scope = session_data.get('scope')
        self.match_replace_rules = session_data.get('match_replace_rules', [])

class BrowserAgent:
    """AI-powered browser agent for web application inspection"""
    
    def __init__(self):
        self.session = requests.Session()
        self.current_page = None
        self.page_history = []
        self.extracted_data = {}
        
    def navigate_to(self, url: str) -> Dict[str, Any]:
        """Navigate to URL and analyze page"""
        try:
            response = self.session.get(url, timeout=30)
            
            page_data = {
                'url': url,
                'status_code': response.status_code,
                'title': self._extract_title(response.text),
                'forms': self._extract_forms(response.text),
                'links': self._extract_links(response.text),
                'scripts': self._extract_scripts(response.text),
                'timestamp': datetime.now().isoformat()
            }
            
            self.current_page = page_data
            self.page_history.append(page_data)
            
            return {
                'success': True,
                'page_data': page_data,
                'analysis': self._analyze_page(page_data)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _extract_title(self, html: str) -> str:
        """Extract page title"""
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1) if match else "No title"

    def _extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        import re
        forms = []
        form_matches = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        
        for form_html in form_matches:
            inputs = re.findall(r'<input[^>]*>', form_html, re.IGNORECASE)
            forms.append({
                'inputs': len(inputs),
                'html': form_html[:500]
            })
        
        return forms

    def _extract_links(self, html: str) -> List[str]:
        """Extract links from HTML"""
        import re
        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        return list(set(links))[:20]

    def _extract_scripts(self, html: str) -> List[str]:
        """Extract script sources"""
        import re
        scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        return list(set(scripts))

    def _analyze_page(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze page for security issues"""
        analysis = {
            'security_headers': [],
            'potential_issues': [],
            'interesting_endpoints': []
        }
        
        if page_data['forms']:
            analysis['potential_issues'].append('Forms detected - test for injection vulnerabilities')
        
        if page_data['scripts']:
            analysis['potential_issues'].append('External scripts detected - analyze for vulnerabilities')
        
        admin_keywords = ['admin', 'login', 'dashboard', 'panel']
        for link in page_data['links']:
            if any(keyword in link.lower() for keyword in admin_keywords):
                analysis['interesting_endpoints'].append(link)
        
        return analysis

    def get_page_analysis(self) -> Dict[str, Any]:
        """Get comprehensive page analysis"""
        if not self.current_page:
            return {'error': 'No page loaded'}
        
        return {
            'current_page': self.current_page,
            'page_count': len(self.page_history),
            'extracted_data': self.extracted_data
        }
</new_str>
