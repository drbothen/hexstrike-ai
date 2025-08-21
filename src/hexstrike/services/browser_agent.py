"""
AI-powered browser agent for web application testing and inspection.

This module changes when browser automation or web testing strategies change.
"""

import logging
import time
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class BrowserAgent:
    """AI-powered browser agent for web application testing and inspection"""
    
    def __init__(self):
        self.driver = None
        self.current_url = None
        self.test_results = []
        
    def setup_browser(self, headless: bool = True, proxy: str = None) -> bool:
        """Setup browser with security testing configurations"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
            
            chrome_options = Options()
            if headless:
                chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--user-agent=HexStrike-Browser-Agent/1.0')
            
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            
            if proxy:
                chrome_options.add_argument(f'--proxy-server={proxy}')
            
            # Enable logging
            caps = DesiredCapabilities.CHROME
            caps['goog:loggingPrefs'] = {'performance': 'ALL', 'browser': 'ALL'}
            
            self.driver = webdriver.Chrome(options=chrome_options, desired_capabilities=caps)
            self.driver.set_page_load_timeout(30)
            
            logger.info("🌐 Browser agent initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to setup browser: {str(e)}")
            return False
    
    def navigate_and_inspect(self, url: str) -> Dict[str, Any]:
        """Navigate to URL and perform comprehensive security inspection"""
        if not self.driver:
            return {'success': False, 'error': 'Browser not initialized'}
        
        try:
            from hexstrike_server import ModernVisualEngine
            
            logger.info(f"🔍 Navigating to: {url}")
            self.driver.get(url)
            self.current_url = url
            
            time.sleep(3)
            
            inspection_results = {
                'url': url,
                'title': self.driver.title,
                'page_source_length': len(self.driver.page_source),
                'console_errors': self._get_console_errors(),
                'cookies': self._analyze_cookies(),
                'security_headers': self._analyze_security_headers(),
                'mixed_content': self._detect_mixed_content(),
                'forms': self._extract_forms(),
                'links': self._extract_links(),
                'inputs': self._extract_inputs(),
                'scripts': self._extract_scripts(),
                'network_logs': self._get_network_logs(),
                'security_analysis': self._analyze_page_security(),
                'passive_findings': self._extended_passive_analysis()
            }
            
            self.test_results.append(inspection_results)
            
            return {
                'success': True,
                'results': inspection_results,
                'summary': f"Inspected {url} - Found {len(inspection_results.get('forms', []))} forms, {len(inspection_results.get('inputs', []))} inputs"
            }
            
        except Exception as e:
            logger.error(f"❌ Navigation failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _get_console_errors(self) -> List[Dict[str, Any]]:
        """Extract console errors and warnings"""
        try:
            logs = self.driver.get_log('browser')
            errors = []
            for log in logs:
                if log['level'] in ['SEVERE', 'WARNING']:
                    errors.append({
                        'level': log['level'],
                        'message': log['message'],
                        'timestamp': log['timestamp']
                    })
            return errors
        except Exception:
            return []
    
    def _analyze_cookies(self) -> Dict[str, Any]:
        """Analyze cookies for security issues"""
        try:
            cookies = self.driver.get_cookies()
            analysis = {
                'total_cookies': len(cookies),
                'insecure_cookies': [],
                'missing_flags': []
            }
            
            for cookie in cookies:
                if not cookie.get('secure', False):
                    analysis['insecure_cookies'].append(cookie['name'])
                if not cookie.get('httpOnly', False):
                    analysis['missing_flags'].append(f"{cookie['name']} missing HttpOnly")
                if not cookie.get('sameSite'):
                    analysis['missing_flags'].append(f"{cookie['name']} missing SameSite")
            
            return analysis
        except Exception:
            return {'total_cookies': 0, 'insecure_cookies': [], 'missing_flags': []}
    
    def _analyze_security_headers(self) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        try:
            headers_script = """
            var req = new XMLHttpRequest();
            req.open('HEAD', document.location, false);
            req.send(null);
            return req.getAllResponseHeaders();
            """
            
            headers_text = self.driver.execute_script(headers_script)
            headers = {}
            
            for line in headers_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            security_headers = {
                'x-frame-options': headers.get('x-frame-options'),
                'x-content-type-options': headers.get('x-content-type-options'),
                'x-xss-protection': headers.get('x-xss-protection'),
                'strict-transport-security': headers.get('strict-transport-security'),
                'content-security-policy': headers.get('content-security-policy')
            }
            
            missing_headers = [k for k, v in security_headers.items() if not v]
            
            return {
                'headers': security_headers,
                'missing_headers': missing_headers,
                'security_score': (5 - len(missing_headers)) * 20
            }
            
        except Exception:
            return {'headers': {}, 'missing_headers': [], 'security_score': 0}
    
    def _detect_mixed_content(self) -> List[str]:
        """Detect mixed content issues"""
        try:
            if not self.current_url.startswith('https://'):
                return []
            
            mixed_content = []
            
            http_resources = self.driver.execute_script("""
                var resources = [];
                var scripts = document.getElementsByTagName('script');
                var images = document.getElementsByTagName('img');
                var links = document.getElementsByTagName('link');
                
                for (var i = 0; i < scripts.length; i++) {
                    if (scripts[i].src && scripts[i].src.startsWith('http://')) {
                        resources.push('script: ' + scripts[i].src);
                    }
                }
                
                for (var i = 0; i < images.length; i++) {
                    if (images[i].src && images[i].src.startsWith('http://')) {
                        resources.push('image: ' + images[i].src);
                    }
                }
                
                return resources;
            """)
            
            return http_resources or []
            
        except Exception:
            return []
    
    def _extended_passive_analysis(self) -> Dict[str, Any]:
        """Extended passive security analysis"""
        try:
            findings = {
                'sensitive_data_exposure': [],
                'information_disclosure': [],
                'client_side_vulnerabilities': []
            }
            
            page_source = self.driver.page_source.lower()
            
            sensitive_patterns = [
                ('password', 'Password field detected'),
                ('api_key', 'API key reference found'),
                ('secret', 'Secret reference found'),
                ('token', 'Token reference found'),
                ('admin', 'Admin interface detected')
            ]
            
            for pattern, description in sensitive_patterns:
                if pattern in page_source:
                    findings['sensitive_data_exposure'].append(description)
            
            disclosure_patterns = [
                ('debug', 'Debug information exposed'),
                ('error', 'Error messages exposed'),
                ('exception', 'Exception details exposed'),
                ('stack trace', 'Stack trace exposed')
            ]
            
            for pattern, description in disclosure_patterns:
                if pattern in page_source:
                    findings['information_disclosure'].append(description)
            
            return findings
            
        except Exception:
            return {'sensitive_data_exposure': [], 'information_disclosure': [], 'client_side_vulnerabilities': []}
    
    def run_active_tests(self, target_forms: List[Dict] = None) -> Dict[str, Any]:
        """Run active security tests on forms and inputs"""
        if not self.driver:
            return {'success': False, 'error': 'Browser not initialized'}
        
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            
            test_results = {
                'xss_tests': [],
                'sql_injection_tests': [],
                'form_tests': []
            }
            
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>"
            ]
            
            sql_payloads = [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM information_schema.tables --"
            ]
            
            forms = target_forms or self._extract_forms()
            
            for form in forms[:3]:  # Limit to first 3 forms
                for payload in xss_payloads[:2]:  # Limit payloads
                    try:
                        inputs = self.driver.find_elements(By.TAG_NAME, "input")
                        for input_elem in inputs[:2]:  # Limit inputs
                            if input_elem.get_attribute('type') in ['text', 'search', 'email']:
                                input_elem.clear()
                                input_elem.send_keys(payload)
                                
                                if payload in self.driver.page_source:
                                    test_results['xss_tests'].append({
                                        'payload': payload,
                                        'reflected': True,
                                        'input_name': input_elem.get_attribute('name')
                                    })
                    except Exception:
                        continue
            
            return {'success': True, 'results': test_results}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _get_local_storage(self) -> Dict[str, Any]:
        """Extract local storage data"""
        try:
            local_storage = self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    storage[key] = localStorage.getItem(key);
                }
                return storage;
            """)
            return local_storage or {}
        except Exception:
            return {}
    
    def _get_session_storage(self) -> Dict[str, Any]:
        """Extract session storage data"""
        try:
            session_storage = self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    storage[key] = sessionStorage.getItem(key);
                }
                return storage;
            """)
            return session_storage or {}
        except Exception:
            return {}
    
    def _extract_forms(self) -> List[Dict[str, Any]]:
        """Extract all forms from the page"""
        try:
            from selenium.webdriver.common.by import By
            
            forms = []
            form_elements = self.driver.find_elements(By.TAG_NAME, "form")
            
            for form in form_elements:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'inputs': []
                }
                
                inputs = form.find_elements(By.TAG_NAME, "input")
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.get_attribute('name') or '',
                        'type': input_elem.get_attribute('type') or 'text',
                        'value': input_elem.get_attribute('value') or ''
                    })
                
                forms.append(form_data)
            
            return forms
        except Exception:
            return []
    
    def _extract_links(self) -> List[str]:
        """Extract all links from the page"""
        try:
            from selenium.webdriver.common.by import By
            
            links = []
            link_elements = self.driver.find_elements(By.TAG_NAME, "a")
            
            for link in link_elements:
                href = link.get_attribute('href')
                if href:
                    links.append(href)
            
            return list(set(links))  # Remove duplicates
        except Exception:
            return []
    
    def _extract_inputs(self) -> List[Dict[str, str]]:
        """Extract all input fields from the page"""
        try:
            from selenium.webdriver.common.by import By
            
            inputs = []
            input_elements = self.driver.find_elements(By.TAG_NAME, "input")
            
            for input_elem in input_elements:
                inputs.append({
                    'name': input_elem.get_attribute('name') or '',
                    'type': input_elem.get_attribute('type') or 'text',
                    'id': input_elem.get_attribute('id') or '',
                    'placeholder': input_elem.get_attribute('placeholder') or ''
                })
            
            return inputs
        except Exception:
            return []
    
    def _extract_scripts(self) -> List[Dict[str, str]]:
        """Extract all script tags from the page"""
        try:
            from selenium.webdriver.common.by import By
            
            scripts = []
            script_elements = self.driver.find_elements(By.TAG_NAME, "script")
            
            for script in script_elements:
                scripts.append({
                    'src': script.get_attribute('src') or '',
                    'type': script.get_attribute('type') or '',
                    'inline': bool(script.get_attribute('innerHTML'))
                })
            
            return scripts
        except Exception:
            return []
    
    def _get_network_logs(self) -> List[Dict[str, Any]]:
        """Extract network logs for analysis"""
        try:
            logs = self.driver.get_log('performance')
            network_logs = []
            
            for log in logs:
                message = log.get('message', {})
                if isinstance(message, str):
                    import json
                    try:
                        message = json.loads(message)
                    except:
                        continue
                
                if message.get('message', {}).get('method') == 'Network.responseReceived':
                    response = message['message']['params']['response']
                    network_logs.append({
                        'url': response.get('url', ''),
                        'status': response.get('status', 0),
                        'mimeType': response.get('mimeType', ''),
                        'headers': response.get('headers', {})
                    })
            
            return network_logs
        except Exception:
            return []
    
    def _analyze_page_security(self) -> Dict[str, Any]:
        """Comprehensive page security analysis"""
        try:
            security_analysis = {
                'https_usage': self.current_url.startswith('https://') if self.current_url else False,
                'local_storage': self._get_local_storage(),
                'session_storage': self._get_session_storage(),
                'mixed_content_issues': len(self._detect_mixed_content()),
                'console_errors': len(self._get_console_errors()),
                'security_score': 0
            }
            
            score = 0
            if security_analysis['https_usage']:
                score += 20
            if security_analysis['mixed_content_issues'] == 0:
                score += 20
            if security_analysis['console_errors'] == 0:
                score += 20
            if len(security_analysis['local_storage']) == 0:
                score += 20
            if len(security_analysis['session_storage']) == 0:
                score += 20
            
            security_analysis['security_score'] = score
            
            return security_analysis
        except Exception:
            return {'https_usage': False, 'security_score': 0}
    
    def close_browser(self):
        """Close the browser and cleanup"""
        if self.driver:
            self.driver.quit()
            self.driver = None
            logger.info("🔒 Browser agent closed")
