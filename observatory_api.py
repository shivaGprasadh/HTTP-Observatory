import requests
import logging
import time
from urllib.parse import urljoin, quote
import json
import re
from bs4 import BeautifulSoup

class ObservatoryAPI:
    """Interface to Mozilla HTTP Observatory via MDN Observatory pages"""
    
    BASE_URL = "https://developer.mozilla.org/en-US/observatory/analyze"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site'
        })
    
    def scan_domain(self, hostname):
        """
        Perform a comprehensive security scan of a domain by scraping MDN Observatory pages
        Returns a dictionary with scan results or error information
        """
        try:
            # Get main scoring page
            main_url = f"{self.BASE_URL}?host={quote(hostname)}"
            response = self.session.get(main_url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract security score and grade
            score, grade = self._extract_score_and_grade(soup)
            
            # Get CSP issues
            csp_issues = self._get_csp_issues(hostname)
            
            # Get cookie issues  
            cookie_issues = self._get_cookie_issues(hostname)
            
            # Get header issues
            header_issues = self._get_header_issues(hostname)
            
            return {
                'status': 'success',
                'score': score,
                'grade': grade,
                'csp_issues': csp_issues,
                'cookie_issues': cookie_issues,
                'header_issues': header_issues
            }
            
        except Exception as e:
            logging.error(f"Error scanning {hostname}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _extract_score_and_grade(self, soup):
        """Extract security score and grade from main page"""
        score = None
        grade = None
        
        try:
            # Look for score in various possible selectors
            score_selectors = [
                '.score', '.security-score', '[data-score]', 
                '.grade-score', '.total-score'
            ]
            
            for selector in score_selectors:
                score_elem = soup.select_one(selector)
                if score_elem:
                    score_text = score_elem.get_text(strip=True)
                    score_match = re.search(r'(\d+)', score_text)
                    if score_match:
                        score = int(score_match.group(1))
                        break
            
            # Look for grade
            grade_selectors = [
                '.grade', '.security-grade', '[data-grade]',
                '.letter-grade', '.overall-grade'
            ]
            
            for selector in grade_selectors:
                grade_elem = soup.select_one(selector)
                if grade_elem:
                    grade_text = grade_elem.get_text(strip=True)
                    grade_match = re.search(r'([A-F][+\-]?)', grade_text)
                    if grade_match:
                        grade = grade_match.group(1)
                        break
                        
        except Exception as e:
            logging.warning(f"Error extracting score/grade: {str(e)}")
            
        return score, grade
    
    def _get_csp_issues(self, hostname):
        """Extract CSP-related security issues from CSP page"""
        issues = []
        try:
            csp_url = f"{self.BASE_URL}?host={quote(hostname)}#csp"
            response = self.session.get(csp_url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Look for CSP issues in various selectors
            issue_selectors = [
                '.csp-issue', '.security-issue', '.test-fail',
                '.warning', '.error', '.issue'
            ]
            
            for selector in issue_selectors:
                elements = soup.select(selector)
                for elem in elements:
                    text = elem.get_text(strip=True)
                    if 'csp' in text.lower() or 'content-security-policy' in text.lower():
                        issues.append({
                            'test': 'CSP Issue',
                            'score_description': text,
                            'score_modifier': -5
                        })
                        
        except Exception as e:
            logging.warning(f"Error getting CSP issues: {str(e)}")
            
        return issues
    
    def _get_cookie_issues(self, hostname):
        """Extract cookie-related security issues from cookies page"""
        issues = []
        try:
            cookie_url = f"{self.BASE_URL}?host={quote(hostname)}#cookies"
            response = self.session.get(cookie_url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Look for cookie issues
            issue_selectors = [
                '.cookie-issue', '.security-issue', '.test-fail',
                '.warning', '.error', '.issue'
            ]
            
            for selector in issue_selectors:
                elements = soup.select(selector)
                for elem in elements:
                    text = elem.get_text(strip=True)
                    if 'cookie' in text.lower() or 'secure' in text.lower() or 'httponly' in text.lower():
                        issues.append({
                            'test': 'Cookie Security Issue',
                            'score_description': text,
                            'score_modifier': -3
                        })
                        
        except Exception as e:
            logging.warning(f"Error getting cookie issues: {str(e)}")
            
        return issues
    
    def _get_header_issues(self, hostname):
        """Extract header-related security issues from headers page"""
        issues = []
        try:
            header_url = f"{self.BASE_URL}?host={quote(hostname)}#headers"
            response = self.session.get(header_url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Look for header issues
            issue_selectors = [
                '.header-issue', '.security-issue', '.test-fail',
                '.warning', '.error', '.issue'
            ]
            
            for selector in issue_selectors:
                elements = soup.select(selector)
                for elem in elements:
                    text = elem.get_text(strip=True)
                    if any(header in text.lower() for header in ['header', 'hsts', 'x-frame', 'x-content']):
                        issues.append({
                            'test': 'HTTP Header Issue',
                            'score_description': text,
                            'score_modifier': -2
                        })
                        
        except Exception as e:
            logging.warning(f"Error getting header issues: {str(e)}")
            
        return issues
    
    def _wait_for_scan_completion(self, scan_id, max_attempts=30, delay=2):
        """Wait for scan to complete"""
        for attempt in range(max_attempts):
            try:
                url = urljoin(self.BASE_URL, f"getScanResults?scan={scan_id}")
                response = self.session.get(url)
                response.raise_for_status()
                
                data = response.json()
                
                if data.get('state') == 'FINISHED':
                    return {
                        'status': 'success',
                        'data': data
                    }
                elif data.get('state') == 'FAILED':
                    return {
                        'status': 'error',
                        'error': 'Scan failed'
                    }
                
                time.sleep(delay)
                
            except Exception as e:
                logging.warning(f"Error checking scan status (attempt {attempt + 1}): {str(e)}")
                time.sleep(delay)
        
        return {
            'status': 'error',
            'error': 'Scan timeout - took too long to complete'
        }
    
    def _get_detailed_results(self, hostname, scan_id):
        """Get detailed scan results"""
        results = {
            'score': None,
            'grade': None,
            'csp_issues': [],
            'cookie_issues': [],
            'header_issues': []
        }
        
        try:
            # Get basic scan results
            basic_url = urljoin(self.BASE_URL, f"getScanResults?scan={scan_id}")
            response = self.session.get(basic_url)
            response.raise_for_status()
            data = response.json()
            
            results['score'] = data.get('score')
            results['grade'] = data.get('grade')
            
            # Get CSP results
            csp_results = self._get_csp_results(hostname)
            results['csp_issues'] = csp_results
            
            # Get cookie results
            cookie_results = self._get_cookie_results(hostname)
            results['cookie_issues'] = cookie_results
            
            # Get header results
            header_results = self._get_header_results(hostname)
            results['header_issues'] = header_results
            
        except Exception as e:
            logging.error(f"Error getting detailed results: {str(e)}")
        
        return results
    
    def _get_csp_results(self, hostname):
        """Extract CSP-related security issues"""
        issues = []
        try:
            url = urljoin(self.BASE_URL, f"getScanHistory?host={quote(hostname)}")
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            # Look for CSP-related test results
            for scan in data:
                if 'tests' in scan:
                    for test_name, test_result in scan['tests'].items():
                        if 'csp' in test_name.lower():
                            if test_result.get('pass') == False:
                                issues.append({
                                    'test': test_name,
                                    'score_modifier': test_result.get('score_modifier', 0),
                                    'score_description': test_result.get('score_description', '')
                                })
                break  # Only check the latest scan
                
        except Exception as e:
            logging.error(f"Error getting CSP results: {str(e)}")
        
        return issues
    
    def _get_cookie_results(self, hostname):
        """Extract cookie-related security issues"""
        issues = []
        try:
            url = urljoin(self.BASE_URL, f"getScanHistory?host={quote(hostname)}")
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            for scan in data:
                if 'tests' in scan:
                    for test_name, test_result in scan['tests'].items():
                        if 'cookie' in test_name.lower():
                            if test_result.get('pass') == False:
                                issues.append({
                                    'test': test_name,
                                    'score_modifier': test_result.get('score_modifier', 0),
                                    'score_description': test_result.get('score_description', '')
                                })
                break
                
        except Exception as e:
            logging.error(f"Error getting cookie results: {str(e)}")
        
        return issues
    
    def _get_header_results(self, hostname):
        """Extract header-related security issues"""
        issues = []
        try:
            url = urljoin(self.BASE_URL, f"getScanHistory?host={quote(hostname)}")
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            for scan in data:
                if 'tests' in scan:
                    for test_name, test_result in scan['tests'].items():
                        if any(header in test_name.lower() for header in ['header', 'hsts', 'x-frame', 'x-content']):
                            if test_result.get('pass') == False:
                                issues.append({
                                    'test': test_name,
                                    'score_modifier': test_result.get('score_modifier', 0),
                                    'score_description': test_result.get('score_description', '')
                                })
                break
                
        except Exception as e:
            logging.error(f"Error getting header results: {str(e)}")
        
        return issues
    
    def get_scan_history(self, hostname):
        """Get scan history for a domain"""
        try:
            url = urljoin(self.BASE_URL, f"getScanHistory?host={quote(hostname)}")
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logging.error(f"Error getting scan history: {str(e)}")
            return []
