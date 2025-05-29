
import requests
import logging
import time
from urllib.parse import urljoin, quote
import json
import re
from bs4 import BeautifulSoup

class ObservatoryAPI:
    """Interface to Mozilla HTTP Observatory via API"""

    BASE_URL = "https://developer.mozilla.org/en-US/observatory/analyze"
    API_BASE_URL = "https://observatory-api.mdn.mozilla.net/api/v2"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
        })

    def scan_domain(self, hostname):
        """
        Perform a comprehensive security scan of a domain
        Returns a dictionary with scan results or error information
        """
        try:
            logging.info(f"Starting scan for {hostname}")

            # Step 1: Trigger scan by loading MDN Observatory page
            trigger_url = f"{self.BASE_URL}?host={quote(hostname)}"
            logging.info(f"Triggering scan at: {trigger_url}")
            
            trigger_response = self.session.get(trigger_url, timeout=30)
            trigger_response.raise_for_status()
            
            # Wait a moment for scan to initiate
            time.sleep(2)

            # Step 2: Fetch data from API endpoint
            api_url = f"{self.API_BASE_URL}/analyze?host={quote(hostname)}"
            logging.info(f"Fetching data from API: {api_url}")
            
            api_response = self.session.get(api_url, timeout=30)
            api_response.raise_for_status()
            
            data = api_response.json()
            logging.info(f"API response received for {hostname}")

            # Parse the API response
            return self._parse_api_response(data, hostname)

        except requests.exceptions.RequestException as e:
            logging.error(f"Network error scanning {hostname}: {str(e)}")
            return {
                'status': 'error',
                'error': f'Network error: {str(e)}'
            }
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error for {hostname}: {str(e)}")
            return {
                'status': 'error',
                'error': f'Invalid API response: {str(e)}'
            }
        except Exception as e:
            logging.error(f"Error scanning {hostname}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def _parse_api_response(self, data, hostname):
        """Parse the API response and extract security information"""
        try:
            # Extract basic information
            scan_info = data.get('scan', {})
            score = scan_info.get('score', 0)
            grade = scan_info.get('grade', 'F')
            
            # Extract test results
            tests = data.get('tests', {})
            
            # Parse all test details
            test_results = self._extract_all_test_details(tests)
            
            # Extract response headers and cookies information
            response_headers = scan_info.get('response_headers', {})
            
            # Extract cookies information from the tests data
            cookies_data = {}
            if 'cookies' in tests:
                cookies_test = tests['cookies']
                # Extract detailed cookie information if available
                if 'cookies' in cookies_test:
                    cookies_data = cookies_test['cookies']
            
            # Extract policy information from various tests
            policy_data = self._extract_policy_data(tests, response_headers)
            
            # Combine scan info with additional data
            enhanced_scan_info = {
                'response_headers': response_headers,
                'cookies': cookies_data,
                'policy': policy_data,
                'scan_id': scan_info.get('scan_id'),
                'start_time': scan_info.get('start_time'),
                'end_time': scan_info.get('end_time'),
                'state': scan_info.get('state')
            }
            
            logging.info(f"Parsed data for {hostname} - Score: {score}, Grade: {grade}")
            logging.info(f"Total tests found: {len(test_results)}")
            logging.info(f"Response headers found: {len(response_headers)}")
            logging.info(f"Cookies found: {len(cookies_data)}")

            return {
                'status': 'success',
                'score': score,
                'grade': grade,
                'test_results': test_results,
                'scan_info': enhanced_scan_info
            }

        except Exception as e:
            logging.error(f"Error parsing API response for {hostname}: {str(e)}")
            return {
                'status': 'error',
                'error': f'Error parsing response: {str(e)}'
            }

    def _extract_all_test_details(self, tests):
        """Extract all test details from the API response"""
        test_results = []
        
        # Define test mapping with display names
        test_mapping = {
            'content-security-policy': 'Content Security Policy (CSP)',
            'cookies': 'Cookies',
            'cross-origin-resource-sharing': 'Cross Origin Resource Sharing (CORS)',
            'redirection': 'Redirection',
            'referrer-policy': 'Referrer Policy',
            'strict-transport-security': 'Strict Transport Security (HSTS)',
            'subresource-integrity': 'Subresource Integrity',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-frame-options': 'X-Frame-Options',
            'cross-origin-resource-policy': 'Cross Origin Resource Policy'
        }
        
        for test_key, test_name in test_mapping.items():
            test_data = tests.get(test_key, {})
            if test_data:
                score_modifier = test_data.get('score_modifier', 0)
                result = test_data.get('result', '')
                pass_status = test_data.get('pass')
                
                # Determine status
                if pass_status is True:
                    status = 'Passed'
                elif pass_status is False:
                    status = 'Failed'
                else:
                    status = 'Info'
                
                # Clean up score description and recommendation
                score_description = test_data.get('score_description', '')
                recommendation = test_data.get('recommendation', '')
                
                # Remove HTML tags from descriptions
                if score_description:
                    score_description = re.sub(r'<[^>]+>', '', score_description).strip()
                    score_description = re.sub(r'\s+', ' ', score_description)
                
                if recommendation:
                    recommendation = re.sub(r'<[^>]+>', '', recommendation).strip()
                    recommendation = re.sub(r'\s+', ' ', recommendation)
                
                # Handle special cases for display
                if score_modifier == 0 and status == 'Passed':
                    if 'preload' in score_description.lower():
                        score_display = '0*'
                    else:
                        score_display = '0'
                elif score_modifier == 0 and test_key in ['cookies', 'subresource-integrity']:
                    score_display = '-'
                else:
                    score_display = str(score_modifier) if score_modifier != 0 else '0'
                
                test_results.append({
                    'test_name': test_name,
                    'score': score_modifier,
                    'score_display': score_display,
                    'status': status,
                    'result': result,
                    'score_description': score_description or 'No description available',
                    'recommendation': recommendation or 'None',
                    'pass': pass_status
                })
        
        return test_results

    def _extract_policy_data(self, tests, response_headers):
        """Extract policy information from test results and headers"""
        policy_data = {}
        
        # Extract CSP policy
        if 'content-security-policy' in tests:
            csp_test = tests['content-security-policy']
            policy_data['content_security_policy'] = {
                'present': csp_test.get('pass', False),
                'policy': csp_test.get('policy', ''),
                'score_description': csp_test.get('score_description', ''),
                'recommendation': csp_test.get('recommendation', '')
            }
        
        # Extract HSTS policy
        if 'strict-transport-security' in tests:
            hsts_test = tests['strict-transport-security']
            policy_data['strict_transport_security'] = {
                'present': hsts_test.get('pass', False),
                'policy': hsts_test.get('policy', ''),
                'max_age': hsts_test.get('max-age', ''),
                'include_subdomains': hsts_test.get('includeSubDomains', False),
                'preload': hsts_test.get('preload', False),
                'score_description': hsts_test.get('score_description', ''),
                'recommendation': hsts_test.get('recommendation', '')
            }
        
        # Extract Referrer Policy
        if 'referrer-policy' in tests:
            referrer_test = tests['referrer-policy']
            policy_data['referrer_policy'] = {
                'present': referrer_test.get('pass', False),
                'policy': referrer_test.get('policy', ''),
                'score_description': referrer_test.get('score_description', ''),
                'recommendation': referrer_test.get('recommendation', '')
            }
        
        # Extract CORS policy
        if 'cross-origin-resource-sharing' in tests:
            cors_test = tests['cross-origin-resource-sharing']
            policy_data['cors_policy'] = {
                'present': cors_test.get('pass', False),
                'policy': cors_test.get('policy', ''),
                'acao': cors_test.get('acao', ''),
                'acah': cors_test.get('acah', ''),
                'score_description': cors_test.get('score_description', ''),
                'recommendation': cors_test.get('recommendation', '')
            }
        
        # Extract Cross-Origin Resource Policy
        if 'cross-origin-resource-policy' in tests:
            corp_test = tests['cross-origin-resource-policy']
            policy_data['cross_origin_resource_policy'] = {
                'present': corp_test.get('pass', False),
                'policy': corp_test.get('policy', ''),
                'score_description': corp_test.get('score_description', ''),
                'recommendation': corp_test.get('recommendation', '')
            }
        
        # Extract policies from response headers
        policy_headers = {
            'Content-Security-Policy': response_headers.get('content-security-policy', ''),
            'Strict-Transport-Security': response_headers.get('strict-transport-security', ''),
            'Referrer-Policy': response_headers.get('referrer-policy', ''),
            'Cross-Origin-Resource-Policy': response_headers.get('cross-origin-resource-policy', ''),
            'Cross-Origin-Embedder-Policy': response_headers.get('cross-origin-embedder-policy', ''),
            'Cross-Origin-Opener-Policy': response_headers.get('cross-origin-opener-policy', ''),
            'X-Frame-Options': response_headers.get('x-frame-options', ''),
            'X-Content-Type-Options': response_headers.get('x-content-type-options', ''),
            'X-XSS-Protection': response_headers.get('x-xss-protection', '')
        }
        
        policy_data['response_headers'] = policy_headers
        
        return policy_data

    def get_scan_history(self, hostname):
        """Get scan history for a domain from API"""
        try:
            history_url = f"{self.API_BASE_URL}/getScanHistory?host={quote(hostname)}"
            response = self.session.get(history_url, timeout=30)
            response.raise_for_status()
            
            return response.json()

        except Exception as e:
            logging.error(f"Error getting scan history for {hostname}: {str(e)}")
            return []

    def get_benchmark_comparison(self, hostname):
        """Get benchmark comparison data"""
        try:
            # The API doesn't have a direct benchmark endpoint, so we'll return basic info
            return {
                'comparison_available': True,
                'details': f'Benchmark data available via Observatory API for {hostname}'
            }

        except Exception as e:
            logging.error(f"Error getting benchmark comparison for {hostname}: {str(e)}")
            return {}
