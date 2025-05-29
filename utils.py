import re
from html import unescape

def parse_csp_policy_data(policy_data):
    """
    Parse Content Security Policy data and make it human readable
    """
    if not policy_data or not isinstance(policy_data, dict):
        return []

    # Map of technical keys to human-readable names
    csp_tests = {
        'antiClickjacking': 'Clickjacking Protection',
        'defaultNone': 'Default Deny Policy',
        'insecureBaseUri': 'Base URI Security',
        'insecureFormAction': 'Form Action Security',
        'insecureSchemeActive': 'Active Content Security (HTTPS)',
        'insecureSchemePassive': 'Passive Content Security (HTTPS)',
        'strictDynamic': 'Strict Dynamic Loading',
        'unsafeEval': 'JavaScript eval() Protection',
        'unsafeInline': 'Inline JavaScript Protection',
        'unsafeInlineStyle': 'Inline Style Protection',
        'unsafeObjects': 'Plugin Execution Protection'
    }

    parsed_tests = []

    for key, data in policy_data.items():
        if key in csp_tests:
            test_info = {
                'name': csp_tests[key],
                'technical_name': key,
                'pass': data.get('pass'),
                'description': clean_html_tags(data.get('description', '')),
                'info': clean_html_tags(data.get('info', '')),
                'status': get_status_from_pass(data.get('pass'))
            }
            parsed_tests.append(test_info)

    return parsed_tests

def clean_html_tags(text):
    """
    Remove HTML tags and convert HTML entities to plain text
    """
    if not text:
        return ''

    # Remove HTML tags
    clean_text = re.sub(r'<[^>]+>', '', text)

    # Convert HTML entities
    clean_text = unescape(clean_text)

    return clean_text.strip()

def get_status_from_pass(pass_value):
    """
    Convert pass boolean to human readable status
    """
    if pass_value is True:
        return 'Passed'
    elif pass_value is False:
        return 'Failed'
    else:
        return 'Info'

def get_status_badge_class(pass_value):
    """Get Bootstrap badge class for CSP test status"""
    if pass_value is True:
        return 'bg-success'
    elif pass_value is False:
        return 'bg-danger'
    else:
        return 'bg-secondary'

def parse_csp_policy_raw_data(raw_data):
    """
    Parse raw CSP policy data from attached file format into human readable format
    """
    if not raw_data or not isinstance(raw_data, dict):
        return []

    # Map of technical keys to human-readable names and status mapping
    csp_tests_map = {
        'antiClickjacking': 'Clickjacking Protection',
        'defaultNone': 'Default Deny Policy', 
        'insecureBaseUri': 'Base URI Security',
        'insecureFormAction': 'Form Action Security',
        'insecureSchemeActive': 'Active Content Security (HTTPS)',
        'insecureSchemePassive': 'Passive Content Security (HTTPS)', 
        'strictDynamic': 'Strict Dynamic Loading',
        'unsafeEval': 'JavaScript eval() Protection',
        'unsafeInline': 'Inline JavaScript Protection',
        'unsafeInlineStyle': 'Inline Style Protection'
    }

    parsed_tests = []

    for key, data in raw_data.items():
        if key in csp_tests_map and isinstance(data, dict):
            test_info = {
                'name': csp_tests_map[key],
                'technical_name': key,
                'pass': data.get('pass'),
                'description': clean_html_tags(data.get('description', '')),
                'info': clean_html_tags(data.get('info', '')),
                'status': 'Passed' if data.get('pass') is True else 'Failed' if data.get('pass') is False else 'N/A'
            }
            parsed_tests.append(test_info)

    return parsed_tests