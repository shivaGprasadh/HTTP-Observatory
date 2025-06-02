import csv
import io
import json
import logging
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, make_response, jsonify
from app import app, db, scan_results, scan_history
from models import Domain, ScanResult
from observatory_api import ObservatoryAPI
from utils import parse_csp_policy_data, get_status_badge_class

observatory = ObservatoryAPI()

@app.route('/')
def index():
    """Main page showing domain management interface"""
    domains = Domain.query.filter_by(is_active=True).all()
    return render_template('index.html', domains=domains)

@app.route('/add_domain', methods=['POST'])
def add_domain():
    """Add a new domain for scanning"""
    hostname = request.form.get('hostname', '').strip()
    
    if not hostname:
        flash('Please enter a valid hostname', 'error')
        return redirect(url_for('index'))
    
    # Remove protocol if present
    if hostname.startswith(('http://', 'https://')):
        hostname = hostname.split('://', 1)[1]
    
    # Check if domain already exists
    existing_domain = Domain.query.filter_by(hostname=hostname).first()
    if existing_domain:
        if existing_domain.is_active:
            flash(f'Domain {hostname} is already in the list', 'warning')
        else:
            existing_domain.is_active = True
            db.session.commit()
            flash(f'Domain {hostname} has been reactivated', 'success')
        return redirect(url_for('index'))
    
    # Add new domain
    new_domain = Domain(hostname=hostname)
    db.session.add(new_domain)
    db.session.commit()
    
    flash(f'Domain {hostname} added successfully', 'success')
    return redirect(url_for('index'))

@app.route('/bulk_upload_domains', methods=['POST'])
def bulk_upload_domains():
    """Bulk upload domains from a file"""
    if 'domain_file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    file = request.files['domain_file']
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    if not file.filename.lower().endswith(('.txt', '.csv')):
        flash('Please upload a .txt or .csv file', 'error')
        return redirect(url_for('index'))
    
    try:
        # Read file content
        content = file.read().decode('utf-8')
        lines = content.strip().split('\n')
        
        added_count = 0
        skipped_count = 0
        error_count = 0
        
        for line in lines:
            # Handle CSV files - try to extract domain from different columns
            if file.filename.lower().endswith('.csv'):
                # Split by comma and try to find a domain-like string
                parts = [part.strip().strip('"') for part in line.split(',')]
                hostname = None
                for part in parts:
                    # Look for domain-like patterns
                    if part and '.' in part and not part.startswith('http') and len(part) > 3:
                        hostname = part
                        break
                if not hostname and parts:
                    hostname = parts[0].strip().strip('"')
            else:
                # Text file - one domain per line
                hostname = line.strip()
            
            if not hostname or hostname.lower() in ['domain', 'hostname', 'url', 'website']:
                continue  # Skip header rows or empty lines
            
            # Clean up the hostname
            hostname = hostname.strip().lower()
            
            # Remove protocol if present
            if hostname.startswith(('http://', 'https://')):
                hostname = hostname.split('://', 1)[1]
            
            # Remove trailing slash and paths
            hostname = hostname.split('/')[0]
            
            # Basic domain validation
            if not hostname or '.' not in hostname or len(hostname) < 4:
                error_count += 1
                continue
            
            # Check if domain already exists
            existing_domain = Domain.query.filter_by(hostname=hostname).first()
            if existing_domain:
                if existing_domain.is_active:
                    skipped_count += 1
                else:
                    existing_domain.is_active = True
                    added_count += 1
            else:
                # Add new domain
                new_domain = Domain(hostname=hostname)
                db.session.add(new_domain)
                added_count += 1
        
        db.session.commit()
        
        # Provide feedback
        message_parts = []
        if added_count > 0:
            message_parts.append(f"{added_count} domains added")
        if skipped_count > 0:
            message_parts.append(f"{skipped_count} already existed")
        if error_count > 0:
            message_parts.append(f"{error_count} invalid entries skipped")
        
        if added_count > 0:
            flash(f"Bulk upload completed: {', '.join(message_parts)}", 'success')
        else:
            flash(f"No new domains added: {', '.join(message_parts)}", 'warning')
            
    except Exception as e:
        logging.error(f"Error processing bulk upload: {str(e)}")
        flash(f'Error processing file: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/remove_domain/<int:domain_id>')
def remove_domain(domain_id):
    """Remove a domain from the list"""
    domain = Domain.query.get_or_404(domain_id)
    domain.is_active = False
    db.session.commit()
    
    flash(f'Domain {domain.hostname} removed successfully', 'success')
    return redirect(url_for('index'))

@app.route('/scan_domain/<int:domain_id>')
def scan_domain(domain_id):
    """Scan a single domain"""
    domain = Domain.query.get_or_404(domain_id)
    
    try:
        logging.info(f"Starting scan for domain: {domain.hostname}")
        
        # Perform the scan
        scan_result = observatory.scan_domain(domain.hostname)
        
        logging.info(f"Scan result for {domain.hostname}: {scan_result}")
        
        if scan_result['status'] == 'success':
            # Store scan results
            score = scan_result.get('score')
            grade = scan_result.get('grade')
            
            logging.info(f"Storing scan for {domain.hostname}: Score={score}, Grade={grade}")
            
            new_scan = ScanResult(
                domain_id=domain.id,
                overall_score=score,
                grade=grade,
                status='completed',
                csp_issues=json.dumps(scan_result.get('test_results', [])),
                cookie_issues=json.dumps(scan_result.get('scan_info', {})),
                header_issues=json.dumps(scan_result.get('test_results', []))
            )
            
            domain.last_scan_date = datetime.utcnow()
            db.session.add(new_scan)
            db.session.commit()
            
            test_results = scan_result.get('test_results', [])
            failed_tests = [test for test in test_results if test.get('status') == 'Failed']
            flash(f'Scan completed for {domain.hostname} - Score: {scan_result.get("score", "N/A")}, Grade: {scan_result.get("grade", "N/A")}, Failed Tests: {len(failed_tests)}', 'success')
        else:
            # Store failed scan
            new_scan = ScanResult(
                domain_id=domain.id,
                status='failed',
                error_message=scan_result.get('error', 'Unknown error occurred')
            )
            db.session.add(new_scan)
            db.session.commit()
            
            flash(f'Scan failed for {domain.hostname}: {scan_result.get("error", "Unknown error")}', 'error')
            
    except Exception as e:
        logging.error(f"Error scanning domain {domain.hostname}: {str(e)}")
        flash(f'Error scanning {domain.hostname}: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/scan_all')
def scan_all():
    """Scan all active domains"""
    domains = Domain.query.filter_by(is_active=True).all()
    
    if not domains:
        flash('No domains to scan', 'warning')
        return redirect(url_for('index'))
    
    success_count = 0
    failed_count = 0
    
    for domain in domains:
        try:
            scan_result = observatory.scan_domain(domain.hostname)
            
            if scan_result['status'] == 'success':
                new_scan = ScanResult(
                    domain_id=domain.id,
                    overall_score=scan_result.get('score'),
                    grade=scan_result.get('grade'),
                    status='completed',
                    csp_issues=json.dumps(scan_result.get('test_results', [])),
                    cookie_issues=json.dumps(scan_result.get('scan_info', {})),
                    header_issues=json.dumps(scan_result.get('test_results', []))
                )
                domain.last_scan_date = datetime.utcnow()
                success_count += 1
            else:
                new_scan = ScanResult(
                    domain_id=domain.id,
                    status='failed',
                    error_message=scan_result.get('error', 'Unknown error occurred')
                )
                failed_count += 1
            
            db.session.add(new_scan)
            
        except Exception as e:
            logging.error(f"Error scanning domain {domain.hostname}: {str(e)}")
            new_scan = ScanResult(
                domain_id=domain.id,
                status='failed',
                error_message=str(e)
            )
            db.session.add(new_scan)
            failed_count += 1
    
    db.session.commit()
    
    flash(f'Bulk scan completed. Success: {success_count}, Failed: {failed_count}', 'info')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    """Dashboard showing all scan results"""
    # Get latest scan results for each domain using a subquery
    from sqlalchemy import func
    
    # Subquery to get the latest scan date for each domain
    latest_scan_dates = db.session.query(
        ScanResult.domain_id,
        func.max(ScanResult.scan_date).label('latest_date')
    ).group_by(ScanResult.domain_id).subquery()
    
    # Join with the subquery to get the complete latest scan records
    latest_scans = db.session.query(ScanResult).join(Domain).join(
        latest_scan_dates,
        (ScanResult.domain_id == latest_scan_dates.c.domain_id) &
        (ScanResult.scan_date == latest_scan_dates.c.latest_date)
    ).filter(Domain.is_active == True).all()
    
    return render_template('dashboard.html', scans=latest_scans)

@app.route('/domain_results/<int:domain_id>')
def domain_results(domain_id):
    """Detailed results for a specific domain"""
    domain = Domain.query.get_or_404(domain_id)
    scans = ScanResult.query.filter_by(domain_id=domain_id).order_by(ScanResult.scan_date.desc()).all()
    
    return render_template('domain_results.html', domain=domain, scans=scans)

@app.route('/export_csv')
def export_csv():
    """Export latest scan results in the exact format requested"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Get latest scan results for each domain (to avoid duplicates)
    from sqlalchemy import func
    
    # Subquery to get the latest scan date for each domain
    latest_scan_dates = db.session.query(
        ScanResult.domain_id,
        func.max(ScanResult.scan_date).label('latest_date')
    ).group_by(ScanResult.domain_id).subquery()
    
    # Join with the subquery to get the complete latest scan records
    latest_scans = db.session.query(ScanResult).join(Domain).join(
        latest_scan_dates,
        (ScanResult.domain_id == latest_scan_dates.c.domain_id) &
        (ScanResult.scan_date == latest_scan_dates.c.latest_date)
    ).filter(Domain.is_active == True).order_by(Domain.hostname).all()
    
    for scan in latest_scans:
        domain_name = scan.domain.hostname
        
        # Parse test results
        test_results = json.loads(scan.csp_issues) if scan.csp_issues else []
        scan_info = json.loads(scan.cookie_issues) if scan.cookie_issues else {}
        
        # Create a mapping of test results by name for easy lookup
        test_map = {}
        if test_results:
            for test in test_results:
                test_map[test.get('test_name', '')] = test
        
        # DETAILED SECURITY RESULTS SECTION
        writer.writerow([f'Detailed Security Results - {domain_name}'])
        writer.writerow(['Test', 'Score', 'Reason', 'Recommendation'])
        
        # Define the test order and format scores according to the example
        security_tests = [
            'Content Security Policy (CSP)',
            'Cookies',
            'Cross Origin Resource Sharing (CORS)',
            'Redirection',
            'Referrer Policy',
            'Strict Transport Security (HSTS)',
            'Subresource Integrity',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Cross Origin Resource Policy'
        ]
        
        for test_name in security_tests:
            test = test_map.get(test_name, {})
            
            # Format score display according to the example
            score = test.get('score', 0)
            status = test.get('status', 'N/A')
            
            if test_name in ['Cookies', 'Subresource Integrity'] and status == 'Info':
                score_display = '-'
            elif score == 0 and status == 'Passed':
                if 'preload' in test.get('score_description', '').lower():
                    score_display = '0*'
                else:
                    score_display = '0'
            else:
                score_display = str(score) if score != 0 else '0'
            
            # Get reason (score_description) and recommendation
            reason = test.get('score_description', 'No description available')
            recommendation = test.get('recommendation', 'None')
            
            # Clean up the reason text
            if status == 'Info':
                reason = f"Info {reason}"
            elif status == 'Passed':
                reason = f"Passed {reason}"
            elif status == 'Failed':
                reason = f"Failed {reason}"
            
            writer.writerow([test_name, score_display, reason, recommendation])
        
        # Add empty rows for spacing
        writer.writerow([])
        writer.writerow([])
        
        # CSP ANALYSIS SECTION
        writer.writerow(['CSP Analysis'])
        writer.writerow(['Security Test', 'Status', 'Description', 'Additional Information'])
        
        # Parse CSP analysis from scan info
        policy_data = scan_info.get('policy', {}) if scan_info else {}
        csp_analysis = {}
        csp_descriptions = {}
        
        if policy_data and policy_data.get('content_security_policy', {}).get('policy'):
            from utils import parse_csp_policy_data
            csp_policy = policy_data['content_security_policy']['policy']
            csp_tests = parse_csp_policy_data(csp_policy)
            for test in csp_tests:
                csp_analysis[test.get('technical_name', '')] = test.get('pass', False)
                csp_descriptions[test.get('technical_name', '')] = {
                    'name': test.get('name', ''),
                    'description': test.get('description', ''),
                    'info': test.get('info', '')
                }
        
        # Define CSP tests in the order from the example
        csp_test_order = [
            ('antiClickjacking', 'Clickjacking Protection'),
            ('defaultNone', 'Default Deny Policy'),
            ('insecureBaseUri', 'Base URI Security'),
            ('insecureFormAction', 'Form Action Security'),
            ('insecureSchemeActive', 'Active Content Security (HTTPS)'),
            ('insecureSchemePassive', 'Passive Content Security (HTTPS)'),
            ('strictDynamic', 'Strict Dynamic Loading'),
            ('unsafeEval', 'JavaScript eval() Protection'),
            ('unsafeInline', 'Inline JavaScript Protection'),
            ('unsafeInlineStyle', 'Inline Style Protection'),
            ('unsafeObjects', 'Plugin Execution Protection')
        ]
        
        for key, name in csp_test_order:
            test_pass = csp_analysis.get(key, False)
            status = 'Passed' if test_pass else 'Failed' if test_pass is False else 'Info'
            
            test_info = csp_descriptions.get(key, {})
            description = test_info.get('description', f'{name} test')
            additional_info = test_info.get('info', 'No additional information available')
            
            writer.writerow([name, status, description, additional_info])
        
        # Add empty rows for spacing
        writer.writerow([])
        writer.writerow([])
        
        # COOKIES SECURITY ANALYSIS SECTION
        writer.writerow(['Cookies Security Analysis'])
        writer.writerow(['Cookie Name', 'Secure', 'HttpOnly', 'SameSite', 'Issues'])
        
        cookies_data = scan_info.get('cookies', {}) if scan_info else {}
        
        if isinstance(cookies_data, dict) and cookies_data:
            for cookie_name, cookie_info in cookies_data.items():
                if isinstance(cookie_info, dict):
                    secure = 'Yes' if cookie_info.get('secure') else 'No'
                    httponly = 'Yes' if cookie_info.get('httponly') else 'No'
                    samesite = cookie_info.get('samesite', 'Not Set')
                    
                    # Check for issues
                    issues = []
                    if not cookie_info.get('secure'):
                        issues.append("Not Secure")
                    if not cookie_info.get('httponly'):
                        issues.append("Not HttpOnly")
                    if not cookie_info.get('samesite'):
                        issues.append("No SameSite")
                    
                    issues_text = ', '.join(issues) if issues else 'No issues'
                    
                    writer.writerow([cookie_name, secure, httponly, samesite, issues_text])
        else:
            writer.writerow(['No cookies detected', '-', '-', '-', 'No cookies found'])
        
        # Add empty rows for spacing
        writer.writerow([])
        writer.writerow([])
        
        # SECURITY POLICY ANALYSIS SECTION
        writer.writerow(['Security Policy Analysis'])
        writer.writerow(['Policy', 'Present', 'Value', 'Issues'])
        
        response_headers = policy_data.get('response_headers', {}) if policy_data else {}
        
        # HSTS Analysis
        hsts_data = policy_data.get('strict_transport_security', {}) if policy_data else {}
        hsts_present = 'Yes' if response_headers.get('Strict-Transport-Security') else 'No'
        hsts_value = f"max-age={hsts_data.get('max_age', 'Not Set')}"
        if hsts_data.get('include_subdomains'):
            hsts_value += '; includeSubDomains'
        if hsts_data.get('preload'):
            hsts_value += '; preload'
        hsts_issues = 'No issues' if hsts_present == 'Yes' else 'HSTS not implemented'
        
        writer.writerow(['HSTS', hsts_present, hsts_value, hsts_issues])
        
        # Referrer Policy Analysis
        referrer_data = policy_data.get('referrer_policy', {}) if policy_data else {}
        referrer_present = 'Yes' if response_headers.get('Referrer-Policy') else 'No'
        referrer_value = referrer_data.get('policy', 'Not Set')
        referrer_issues = 'No issues' if referrer_present == 'Yes' else 'Referrer Policy not set'
        
        writer.writerow(['Referrer Policy', referrer_present, referrer_value, referrer_issues])
        
        # CSP Policy Analysis
        csp_present = 'Yes' if response_headers.get('Content-Security-Policy') else 'No'
        csp_value = 'Present' if csp_present == 'Yes' else 'Not Set'
        csp_issues = 'Review CSP directives' if csp_present == 'Yes' else 'CSP not implemented'
        
        writer.writerow(['Content Security Policy', csp_present, csp_value, csp_issues])
        
        # Add empty rows for spacing
        writer.writerow([])
        writer.writerow([])
        
        # MISSING SECURITY HEADERS SECTION
        writer.writerow(['Missing Security Headers'])
        writer.writerow(['Policy Header', 'Status', 'Value', 'Recommendation'])
        
        security_headers = {
            'Strict-Transport-Security': 'Implement HSTS to enforce HTTPS',
            'Content-Security-Policy': 'Implement CSP to prevent XSS attacks',
            'X-Frame-Options': 'Implement to prevent clickjacking',
            'X-Content-Type-Options': 'Set to nosniff to prevent MIME sniffing',
            'X-Permitted-Cross-Domain-Policies': 'Control cross-domain policy files',
            'Cross-Origin-Opener-Policy': 'Set to control cross-origin window access',
            'Cross-Origin-Resource-Policy': 'Implement to control cross-origin access',
            'Permissions-Policy': 'Control access to browser features and APIs',
            'Referrer-Policy': 'Set referrer policy to control referrer information',
            'Cross-Origin-Embedder-Policy': 'Set to control cross-origin embedding',
            'X-XSS-Protection': 'Enable XSS filtering (legacy but still useful)'
        }
        
        for header, recommendation in security_headers.items():
            header_value = response_headers.get(header, '')
            present = bool(header_value)
            status = 'Present' if present else 'Missing'
            value = header_value if present else 'Not Set'
            rec = 'Already implemented' if present else recommendation
            
            writer.writerow([header, status, value, rec])
        
        # Add separator between domains
        writer.writerow([])
        writer.writerow(['=' * 80])
        writer.writerow([])
    
    output.seek(0)
    
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=security_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response.headers["Content-type"] = "text/csv"
    
    return response

@app.route('/delete_scan/<int:scan_id>')
def delete_scan(scan_id):
    """Delete a specific scan result"""
    scan = ScanResult.query.get_or_404(scan_id)
    domain_id = scan.domain_id
    domain_name = scan.domain.hostname
    
    db.session.delete(scan)
    db.session.commit()
    
    flash(f'Scan result deleted for {domain_name}', 'success')
    return redirect(url_for('domain_results', domain_id=domain_id))

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
