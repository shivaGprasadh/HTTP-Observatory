import csv
import io
import json
import logging
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, make_response, jsonify
from app import app, db, scan_results, scan_history
from models import Domain, ScanResult
from observatory_api import ObservatoryAPI

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
    """Export all scan results as CSV"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # CSV Headers
    headers = [
        'Domain', 'Scan Date', 'Overall Score', 'Grade', 'Status',
        'CSP Issues Count', 'Cookie Issues Count', 'Header Issues Count',
        'CSP Details', 'Cookie Details', 'Header Details', 'Error Message'
    ]
    writer.writerow(headers)
    
    # Get all scan results
    scans = db.session.query(ScanResult).join(Domain).filter(
        Domain.is_active == True
    ).order_by(Domain.hostname, ScanResult.scan_date.desc()).all()
    
    for scan in scans:
        csp_issues = json.loads(scan.csp_issues) if scan.csp_issues else []
        cookie_issues = json.loads(scan.cookie_issues) if scan.cookie_issues else []
        header_issues = json.loads(scan.header_issues) if scan.header_issues else []
        
        row = [
            scan.domain.hostname,
            scan.scan_date.strftime('%Y-%m-%d %H:%M:%S') if scan.scan_date else '',
            scan.overall_score or '',
            scan.grade or '',
            scan.status,
            len(csp_issues),
            len(cookie_issues),
            len(header_issues),
            '; '.join([str(issue) for issue in csp_issues]) if csp_issues else '',
            '; '.join([str(issue) for issue in cookie_issues]) if cookie_issues else '',
            '; '.join([str(issue) for issue in header_issues]) if header_issues else '',
            scan.error_message or ''
        ]
        writer.writerow(row)
    
    output.seek(0)
    
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=security_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response.headers["Content-type"] = "text/csv"
    
    return response

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
