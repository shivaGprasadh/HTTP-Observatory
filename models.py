from app import db
from datetime import datetime

class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    added_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_scan_date = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Domain {self.hostname}>'

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    overall_score = db.Column(db.Integer)
    grade = db.Column(db.String(5))
    status = db.Column(db.String(50))  # 'completed', 'failed', 'pending'
    error_message = db.Column(db.Text)
    
    # Security findings
    csp_issues = db.Column(db.Text)  # JSON string
    cookie_issues = db.Column(db.Text)  # JSON string
    header_issues = db.Column(db.Text)  # JSON string
    
    domain = db.relationship('Domain', backref=db.backref('scan_results', lazy=True))
    
    def __repr__(self):
        return f'<ScanResult {self.domain.hostname} - {self.scan_date}>'
