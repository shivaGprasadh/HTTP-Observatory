
import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///observatory.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# In-memory storage for scan results (MVP approach)
scan_results = {}
scan_history = {}

# Add custom Jinja2 filters
import json

@app.template_filter('from_json')
def from_json_filter(value):
    """Convert JSON string to Python object"""
    if not value:
        return []
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []

@app.template_filter('parse_csp')
def parse_csp_filter(value):
    """Parse CSP policy data for human readable display"""
    from utils import parse_csp_policy_data, parse_csp_policy_raw_data
    if not value:
        return []
    try:
        data = json.loads(value) if isinstance(value, str) else value
        if isinstance(data, dict):
            # Check if it's the raw format from the attached file
            if 'antiClickjacking' in data or 'unsafeInline' in data:
                return parse_csp_policy_raw_data(data)
            # Check if it's nested policy data
            elif 'policy' in data:
                csp_policy = data.get('policy', {}).get('content_security_policy', {}).get('policy', {})
                return parse_csp_policy_data(csp_policy)
        return []
    except (json.JSONDecodeError, TypeError, AttributeError):
        return []

@app.template_filter('status_badge_class')
def status_badge_class_filter(pass_value):
    """Get Bootstrap badge class for CSP test status"""
    from utils import get_status_badge_class
    return get_status_badge_class(pass_value)

# Import models and routes after app setup to avoid circular imports
import models
import routes

with app.app_context():
    # Create all tables
    db.create_all()
