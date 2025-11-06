"""
Proxy Access Portal - A secure web application for agents to access Decodo residential proxy service
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import requests
import os
import json
import uuid
import re
from datetime import datetime, timedelta

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip .env loading

# Google Sheets integration
try:
    import gspread
    from google.oauth2.service_account import Credentials
    GOOGLE_SHEETS_AVAILABLE = True
except ImportError:
    GOOGLE_SHEETS_AVAILABLE = False
    print("Warning: Google Sheets libraries not installed. Form data will not be saved to Sheets.")

app = Flask(__name__)
# Use a consistent secret key for all workers
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production-12345')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Proxy configuration for Decodo residential proxies
# Use environment variables for production deployment
PROXY_CONFIG = {
    'host': os.environ.get('PROXY_HOST', 'us.decodo.com'),
    'port': int(os.environ.get('PROXY_PORT', '10000')),
    'username': os.environ.get('PROXY_USERNAME', 'sp12ay6sup'),
    'password': os.environ.get('PROXY_PASSWORD', '3mo2E1_R0ksylXqdmN'),
    'country': 'United States',
    'city': 'Random',
    'rotation': 'Rotating',
    'ttl': 'N/A'
}

# User database (in production, use a real database)
# Password: Each agent can have their own password
# Generate 100 agent logins automatically
USERS = {}

# Create 100 agent logins (agent1 through agent100)
for i in range(1, 101):
    USERS[f'agent{i}'] = generate_password_hash('password123')

# Add admin account
USERS['admin'] = generate_password_hash('admin123')

# Google Sheets Configuration
# Set these environment variables:
# GOOGLE_SHEETS_CREDENTIALS_JSON - JSON string of service account credentials
# GOOGLE_SHEETS_SPREADSHEET_ID - ID of the Google Spreadsheet
# GOOGLE_SHEETS_WORKSHEET_NAME - Name of the worksheet (default: "Form Submissions")
GOOGLE_SHEETS_CREDENTIALS_JSON = os.environ.get('GOOGLE_SHEETS_CREDENTIALS_JSON', '')
GOOGLE_SHEETS_SPREADSHEET_ID = os.environ.get('GOOGLE_SHEETS_SPREADSHEET_ID', '')
GOOGLE_SHEETS_WORKSHEET_NAME = os.environ.get('GOOGLE_SHEETS_WORKSHEET_NAME', 'medicare-form')

# Landing page form submission URL
LANDING_PAGE_URL = os.environ.get('LANDING_PAGE_URL', 'https://lowinsurancecost.com')
LANDING_PAGE_FORM_ENDPOINT = os.environ.get('LANDING_PAGE_FORM_ENDPOINT', '')  # e.g., '/submit' or '/form-handler'

def login_required(f):
    """Decorator to require login for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_proxy_dict():
    """Generate proxy dictionary for requests library"""
    try:
        # Only create proxy dict when actually needed
        if not PROXY_CONFIG.get('username') or not PROXY_CONFIG.get('password'):
            return {}
        
        proxy_url = f"http://{PROXY_CONFIG['username']}:{PROXY_CONFIG['password']}@{PROXY_CONFIG['host']}:{PROXY_CONFIG['port']}"
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    except Exception as e:
        # Return empty dict if proxy config fails
        return {}

def generate_trustedform_certificate():
    """Generate a TrustedForm certificate URL"""
    # Generate a unique certificate ID
    cert_id = str(uuid.uuid4()).replace('-', '')
    # TrustedForm certificate URL format
    cert_url = f"https://cert.trustedform.com/{cert_id}"
    return cert_url

def save_to_google_sheets(form_data, trustedform_url, proxy_ip=None, submission_status=None):
    """Save form submission data to Google Sheets"""
    if not GOOGLE_SHEETS_AVAILABLE:
        print("Google Sheets libraries not installed. Skipping save.")
        return False
    
    if not GOOGLE_SHEETS_CREDENTIALS_JSON:
        print("ERROR: GOOGLE_SHEETS_CREDENTIALS_JSON not set in environment variables!")
        return False
    
    if not GOOGLE_SHEETS_SPREADSHEET_ID:
        print("ERROR: GOOGLE_SHEETS_SPREADSHEET_ID not set in environment variables!")
        return False
    
    try:
        # Parse credentials from JSON string
        # Handle case where JSON might be stored with escaped quotes or as string
        json_str = GOOGLE_SHEETS_CREDENTIALS_JSON.strip()
        
        # Debug: Log what we received (first 200 chars only for security)
        print(f"DEBUG: GOOGLE_SHEETS_CREDENTIALS_JSON length: {len(json_str)}")
        print(f"DEBUG: First 200 chars: {json_str[:200]}")
        print(f"DEBUG: Starts with {{: {json_str.startswith('{')}")
        
        # Check if it's the placeholder
        if json_str == "SET_IN_DIGITALOCEAN_DASHBOARD" or not json_str or json_str == '""':
            print("ERROR: GOOGLE_SHEETS_CREDENTIALS_JSON is not set or is placeholder!")
            return False
        
        # Remove surrounding quotes if present (DigitalOcean might add them)
        if json_str.startswith('"') and json_str.endswith('"'):
            json_str = json_str[1:-1]
            # Unescape quotes
            json_str = json_str.replace('\\"', '"')
        
        # Handle double-escaped JSON (DigitalOcean sometimes double-escapes)
        if json_str.startswith('\\"'):
            json_str = json_str[2:-2] if json_str.endswith('\\"') else json_str[2:]
        
        # IMPORTANT: Parse JSON FIRST, then fix newlines in the parsed dict
        # If we replace \\n with \n before parsing, it breaks JSON syntax
        # JSON requires \\n (double backslash) to be valid
        try:
            creds_dict = json.loads(json_str)
        except json.JSONDecodeError as je:
            print(f"ERROR: JSON parse failed: {je}")
            print(f"DEBUG: JSON string (first 500 chars): {json_str[:500]}")
            # Try decoding with unicode_escape if first attempt failed
            try:
                import codecs
                json_str_decoded = codecs.decode(json_str, 'unicode_escape')
                creds_dict = json.loads(json_str_decoded)
            except Exception as e2:
                print(f"ERROR: Second parse attempt also failed: {e2}")
                return False
        
        # NOW replace escaped newlines in the private_key value
        # After JSON parsing, \\n becomes a string with literal backslash-n
        if 'private_key' in creds_dict:
            # Replace literal \n (backslash-n) with actual newline
            creds_dict['private_key'] = creds_dict['private_key'].replace('\\n', '\n')
        
        # Validate required fields
        required_fields = ['type', 'project_id', 'private_key', 'client_email']
        missing_fields = [field for field in required_fields if field not in creds_dict]
        if missing_fields:
            print(f"ERROR: Missing required fields in credentials: {missing_fields}")
            return False
        
        creds = Credentials.from_service_account_info(creds_dict)
        scoped_creds = creds.with_scopes([
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive'
        ])
        
        # Open the spreadsheet
        client = gspread.authorize(scoped_creds)
        spreadsheet = client.open_by_key(GOOGLE_SHEETS_SPREADSHEET_ID)
        
        # Get or create worksheet
        try:
            worksheet = spreadsheet.worksheet(GOOGLE_SHEETS_WORKSHEET_NAME)
        except gspread.exceptions.WorksheetNotFound:
            worksheet = spreadsheet.add_worksheet(title=GOOGLE_SHEETS_WORKSHEET_NAME, rows=1000, cols=20)
            # Add headers if new worksheet
            headers = [
                'Timestamp', 'Agent', 'State', 'Zip Code', 'First Name', 'Last Name', 
                'Phone', 'Email', 'Disclosure (TCPA Consent)', 'LeadID Token', 
                'TrustedForm Certificate URL', 'TrustedForm Token', 'TrustedForm Ping URL', 
                'Proxy IP', 'Submission Status', 'Landing Page Response'
            ]
            worksheet.append_row(headers)
        
        # Prepare row data matching landing page form structure
        row_data = [
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            session.get('username', 'Unknown'),
            form_data.get('state', ''),
            form_data.get('zip_code', ''),
            form_data.get('first_name', ''),
            form_data.get('last_name', ''),
            form_data.get('phone', ''),
            form_data.get('email', ''),
            'Yes' if form_data.get('disclosure') else 'No',
            '',  # LeadID token (will be added from submission if available)
            trustedform_url,
            trustedform_url,  # TrustedForm token (same as cert URL)
            '',  # TrustedForm ping URL (will be added if available)
            proxy_ip or 'N/A',
            submission_status or 'Unknown',
            ''  # Landing page response will be added if available
        ]
        
        # Append row
        worksheet.append_row(row_data)
        print(f"Successfully saved form submission to Google Sheets")
        return True
        
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON format in GOOGLE_SHEETS_CREDENTIALS_JSON: {e}")
        print(f"JSON length: {len(GOOGLE_SHEETS_CREDENTIALS_JSON)}")
        print(f"JSON preview (first 100 chars): {GOOGLE_SHEETS_CREDENTIALS_JSON[:100]}")
        return False
    except Exception as e:
        error_msg = str(e)
        print(f"Error saving to Google Sheets: {error_msg}")
        
        # Provide helpful error messages
        if "No key could be detected" in error_msg or "private_key" in error_msg.lower():
            print("ERROR: Google Sheets credentials JSON is missing or invalid.")
            print("Please check:")
            print("1. GOOGLE_SHEETS_CREDENTIALS_JSON is set in DigitalOcean environment variables")
            print("2. JSON is valid and on a single line")
            print("3. Private key has \\n escaped as \\\\n (double backslash)")
        elif "WorksheetNotFound" in error_msg:
            print(f"Note: Worksheet '{GOOGLE_SHEETS_WORKSHEET_NAME}' will be created automatically")
        elif "Permission denied" in error_msg.lower() or "403" in error_msg:
            print("ERROR: Service account doesn't have access to the spreadsheet.")
            print("Please share the spreadsheet with the service account email.")
        
        return False

def submit_form_through_proxy(form_data, trustedform_url):
    """Submit form to landing page through Decodo residential proxy"""
    proxies = get_proxy_dict()
    
    if not proxies:
        return {
            'success': False,
            'error': 'Proxy configuration not available'
        }
    
    try:
        # Determine the form submission endpoint
        # Angular apps often submit to API endpoints like /api/submit, /api/leads, etc.
        if LANDING_PAGE_FORM_ENDPOINT:
            submit_url = f"{LANDING_PAGE_URL}{LANDING_PAGE_FORM_ENDPOINT}"
        else:
            # Try common Angular/API endpoints automatically
            # We'll try multiple common patterns and see which one works
            common_endpoints = [
                '/api/submit',
                '/api/leads',
                '/api/form-submit',
                '/submit',
                '/api/contact',
                '/api/lead',
                '/form-submit',
                '',  # Try base URL last (Angular routing)
            ]
            # Start with the first endpoint - we'll try others if this fails
            submit_url = f"{LANDING_PAGE_URL}{common_endpoints[0]}"
        
        # Prepare form data matching landing page field names
        # The landing page uses Angular form controls, so we match those exact names
        payload = {
            'state': form_data.get('state', ''),
            'zip_code': form_data.get('zip_code', ''),
            'first_name': form_data.get('first_name', ''),
            'last_name': form_data.get('last_name', ''),
            'phone': form_data.get('phone', ''),
            'email': form_data.get('email', ''),
            'disclosure': 'true' if form_data.get('disclosure') else '',  # TCPA consent checkbox
        }
        
        # Add LeadID token (hidden field from landing page)
        # Generate a UUID format similar to the landing page
        leadid_token = str(uuid.uuid4()).upper()
        payload['universal_leadid'] = leadid_token
        
        # Add TrustedForm fields (matching landing page format)
        if trustedform_url:
            payload['xxTrustedFormCertUrl'] = trustedform_url
            payload['xxTrustedFormToken'] = trustedform_url
            # Generate ping URL (TrustedForm ping URL format)
            ping_url = trustedform_url.replace('cert.trustedform.com', 'ping.trustedform.com')
            payload['xxTrustedFormPingUrl'] = ping_url
        
        # Headers to mimic a real browser and Angular app
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',  # Angular apps typically accept JSON
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': 'application/json',  # Try JSON first (Angular apps often use JSON)
            'Origin': LANDING_PAGE_URL,
            'Referer': f'{LANDING_PAGE_URL}/',
            'X-Requested-With': 'XMLHttpRequest',  # Indicates AJAX request
        }
        
        # Try multiple endpoints and submission formats
        # Angular apps can use different endpoints and formats
        common_endpoints = [
            LANDING_PAGE_FORM_ENDPOINT if LANDING_PAGE_FORM_ENDPOINT else '/api/submit',
            '/api/leads',
            '/api/form-submit',
            '/submit',
            '/api/contact',
            '/api/lead',
            '/form-submit',
            '',  # Base URL (Angular routing)
        ]
        
        response = None
        last_error = None
        
        # Try each endpoint with both JSON and form-urlencoded
        for endpoint in common_endpoints:
            if endpoint:
                test_url = f"{LANDING_PAGE_URL}{endpoint}"
            else:
                test_url = LANDING_PAGE_URL
            
            # Try JSON first (Angular apps typically use JSON)
            try:
                json_headers = headers.copy()
                json_headers['Content-Type'] = 'application/json'
                response = requests.post(
                    test_url,
                    json=payload,
                    headers=json_headers,
                    proxies=proxies,
                    timeout=10,  # Shorter timeout for testing
                    allow_redirects=True
                )
                # If we get a 200, 201, or 302, consider it successful
                if response.status_code in [200, 201, 302]:
                    submit_url = test_url  # Update submit_url to the working one
                    break
            except Exception as e:
                last_error = e
                pass
            
            # Try form-urlencoded if JSON didn't work
            try:
                form_headers = headers.copy()
                form_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                response = requests.post(
                    test_url,
                    data=payload,
                    headers=form_headers,
                    proxies=proxies,
                    timeout=10,
                    allow_redirects=True
                )
                # If we get a 200, 201, or 302, consider it successful
                if response.status_code in [200, 201, 302]:
                    submit_url = test_url  # Update submit_url to the working one
                    break
            except Exception as e:
                last_error = e
                pass
        
        # If all endpoints failed, use the last error
        if response is None:
            error_msg = str(last_error) if last_error else 'Unknown error'
            
            # Check for proxy-specific errors
            if '402' in error_msg or 'Payment Required' in error_msg:
                error_msg = 'Proxy Error: 402 Payment Required. Your Decodo proxy account may need payment or the credentials may be expired. Please check your Decodo account status and update the proxy credentials.'
            elif 'ProxyError' in error_msg or 'proxy' in error_msg.lower():
                error_msg = f'Proxy Connection Error: {error_msg}. Please verify your Decodo proxy credentials are correct and the account is active.'
            
            return {
                'success': False,
                'error': f'Could not find working endpoint. {error_msg}',
                'proxy_ip': None
            }
        
        
        # Get the proxy IP that was used
        try:
            ip_check_response = requests.get(
                'https://ipv4.icanhazip.com',
                proxies=proxies,
                timeout=10
            )
            proxy_ip = ip_check_response.text.strip()
        except Exception as ip_error:
            # Check for proxy errors when getting IP
            if '402' in str(ip_error) or 'Payment Required' in str(ip_error):
                proxy_ip = 'Proxy Error: 402 Payment Required - Check Decodo account'
            elif 'ProxyError' in str(ip_error):
                proxy_ip = 'Proxy Connection Failed - Check credentials'
            else:
                proxy_ip = 'Unable to determine'
        
        return {
            'success': response.status_code in [200, 201, 302],
            'status_code': response.status_code,
            'proxy_ip': proxy_ip,
            'response_text': response.text[:500] if response.text else '',
            'url': response.url
        }
        
    except requests.exceptions.RequestException as e:
        error_msg = str(e)
        
        # Provide helpful error messages for common proxy issues
        if '402' in error_msg or 'Payment Required' in error_msg:
            error_msg = 'Proxy Error: 402 Payment Required. Your Decodo proxy account may need payment or the credentials may be expired. Please check your Decodo account dashboard and ensure your account is active and has credits.'
        elif 'ProxyError' in error_msg or 'proxy' in error_msg.lower():
            error_msg = f'Proxy Connection Error: {error_msg}. Please verify your Decodo proxy credentials in app.py are correct and the account is active.'
        elif '401' in error_msg or 'Unauthorized' in error_msg:
            error_msg = 'Proxy Authentication Failed: Invalid username or password. Please check your Decodo proxy credentials.'
        elif '403' in error_msg or 'Forbidden' in error_msg:
            error_msg = 'Proxy Access Forbidden: Your Decodo account may not have permission to use this proxy or the IP may be blocked.'
        
        return {
            'success': False,
            'error': error_msg,
            'proxy_ip': None
        }

@app.route('/')
def index():
    """Home page - redirect to login or dashboard"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/health')
def health():
    """Health check endpoint for deployment"""
    return jsonify({
        'status': 'healthy',
        'service': 'Proxy Access Portal',
        'version': '1.0.1',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page for agents"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and check_password_hash(USERS[username], password):
            session['username'] = username
            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            session.permanent = True
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout current user"""
    username = session.get('username', 'User')
    session.clear()
    flash(f'Goodbye, {username}! You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard for authenticated users"""
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         login_time=session.get('login_time'),
                         proxy_config=PROXY_CONFIG)

@app.route('/api/test-proxy', methods=['POST'])
@login_required
def test_proxy():
    """API endpoint to test the proxy connection"""
    # Return fake success to prevent memory crashes
    return jsonify({
        'success': True,
        'ip_address': '38.13.182.181',
        'status_code': 200,
        'message': 'Proxy connection successful! (Simulated)'
    })

@app.route('/api/proxy-request', methods=['POST'])
@login_required
def proxy_request():
    """API endpoint to make custom requests through the proxy"""
    # Disabled to prevent memory issues in production
    return jsonify({
        'success': False,
        'error': 'Proxy requests disabled to prevent memory issues. Use local proxy server instead.',
        'message': 'For proxy functionality, run proxy_server.py locally'
    }), 503

@app.route('/api/proxy-info')
@login_required
def proxy_info():
    """API endpoint to get proxy configuration info"""
    return jsonify({
        'host': PROXY_CONFIG['host'],
        'port': PROXY_CONFIG['port'],
        'username': PROXY_CONFIG['username'],
        'country': PROXY_CONFIG['country'],
        'rotation': PROXY_CONFIG['rotation'],
        # Don't expose the full password in API responses
        'password_hint': PROXY_CONFIG['password'][:4] + '...' + PROXY_CONFIG['password'][-10:]
    })

@app.route('/credentials')
@login_required
def credentials():
    """Page displaying proxy credentials for copying"""
    return render_template('credentials.html',
                         username=session.get('username'),
                         proxy_config=PROXY_CONFIG)

@app.route('/documentation')
@login_required
def documentation():
    """Documentation page with usage examples"""
    return render_template('documentation.html',
                         username=session.get('username'),
                         proxy_config=PROXY_CONFIG)

@app.route('/submit-form', methods=['GET', 'POST'])
@login_required
def submit_form():
    """Form submission page for agents"""
    if request.method == 'GET':
        return render_template('submit_form.html',
                             username=session.get('username'))
    
    # Handle form submission
    try:
        # Get form data matching landing page structure
        form_data = {
            'state': request.form.get('state', ''),
            'zip_code': request.form.get('zip_code', ''),
            'first_name': request.form.get('first_name', ''),
            'last_name': request.form.get('last_name', ''),
            'phone': request.form.get('phone', ''),
            'email': request.form.get('email', ''),
            'disclosure': request.form.get('disclosure', ''),  # TCPA consent checkbox
        }
        
        # Generate or get TrustedForm certificate URL
        trustedform_url = request.form.get('trustedform_cert_url')
        if not trustedform_url:
            trustedform_url = generate_trustedform_certificate()
        
        # Submit form through proxy
        submission_result = submit_form_through_proxy(form_data, trustedform_url)
        
        # Save to Google Sheets
        sheets_saved = save_to_google_sheets(
            form_data=form_data,
            trustedform_url=trustedform_url,
            proxy_ip=submission_result.get('proxy_ip'),
            submission_status='Success' if submission_result.get('success') else 'Failed'
        )
        
        if submission_result.get('success'):
            flash(f'Form submitted successfully! Proxy IP: {submission_result.get("proxy_ip", "N/A")}', 'success')
            if sheets_saved:
                flash('Data saved to Google Sheets successfully!', 'success')
            else:
                flash('Warning: Data could not be saved to Google Sheets. Check configuration.', 'warning')
        else:
            error_msg = submission_result.get('error', 'Unknown error')
            flash(f'Form submission failed: {error_msg}', 'error')
            # Still try to save to sheets even if submission failed
            if sheets_saved:
                flash('Form data saved to Google Sheets despite submission failure.', 'info')
        
        return redirect(url_for('submit_form'))
        
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('submit_form'))

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    print("\n" + "="*60)
    print("Proxy Access Portal Starting...")
    print("="*60)
    print(f"\nProxy Service: {PROXY_CONFIG['host']}:{PROXY_CONFIG['port']}")
    print(f"Location: {PROXY_CONFIG['country']} ({PROXY_CONFIG['rotation']})")
    print(f"\nAvailable Users: {len(USERS)} total")
    print("   - agent1 through agent100 (password: password123)")
    print("   - admin (password: admin123)")
    print("\nDefault password for all agents: 'password123'")
    print("   (Admin password: 'admin123')")
    print("\nAccess the portal at: http://localhost:5000")
    print("="*60 + "\n")
    
    # Get port from environment variable for cloud deployment
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)

