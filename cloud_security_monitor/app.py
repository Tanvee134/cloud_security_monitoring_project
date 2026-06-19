"""
app.py — Main Flask Application
=================================
AI-Powered Cloud Security Monitoring & Risk Assessment Platform

This is the entry point for the Flask application. It defines:
  - Database models (User, Server, ScanSession, ScanResult)
  - Authentication routes (login, register, logout)
  - Server CRUD routes (add, edit, delete, view)
  - Security scanner routes (scan a server)
  - Dashboard & analytics routes
  - Scan results & session detail routes

Usage:
    python app.py
"""

import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

from scanner.port_scanner import PortScanner, RiskAssessor, PORT_INFO

# ────────────────────────────────────────────────────────────
# App & Extension Initialisation
# ────────────────────────────────────────────────────────────

app = Flask(__name__)

# Load configuration
app.config.from_object('config.Config')

# Ensure the database directory exists (for SQLite fallback)
db_dir = os.path.join(os.path.dirname(__file__), 'database')
os.makedirs(db_dir, exist_ok=True)

# Ensure the reports directory exists
os.makedirs(app.config.get('REPORTS_DIR', 'reports'), exist_ok=True)

# Initialise SQLAlchemy
db = SQLAlchemy(app)

# Initialise Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


# ────────────────────────────────────────────────────────────
# Database Models
# ────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    """Registered user accounts."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship: one user → many servers
    servers = db.relationship('Server', backref='owner', lazy=True,
                              cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.email}>'


class Server(db.Model):
    """Servers registered for security monitoring."""
    __tablename__ = 'servers'

    id = db.Column(db.Integer, primary_key=True)
    server_name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    provider = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    scan_sessions = db.relationship('ScanSession', backref='server', lazy=True,
                                    cascade='all, delete-orphan',
                                    order_by='ScanSession.scan_time.desc()')

    def __repr__(self):
        return f'<Server {self.server_name} ({self.ip_address})>'


class ScanSession(db.Model):
    """Groups individual port results into one logical scan."""
    __tablename__ = 'scan_sessions'

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), default='Low')
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship: one session → many results
    results = db.relationship('ScanResult', backref='session', lazy=True,
                              cascade='all, delete-orphan')

    def __repr__(self):
        return f'<ScanSession server={self.server_id} score={self.risk_score}>'


class ScanResult(db.Model):
    """Individual port scan result within a scan session."""
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('scan_sessions.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False)       # 'open' or 'closed'
    risk_level = db.Column(db.String(20), default='None')    # Low, Medium, High, Critical
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ScanResult port={self.port} status={self.status}>'


# ────────────────────────────────────────────────────────────
# Flask-Login User Loader
# ────────────────────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login session management."""
    return db.session.get(User, int(user_id))


# ────────────────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────────────────

def get_risk_color(level):
    """Return the CSS colour for a given risk level."""
    colors = {
        'Low': '#00e676',
        'Medium': '#ffab00',
        'High': '#ff5252',
        'Critical': '#e91e63'
    }
    return colors.get(level, '#94a3b8')


def get_dashboard_stats(user_id):
    """
    Compute dashboard KPI statistics for the given user.
    Returns a dict with counts for total servers, scans, and risk levels.
    """
    servers = Server.query.filter_by(user_id=user_id).all()
    total_servers = len(servers)

    # Get the latest scan session for each server
    latest_sessions = []
    for server in servers:
        latest = ScanSession.query.filter_by(server_id=server.id) \
            .order_by(ScanSession.scan_time.desc()).first()
        if latest:
            latest_sessions.append(latest)

    total_scans = ScanSession.query.join(Server) \
        .filter(Server.user_id == user_id).count()

    low_risk = sum(1 for s in latest_sessions if s.risk_level == 'Low')
    medium_risk = sum(1 for s in latest_sessions if s.risk_level == 'Medium')
    high_risk = sum(1 for s in latest_sessions if s.risk_level == 'High')
    critical_risk = sum(1 for s in latest_sessions if s.risk_level == 'Critical')

    # Average risk score
    scores = [s.risk_score for s in latest_sessions]
    avg_score = sum(scores) / len(scores) if scores else 0

    return {
        'total_servers': total_servers,
        'total_scans': total_scans,
        'low_risk': low_risk,
        'medium_risk': medium_risk,
        'high_risk': high_risk,
        'critical_risk': critical_risk,
        'avg_score': avg_score
    }


def get_server_risk_data(user_id):
    """
    Get server names and their latest risk scores for charts.
    Returns dict with 'names' and 'scores' lists.
    """
    servers = Server.query.filter_by(user_id=user_id).all()
    names = []
    scores = []

    for server in servers:
        latest = ScanSession.query.filter_by(server_id=server.id) \
            .order_by(ScanSession.scan_time.desc()).first()
        if latest:
            names.append(server.server_name)
            scores.append(latest.risk_score)

    return {'names': names, 'scores': scores}


# ────────────────────────────────────────────────────────────
# AUTH ROUTES
# ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Root route — redirect to dashboard if logged in, else to login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with email and password."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('Welcome back, ' + user.name + '!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """New user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        # Validation
        if not name or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists.', 'danger')
            return redirect(url_for('register'))

        # Create user with hashed password
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please sign in.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')


@app.route('/logout')
@login_required
def logout():
    """Log the user out and redirect to login."""
    logout_user()
    flash('You have been signed out.', 'info')
    return redirect(url_for('login'))


# ────────────────────────────────────────────────────────────
# CONTEXT PROCESSORS
# ────────────────────────────────────────────────────────────

@app.context_processor
def inject_notifications():
    """Inject recent notifications into all templates."""
    if current_user.is_authenticated:
        # Get 5 most recent scan sessions for the user's servers
        notifications = db.session.query(
            ScanSession.risk_score,
            ScanSession.risk_level,
            ScanSession.scan_time,
            Server.server_name
        ).join(Server).filter(
            Server.user_id == current_user.id
        ).order_by(
            ScanSession.scan_time.desc()
        ).limit(5).all()
        return dict(notifications=notifications, notification_count=len(notifications))
    return dict(notifications=[], notification_count=0)


# ────────────────────────────────────────────────────────────
# ACCOUNT SETTINGS ROUTES
# ────────────────────────────────────────────────────────────

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user's name and email."""
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()

    if not name or not email:
        flash('Name and email are required.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    # Check if email is already taken by another user
    existing_user = User.query.filter(User.email == email, User.id != current_user.id).first()
    if existing_user:
        flash('Email address is already in use.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    user = User.query.get(current_user.id)
    user.name = name
    user.email = email
    db.session.commit()

    flash('Profile updated successfully.', 'success')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/profile/password', methods=['POST'])
@login_required
def change_password():
    """Change user password."""
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')

    if not current_password or not new_password:
        flash('Both current and new passwords are required.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    user = User.query.get(current_user.id)

    if not check_password_hash(user.password, current_password):
        flash('Incorrect current password.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    if len(new_password) < 6:
        flash('New password must be at least 6 characters.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.commit()

    flash('Password changed successfully.', 'success')
    return redirect(request.referrer or url_for('dashboard'))



# ────────────────────────────────────────────────────────────
# DASHBOARD
# ────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with KPIs, charts, and recent activity."""
    stats = get_dashboard_stats(current_user.id)
    server_risk_data = get_server_risk_data(current_user.id)

    # Recent scan activity (last 10 scan sessions)
    recent_scans = db.session.query(
        ScanSession.risk_score,
        ScanSession.risk_level,
        ScanSession.scan_time,
        Server.server_name
    ).join(Server).filter(
        Server.user_id == current_user.id
    ).order_by(
        ScanSession.scan_time.desc()
    ).limit(10).all()

    return render_template('dashboard.html',
                           stats=stats,
                           server_risk_data=server_risk_data,
                           recent_scans=recent_scans)


# ────────────────────────────────────────────────────────────
# SERVER MANAGEMENT
# ────────────────────────────────────────────────────────────

@app.route('/servers')
@login_required
def servers():
    """List all servers belonging to the current user."""
    user_servers = Server.query.filter_by(user_id=current_user.id) \
        .order_by(Server.date_added.desc()).all()

    # Attach latest risk level to each server object
    for server in user_servers:
        latest = ScanSession.query.filter_by(server_id=server.id) \
            .order_by(ScanSession.scan_time.desc()).first()
        server.latest_risk = latest.risk_level if latest else None

    return render_template('servers/index.html', servers=user_servers)


@app.route('/servers/add', methods=['GET', 'POST'])
@login_required
def add_server():
    """Add a new server for monitoring."""
    if request.method == 'POST':
        server_name = request.form.get('server_name', '').strip()
        ip_address = request.form.get('ip_address', '').strip()
        provider = request.form.get('provider', '').strip()

        if not server_name or not ip_address or not provider:
            flash('All fields are required.', 'danger')
            return redirect(url_for('add_server'))

        new_server = Server(
            server_name=server_name,
            ip_address=ip_address,
            provider=provider,
            user_id=current_user.id
        )
        db.session.add(new_server)
        db.session.commit()

        flash(f'Server "{server_name}" added successfully!', 'success')
        return redirect(url_for('servers'))

    return render_template('servers/add.html')


@app.route('/servers/<int:server_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_server(server_id):
    """Edit an existing server's details."""
    server = Server.query.get_or_404(server_id)

    # Ensure the server belongs to the current user
    if server.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('servers'))

    if request.method == 'POST':
        server.server_name = request.form.get('server_name', '').strip()
        server.ip_address = request.form.get('ip_address', '').strip()
        server.provider = request.form.get('provider', '').strip()

        if not server.server_name or not server.ip_address or not server.provider:
            flash('All fields are required.', 'danger')
            return redirect(url_for('edit_server', server_id=server_id))

        db.session.commit()
        flash(f'Server "{server.server_name}" updated successfully!', 'success')
        return redirect(url_for('servers'))

    return render_template('servers/edit.html', server=server)


@app.route('/servers/<int:server_id>/delete', methods=['POST'])
@login_required
def delete_server(server_id):
    """Delete a server and all associated scan data."""
    server = Server.query.get_or_404(server_id)

    if server.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('servers'))

    server_name = server.server_name
    db.session.delete(server)
    db.session.commit()

    flash(f'Server "{server_name}" and all scan history deleted.', 'success')
    return redirect(url_for('servers'))


@app.route('/servers/<int:server_id>')
@login_required
def server_detail(server_id):
    """View detailed information about a specific server."""
    server = Server.query.get_or_404(server_id)

    if server.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('servers'))

    # Get all scan sessions for this server (newest first)
    scan_sessions = ScanSession.query.filter_by(server_id=server.id) \
        .order_by(ScanSession.scan_time.desc()).all()

    # Latest session data
    latest_session = scan_sessions[0] if scan_sessions else None
    latest_results = []

    if latest_session:
        latest_session.risk_color = get_risk_color(latest_session.risk_level)
        results = ScanResult.query.filter_by(session_id=latest_session.id).all()
        for r in results:
            port_info = PORT_INFO.get(r.port, {'service': 'Unknown'})
            latest_results.append({
                'port': r.port,
                'service': port_info['service'],
                'status': r.status
            })

    return render_template('servers/detail.html',
                           server=server,
                           scan_sessions=scan_sessions,
                           latest_session=latest_session,
                           latest_results=latest_results)


# ────────────────────────────────────────────────────────────
# SECURITY SCANNER
# ────────────────────────────────────────────────────────────

@app.route('/servers/<int:server_id>/scan', methods=['POST'])
@login_required
def scan_server(server_id):
    """
    Run a port scan on the specified server.
    Scans ports 22, 80, 443, 3306, 5432, 8080.
    Calculates risk score and generates recommendations.
    """
    server = Server.query.get_or_404(server_id)

    if server.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('servers'))

    # Initialise the port scanner
    scanner = PortScanner(
        timeout=app.config.get('SCAN_TIMEOUT', 2),
        ports=app.config.get('SCAN_PORTS', [22, 80, 443, 3306, 5432, 8080])
    )

    # Perform the scan
    scan_data = scanner.scan_all_ports(server.ip_address)

    # Calculate risk assessment
    risk = RiskAssessor.calculate_risk(scan_data['results'])

    # Create a new scan session
    session = ScanSession(
        server_id=server.id,
        risk_score=risk['score'],
        risk_level=risk['level'],
        scan_time=scan_data['scan_time']
    )
    db.session.add(session)
    db.session.flush()  # Get the session ID

    # Save individual port results
    for result in scan_data['results']:
        scan_result = ScanResult(
            session_id=session.id,
            server_id=server.id,
            port=result['port'],
            status=result['status'],
            risk_level=result['risk_level'] if result['status'] == 'open' else 'None',
            scan_time=scan_data['scan_time']
        )
        db.session.add(scan_result)

    db.session.commit()

    flash(
        f'Scan complete for "{server.server_name}" — '
        f'Risk Score: {risk["score"]}/100 ({risk["level"]})',
        'success' if risk['level'] in ['Low', 'Medium'] else 'warning'
    )

    return redirect(url_for('view_scan_session', session_id=session.id))


# ────────────────────────────────────────────────────────────
# SCAN RESULTS
# ────────────────────────────────────────────────────────────

@app.route('/scans')
@login_required
def scan_results():
    """List all scan sessions for the current user's servers."""
    sessions = ScanSession.query.join(Server) \
        .filter(Server.user_id == current_user.id) \
        .order_by(ScanSession.scan_time.desc()).all()

    return render_template('scan/results.html', sessions=sessions)


@app.route('/scans/<int:session_id>')
@login_required
def view_scan_session(session_id):
    """View detailed results of a specific scan session."""
    session = ScanSession.query.get_or_404(session_id)

    # Verify ownership
    if session.server.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('scan_results'))

    # Get all port results for this session
    raw_results = ScanResult.query.filter_by(session_id=session.id) \
        .order_by(ScanResult.port).all()

    # Enrich results with service names
    results = []
    for r in raw_results:
        port_info = PORT_INFO.get(r.port, {'service': 'Unknown', 'description': 'Unknown'})
        results.append({
            'port': r.port,
            'status': r.status,
            'risk_level': r.risk_level,
            'service': port_info['service'],
            'description': port_info.get('description', '')
        })

    # Counts
    open_count = sum(1 for r in results if r['status'] == 'open')
    closed_count = sum(1 for r in results if r['status'] == 'closed')

    # Generate recommendations based on the scan results
    recommendations = RiskAssessor.generate_recommendations(results)

    # Risk colour
    risk_color = get_risk_color(session.risk_level)

    return render_template('scan/session_detail.html',
                           session=session,
                           results=results,
                           open_count=open_count,
                           closed_count=closed_count,
                           recommendations=recommendations,
                           risk_color=risk_color)


# ────────────────────────────────────────────────────────────
# ANALYTICS
# ────────────────────────────────────────────────────────────

@app.route('/analytics')
@login_required
def analytics():
    """Security analytics page with charts and insights."""
    stats = get_dashboard_stats(current_user.id)
    server_risk_data = get_server_risk_data(current_user.id)

    # Risk distribution counts
    risk_counts = {
        'low': stats['low_risk'],
        'medium': stats['medium_risk'],
        'high': stats['high_risk'],
        'critical': stats['critical_risk']
    }

    # Open ports frequency data
    port_freq = {}
    user_servers = Server.query.filter_by(user_id=current_user.id).all()
    for server in user_servers:
        latest = ScanSession.query.filter_by(server_id=server.id) \
            .order_by(ScanSession.scan_time.desc()).first()
        if latest:
            open_results = ScanResult.query.filter_by(
                session_id=latest.id, status='open'
            ).all()
            for r in open_results:
                port_label = f'{r.port}'
                port_info = PORT_INFO.get(r.port)
                if port_info:
                    port_label = f'{r.port} ({port_info["service"]})'
                port_freq[port_label] = port_freq.get(port_label, 0) + 1

    port_data = {
        'ports': list(port_freq.keys()),
        'counts': list(port_freq.values())
    }

    # Risk score trend (last 15 scans)
    recent_sessions = ScanSession.query.join(Server) \
        .filter(Server.user_id == current_user.id) \
        .order_by(ScanSession.scan_time.asc()) \
        .limit(15).all()

    trend_data = {
        'dates': [s.scan_time.strftime('%b %d') for s in recent_sessions],
        'scores': [s.risk_score for s in recent_sessions]
    }

    return render_template('analytics.html',
                           stats=stats,
                           risk_counts=risk_counts,
                           server_risk_data=server_risk_data,
                           port_data=port_data,
                           trend_data=trend_data)


# ────────────────────────────────────────────────────────────
# API ENDPOINTS (optional JSON API)
# ────────────────────────────────────────────────────────────

@app.route('/api/stats')
@login_required
def api_stats():
    """Return dashboard statistics as JSON."""
    stats = get_dashboard_stats(current_user.id)
    return jsonify(stats)


# ────────────────────────────────────────────────────────────
# ERROR HANDLERS
# ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    flash('Page not found.', 'warning')
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    db.session.rollback()
    flash('An internal error occurred. Please try again.', 'danger')
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# ────────────────────────────────────────────────────────────
# Application Entry Point
# ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Create all database tables on first run
    with app.app_context():
        db.create_all()
        print('[OK] Database tables created successfully.')

    # Run the development server
    print('=' * 60)
    print('  CloudShield — Cloud Security Monitoring Platform')
    print('  Running at http://127.0.0.1:5000')
    print('=' * 60)

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
