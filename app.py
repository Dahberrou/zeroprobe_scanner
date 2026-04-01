# app.py — ZeroProbe | Security Intelligence Platform
# Developed by Dah Berrou © 2026

import os
import json
import time
import threading
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   Response, send_file, redirect, url_for, flash, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         logout_user, login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from scanner.xss_scanner     import scan_xss
from scanner.sqli_scanner    import scan_sqli
from scanner.headers_scanner import scan_headers
from scanner.subdomain_scanner import run_subdomain_scan
from scanner.dir_scanner       import run_dir_scan
from utils.ai_report    import generate_ai_report
from utils.severity     import calculate_severity
from utils.pdf_report   import generate_pdf

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'zeroprobe-dev-secret-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zeroprobe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'


# ── Models ────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    scans         = db.relationship('ScanRecord', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class ScanRecord(db.Model):
    __tablename__ = 'scan_records'
    id              = db.Column(db.Integer, primary_key=True)
    target_url      = db.Column(db.String(500), nullable=False)
    scan_type       = db.Column(db.String(50), default='full')
    timestamp       = db.Column(db.DateTime, default=datetime.utcnow)
    severity        = db.Column(db.String(20), default='low')
    risk_score      = db.Column(db.Integer, default=0)
    xss_count       = db.Column(db.Integer, default=0)
    sqli_count      = db.Column(db.Integer, default=0)
    headers_missing = db.Column(db.Integer, default=0)
    report_json     = db.Column(db.Text)
    ai_analysis     = db.Column(db.Text)
    duration_s      = db.Column(db.Float, default=0.0)
    user_id         = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)


with app.app_context():
    db.create_all()

# ── In-memory SSE progress store ──────────────────────────────────────────────
_progress: dict = {}


# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('All fields are required.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('home'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password   = request.form.get('password', '')
        user = (User.query.filter_by(email=identifier.lower()).first() or
                User.query.filter_by(username=identifier).first())
        if user and user.check_password(password):
            login_user(user, remember=request.form.get('remember') == 'on')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    recent = []
    stats = {'total': 0, 'critical': 0, 'high': 0}
    if current_user.is_authenticated:
        q = ScanRecord.query.filter_by(user_id=current_user.id)
        recent = q.order_by(ScanRecord.timestamp.desc()).limit(5).all()
        stats = {
            'total':    q.count(),
            'critical': q.filter_by(severity='critical').count(),
            'high':     q.filter_by(severity='high').count(),
        }
    return render_template('index.html', recent=recent, stats=stats)


@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    scan_id = f"scan_{int(time.time() * 1000)}"
    _progress[scan_id] = {
        'status': 'running', 'progress': 0,
        'stage': 'Initializing scanner...', 'logs': []
    }
    save_to_db = current_user.is_authenticated
    _owner_id = current_user.id if save_to_db else None  # capture before thread

    def _log(msg):
        ts = datetime.now().strftime('%H:%M:%S')
        _progress[scan_id]['logs'].append(f"[{ts}] {msg}")

    def run():
        start = time.time()
        try:
            _log("Target acquired. Beginning reconnaissance...")
            _progress[scan_id].update({'progress': 8, 'stage': 'Probing target host...'})
            time.sleep(0.2)

            _log("Injecting XSS test payloads into parameters...")
            _progress[scan_id].update({'progress': 14, 'stage': 'Running XSS scanner...'})
            xss = scan_xss(url)
            xss_found = sum(1 for x in xss if x.get('vulnerable'))
            _log(f"XSS scan complete — {xss_found} vulnerabilities detected")

            _progress[scan_id].update({'progress': 42, 'stage': 'Running SQL injection scanner...'})
            _log("Testing SQL injection vectors...")
            sqli = scan_sqli(url)
            sqli_found = sum(1 for s in sqli if s.get('vulnerable'))
            _log(f"SQLi scan complete — {sqli_found} vulnerabilities detected")

            _progress[scan_id].update({'progress': 70, 'stage': 'Auditing HTTP security headers...'})
            _log("Auditing HTTP security headers...")
            headers = scan_headers(url)
            missing = sum(1 for h in headers if h.get('status') == 'Missing')
            _log(f"Headers audit complete — {missing} missing headers")

            _progress[scan_id].update({'progress': 80, 'stage': 'Computing risk severity score...'})
            report = {'url': url, 'xss': xss, 'sqli': sqli, 'headers': headers}
            severity = calculate_severity(report)
            _log(f"Risk level: {severity['level']} (score: {severity['issues']})")

            _progress[scan_id].update({'progress': 88, 'stage': 'Generating AI security analysis...'})
            _log("Running AI-powered vulnerability analysis...")
            ai = generate_ai_report(report)

            elapsed = round(time.time() - start, 1)

            if save_to_db:
                _progress[scan_id].update({'progress': 95, 'stage': 'Persisting scan record...'})
                with app.app_context():
                    rec = ScanRecord(
                        target_url=url,
                        scan_type='full',
                        severity=severity['level'].lower(),
                        risk_score=severity['issues'],
                        xss_count=xss_found,
                        sqli_count=sqli_found,
                        headers_missing=missing,
                        report_json=json.dumps(report),
                        ai_analysis=ai,
                        duration_s=elapsed,
                        user_id=_owner_id
                    )
                    db.session.add(rec)
                    db.session.commit()
                    record_id = rec.id
                _log(f"Scan complete in {elapsed}s — record #{record_id} saved")
                _progress[scan_id].update({
                    'status': 'done', 'progress': 100,
                    'stage': 'Scan complete!', 'record_id': record_id
                })
            else:
                _progress[scan_id].update({'progress': 95, 'stage': 'Finalizing results...'})
                _log(f"Scan complete in {elapsed}s — login to save results")
                _progress[scan_id].update({
                    'status': 'done', 'progress': 100,
                    'stage': 'Scan complete!',
                    'temp_scan_id': scan_id,
                    'temp_report': {
                        'url': url, 'xss': xss, 'sqli': sqli,
                        'headers': headers, 'severity': severity,
                        'ai': ai, 'duration_s': elapsed
                    }
                })

        except Exception as e:
            _log(f"Error: {e}")
            _progress[scan_id].update({'status': 'error', 'stage': f'Error: {e}'})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'scan_id': scan_id})


@app.route('/scan-progress/<scan_id>')
def scan_progress(scan_id):
    def stream():
        while True:
            data = _progress.get(scan_id, {'status': 'unknown'})
            yield f"data: {json.dumps(data)}\n\n"
            if data.get('status') in ('done', 'error'):
                break
            time.sleep(0.4)
    return Response(
        stream(), mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/report/temp/<scan_id>')
def report_temp(scan_id):
    data = _progress.get(scan_id)
    if not data or 'temp_report' not in data:
        abort(404)
    t = data['temp_report']
    report_data = {'url': t['url'], 'xss': t['xss'], 'sqli': t['sqli'], 'headers': t['headers']}
    sev = calculate_severity(report_data)
    return render_template('report.html', record=None, report=report_data,
                           severity=sev, ai=t['ai'],
                           temp=True, temp_scan_id=scan_id,
                           duration_s=t['duration_s'])


@app.route('/report/<int:record_id>')
def report(record_id):
    rec = ScanRecord.query.get_or_404(record_id)
    if rec.user_id is not None:
        if not current_user.is_authenticated or rec.user_id != current_user.id:
            abort(403)
    report_data = json.loads(rec.report_json)
    sev = calculate_severity(report_data)
    return render_template('report.html', record=rec, report=report_data,
                           severity=sev, ai=rec.ai_analysis,
                           temp=False, duration_s=rec.duration_s)


@app.route('/report/<int:record_id>/pdf')
def download_pdf(record_id):
    rec = ScanRecord.query.get_or_404(record_id)
    if rec.user_id is not None:
        if not current_user.is_authenticated or rec.user_id != current_user.id:
            abort(403)
    report_data = json.loads(rec.report_json)
    sev = calculate_severity(report_data)
    path = generate_pdf(report=report_data, severity=sev, ai_report=rec.ai_analysis)
    return send_file(path, as_attachment=True,
                     download_name=f"zeroprobe_report_{record_id}.pdf")


@app.route('/dashboard')
def dashboard():
    if not current_user.is_authenticated:
        return render_template('dashboard.html', stats=None, recent=[], daily_json='[]', severity_json='{}')
    from sqlalchemy import func
    uid = current_user.id
    base_q = ScanRecord.query.filter_by(user_id=uid)
    total  = base_q.count()
    by_sev = dict(
        db.session.query(ScanRecord.severity, func.count(ScanRecord.id))
        .filter(ScanRecord.user_id == uid)
        .group_by(ScanRecord.severity).all()
    )
    recent = base_q.order_by(ScanRecord.timestamp.desc()).limit(10).all()
    daily_raw = (
        db.session.query(
            func.strftime('%Y-%m-%d', ScanRecord.timestamp).label('day'),
            func.count(ScanRecord.id).label('cnt')
        )
        .filter(ScanRecord.user_id == uid)
        .group_by('day').order_by('day').limit(14).all()
    )
    daily = [{'date': r.day, 'count': r.cnt} for r in daily_raw]
    avg_score = (db.session.query(func.avg(ScanRecord.risk_score))
                 .filter(ScanRecord.user_id == uid).scalar() or 0)
    stats = {
        'total':     total,
        'critical':  by_sev.get('critical', 0),
        'high':      by_sev.get('high', 0),
        'medium':    by_sev.get('medium', 0),
        'low':       by_sev.get('low', 0),
        'avg_score': round(avg_score, 1),
    }
    return render_template('dashboard.html', stats=stats, recent=recent,
                           daily_json=json.dumps(daily),
                           severity_json=json.dumps(by_sev))


@app.route('/history')
def history():
    if not current_user.is_authenticated:
        return render_template('history.html', records=None, sev_filter='')
    page       = request.args.get('page', 1, type=int)
    sev_filter = request.args.get('severity', '')
    q = ScanRecord.query.filter_by(user_id=current_user.id).order_by(ScanRecord.timestamp.desc())
    if sev_filter:
        q = q.filter_by(severity=sev_filter)
    records = q.paginate(page=page, per_page=20, error_out=False)
    return render_template('history.html', records=records, sev_filter=sev_filter)


@app.route('/subdomains', methods=['GET', 'POST'])
def subdomains():
    results, domain = None, ''
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        if domain:
            results = run_subdomain_scan(domain)
    return render_template('subdomains.html', results=results, domain=domain)


@app.route('/dirscan', methods=['GET', 'POST'])
def dirscan():
    results, url = None, ''
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            results = run_dir_scan(url)
    return render_template('dirscan.html', results=results, url=url)


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True, port=5000)
