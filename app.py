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
from scanner.xss_scanner       import scan_xss
from scanner.sqli_scanner      import scan_sqli
from scanner.headers_scanner   import scan_headers
from scanner.subdomain_scanner import run_subdomain_scan
from scanner.dir_scanner       import run_dir_scan_stream
from utils.ai_report  import generate_ai_report
from utils.severity   import calculate_severity
from utils.pdf_report import generate_pdf

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
    is_active     = db.Column(db.Boolean, default=True, nullable=False)
    role          = db.Column(db.String(20), default='user', nullable=False)
    last_login    = db.Column(db.DateTime, nullable=True)
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
    duration_s      = db.Column(db.Float, default=0.0)
    user_id         = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    report          = db.relationship('Report', backref='scan', uselist=False,
                                      cascade='all, delete-orphan')
    xss_findings    = db.relationship('XssFinding', backref='scan', lazy=True,
                                      cascade='all, delete-orphan')
    sqli_findings   = db.relationship('SqliFinding', backref='scan', lazy=True,
                                      cascade='all, delete-orphan')
    header_findings = db.relationship('HeaderFinding', backref='scan', lazy=True,
                                      cascade='all, delete-orphan')


class Report(db.Model):
    __tablename__ = 'reports'
    id           = db.Column(db.Integer, primary_key=True)
    scan_id      = db.Column(db.Integer, db.ForeignKey('scan_records.id'),
                             nullable=False, unique=True)
    ai_analysis  = db.Column(db.Text)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    pdf_path     = db.Column(db.String(500), nullable=True)


class XssFinding(db.Model):
    __tablename__ = 'xss_findings'
    id             = db.Column(db.Integer, primary_key=True)
    scan_id        = db.Column(db.Integer, db.ForeignKey('scan_records.id'), nullable=False)
    payload        = db.Column(db.Text)
    parameter      = db.Column(db.String(100))
    vuln_type      = db.Column('type', db.String(100))
    vulnerable     = db.Column(db.Boolean, default=False)
    risk           = db.Column(db.String(20))
    url            = db.Column(db.Text)
    status_code    = db.Column(db.Integer)
    description    = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    error          = db.Column(db.Text)


class SqliFinding(db.Model):
    __tablename__ = 'sqli_findings'
    id             = db.Column(db.Integer, primary_key=True)
    scan_id        = db.Column(db.Integer, db.ForeignKey('scan_records.id'), nullable=False)
    payload        = db.Column(db.Text)
    parameter      = db.Column(db.String(100))
    vuln_type      = db.Column('type', db.String(100))
    technique      = db.Column(db.String(100))
    vulnerable     = db.Column(db.Boolean, default=False)
    risk           = db.Column(db.String(20))
    db_type        = db.Column(db.String(50))
    detection      = db.Column(db.String(50))
    url            = db.Column(db.Text)
    status_code    = db.Column(db.Integer)
    description    = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    error          = db.Column(db.Text)


class HeaderFinding(db.Model):
    __tablename__ = 'header_findings'
    id             = db.Column(db.Integer, primary_key=True)
    scan_id        = db.Column(db.Integer, db.ForeignKey('scan_records.id'), nullable=False)
    header         = db.Column(db.String(100))
    status         = db.Column(db.String(20))
    risk           = db.Column(db.String(20))
    value          = db.Column(db.Text)
    description    = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    impact         = db.Column(db.Text)
    error          = db.Column(db.Text)


# ── Database initialization & migration ───────────────────────────────────────

def _run_migrations():
    with db.engine.connect() as conn:

        # ── users: add new columns if missing ────────────────────────────────
        user_cols = {r[1] for r in conn.execute(
            db.text("PRAGMA table_info(users)")).fetchall()}
        for col, ddl in [
            ('is_active', "ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1"),
            ('role',      "ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'"),
            ('last_login',"ALTER TABLE users ADD COLUMN last_login DATETIME"),
        ]:
            if col not in user_cols:
                conn.execute(db.text(ddl))

        # ── scan_records: migrate blobs → normalized tables, then rebuild ────
        sc_cols = {r[1] for r in conn.execute(
            db.text("PRAGMA table_info(scan_records)")).fetchall()}

        if 'report_json' in sc_cols:
            rows = conn.execute(db.text(
                "SELECT id, report_json, ai_analysis FROM scan_records"
            )).fetchall()

            for scan_id, report_json, ai_analysis in rows:
                # Create Report row
                if not conn.execute(db.text(
                    "SELECT 1 FROM reports WHERE scan_id = :sid"
                ), {"sid": scan_id}).fetchone():
                    conn.execute(db.text(
                        "INSERT INTO reports (scan_id, ai_analysis, generated_at)"
                        " VALUES (:sid, :ai, :ts)"
                    ), {"sid": scan_id, "ai": ai_analysis, "ts": datetime.utcnow()})

                if not report_json:
                    continue
                try:
                    data = json.loads(report_json)
                except Exception:
                    continue

                # XSS findings
                if not conn.execute(db.text(
                    "SELECT 1 FROM xss_findings WHERE scan_id = :sid"
                ), {"sid": scan_id}).fetchone():
                    for x in data.get('xss', []):
                        conn.execute(db.text("""
                            INSERT INTO xss_findings
                              (scan_id, payload, parameter, type, vulnerable,
                               risk, url, status_code, description, recommendation, error)
                            VALUES
                              (:sid, :payload, :param, :type, :vuln,
                               :risk, :url, :sc, :desc, :rec, :err)
                        """), {
                            "sid": scan_id,
                            "payload": x.get('payload'),  "param": x.get('parameter'),
                            "type":    x.get('type'),     "vuln":  bool(x.get('vulnerable')),
                            "risk":    x.get('risk'),     "url":   x.get('url'),
                            "sc":      x.get('status'),   "desc":  x.get('description'),
                            "rec":     x.get('recommendation'), "err": x.get('error'),
                        })

                # SQLi findings
                if not conn.execute(db.text(
                    "SELECT 1 FROM sqli_findings WHERE scan_id = :sid"
                ), {"sid": scan_id}).fetchone():
                    for s in data.get('sqli', []):
                        conn.execute(db.text("""
                            INSERT INTO sqli_findings
                              (scan_id, payload, parameter, type, technique, vulnerable,
                               risk, db_type, detection, url, status_code,
                               description, recommendation, error)
                            VALUES
                              (:sid, :payload, :param, :type, :tech, :vuln,
                               :risk, :dbt, :det, :url, :sc,
                               :desc, :rec, :err)
                        """), {
                            "sid":     scan_id,
                            "payload": s.get('payload'),  "param": s.get('parameter'),
                            "type":    s.get('type'),     "tech":  s.get('technique'),
                            "vuln":    bool(s.get('vulnerable')), "risk": s.get('risk'),
                            "dbt":     s.get('db_type'),  "det":   s.get('detection'),
                            "url":     s.get('url'),      "sc":    s.get('status'),
                            "desc":    s.get('description'), "rec": s.get('recommendation'),
                            "err":     s.get('error'),
                        })

                # Header findings
                if not conn.execute(db.text(
                    "SELECT 1 FROM header_findings WHERE scan_id = :sid"
                ), {"sid": scan_id}).fetchone():
                    for h in data.get('headers', []):
                        conn.execute(db.text("""
                            INSERT INTO header_findings
                              (scan_id, header, status, risk, value,
                               description, recommendation, impact, error)
                            VALUES
                              (:sid, :hdr, :status, :risk, :val,
                               :desc, :rec, :impact, :err)
                        """), {
                            "sid":    scan_id,     "hdr":    h.get('header'),
                            "status": h.get('status'), "risk": h.get('risk'),
                            "val":    h.get('value'),  "desc": h.get('description'),
                            "rec":    h.get('recommendation'), "impact": h.get('impact'),
                            "err":    h.get('error'),
                        })

            conn.commit()

            # Recreate scan_records without blob columns
            conn.execute(db.text("DROP TABLE IF EXISTS scan_records_new"))
            conn.execute(db.text("""
                CREATE TABLE scan_records_new (
                    id              INTEGER PRIMARY KEY,
                    target_url      VARCHAR(500) NOT NULL,
                    scan_type       VARCHAR(50)  DEFAULT 'full',
                    timestamp       DATETIME,
                    severity        VARCHAR(20)  DEFAULT 'low',
                    risk_score      INTEGER      DEFAULT 0,
                    xss_count       INTEGER      DEFAULT 0,
                    sqli_count      INTEGER      DEFAULT 0,
                    headers_missing INTEGER      DEFAULT 0,
                    duration_s      FLOAT        DEFAULT 0.0,
                    user_id         INTEGER REFERENCES users(id)
                )
            """))
            # Only copy columns that actually exist in the old table
            old_cols = {r[1] for r in conn.execute(
                db.text("PRAGMA table_info(scan_records)")).fetchall()}
            copy_cols = [c for c in [
                'id', 'target_url', 'scan_type', 'timestamp', 'severity',
                'risk_score', 'xss_count', 'sqli_count', 'headers_missing',
                'duration_s', 'user_id',
            ] if c in old_cols]
            cols_sql = ', '.join(copy_cols)
            conn.execute(db.text(
                f"INSERT INTO scan_records_new ({cols_sql}) SELECT {cols_sql} FROM scan_records"
            ))
            conn.execute(db.text("DROP TABLE scan_records"))
            conn.execute(db.text("ALTER TABLE scan_records_new RENAME TO scan_records"))
            conn.commit()

        # ── Indexes (idempotent) ──────────────────────────────────────────────
        conn.execute(db.text(
            "CREATE INDEX IF NOT EXISTS ix_scan_user_ts  ON scan_records(user_id, timestamp)"))
        conn.execute(db.text(
            "CREATE INDEX IF NOT EXISTS ix_scan_user_sev ON scan_records(user_id, severity)"))
        conn.commit()


with app.app_context():
    db.create_all()
    _run_migrations()


# ── In-memory SSE progress stores ─────────────────────────────────────────────
_progress:     dict = {}
_dir_progress: dict = {}


# ── Helper ────────────────────────────────────────────────────────────────────

def _build_report_dict(rec: ScanRecord) -> dict:
    """Reconstruct the report dict from normalized tables (same shape templates expect)."""
    return {
        'url': rec.target_url,
        'xss': [{
            'payload':        f.payload,
            'parameter':      f.parameter,
            'type':           f.vuln_type,
            'vulnerable':     f.vulnerable,
            'risk':           f.risk,
            'url':            f.url,
            'status':         f.status_code,
            'description':    f.description,
            'recommendation': f.recommendation,
            'error':          f.error,
        } for f in rec.xss_findings],
        'sqli': [{
            'payload':        f.payload,
            'parameter':      f.parameter,
            'type':           f.vuln_type,
            'technique':      f.technique,
            'vulnerable':     f.vulnerable,
            'risk':           f.risk,
            'db_type':        f.db_type,
            'detection':      f.detection,
            'url':            f.url,
            'status':         f.status_code,
            'description':    f.description,
            'recommendation': f.recommendation,
            'error':          f.error,
        } for f in rec.sqli_findings],
        'headers': [{
            'header':         f.header,
            'status':         f.status,
            'risk':           f.risk,
            'value':          f.value,
            'description':    f.description,
            'recommendation': f.recommendation,
            'impact':         f.impact,
            'error':          f.error,
        } for f in rec.header_findings],
    }


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
            user.last_login = datetime.utcnow()
            db.session.commit()
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
    _owner_id  = current_user.id if save_to_db else None

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
                        duration_s=elapsed,
                        user_id=_owner_id,
                    )
                    db.session.add(rec)
                    db.session.flush()   # populate rec.id before adding children

                    for x in xss:
                        db.session.add(XssFinding(
                            scan_id=rec.id,
                            payload=x.get('payload'),
                            parameter=x.get('parameter'),
                            vuln_type=x.get('type'),
                            vulnerable=bool(x.get('vulnerable')),
                            risk=x.get('risk'),
                            url=x.get('url'),
                            status_code=x.get('status'),
                            description=x.get('description'),
                            recommendation=x.get('recommendation'),
                            error=x.get('error'),
                        ))

                    for s in sqli:
                        db.session.add(SqliFinding(
                            scan_id=rec.id,
                            payload=s.get('payload'),
                            parameter=s.get('parameter'),
                            vuln_type=s.get('type'),
                            technique=s.get('technique'),
                            vulnerable=bool(s.get('vulnerable')),
                            risk=s.get('risk'),
                            db_type=s.get('db_type'),
                            detection=s.get('detection'),
                            url=s.get('url'),
                            status_code=s.get('status'),
                            description=s.get('description'),
                            recommendation=s.get('recommendation'),
                            error=s.get('error'),
                        ))

                    for h in headers:
                        db.session.add(HeaderFinding(
                            scan_id=rec.id,
                            header=h.get('header'),
                            status=h.get('status'),
                            risk=h.get('risk'),
                            value=h.get('value'),
                            description=h.get('description'),
                            recommendation=h.get('recommendation'),
                            impact=h.get('impact'),
                            error=h.get('error'),
                        ))

                    db.session.add(Report(
                        scan_id=rec.id,
                        ai_analysis=ai,
                        generated_at=datetime.utcnow(),
                    ))
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
                        'ai': ai, 'duration_s': elapsed,
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
    report_data = _build_report_dict(rec)
    sev      = calculate_severity(report_data)
    ai_text  = rec.report.ai_analysis if rec.report else ''
    return render_template('report.html', record=rec, report=report_data,
                           severity=sev, ai=ai_text,
                           temp=False, duration_s=rec.duration_s)


@app.route('/report/<int:record_id>/pdf')
def download_pdf(record_id):
    rec = ScanRecord.query.get_or_404(record_id)
    if rec.user_id is not None:
        if not current_user.is_authenticated or rec.user_id != current_user.id:
            abort(403)
    report_data = _build_report_dict(rec)
    sev     = calculate_severity(report_data)
    ai_text = rec.report.ai_analysis if rec.report else ''
    path    = generate_pdf(report=report_data, severity=sev, ai_report=ai_text)
    return send_file(path, as_attachment=True,
                     download_name=f"zeroprobe_report_{record_id}.pdf")


@app.route('/dashboard')
def dashboard():
    if not current_user.is_authenticated:
        return render_template('dashboard.html', stats=None, recent=[], daily_json='[]', severity_json='{}')
    from sqlalchemy import func
    uid    = current_user.id
    base_q = ScanRecord.query.filter_by(user_id=uid)
    total  = base_q.count()
    by_sev = dict(
        db.session.query(ScanRecord.severity, func.count(ScanRecord.id))
        .filter(ScanRecord.user_id == uid)
        .group_by(ScanRecord.severity).all()
    )
    recent    = base_q.order_by(ScanRecord.timestamp.desc()).limit(10).all()
    daily_raw = (
        db.session.query(
            func.strftime('%Y-%m-%d', ScanRecord.timestamp).label('day'),
            func.count(ScanRecord.id).label('cnt')
        )
        .filter(ScanRecord.user_id == uid)
        .group_by('day').order_by('day').limit(14).all()
    )
    daily     = [{'date': r.day, 'count': r.cnt} for r in daily_raw]
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
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            return jsonify({'error': 'URL required'}), 400
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        scan_id = f"dir_{int(time.time() * 1000)}"
        _dir_progress[scan_id] = {
            'status': 'running', 'checked': 0, 'total': 0,
            'found': 0, 'url': url,
        }

        def _run():
            def on_progress(checked, total, found_count):
                _dir_progress[scan_id].update({
                    'checked': checked, 'total': total, 'found': found_count,
                })
            try:
                results = run_dir_scan_stream(url, on_progress)
                _dir_progress[scan_id].update({
                    'status': 'done', 'results': results, 'found': len(results),
                })
            except Exception as e:
                _dir_progress[scan_id].update({
                    'status': 'error', 'error': str(e),
                })

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({'scan_id': scan_id, 'url': url})

    return render_template('dirscan.html', url='')


@app.route('/dirscan-progress/<scan_id>')
def dirscan_progress(scan_id):
    def _stream():
        while True:
            data = _dir_progress.get(scan_id)
            if not data:
                yield f"data: {json.dumps({'status': 'error', 'error': 'Scan not found'})}\n\n"
                break
            if data.get('status') in ('done', 'error'):
                yield f"data: {json.dumps(data)}\n\n"
                break
            # Send progress without the (not-yet-complete) results list
            yield f"data: {json.dumps({k: v for k, v in data.items() if k != 'results'})}\n\n"
            time.sleep(0.5)
    return Response(
        _stream(), mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True, port=5000)
