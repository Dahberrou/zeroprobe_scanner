# app.py — ZeroProbe | Security Intelligence Platform
# Developed by Dah Berrou © 2026

import os
import json
import time
import threading
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   Response, send_file, redirect, url_for)
from flask_sqlalchemy import SQLAlchemy
from scanner.xss_scanner     import scan_xss
from scanner.sqli_scanner    import scan_sqli
from scanner.headers_scanner import scan_headers
from scanner.subdomain_scanner import run_subdomain_scan
from scanner.dir_scanner       import run_dir_scan
from utils.ai_report    import generate_ai_report
from utils.severity     import calculate_severity
from utils.pdf_report   import generate_pdf

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zeroprobe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# ── Model ─────────────────────────────────────────────────────────────────────
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


with app.app_context():
    db.create_all()

# ── In-memory SSE progress store ──────────────────────────────────────────────
_progress: dict = {}


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    recent = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(5).all()
    stats = {
        'total':    ScanRecord.query.count(),
        'critical': ScanRecord.query.filter_by(severity='critical').count(),
        'high':     ScanRecord.query.filter_by(severity='high').count(),
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
                    duration_s=round(time.time() - start, 1)
                )
                db.session.add(rec)
                db.session.commit()
                record_id = rec.id

            elapsed = round(time.time() - start, 1)
            _log(f"Scan complete in {elapsed}s — record #{record_id} saved")
            _progress[scan_id].update({
                'status': 'done', 'progress': 100,
                'stage': 'Scan complete!', 'record_id': record_id
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


@app.route('/report/<int:record_id>')
def report(record_id):
    rec = ScanRecord.query.get_or_404(record_id)
    report_data = json.loads(rec.report_json)
    sev = calculate_severity(report_data)
    return render_template('report.html', record=rec,
                           report=report_data, severity=sev, ai=rec.ai_analysis)


@app.route('/report/<int:record_id>/pdf')
def download_pdf(record_id):
    rec = ScanRecord.query.get_or_404(record_id)
    report_data = json.loads(rec.report_json)
    sev = calculate_severity(report_data)
    path = generate_pdf(report=report_data, severity=sev, ai_report=rec.ai_analysis)
    return send_file(path, as_attachment=True,
                     download_name=f"zeroprobe_report_{record_id}.pdf")


@app.route('/dashboard')
def dashboard():
    from sqlalchemy import func
    total  = ScanRecord.query.count()
    by_sev = dict(
        db.session.query(ScanRecord.severity, func.count(ScanRecord.id))
        .group_by(ScanRecord.severity).all()
    )
    recent = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(10).all()
    daily_raw = (
        db.session.query(
            func.strftime('%Y-%m-%d', ScanRecord.timestamp).label('day'),
            func.count(ScanRecord.id).label('cnt')
        )
        .group_by('day').order_by('day').limit(14).all()
    )
    daily = [{'date': r.day, 'count': r.cnt} for r in daily_raw]
    avg_score = db.session.query(func.avg(ScanRecord.risk_score)).scalar() or 0
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
    page       = request.args.get('page', 1, type=int)
    sev_filter = request.args.get('severity', '')
    q = ScanRecord.query.order_by(ScanRecord.timestamp.desc())
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
