"""
PhishGuard v3 — Flask Application
Fuses ML prediction with 5 real-time zero-API-key checks.
"""

from flask import Flask, request, jsonify, render_template
import joblib, json, os
from feature_extractor import extract_features, FEATURE_NAMES
from realtime_scanner import run_all_checks
import concurrent.futures
import numpy as np

app = Flask(__name__)

# ── Load model ────────────────────────────────────────────────────────────────
MODEL_PATH  = "models/phishguard_rf.pkl"
SCALER_PATH = "models/scaler.pkl"
META_PATH   = "models/metadata.json"

model, scaler, meta = None, None, {}

def load_model():
    global model, scaler, meta
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model  = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        if os.path.exists(META_PATH):
            with open(META_PATH) as f:
                meta = json.load(f)
        print("[OK] Model loaded.")
    else:
        print("[WARN] No trained model found. Run train_model.py first.")


# ── Risk fusion ───────────────────────────────────────────────────────────────

def fuse_risk(ml_score: float, rt_checks: dict) -> dict:
    """
    Weighted fusion:
      40% ML probability
      60% real-time signals (blacklist, DNS, SSL, redirects, WHOIS)
    """
    # Normalise each signal to 0-100
    bl_risk = rt_checks['blacklist']['risk']              # 0 or 100
    dns_risk = rt_checks['dns']['risk']                   # 0-50
    ssl_risk = rt_checks['ssl']['risk']                   # 0-60
    red_risk = rt_checks['redirects']['risk']             # 0-50
    who_risk = rt_checks['whois']['risk']                 # 0-50

    rt_raw  = (bl_risk * 0.40 +
               dns_risk * 0.15 +
               ssl_risk * 0.20 +
               red_risk * 0.10 +
               who_risk * 0.15)

    ml_pct  = ml_score * 100          # 0-100
    final   = (ml_pct * 0.40) + (rt_raw * 0.60)
    final   = min(final, 100)

    if rt_checks['blacklist']['blacklisted']:
        final = 100   # hard override

    if final >= 75:
        verdict = 'PHISHING'
        color   = '#ef4444'
    elif final >= 45:
        verdict = 'SUSPICIOUS'
        color   = '#f59e0b'
    else:
        verdict = 'LEGITIMATE'
        color   = '#22c55e'

    return {
        'final_score': round(final, 1),
        'ml_score':    round(ml_pct, 1),
        'rt_score':    round(rt_raw, 1),
        'verdict':     verdict,
        'color':       color,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', meta=meta)


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    if len(url) > 2048:
        return jsonify({'error': 'URL too long'}), 400

    # 1. ML prediction (instant)
    features = extract_features(url)
    feat_vals = [features.get(n, 0) for n in FEATURE_NAMES]

    ml_prob = 0.5  # default if no model
    if model and scaler:
        try:
            X = scaler.transform([feat_vals])
            ml_prob = float(model.predict_proba(X)[0][1])
        except Exception as e:
            print(f"[WARN] ML error: {e}")

    # 2. Real-time checks (parallel, ~3-5 sec)
    rt = run_all_checks(url)

    # 3. Fuse
    risk = fuse_risk(ml_prob, rt)

    return jsonify({
        'url':      url,
        'risk':     risk,
        'features': features,
        'checks':   {
            'dns':       rt['dns'],
            'ssl':       rt['ssl'],
            'redirects': rt['redirects'],
            'blacklist': rt['blacklist'],
            'whois':     rt['whois'],
        }
    })


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'model_loaded': model is not None})


@app.route('/meta')
def get_meta():
    if not meta:
        return jsonify({'error': 'no model'}), 404
    return jsonify(meta)


if __name__ == '__main__':
    load_model()
    app.run(debug=True, port=5000)
