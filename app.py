import os
import threading
import webbrowser
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from analyzer import analyze_eml

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
SAMPLE_DIR = os.path.join(BASE_DIR, 'sample_emails')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB


@app.route('/')
def index():
    samples = sorted(f for f in os.listdir(SAMPLE_DIR) if f.endswith('.eml'))
    return render_template('index.html', samples=samples)


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    # Either a file was uploaded, or a sample filename was requested
    if 'file' in request.files and request.files['file'].filename:
        f = request.files['file']
        filename = secure_filename(f.filename)
        if not filename.lower().endswith('.eml'):
            return jsonify({'error': 'Please upload a .eml file'}), 400
        path = os.path.join(UPLOAD_DIR, filename)
        f.save(path)
    else:
        sample = request.form.get('sample') or (request.json or {}).get('sample')
        if not sample:
            return jsonify({'error': 'No file or sample provided'}), 400
        path = os.path.join(SAMPLE_DIR, secure_filename(sample))
        if not os.path.exists(path):
            return jsonify({'error': 'Sample not found'}), 404

    try:
        findings = analyze_eml(path)
    except Exception as e:
        return jsonify({'error': f'Could not parse email: {e}'}), 400

    return jsonify(findings)


def open_browser():
    webbrowser.open('http://127.0.0.1:5000')


if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        threading.Timer(1.0, open_browser).start()
    app.run(debug=True)
