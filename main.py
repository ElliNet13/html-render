from flask import Flask, render_template, request, make_response
import os
import base64
import hashlib

app = Flask(__name__)

def calculate_sha256_hash(data):
    return hashlib.sha256(data.encode('utf-8')).digest()

@app.route('/', methods=['GET', 'POST'])
def index():
    nonce = base64.b64encode(os.urandom(16)).decode('utf-8')

    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        # Perform proper validation and sanitization on user_input here
        # For demonstration purposes, let's assume it's safe for now

        # Calculate the hash for the inline script
        inline_script = "alert('This is an inline script!');"
        script_hash = base64.b64encode(calculate_sha256_hash(inline_script)).decode('utf-8')

        # Set the Content-Security-Policy header
        csp_header = f"script-src 'nonce-{nonce}' 'self' 'unsafe-inline' 'sha256-{script_hash}';"
        csp_header += f"script-src-elem 'nonce-{nonce}' 'self';"
        csp_header += f"style-src 'nonce-{nonce}' 'self' 'unsafe-inline';"
        csp_header += f"img-src 'nonce-{nonce}' 'self';"
        csp_header += f"iframe-src 'nonce-{nonce}' 'self';"
        response = make_response(render_template('index.html', nonce=nonce, user_input=user_input))
        response.headers['Content-Security-Policy'] = csp_header
        return response

    # Set the Content-Security-Policy header for the initial request
    csp_header = f"script-src 'nonce-{nonce}' 'self' 'unsafe-inline'; script-src-elem 'nonce-{nonce}' 'self';"
    csp_header += f"style-src 'nonce-{nonce}' 'self' 'unsafe-inline'; img-src 'nonce-{nonce}' 'self'; iframe-src 'nonce-{nonce}' 'self';"
    response = make_response(render_template('index.html', nonce=nonce))
    response.headers['Content-Security-Policy'] = csp_header
    return response

@app.route('/js')
def js():
    # You can render the template index.js here
    # Adjust the path if needed, assuming it's in a folder named 'templates'
    return render_template('index.js')

@app.route('/css')
def css():
    # You can render the template index.js here
    # Adjust the path if needed, assuming it's in a folder named 'templates'
    return render_template('index.css')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', threaded=True)