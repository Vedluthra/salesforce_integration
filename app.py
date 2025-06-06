
from flask import Flask, request, redirect, session, render_template, jsonify, url_for
import requests
import sqlite3
import json
import os
import secrets
import hashlib
import base64
from urllib.parse import urlencode
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

DB_PATH = 'tokens.db'

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS tokens (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            access_token TEXT,
                            refresh_token TEXT,
                            instance_url TEXT,
                            issued_at TEXT
                        )''')
init_db()

CLIENT_ID = os.getenv('SALESFORCE_CLIENT_ID')
CLIENT_SECRET = os.getenv('SALESFORCE_CLIENT_SECRET')
REDIRECT_URI = os.getenv('SALESFORCE_REDIRECT_URI')
AUTH_URL = 'https://login.salesforce.com/services/oauth2/authorize'
TOKEN_URL = 'https://login.salesforce.com/services/oauth2/token'

def generate_code_verifier(length=128):
    return secrets.token_urlsafe(length)

def generate_code_challenge(code_verifier):
    s256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(s256).decode('utf-8').rstrip('=')

@app.route('/')
def index():
    return '<a href="/login">Login with Salesforce</a>'

@app.route('/login')
def login():
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    session['code_verifier'] = code_verifier

    query = urlencode({
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'scope': 'full refresh_token api offline_access',
        'prompt': 'login consent'
    })
    return redirect(f"{AUTH_URL}?{query}")

@app.route('/callback')
def callback():
    error = request.args.get('error')
    if error:
        return f"Authorization Error: {error} - {request.args.get('error_description')}"

    code = request.args.get('code')
    code_verifier = session.pop('code_verifier', None)
    if not code or not code_verifier:
        return "Missing authorization code or PKCE code_verifier."

    token_payload = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'code': code,
        'code_verifier': code_verifier
    }

    try:
        response = requests.post(TOKEN_URL, data=token_payload)
        response.raise_for_status()
        token_data = response.json()

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM tokens")
            conn.execute("INSERT INTO tokens (access_token, refresh_token, instance_url, issued_at) VALUES (?, ?, ?, ?)",
                         (token_data['access_token'], token_data['refresh_token'], token_data['instance_url'], token_data['issued_at']))

        return redirect('/leads')

    except requests.exceptions.RequestException as e:
        return f"Error exchanging token: {e}. Response: {response.text if 'response' in locals() else 'N/A'}"

def get_token():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("SELECT access_token, instance_url FROM tokens ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        if row:
            return row[0], row[1]
    return None, None

@app.route('/leads')
def leads():
    return render_template('leads.html')

@app.route('/update-lead', methods=['POST'])
def update_lead():
    access_token, instance_url = get_token()
    if not access_token:
        return redirect('/')

    lead_id = request.form['lead_id']
    update_data = {
        "FirstName": request.form.get('first_name', ''),
        "LastName": request.form.get('last_name', ''),
        "Email": request.form.get('email', '')
    }

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    url = f"{instance_url}/services/data/v59.0/sobjects/Lead/{lead_id}"
    response = requests.patch(url, headers=headers, data=json.dumps(update_data))

    return jsonify(response.json() if response.status_code != 204 else {"status": "Lead updated successfully"})

@app.route('/get_leads')
def get_leads():
    access_token, instance_url = get_token()
    if not access_token or not instance_url:
        return redirect(url_for('login'))

    query = "SELECT Id, Name, Email, Company FROM Lead LIMIT 10"
    url = f"{instance_url}/services/data/v59.0/query"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, params={'q': query})
        response.raise_for_status()
        records = response.json().get('records', [])

        leads_html = '<h2>Salesforce Leads:</h2><ul>'
        for lead in records:
            leads_html += f"<li>{lead.get('Name')} ({lead.get('Email')}) - {lead.get('Company')}</li>"
        leads_html += '</ul>'
        return leads_html

    except requests.exceptions.RequestException as e:
        return f"Error fetching leads: {e}. Response: {response.text if 'response' in locals() else 'N/A'}"

if __name__ == '__main__':
    app.run(debug=False)
