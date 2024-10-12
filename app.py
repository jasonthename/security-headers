from flask import Flask, request, jsonify, render_template, send_from_directory
from talisman import Talisman
import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from urllib.parse import urlparse
import ipaddress

import ssl
import socket

import os
from dotenv import load_dotenv

app = Flask(__name__, static_folder='templates')
load_dotenv()

app.config['SSL_CERT_PATH'] = os.getenv('SSL_CERT_PATH')
app.config['SSL_KEY_PATH'] = os.getenv('SSL_KEY_PATH')

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(app.config['SSL_CERT_PATH'], app.config['SSL_KEY_PATH'])
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.set_ciphers('HIGH:!aNULL:!MD5:!RC4:!DH:!ECDH')

csp = {
    'default-src': "'self'",
    'img-src': "'self' data: https://github.githubassets.com",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline'",
    'font-src': "'self'",
    'frame-ancestors': "'none'",
    'form-action': "'self'"
}

Talisman(app, content_security_policy=csp)

# Security headers to check for
sec_headers = {
    'X-XSS-Protection': 'warning',
    'X-Frame-Options': 'warning',
    'X-Content-Type-Options': 'warning',
    'Strict-Transport-Security': 'error',
    'Content-Security-Policy': 'warning',
    'Referrer-Policy': 'warning',
    'Permissions-Policy': 'warning',
    'Cross-Origin-Embedder-Policy': 'warning',
    'Cross-Origin-Resource-Policy': 'warning',
    'Cross-Origin-Opener-Policy': 'warning'
}

information_headers = {
    'X-Powered-By',
    'Server'
}

cache_headers = {
    'Cache-Control',
    'Pragma',
    'Expires',
    'ETag'
}

# Custom headers to send with the request
custom_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Upgrade-Insecure-Requests': '1',
    'Connection': 'close'
}

class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_version=ssl.PROTOCOL_TLSv1_2
        )

def is_https(url):
    parsed = urlparse(url)
    return parsed.scheme == 'https'

def normalize_url(url):
    try:
        parsed = urlparse(url)
        
        # If no scheme is provided, assume http
        if not parsed.scheme:
            url = 'http://' + url
            parsed = urlparse(url)
        
        # Validate the hostname
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise ValueError("Private or local IP addresses are not allowed")
        except ValueError:
            # Not an IP address, so it's a hostname
            socket.gethostbyname(parsed.hostname)  # This will raise an exception if the hostname is invalid
        
        # Ensure the scheme is either http or https
        if parsed.scheme not in ('http', 'https'):
            raise ValueError("Only http and https schemes are allowed")
        
        return url
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'templates', 'media'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/check-headers')
def check_headers():
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    url = normalize_url(url)

    try:
        session = requests.Session()
        session.mount('https://', TLSAdapter())

        response = session.get(url, headers=custom_headers, timeout=10, verify=True)
        response_headers = response.headers

        # Remove X-Frame-Options if CSP with frame-ancestors is present
        if "Content-Security-Policy" in response_headers and "frame-ancestors" in response_headers["Content-Security-Policy"].lower():
            sec_headers.pop("X-Frame-Options", None)

        security_headers = {}
        information_disclosure = {}
        caching_headers = {}
        missing_headers = []

        for header, severity in sec_headers.items():
            if header.lower() in response_headers:
                security_headers[header] = response_headers[header.lower()]
            else:
                if header != 'Strict-Transport-Security' or url.startswith('https://'):
                    missing_headers.append(header)

        for header in information_headers:
            if header.lower() in response_headers:
                information_disclosure[header] = response_headers[header.lower()]

        for header in cache_headers:
            if header.lower() in response_headers:
                caching_headers[header] = response_headers[header.lower()]

        result = {
            'url': url,
            'security_headers': security_headers,
            'missing_headers': missing_headers,
            'information_disclosure': information_disclosure,
            'caching_headers': caching_headers
        }

        return jsonify(result)

    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500