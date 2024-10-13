<div style="display: flex; align-items: center;">
        <div style="margin-right: 20px;">
            <h2 style="margin: 0;">Security Headers Scanner</h2>
            <p style="margin: 0;">Self-hosted configuration includes TLS configuration and local security headers.</p>
        </div>
        <img src="templates/media/expo.jpg" alt="Expo Image" style="width: 100px; height: auto;">
    </div>

### Getting Started

1. Generating SSL Key and Certificate
Create a directory named crypt to store the SSL key and certificate:

```
> mkdir crypt
> cd crypt
```

2. Generate a private key and self-signed certificate using OpenSSL.

```
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
```

* This command generates a new 2048-bit RSA private key (key.pem) and a self-signed certificate (cert.pem) valid for 365 days.

* You will be prompted to enter information for the certificate, such as country, state, organization, etc. For local development, you can leave most fields blank or enter dummy values.

* Install the requirements:
```
pip install -r requirements.txt
```

3. With the virtual environment activated, run the Flask application:
```
gunicorn --certfile=crypt/cert.pem --keyfile=crypt/key.pem --bind 0.0.0.0:5000 wsgi:app
```

2. The application will be available at `https://localhost:5000` (note the HTTPS).

Since the certificate is self-signed, your browser may display a security warning. You can safely proceed to the website for local development.

3. You can review the [Code security report](security.md) to analyze the code's vulnerability history and remediations.

