# SafeNotes

A secure note-taking web application built with Flask that emphasizes privacy and security. Features include end-to-end encryption, two-factor authentication, note sharing, and digital signatures.
The application is deployed in a production-ready configuration using uWSGI and Nginx as reverse proxy.

## Features

- **Web Security** 
  - HTTPS/TLS support
  - XSS protection
  - SQL injection protection
  - CSRF protection
  - Content Security Policy
  - Rate limiting
  - Secure headers

- **User Authentication & Security**
  - Two-factor authentication (TOTP)
  - Password strength requirements
  - Brute force protection with rate limiting
  - Session management
  - Login history tracking

- **Note Management**
  - Create private, public and shared with chosen users notes
  - Markdown support with safe HTML rendering
  - End-to-end encryption for sensitive notes
  - RSA signatures for author verification
  - AES-GCM encryption

## Installation

1. Clone the repository:
```bash
git clone https://github.com/adzia0/safeNotes.git
cd safenotes
```

2. Create and configure the `.env` file:
```bash
SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///path/to/your/database.db
AES_KEY_TOTP=your_aes_key_for_totp
AES_KEY_RSA=your_aes_key_for_rsa
AES_KEY_NOTE=your_aes_key_for_notes
MAIL_SERVER=your_mail_server
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email
MAIL_PASSWORD=your_email_password
```

3. Generate your  self-signed SSL certificates:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout docker/nginx/safenotes.key \
  -out docker/nginx/safenotes.crt
```

4. Build and run with Docker Compose:
```bash
docker-compose up --build
```

The application will be available at `https://localhost`