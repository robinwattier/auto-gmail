#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Assistant d'Authentification OAuth2 Gmail pour Déploiement Cloud 24h/24.
"""

import os
import sys
import json
import base64
from urllib.parse import urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler

# Forcer l'encodage UTF-8 pour Windows
if sys.platform.startswith('win'):
    try:
        if sys.stdout.encoding != 'utf-8':
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if sys.stderr.encoding != 'utf-8':
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

SCOPES = ['https://mail.google.com/']
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(BASE_DIR, 'credentials.json')
TOKEN_FILE = os.path.join(BASE_DIR, 'token.json')
RENDER_VARS_FILE = os.path.join(BASE_DIR, 'RENDER_VARS.txt')
URL_FILE = os.path.join(BASE_DIR, 'AUTH_URL.txt')

AUTH_CODE = None
AUTH_ERROR = None


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        global AUTH_CODE, AUTH_ERROR
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if 'code' in params:
            AUTH_CODE = params['code'][0]
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"><title>Connexion Réussie</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px; background-color: #f0fdf4;">
                <h1 style="color: #16a34a; font-size: 32px;">✅ Authentification Gmail Réussie !</h1>
                <p style="font-size: 18px; color: #374151;">Votre token a été enregistré avec succès.</p>
                <p style="font-size: 16px; color: #6b7280;">Vous pouvez fermer cet onglet et retourner dans votre IDE.</p>
            </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        elif 'error' in params:
            AUTH_ERROR = params['error'][0]
            self.send_response(400)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            html = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"><title>Erreur</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px; background-color: #fef2f2;">
                <h1 style="color: #dc2626;">❌ Erreur d'authentification</h1>
                <p style="color: #374151;">Détail : {AUTH_ERROR}</p>
            </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()


def main():
    print("=" * 75, flush=True)
    print(" 🔐 ASSISTANT DE CONFIGURATION OAUTH2 GMAIL POUR LE CLOUD", flush=True)
    print("=" * 75, flush=True)

    if not os.path.exists(CREDENTIALS_FILE):
        print(f"\n❌ Erreur : Le fichier '{CREDENTIALS_FILE}' est introuvable.", flush=True)
        sys.exit(1)

    flow = Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=SCOPES,
        redirect_uri="http://localhost:8085/"
    )

    auth_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent"
    )

    # Sauvegarde de l'URL
    with open(URL_FILE, 'w', encoding='utf-8') as f:
        f.write(auth_url)

    print("\n👉 LIEN D'AUTHENTIFICATION GOOGLE :", flush=True)
    print(auth_url, flush=True)
    print("=" * 75, flush=True)
    print("Serveur local en écoute sur http://localhost:8085/ ...", flush=True)

    server = HTTPServer(('127.0.0.1', 8085), OAuthCallbackHandler)

    # Attente de la requête de callback
    while AUTH_CODE is None and AUTH_ERROR is None:
        server.handle_request()

    server.server_close()

    if AUTH_ERROR:
        print(f"\n❌ Erreur reçue de Google : {AUTH_ERROR}", flush=True)
        sys.exit(1)

    print("\nÉchange du code d'autorisation contre les tokens...", flush=True)
    flow.fetch_token(code=AUTH_CODE)
    creds = flow.credentials

    # Sauvegarde locale
    with open(TOKEN_FILE, 'w', encoding='utf-8') as f:
        f.write(creds.to_json())
    print(f"✅ 'token.json' généré et sauvegardé avec succès dans : {TOKEN_FILE}", flush=True)

    # Test de validation API
    print("\nValidation de la connexion à l'API Gmail...", flush=True)
    service = build('gmail', 'v1', credentials=creds)
    profile = service.users().getProfile(userId='me').execute()
    email_address = profile.get('emailAddress', 'Inconnu')
    print(f"🎉 Connexion réussie ! Compte connecté : {email_address}", flush=True)

    # Export pour le Cloud
    with open(TOKEN_FILE, 'r', encoding='utf-8') as f:
        token_json_str = f.read()

    token_compact = json.dumps(json.loads(token_json_str))

    with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
        creds_json_str = f.read()
    creds_compact = json.dumps(json.loads(creds_json_str))

    # Enregistrement dans RENDER_VARS.txt
    gemini_key = os.getenv('GEMINI_API_KEY', '')
    user_name = os.getenv('USER_NAME', 'Robin')
    render_env_content = f"""GEMINI_API_KEY={gemini_key}
USER_NAME={user_name}
CHECK_INTERVAL_SECONDS=180
AUTO_DRAFT=true
PORT=8080
GMAIL_CREDENTIALS_JSON={creds_compact}
GMAIL_TOKEN_JSON={token_compact}
"""
    with open(RENDER_VARS_FILE, 'w', encoding='utf-8') as f:
        f.write(render_env_content)

    print("\n" + "=" * 75, flush=True)
    print(" ☁️  VARIABLES D'ENVIRONNEMENT ENREGISTRÉES DANS 'RENDER_VARS.txt'", flush=True)
    print("=" * 75, flush=True)
    print(render_env_content, flush=True)
    print("=" * 75, flush=True)


if __name__ == '__main__':
    main()
