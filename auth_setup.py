#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Assistant d'Authentification OAuth2 Gmail pour Déploiement Cloud 24h/24.

Ce script :
1. Démarre le flux OAuth2 Google pour autoriser l'accès Gmail.
2. Génère un token.json frais et valide.
3. Teste immédiatement la connexion avec l'API Gmail.
4. Affiche les variables d'environnement prêtes à être copiées-collées dans votre hébergeur cloud (Render, Railway, GitHub Actions, etc.).
"""

import os
import sys
import json
import base64
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

SCOPES = ['https://mail.google.com/']
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(BASE_DIR, 'credentials.json')
TOKEN_FILE = os.path.join(BASE_DIR, 'token.json')


def main():
    print("=" * 75)
    print(" 🔐 ASSISTANT DE CONFIGURATION OAUTH2 GMAIL POUR LE CLOUD")
    print("=" * 75)

    if not os.path.exists(CREDENTIALS_FILE):
        print(f"\n❌ Erreur : Le fichier '{CREDENTIALS_FILE}' est introuvable.")
        print("👉 Veuillez placer votre fichier client secrets Google (OAuth 2.0) sous le nom 'credentials.json'.")
        sys.exit(1)

    print(f"\n1. Fichier 'credentials.json' détecté avec succès.")
    print("2. Lancement du navigateur pour vous connecter à votre compte Google...")

    try:
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        creds = flow.run_local_server(port=0)

        # Sauvegarde locale
        with open(TOKEN_FILE, 'w', encoding='utf-8') as f:
            f.write(creds.to_json())
        print(f"✅ 'token.json' généré et sauvegardé avec succès dans : {TOKEN_FILE}")

        # Test de validation
        print("\n3. Validation de la connexion à l'API Gmail...")
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        email_address = profile.get('emailAddress', 'Inconnu')
        print(f"🎉 Connexion réussie ! Compte connecté : {email_address}")

        # Export pour le Cloud
        with open(TOKEN_FILE, 'r', encoding='utf-8') as f:
            token_json_str = f.read()

        token_compact = json.dumps(json.loads(token_json_str))
        token_b64 = base64.b64encode(token_json_str.encode('utf-8')).decode('utf-8')

        with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
            creds_json_str = f.read()
        creds_compact = json.dumps(json.loads(creds_json_str))

        print("\n" + "=" * 75)
        print(" ☁️  VARIABLES D'ENVIRONNEMENT POUR LE DÉPLOIEMENT EN LIGNE (24h/24)")
        print("=" * 75)
        print("\nCopiez-collez ces valeurs dans les 'Environment Variables' de votre hébergeur :")
        print("\n--- [GMAIL_TOKEN_JSON] (Recommandé) ---")
        print(token_compact)
        print("\n--- [GMAIL_CREDENTIALS_JSON] ---")
        print(creds_compact)
        print("\n--- [GMAIL_TOKEN_BASE64] (Alternative si votre hébergeur gère mal les guillemets) ---")
        print(token_b64)
        print("\n" + "=" * 75)
        print("💡 Vous pouvez maintenant déployer sur Render, Railway, GitHub Actions ou VPS !")
        print("Consultez le fichier DEPLOIEMENT.md pour le guide complet.")
        print("=" * 75)

    except Exception as e:
        print(f"\n❌ Une erreur est survenue lors de l'authentification : {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
