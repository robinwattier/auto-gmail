#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent Gmail Exécutif & Intelligent
Conforme aux spécifications de prompt.md :
- Règles de sécurité absolues (Mails à ne JAMAIS supprimer) :
    1. Échanges humains directs (fils de discussion, personnes physiques).
    2. Finances & Légal (banques, impôts, factures, devis, contrats, signatures électroniques).
    3. Sécurité & Accès (2FA/OTP, réinitialisation de mot de passe, alertes).
    4. Logistique & Déplacements (billets de train/avion, hôtels, transports, rendez-vous/agenda).
    5. Documents utiles (e-mails avec pièces jointes PDF, DOCX, XLSX, etc.).
- Purification :
    - Newsletters & marketing : Désabonnement HTTP (List-Unsubscribe) + mise en corbeille + purge.
    - E-mails futiles / notifications de basse valeur : Mise directe en corbeille.
- E-mails Importants & Actionnables :
    - Génération d'une réponse de haute qualité via Gemini 2.5 Flash.
    - Création automatique d'un brouillon officiel Gmail (Draft).
    - Format de validation obligatoire strict et validation interactive avant envoi.
"""

import os
import sys
import time
import re
import json
import base64
import argparse
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.header import Header
from email import encoders
from typing import Optional, Dict, Any, List, Tuple

import requests
from dotenv import load_dotenv

# Google APIs
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Google GenAI SDK (Gemini)
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

# Charger les variables d'environnement
load_dotenv()

# Forcer l'encodage UTF-8 pour Windows
if sys.platform.startswith('win'):
    try:
        if sys.stdout.encoding != 'utf-8':
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if sys.stderr.encoding != 'utf-8':
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Configuration
SCOPES = ['https://mail.google.com/']
CREDENTIALS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'credentials.json')
TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'token.json')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '').strip()
USER_NAME = os.getenv('USER_NAME', 'Robin').strip()
DEFAULT_CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL_SECONDS', '180'))
DEFAULT_CV_FILE = os.getenv('CV_FILE', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'CV_Robin_Wattier.pdf'))

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("GmailAgent")

# Statistiques d'exécution pour le Cloud & le Healthcheck
AGENT_STATS = {
    "start_time": time.time(),
    "cycles_completed": 0,
    "last_scan_time": None,
    "last_status": "Initialisation...",
    "errors_count": 0,
}


# ==============================================================================
# SERVEUR DE SANTÉ HTTP POUR DÉPLOIEMENT CLOUD (Render, Railway, Cloud Run...)
# ==============================================================================

class HealthCheckHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Désactiver les logs verbeux de requêtes HTTP
        pass

    def do_GET(self):
        if self.path in ['/', '/health', '/status', '/ping']:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            uptime_sec = int(time.time() - AGENT_STATS["start_time"])
            response_data = {
                "status": "healthy",
                "service": "Gmail Executive Agent",
                "uptime_seconds": uptime_sec,
                "uptime_human": f"{uptime_sec // 3600}h {(uptime_sec % 3600) // 60}m {uptime_sec % 60}s",
                "cycles_completed": AGENT_STATS["cycles_completed"],
                "last_scan_time": AGENT_STATS["last_scan_time"],
                "last_status": AGENT_STATS["last_status"],
                "errors_count": AGENT_STATS["errors_count"],
            }
            self.wfile.write(json.dumps(response_data, ensure_ascii=False, indent=2).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error": "Not Found"}')


def start_healthcheck_server(port: int = 8080):
    """Démarre un serveur HTTP minimaliste en tâche de fond pour satisfaire les checks de santé cloud."""
    try:
        server = HTTPServer(('0.0.0.0', port), HealthCheckHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logger.info(f"🌐 Serveur de santé HTTP actif sur le port {port} (Endpoint: http://0.0.0.0:{port}/health)")
        return server
    except Exception as e:
        logger.warning(f"⚠️ Impossible de démarrer le serveur HTTP de santé sur le port {port}: {e}")
        return None


# ==============================================================================
# 1. RÈGLES DE SÉCURITÉ : MAILS À NE JAMAIS SUPPRIMER (PRIORITÉ ABSOLUE)
# ==============================================================================

# 1.1 SÉCURITÉ & ACCÈS (2FA, codes, alertes)
WHITELIST_SECURITY_SENDERS = [
    r'@accounts\.google\.com',
    r'@(no-reply|security|accountprotection)\.microsoft\.com',
    r'@(id|appleid)\.apple\.com',
    r'@(no-reply|notifications)\.github\.com',
    r'@(no-reply|notifications)\.gitlab\.com',
    r'@.*\.auth0\.com',
    r'@.*\.okta\.com',
    r'@.*\.cloudflare\.com',
    r'@(notification|no-reply)\.aws\.amazon\.com',
    r'@.*\.ovhcloud\.com',
    r'@.*\.infomaniak\.com',
]

WHITELIST_SECURITY_KEYWORDS = [
    r'code de v[ée]rification',
    r'v[ée]rification de s[ée]curit[ée]',
    r'authentification [àa] deux facteurs',
    r'\b2fa\b',
    r'\botp\b',
    r'one[- ]time password',
    r'mot de passe temporaire',
    r'security alert',
    r'alerte de s[ée]curit[ée]',
    r'nouvelle connexion',
    r'connexion suspecte',
    r'sign[- ]in attempt',
    r'tentative de connexion',
    r'r[ée]initialisation de votre mot de passe',
    r'password reset',
    r'v[ée]rifiez votre adresse',
    r'confirm your email',
    r'r[ée]ponse automatique',
    r'automatic reply',
    r'auto[- ]reply',
    r'out of office',
    r'absent(e)? du bureau',
]

# 1.2 FINANCES & LÉGAL (Banques, factures, devis, contrats, signatures électroniques)
WHITELIST_FINANCE_LEGAL_SENDERS = [
    r'@.*\.paypal\.(com|fr)',
    r'@.*\.stripe\.com',
    r'@.*\.bourso(rama)?\.(com|fr)',
    r'@.*\.revolut\.com',
    r'@.*\.credit-agricole\.fr',
    r'@.*\.bnpparibas\.com',
    r'@.*\.societegenerale\.fr',
    r'@.*\.banquepopulaire\.fr',
    r'@.*\.caisse-epargne\.fr',
    r'@.*\.creditmutuel\.fr',
    r'@.*\.cic\.fr',
    r'@.*\.lcl\.fr',
    r'@.*\.n26\.com',
    r'@.*\.wise\.com',
    r'@.*\.sumup\.com',
    r'@.*\.qonto\.com',
    r'@.*\.shine\.fr',
    r'@.*\.payfit\.com',
    r'@.*\.alan\.com',
    r'@.*\.impots\.gouv\.fr',
    r'@.*\.urssaf\.fr',
    # Signatures électroniques & contrats
    r'@.*\.docusign\.(com|net|fr)',
    r'@.*\.yousign\.(com|fr)',
    r'@.*\.echosign\.com',
    r'@.*\.adobesign\.com',
    r'@.*\.hellosign\.com',
    r'@.*\.signaturit\.com',
    r'@.*\.pandadoc\.com',
]

WHITELIST_FINANCE_LEGAL_KEYWORDS = [
    r'relev[ée] de compte',
    r'virement (re[çc]u|effectu[ée]|bancaire)',
    r'pr[ée]l[èe]vement',
    r'paiement (accept[ée]|re[çc]u|effectu[ée]|confirm[ée])',
    r'confirmation de (votre )?paiement',
    r'votre (re[çc]u|facture)',
    r're[çc]u de (votre )?paiement',
    r'avis de d[ée]bit',
    r'facture n[°o]',
    r'\binvoice\b',
    r'payment received',
    r'payment confirmation',
    r'transaction confirmation',
    r'avis d[\'’]op[ée]ration',
    # Légal & Signatures
    r'\bcontrat\b',
    r'\bdevis\b',
    r'\bavenant\b',
    r'signature [ée]lectronique',
    r'document [àa] signer',
    r'veuillez signer',
    r'has requested your signature',
    r'completed:? please sign',
    r'document compl[ée]t[ée]',
]

# 1.3 LOGISTIQUE & DÉPLACEMENTS (Billets train/avion, hôtels, transports, rendez-vous/agenda)
WHITELIST_LOGISTICS_SENDERS = [
    r'@.*\.sncf\.(com|fr)',
    r'@.*\.oui\.sncf',
    r'@.*\.sncf-connect\.com',
    r'@.*\.trainline\.(com|fr)',
    r'@.*\.airfrance\.(com|fr)',
    r'@.*\.eurostar\.com',
    r'@.*\.easyjet\.com',
    r'@.*\.ryanair\.com',
    r'@.*\.transavia\.com',
    r'@.*\.booking\.com',
    r'@.*\.airbnb\.com',
    r'@.*\.accor\.com',
    r'@.*\.hotels\.com',
    r'@.*\.expedia\.(com|fr)',
    r'@.*\.uber\.com',
    r'@.*\.bolt\.eu',
    r'@.*\.blablacar\.(com|fr)',
    r'@.*\.doctolib\.(fr|com)',
    r'@.*\.calendly\.com',
    r'@.*\.calendar\.google\.com',
]

WHITELIST_LOGISTICS_KEYWORDS = [
    r'billet de train',
    r'billet d[\'’]avion',
    r'e[- ]billet',
    r'carte d[\'’]embarquement',
    r'boarding pass',
    r'confirmation de r[ée]servation',
    r'r[ée]servation (d[\'’]h[ôo]tel|confirm[ée]e|de votre s[ée]jour)',
    r'votre voyage',
    r'votre trajet',
    r'votre course',
    r'rappel de rendez[- ]vous',
    r'invitation (au|pour le) rendez[- ]vous',
    r'rendez[- ]vous confirm[ée]',
    r'invitation d[\'’]agenda',
    r'calendly',
    r'doctolib',
]

# 1.4 RECRUTEMENT & CANDIDATURES (Plateformes ATS)
WHITELIST_CAREER_SENDERS = [
    r'@.*\.welcometothejungle\.com',
    r'@.*\.jobteaser\.com',
    r'@.*\.linkedin\.com',
    r'@.*\.indeed\.com',
    r'@.*\.smartrecruiters\.com',
    r'@.*\.greenhouse\.io',
    r'@.*\.lever\.co',
    r'@.*\.workday\.com',
    r'@.*\.myworkday\.com',
    r'@.*\.flatchr\.io',
    r'@.*\.teamtailor\.com',
    r'@.*\.apec\.fr',
    r'@.*\.hellowork\.com',
    r'@.*\.personio\.(de|com)',
    r'@.*\.ashbyhq\.com',
    r'@.*\.recruitee\.com',
]

WHITELIST_CAREER_KEYWORDS = [
    r'accus[ée] de r[ée]ception (de votre candidature|de candidature)',
    r'confirmation de (r[ée]ception|votre candidature|postulation)',
    r'nous avons bien re[çc]u votre candidature',
    r'votre candidature a bien [ée]t[ée] re[çc]ue',
    r'votre candidature a bien [ée]t[ée] transmise',
    r'application (received|confirmed|confirmation)',
    r'thank you for applying',
    r'we received your application',
    r'r[ée]ception de votre cv',
]

# Extensions de pièces jointes utiles à préserver absolument
VALUABLE_ATTACHMENT_EXTENSIONS = {
    '.pdf', '.docx', '.doc', '.xlsx', '.xls', '.csv', '.pptx', '.ppt',
    '.zip', '.rar', '.7z', '.tar.gz', '.ics', '.eml'
}


# ==============================================================================
# 2. PURIFICATION (MARKETING, NEWSLETTERS & PUBS)
# ==============================================================================

MARKETING_PATTERNS = [
    r'\bnewsletter(s)?\b',
    r'\bpromo(tion(s)?)?\b',
    r'\boffres? sp[ée]ciales?\b',
    r'\breduction\b|\br[ée]duction\b|\bremise\b|\bsoldes\b',
    r'\bblack friday\b|\bcyber monday\b|\bvente priv[ée]e\b',
    r'\bwebinar\b|\bwebinaire\b|\binvitation au webinaire\b',
    r'\bne manquez pas\b|\bd[ée]couvrez nos offres\b',
    r'\bmarketing\b',
    r'\bdiffusion\b|\bdigest\b',
    r'\bweekly\b|\bmonthly\b|\bbrief\b',
    r'news@',
    r'newsletters?@',
    r'updates?@',
]


# ==============================================================================
# FONCTIONS UTILITAIRES & AUTHENTIFICATION GMAIL
# ==============================================================================

def get_gmail_service():
    """Initialise et retourne le service client Gmail API via OAuth2 (fichiers ou variables d'environnement)."""
    creds = None

    # 1. Tentative depuis variable d'environnement JSON ou Base64
    env_token = os.getenv('GMAIL_TOKEN_JSON', '').strip()
    env_token_b64 = os.getenv('GMAIL_TOKEN_BASE64', '').strip()

    if env_token:
        try:
            token_data = json.loads(env_token)
            creds = Credentials.from_authorized_user_info(token_data, SCOPES)
            logger.info("🔑 Identifiants Gmail chargés depuis la variable d'environnement GMAIL_TOKEN_JSON.")
        except Exception as e:
            logger.warning(f"Erreur lors du parsing de GMAIL_TOKEN_JSON: {e}")
    elif env_token_b64:
        try:
            token_json_str = base64.b64decode(env_token_b64).decode('utf-8')
            token_data = json.loads(token_json_str)
            creds = Credentials.from_authorized_user_info(token_data, SCOPES)
            logger.info("🔑 Identifiants Gmail chargés depuis la variable d'environnement GMAIL_TOKEN_BASE64.")
        except Exception as e:
            logger.warning(f"Erreur lors du parsing de GMAIL_TOKEN_BASE64: {e}")
    elif os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        except Exception as e:
            logger.warning(f"Erreur lors de la lecture de {TOKEN_FILE}: {e}")

    # 2. Rafraîchissement si expiré
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Renouvellement du token OAuth2 expiré...")
            try:
                creds.refresh(Request())
                logger.info("✅ Token OAuth2 renouvelé avec succès.")
            except Exception as e:
                logger.error(f"Échec du refresh token: {e}. Une nouvelle connexion ou un token valide est requis.")
                creds = None

        if not creds:
            # Vérifier si credentials existe (fichier ou env)
            env_creds = os.getenv('GMAIL_CREDENTIALS_JSON', '').strip()
            env_creds_b64 = os.getenv('GMAIL_CREDENTIALS_BASE64', '').strip()

            if env_creds:
                try:
                    client_config = json.loads(env_creds)
                    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
                except Exception as e:
                    logger.error(f"Erreur configuration GMAIL_CREDENTIALS_JSON: {e}")
                    flow = None
            elif env_creds_b64:
                try:
                    creds_json_str = base64.b64decode(env_creds_b64).decode('utf-8')
                    client_config = json.loads(creds_json_str)
                    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
                except Exception as e:
                    logger.error(f"Erreur configuration GMAIL_CREDENTIALS_BASE64: {e}")
                    flow = None
            elif os.path.exists(CREDENTIALS_FILE):
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            else:
                flow = None

            if flow is None:
                logger.critical(
                    "❌ Aucun identifiant OAuth2 trouvé (GMAIL_TOKEN_JSON, GMAIL_CREDENTIALS_JSON ou credentials.json).\n"
                    "👉 En local : lancez 'python auth_setup.py' pour générer vos identifiants.\n"
                    "👉 En Cloud : définissez la variable d'environnement GMAIL_TOKEN_JSON."
                )
                sys.exit(1)

            # Vérification si nous sommes en environnement headless
            is_headless = not sys.stdin.isatty() or bool(os.getenv('CI') or os.getenv('RENDER') or os.getenv('RAILWAY_ENVIRONMENT'))
            if is_headless:
                logger.critical(
                    "❌ Impossible de démarrer le flux interactif OAuth2 dans un environnement Cloud/Headless sans token préalable.\n"
                    "👉 Veuillez exécuter 'python auth_setup.py' sur votre machine locale pour obtenir le token,\n"
                    "   puis copiez le contenu dans la variable d'environnement GMAIL_TOKEN_JSON sur votre hébergeur."
                )
                sys.exit(1)

            logger.info("Démarrage du flux OAuth2 dans le navigateur local...")
            creds = flow.run_local_server(port=0)

        # Sauvegarder le token si possible
        try:
            with open(TOKEN_FILE, 'w', encoding='utf-8') as token_file:
                token_file.write(creds.to_json())
                logger.info(f"Token sauvegardé dans '{TOKEN_FILE}'.")
        except Exception as e:
            logger.debug(f"Note : Impossible d'écrire {TOKEN_FILE} sur disque (environnement en lecture seule) : {e}")

    return build('gmail', 'v1', credentials=creds)


def decode_body(payload: Dict[str, Any]) -> str:
    """Extrait le texte brut du corps d'un e-mail multipart ou simple."""
    body_text = ""

    if 'parts' in payload:
        for part in payload['parts']:
            mime_type = part.get('mimeType', '')
            if mime_type == 'text/plain' and 'data' in part.get('body', {}):
                data = part['body']['data']
                try:
                    body_text += base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='ignore') + "\n"
                except Exception:
                    pass
            elif mime_type == 'text/html' and not body_text and 'data' in part.get('body', {}):
                data = part['body']['data']
                try:
                    html_content = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='ignore')
                    cleaned = re.sub(r'<[^>]+>', ' ', html_content)
                    body_text += re.sub(r'\s+', ' ', cleaned) + "\n"
                except Exception:
                    pass
            elif 'parts' in part:
                body_text += decode_body(part)
    elif 'body' in payload and 'data' in payload['body']:
        data = payload['body']['data']
        try:
            body_text = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='ignore')
            if payload.get('mimeType') == 'text/html':
                cleaned = re.sub(r'<[^>]+>', ' ', body_text)
                body_text = re.sub(r'\s+', ' ', cleaned)
        except Exception:
            pass

    return body_text.strip()


def get_header_value(headers: List[Dict[str, str]], name: str) -> str:
    """Récupère la valeur d'un en-tête insensible à la casse."""
    name_lower = name.lower()
    for h in headers:
        if h.get('name', '').lower() == name_lower:
            return h.get('value', '')
    return ""


def get_attachments_info(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Parcourt récursivement l'arborescence MIME pour lister les pièces jointes présentes.
    Retourne une liste de dicts: [{'filename': 'doc.pdf', 'mimeType': 'application/pdf', 'size': 12345}].
    """
    attachments = []

    def _walk_parts(p):
        filename = p.get('filename', '')
        mime_type = p.get('mimeType', '')
        body = p.get('body', {})
        if filename:
            attachments.append({
                'filename': filename,
                'mimeType': mime_type,
                'size': body.get('size', 0),
                'attachmentId': body.get('attachmentId', '')
            })
        if 'parts' in p:
            for subpart in p['parts']:
                _walk_parts(subpart)

    _walk_parts(payload)
    return attachments


def has_valuable_attachments(payload: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Vérifie si le message contient des pièces jointes utiles (PDF, DOCX, XLSX, ICS, etc.).
    """
    attachments = get_attachments_info(payload)
    valuable_found = []
    for att in attachments:
        fn = att.get('filename', '').lower()
        _, ext = os.path.splitext(fn)
        if ext in VALUABLE_ATTACHMENT_EXTENSIONS:
            valuable_found.append(att.get('filename'))
    return (len(valuable_found) > 0, valuable_found)


# ==============================================================================
# RÈGLES DE SÉCURITÉ & CLASSIFICATION
# ==============================================================================

def check_security_whitelist(
    sender: str,
    subject: str,
    body: str,
    headers: List[Dict[str, str]],
    payload: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Vérifie les 5 règles de sécurité absolues (Mails à ne JAMAIS supprimer).
    Retourne (est_protégé, raison_détaillée).
    """
    combined_text = f"{sender} {subject} {body}".lower()
    sender_lower = sender.lower()
    subject_lower = subject.lower()

    # 1. Échanges humains directs (fils de discussion en cours)
    in_reply_to = get_header_value(headers, 'In-Reply-To')
    references = get_header_value(headers, 'References')
    if in_reply_to or references:
        return True, "Échange humain direct (Fil de discussion en cours / In-Reply-To)"

    # 2. Documents utiles (pièces jointes PDF, DOCX, XLSX, etc.)
    has_val_att, att_list = has_valuable_attachments(payload)
    if has_val_att:
        return True, f"Document(s) utile(s) en pièce jointe : {', '.join(att_list[:3])}"

    # 3. Sécurité & Accès (2FA, OTP, connexions, mots de passe)
    for pattern in WHITELIST_SECURITY_SENDERS:
        if re.search(pattern, sender_lower):
            return True, f"Sécurité & Accès (Expéditeur officiel : {pattern})"
    for pattern in WHITELIST_SECURITY_KEYWORDS:
        if re.search(pattern, combined_text):
            return True, f"Sécurité & Accès (Mot-clé de sécurité : {pattern})"

    # 4. Finances & Légal (Banques, impôts, factures, devis, contrats, signatures)
    for pattern in WHITELIST_FINANCE_LEGAL_SENDERS:
        if re.search(pattern, sender_lower):
            return True, f"Finances & Légal (Expéditeur financier/légal : {pattern})"
    for pattern in WHITELIST_FINANCE_LEGAL_KEYWORDS:
        if re.search(pattern, subject_lower):
            return True, f"Finances & Légal (Objet financier/légal/signature : {pattern})"

    # 5. Logistique & Déplacements (Billets train/avion, hôtels, transports, rendez-vous)
    for pattern in WHITELIST_LOGISTICS_SENDERS:
        if re.search(pattern, sender_lower):
            return True, f"Logistique & Déplacements (Expéditeur transport/hébergement : {pattern})"
    for pattern in WHITELIST_LOGISTICS_KEYWORDS:
        if re.search(pattern, subject_lower):
            return True, f"Logistique & Déplacements (Voyage/Réservation/Rendez-vous : {pattern})"

    # 6. Recrutement & ATS (Accusés de réception de candidatures)
    for pattern in WHITELIST_CAREER_SENDERS:
        if re.search(pattern, sender_lower):
            return True, f"Recrutement & ATS (Plateforme de recrutement : {pattern})"
    for pattern in WHITELIST_CAREER_KEYWORDS:
        if re.search(pattern, subject_lower):
            return True, f"Recrutement & ATS (Accusé de candidature : {pattern})"

    return False, ""


def is_newsletter_or_marketing(headers: List[Dict[str, str]], label_ids: List[str], sender: str, subject: str) -> Tuple[bool, str]:
    """
    Détecte si un e-mail est une newsletter ou un e-mail promotionnel/marketing.
    """
    # Présence de l'en-tête List-Unsubscribe
    list_unsub = get_header_value(headers, 'List-Unsubscribe')
    if list_unsub:
        return True, "En-tête List-Unsubscribe détecté"

    # Labels Gmail de masse/promotion
    mass_labels = {'CATEGORY_PROMOTIONS', 'CATEGORY_FORUMS', 'CATEGORY_SOCIAL'}
    matched_labels = mass_labels.intersection(set(label_ids or []))
    if matched_labels:
        return True, f"Catégorie Gmail : {', '.join(matched_labels)}"

    # En-tête Precedence bulk/list
    precedence = get_header_value(headers, 'Precedence').lower()
    if precedence in ['bulk', 'list', 'junk']:
        return True, f"En-tête Precedence: {precedence}"

    # Mots-clés marketing dans l'objet ou l'expéditeur
    for pat in MARKETING_PATTERNS:
        if re.search(pat, subject.lower()) or re.search(pat, sender.lower()):
            return True, f"Mot-clé marketing ({pat})"

    return False, ""


def is_futile_notification(sender: str, subject: str, headers: List[Dict[str, str]], label_ids: List[str]) -> Tuple[bool, str]:
    """
    Détecte les e-mails futiles ou notifications automatiques de basse valeur sans interaction requise.
    """
    auto_submitted = get_header_value(headers, 'Auto-Submitted').lower()
    if auto_submitted and auto_submitted != 'no':
        # Ne pas traiter les réponses d'absence ou mails déjà protégés
        return True, f"En-tête Auto-Submitted: {auto_submitted}"

    # Notifications futiles de réseaux sociaux sans action requise
    social_senders = [
        r'@.*\.facebookmail\.com',
        r'@.*\.instagram\.com',
        r'@.*\.tiktok\.com',
        r'@.*\.pinterest\.com',
        r'@.*\.twitter\.com',
        r'@.*\.x\.com',
    ]
    sender_lower = sender.lower()
    for s_pat in social_senders:
        if re.search(s_pat, sender_lower):
            return True, f"Notification réseau social futile ({s_pat})"

    return False, ""


# ==============================================================================
# PURIFICATION : DÉSABONNEMENT HTTP & NETTOYAGE
# ==============================================================================

def execute_http_unsubscribe(list_unsub_header: str, list_unsub_post: str) -> bool:
    """
    Extrait l'URL HTTP/HTTPS de l'en-tête List-Unsubscribe et exécute la requête de désabonnement.
    """
    if not list_unsub_header:
        return False

    urls = re.findall(r'<https?://[^>]+>', list_unsub_header)
    if not urls:
        urls = re.findall(r'https?://[^\s,]+', list_unsub_header)

    success = False
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }

    for raw_url in urls:
        url = raw_url.strip('<>')
        try:
            logger.info(f"   [Désabonnement] Requête vers : {url[:80]}...")
            if list_unsub_post and 'List-Unsubscribe=One-Click' in list_unsub_post:
                res = requests.post(url, data={'List-Unsubscribe': 'One-Click'}, headers=headers, timeout=10)
                logger.info(f"   [Désabonnement] Réponse POST One-Click: HTTP {res.status_code}")
                success = True
            else:
                res = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                logger.info(f"   [Désabonnement] Réponse GET: HTTP {res.status_code}")
                success = True
        except Exception as e:
            logger.warning(f"   [Désabonnement] Échec de la requête sur {url[:60]}: {e}")

    return success


def purge_message(service, msg_id: str, hard_delete: bool = True, dry_run: bool = False):
    """
    Déplace le message à la corbeille puis le supprime définitivement si hard_delete=True.
    """
    if dry_run:
        logger.info(f"   [DRY-RUN] Déplacement à la corbeille {'et purge définitive ' if hard_delete else ''}du message {msg_id}")
        return

    try:
        service.users().messages().trash(userId='me', id=msg_id).execute()
        logger.info(f"   [Nettoyage] Message {msg_id} mis à la corbeille.")

        if hard_delete:
            service.users().messages().delete(userId='me', id=msg_id).execute()
            logger.info(f"   [Nettoyage] Message {msg_id} purgé définitivement.")
    except HttpError as e:
        logger.error(f"   [Nettoyage] Erreur lors de la suppression du message {msg_id}: {e}")


def empty_spam_and_trash(service, dry_run: bool = False):
    """
    Vide et purge définitivement les dossiers Spam et Corbeille de Gmail.
    """
    for folder_name, query in [("Spam", "in:spam"), ("Corbeille", "in:trash")]:
        try:
            res = service.users().messages().list(userId='me', q=query, maxResults=500).execute()
            messages = res.get('messages', [])
            if not messages:
                continue

            msg_ids = [m['id'] for m in messages]
            count = len(msg_ids)
            logger.info(f"🧹 [Vidage {folder_name}] {count} message(s) trouvé(s) à purger définitivement.")

            if dry_run:
                logger.info(f"   [DRY-RUN] Purge de {count} message(s) dans le dossier {folder_name}.")
                continue

            try:
                service.users().messages().batchDelete(userId='me', body={'ids': msg_ids}).execute()
                logger.info(f"   ✅ Dossier {folder_name} entièrement vidé ({count} message(s) supprimé(s) définitivement).")
            except Exception:
                for mid in msg_ids:
                    try:
                        service.users().messages().delete(userId='me', id=mid).execute()
                    except Exception:
                        pass
                logger.info(f"   ✅ Dossier {folder_name} vidé ({count} message(s)).")

        except Exception as e:
            logger.error(f"   Erreur lors du vidage du dossier {folder_name}: {e}")


# ==============================================================================
# GÉNÉRATION DE RÉPONSE INTELLIGENTE VIA GEMINI
# ==============================================================================

def detect_cv_request(subject: str, body: str) -> bool:
    """Détecte si un e-mail demande explicitement l'envoi d'un CV."""
    combined_text = f"{subject} {body}".lower()
    patterns = [
        r'(envoyer|transmettre|fournir|partager|donner|joindre|adresser).{0,30}\b(cv|curriculum|resume)\b',
        r'\b(ton|votre|un)\s+(cv|curriculum\s*vitae|resume)\b',
        r'demande.{0,20}\b(cv|curriculum)\b',
        r'besoin de (ton|votre) cv\b',
    ]
    for pat in patterns:
        if re.search(pat, combined_text):
            return True
    return False


def generate_response_with_gemini(sender: str, subject: str, body: str, has_cv_request: bool = False) -> str:
    """
    Génère un brouillon de réponse adapté, poli, concis et fluide avec Gemini.
    Le mail est rédigé du début à la fin dans la langue de l'e-mail reçu.
    """
    api_key = os.getenv('GEMINI_API_KEY', '').strip()
    if not api_key or not GENAI_AVAILABLE:
        return get_fallback_reply(body, has_cv_request)

    cv_instructions = ""
    if has_cv_request:
        cv_instructions = "- L'expéditeur demande explicitement un CV. Confirme avec courtoisie et enthousiasme que ton CV à jour est bien joint au format PDF à ce message (rédigé dans la même langue)."

    try:
        client = genai.Client(api_key=api_key)
        prompt = f"""
Tu es {USER_NAME} (ou son assistant exécutif direct pour sa correspondance par e-mail).
Tu dois rédiger un brouillon de réponse par e-mail adapté, poli, concis, naturel et professionnel au message reçu.

Détails de l'e-mail reçu :
Expéditeur : {sender}
Objet : {subject}
Contenu du message :
{body[:3500]}

Directives de rédaction :
1. RÈGLE STRICTE DE LANGUE :
   - Détecte la langue principale utilisée par l'expéditeur dans son e-mail (ex: français, anglais, espagnol, allemand, néerlandais, etc.).
   - Rédige l'INTÉGRALITÉ du mail de réponse DANS CETTE MÊME LANGUE DU DÉBUT À LA FIN :
     * Salutation initiale adaptée dans la langue (ex: "Bonjour", "Hello", "Dear...", "Hallo", "Hola", "Guten Tag", etc.).
     * Corps du message rédigé dans cette même langue.
     * Formule de politesse finale et signature obligatoirement rédigées dans la langue de l'e-mail (ex: en anglais "Best regards,\n{USER_NAME}" ou "Kind regards,\n{USER_NAME}", en français "Bien cordialement,\n{USER_NAME}", en allemand "Mit freundlichen Grüßen,\n{USER_NAME}", en espagnol "Un cordial saludo,\n{USER_NAME}", en néerlandais "Met vriendelijke groet,\n{USER_NAME}").
   - Ne mélange JAMAIS les langues (aucun mot ou formule française si le mail reçu est en anglais, et inversement).
2. Rédige UNIQUEMENT le corps de l'e-mail de réponse prêt à l'envoi (aucun objet, aucun commentaire méta, aucun tag HTML).
3. Adopte un ton fluide, chaleureux, concis et professionnel.
4. Analyse l'intention et le sujet avec pertinence :
   - Réponds aux points soulevés de façon claire et bienveillante.
   {cv_instructions}
   - Si la demande implique une analyse approfondie, un devis ou une prise de décision, confirme la prise en charge et indique que {USER_NAME} reviendra très prochainement avec les éléments complets.
5. RÈGLE ABSOLUE : N'utilise AUCUN placeholder entre crochets (pas de [Nom], [Lien], [Date]). Le texte doit être prêt à être lu tel quel.
"""

        models_to_try = [
            'gemini-3.5-flash',
            'gemini-flash-latest',
            'gemini-2.5-flash',
            'gemini-2.0-flash',
            'gemini-1.5-flash'
        ]

        for model_name in models_to_try:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt
                )
                if response and response.text:
                    return response.text.strip()
            except Exception:
                continue

    except Exception as e:
        logger.error(f"   [Gemini] Erreur lors de la génération de réponse : {e}")

    return get_fallback_reply(body, has_cv_request)


def get_fallback_reply(body: str = "", has_cv_request: bool = False) -> str:
    """Brouillon de secours si l'API Gemini est indisponible (adapte la langue en cas d'anglais)."""
    # Détection basique si le message reçu est en anglais
    is_english = bool(re.search(r'\b(the|you|your|thank|regards|please|update|billing|terms|subscription)\b', body.lower()))

    if is_english:
        if has_cv_request:
            return f"""Hello,

Thank you for your message.

As requested, please find my updated CV attached in PDF format. I remain at your disposal should you need any further information.

Best regards,
{USER_NAME}"""
        return f"""Hello,

Thank you for your message.

I have noted your email and will get back to you shortly with all the necessary details.

Best regards,
{USER_NAME}"""

    if has_cv_request:
        return f"""Bonjour,

Je vous remercie pour votre message.

Comme demandé, vous trouverez mon CV à jour joint à cet e-mail au format PDF. Je reste à votre entière disposition pour tout renseignement complémentaire.

Bien cordialement,
{USER_NAME}"""

    return f"""Bonjour,

J'accuse bonne réception de votre message et vous en remercie.

J'ai bien pris note de votre e-mail et je reviendrai vers vous dans les meilleurs délais avec tous les éléments nécessaires.

Bien cordialement,
{USER_NAME}"""


# ==============================================================================
# GESTION DES BROUILLONS GMAIL & ENVOIS
# ==============================================================================

def build_mime_message(
    original_msg: Dict[str, Any],
    reply_text: str,
    attachment_path: Optional[str] = None,
    attachment_filename: Optional[str] = None
) -> Tuple[Dict[str, Any], str, str]:
    """
    Construit le message MIME complet prêt pour envoi ou création de brouillon.
    Retourne (send_body, destinataire_complet, sujet).
    """
    thread_id = original_msg.get('threadId')
    headers = original_msg.get('payload', {}).get('headers', [])

    from_header = get_header_value(headers, 'From')
    subject_header = get_header_value(headers, 'Subject')
    message_id_header = get_header_value(headers, 'Message-ID')
    references_header = get_header_value(headers, 'References')

    real_name, email_addr = email.utils.parseaddr(from_header)
    to_address = email_addr if email_addr else from_header.strip()

    if not subject_header.lower().startswith('re:'):
        reply_subject = f"Re: {subject_header}"
    else:
        reply_subject = subject_header

    if attachment_path and os.path.exists(attachment_path):
        mime_msg = MIMEMultipart('mixed')
        mime_msg.attach(MIMEText(reply_text, 'plain', 'utf-8'))

        fn = attachment_filename or os.path.basename(attachment_path)
        try:
            with open(attachment_path, 'rb') as f:
                part = MIMEBase('application', 'pdf' if fn.endswith('.pdf') else 'octet-stream')
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment', filename=fn)
                mime_msg.attach(part)
                logger.info(f"   [Pièce Jointe] Fichier '{fn}' attaché ({os.path.getsize(attachment_path)} octets).")
        except Exception as e:
            logger.error(f"   [Erreur Pièce Jointe] Impossible d'attacher {attachment_path}: {e}")
    else:
        mime_msg = MIMEText(reply_text, 'plain', 'utf-8')

    if real_name:
        mime_msg['To'] = email.utils.formataddr((str(Header(real_name, 'utf-8')), to_address))
    else:
        mime_msg['To'] = to_address

    mime_msg['Subject'] = str(Header(reply_subject, 'utf-8'))

    if message_id_header:
        mime_msg['In-Reply-To'] = message_id_header
        new_references = f"{references_header} {message_id_header}".strip() if references_header else message_id_header
        mime_msg['References'] = new_references

    raw_message = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode('ascii')
    send_body = {
        'raw': raw_message,
        'threadId': thread_id
    }

    return send_body, mime_msg['To'], reply_subject


def create_gmail_draft(service, original_msg: Dict[str, Any], reply_text: str, attachment_path: Optional[str] = None, dry_run: bool = False) -> Optional[str]:
    """
    Crée un vrai brouillon (Draft) dans Gmail rattaché au fil de discussion.
    Retourne le draft_id créé.
    """
    send_body, to_dest, _ = build_mime_message(original_msg, reply_text, attachment_path)

    if dry_run:
        logger.info(f"   [DRY-RUN] Brouillon Gmail préparé pour {to_dest}.")
        return "draft_dry_run_id"

    try:
        draft = service.users().drafts().create(
            userId='me',
            body={'message': send_body}
        ).execute()
        draft_id = draft.get('id')
        logger.info(f"   📝 [Brouillon Gmail] Brouillon officiel créé avec succès (Draft ID: {draft_id}).")
        return draft_id
    except HttpError as e:
        logger.error(f"   [Erreur Brouillon] Impossible de créer le brouillon dans Gmail : {e}")
        return None


def send_gmail_reply(service, original_msg: Dict[str, Any], reply_text: str, attachment_path: Optional[str] = None, dry_run: bool = False) -> bool:
    """
    Envoie directement la réponse dans le fil de discussion et retire le label UNREAD.
    """
    msg_id = original_msg.get('id')
    send_body, to_dest, _ = build_mime_message(original_msg, reply_text, attachment_path)

    if dry_run:
        logger.info(f"   [DRY-RUN] Envoi réel simulé pour {to_dest}.")
        return True

    try:
        sent_result = service.users().messages().send(userId='me', body=send_body).execute()
        logger.info(f"   🚀 [Message Envoyé] Réponse envoyée avec succès (Message ID: {sent_result.get('id')}).")

        # Marquer comme lu
        service.users().messages().modify(
            userId='me',
            id=msg_id,
            body={'removeLabelIds': ['UNREAD']}
        ).execute()
        return True
    except HttpError as e:
        logger.error(f"   [Erreur Envoi] Impossible d'envoyer l'e-mail: {e}")
        return False


# ==============================================================================
# FORMAT DE VALIDATION OBLIGATOIRE STRICT & INTERACTION
# ==============================================================================

def format_validation_display(sender_name: str, sender_email: str, subject: str, draft_text: str) -> str:
    """
    Formate la demande de validation exactement comme exigé dans prompt.md.
    """
    sender_display = f"**{sender_name}**" if sender_name else f"**{sender_email}**"
    draft_quoted = "\n".join([f"> {line}" for line in draft_text.splitlines()])

    card = f"""
================================================================================
Vous avez reçu un e-mail de {sender_display} (<{sender_email}>) concernant : **{subject}**.

**Voici la réponse que j'ai pré-rédigée :**
{draft_quoted}

**Validation requise :**

1. Est-ce que cette réponse te convient pour envoi immédiat ?
2. As-tu une pièce jointe à ajouter avant que je lance le mail ?
================================================================================
"""
    return card


def handle_interactive_validation(
    service,
    original_msg: Dict[str, Any],
    sender_name: str,
    sender_email: str,
    subject: str,
    draft_text: str,
    detected_cv_path: Optional[str],
    auto_draft: bool = False,
    dry_run: bool = False
):
    """
    Affiche le format de validation obligatoire et gère le choix de l'utilisateur.
    """
    # 1. Affichage du format strict
    validation_card = format_validation_display(sender_name, sender_email, subject, draft_text)
    print(validation_card)

    # 2. Création préventive du brouillon Gmail pour que Robin puisse le retrouver dans Gmail
    draft_id = create_gmail_draft(service, original_msg, draft_text, attachment_path=detected_cv_path, dry_run=dry_run)

    if auto_draft:
        logger.info(f"   ℹ️ Mode non-bloquant (--auto-draft) : Le brouillon est disponible dans Gmail. En attente de validation manuelle.")
        return

    # 3. Validation interactive dans le terminal
    print("\nActions disponibles :")
    if detected_cv_path:
        print(f"   [1] Valider et envoyer immédiatement (avec CV '{os.path.basename(detected_cv_path)}' joint)")
    else:
        print("   [1] Valider et envoyer immédiatement")
    print("   [2] Ajouter/Modifier une pièce jointe et envoyer")
    print("   [3] Conserver uniquement en brouillon Gmail (je l'enverrai manuellement)")
    print("   [4] Ignorer et passer au message suivant")

    try:
        choice = input("\n👉 Votre choix (1/2/3/4) [Défaut: 3] : ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nPassage au suivant.")
        return

    if choice == '1':
        logger.info("Validation reçue : envoi immédiat en cours...")
        success = send_gmail_reply(service, original_msg, draft_text, attachment_path=detected_cv_path, dry_run=dry_run)
        if success and draft_id and not dry_run and draft_id != "draft_dry_run_id":
            # Supprimer le brouillon devenu inutile après l'envoi
            try:
                service.users().drafts().delete(userId='me', id=draft_id).execute()
            except Exception:
                pass

    elif choice == '2':
        custom_file = input("Entrez le chemin absolu ou relatif de la pièce jointe : ").strip().strip('"').strip("'")
        if os.path.exists(custom_file):
            logger.info(f"Pièce jointe validée : '{custom_file}'. Envoi en cours...")
            success = send_gmail_reply(service, original_msg, draft_text, attachment_path=custom_file, dry_run=dry_run)
            if success and draft_id and not dry_run and draft_id != "draft_dry_run_id":
                try:
                    service.users().drafts().delete(userId='me', id=draft_id).execute()
                except Exception:
                    pass
        else:
            logger.error(f"Fichier '{custom_file}' introuvable. Le message reste en brouillon dans Gmail.")

    elif choice == '4':
        logger.info("Message ignoré. Aucune action supplémentaire.")

    else:
        logger.info("Le brouillon est conservé dans votre boîte Gmail pour révision.")


# ==============================================================================
# CYCLE DE TRAITEMENT DES E-MAILS
# ==============================================================================

def process_inbox(service, auto_draft: bool = False, dry_run: bool = False):
    """
    Scanne les e-mails non lus dans la boîte de réception et applique le processus de prompt.md.
    """
    logger.info("Scan des e-mails non lus dans la boîte de réception...")

    try:
        response = service.users().messages().list(
            userId='me',
            q='is:unread in:inbox',
            maxResults=50
        ).execute()

        messages = response.get('messages', [])
        if not messages:
            logger.info("Aucun e-mail non lu à traiter.")
            empty_spam_and_trash(service, dry_run=dry_run)
            return

        logger.info(f"Trouvé {len(messages)} message(s) non lu(s). Analyse des règles de sécurité...")

        for msg_summary in messages:
            msg_id = msg_summary['id']
            try:
                msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
            except HttpError as e:
                logger.error(f"Impossible de récupérer le message {msg_id}: {e}")
                continue

            payload = msg.get('payload', {})
            headers = payload.get('headers', [])
            label_ids = msg.get('labelIds', [])

            from_header = get_header_value(headers, 'From')
            subject = get_header_value(headers, 'Subject')
            date_str = get_header_value(headers, 'Date')
            list_unsub = get_header_value(headers, 'List-Unsubscribe')
            list_unsub_post = get_header_value(headers, 'List-Unsubscribe-Post')
            body = decode_body(payload)

            sender_name, sender_email = email.utils.parseaddr(from_header)
            if not sender_email:
                sender_email = from_header

            logger.info(f"\n--- [Message {msg_id}] ---")
            logger.info(f"De       : {from_header}")
            logger.info(f"Objet    : {subject}")
            logger.info(f"Date     : {date_str}")

            # ------------------------------------------------------------------
            # 1. RÈGLE DE SÉCURITÉ ABSOLUE : NE JAMAIS SUPPRIMER
            # ------------------------------------------------------------------
            is_protected, protect_reason = check_security_whitelist(from_header, subject, body, headers, payload)

            # ------------------------------------------------------------------
            # 2. NEWSLETTERS & MARKETING FROIDS (SI NON PROTÉGÉ)
            # ------------------------------------------------------------------
            if not is_protected:
                is_promo, promo_reason = is_newsletter_or_marketing(headers, label_ids, from_header, subject)
                if is_promo:
                    logger.info(f"🧹 [Newsletters & Marketing] Détecté ({promo_reason}).")
                    if list_unsub:
                        execute_http_unsubscribe(list_unsub, list_unsub_post)
                    purge_message(service, msg_id, hard_delete=True, dry_run=dry_run)
                    continue

                # E-mails futiles / Notifications de basse valeur
                is_futile, futile_reason = is_futile_notification(from_header, subject, headers, label_ids)
                if is_futile:
                    logger.info(f"🗑️  [Notification Futile] Mise en corbeille ({futile_reason}).")
                    purge_message(service, msg_id, hard_delete=False, dry_run=dry_run)
                    continue

            # ------------------------------------------------------------------
            # 3. GESTION DES MESSAGES PROTÉGÉS & NON ACTIONNABLES (Absence, 2FA...)
            # ------------------------------------------------------------------
            if is_protected:
                logger.info(f"🛡️  [Sécurité Absolue] Message protégé : {protect_reason}.")

            # Réponses automatiques d'absence / Out of office (ne jamais répondre dessus)
            is_auto_reply = bool(re.search(r'r[ée]ponse automatique|automatic reply|auto[- ]reply|out of office|absent(e)? du bureau', subject.lower())) or get_header_value(headers, 'Auto-Submitted').lower() in ['auto-replied', 'auto-generated']
            if is_auto_reply:
                logger.info("   ℹ️ Réponse automatique / Absence du bureau détectée : laissé intact dans la boîte, aucune réponse générée.")
                continue

            # Messages purement transactionnels (Sécurité 2FA, ATS, Banques automatisées) sans demande humaine directe
            is_pure_transactional = any([
                re.search(pat, from_header.lower()) for pat in WHITELIST_SECURITY_SENDERS
            ]) or any([
                re.search(pat, from_header.lower()) for pat in WHITELIST_CAREER_SENDERS
            ]) or any([
                re.search(pat, subject.lower()) for pat in WHITELIST_SECURITY_KEYWORDS
            ]) or any([
                re.search(pat, subject.lower()) for pat in WHITELIST_CAREER_KEYWORDS
            ])

            if is_pure_transactional and not get_header_value(headers, 'In-Reply-To'):
                logger.info("   ℹ️ Message transactionnel/automatique protégé : laissé intact dans la boîte, aucune réponse requise.")
                continue

            # Expéditeurs automatisés / no-reply protégés (confirmations de commandes, factures reçues...)
            is_noreply_sender = bool(re.search(r'(no-reply|noreply|donotreply|notifications?@|mailer-daemon)', from_header.lower()))
            if is_noreply_sender and not get_header_value(headers, 'In-Reply-To'):
                logger.info("   ℹ️ Notification automatisée (no-reply) : laissé intact dans la boîte, aucune réponse requise.")
                continue

            # ------------------------------------------------------------------
            # 4. E-MAILS IMPORTANTS & ACTIONNABLES (VRAIS CONTACTS & ÉCHANGES)
            # ------------------------------------------------------------------
            logger.info("✨ [E-mail Important & Actionnable] Préparation du brouillon de réponse...")

            is_cv_req = detect_cv_request(subject, body)
            detected_cv_path = None
            if is_cv_req:
                if os.path.exists(DEFAULT_CV_FILE):
                    detected_cv_path = DEFAULT_CV_FILE
                    logger.info(f"   📄 Demande de CV détectée. '{os.path.basename(DEFAULT_CV_FILE)}' sera proposé en pièce jointe.")
                else:
                    logger.warning(f"   ⚠️ Demande de CV détectée mais '{DEFAULT_CV_FILE}' est introuvable.")

            # Pré-rédaction avec Gemini
            draft_text = generate_response_with_gemini(from_header, subject, body, has_cv_request=bool(detected_cv_path))

            # Présentation du format de validation obligatoire et gestion
            handle_interactive_validation(
                service=service,
                original_msg=msg,
                sender_name=sender_name,
                sender_email=sender_email,
                subject=subject,
                draft_text=draft_text,
                detected_cv_path=detected_cv_path,
                auto_draft=auto_draft,
                dry_run=dry_run
            )

        # Purge automatique des dossiers Spam et Corbeille après chaque scan
        empty_spam_and_trash(service, dry_run=dry_run)
        AGENT_STATS["cycles_completed"] += 1
        AGENT_STATS["last_status"] = "Succès - En attente"

    except HttpError as e:
        AGENT_STATS["errors_count"] += 1
        AGENT_STATS["last_status"] = f"Erreur API Gmail: {e}"
        logger.error(f"Erreur API Gmail lors du traitement: {e}")
    except Exception as e:
        AGENT_STATS["errors_count"] += 1
        AGENT_STATS["last_status"] = f"Erreur inattendue: {e}"
        logger.exception(f"Erreur inattendue lors du scan de la boîte: {e}")


# ==============================================================================
# POINT D'ENTRÉE PRINCIPAL
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Agent Gmail Exécutif Intelligent")
    parser.add_argument('--once', action='store_true', help="Exécute un seul cycle de vérification et quitte.")
    parser.add_argument('--interval', type=int, default=DEFAULT_CHECK_INTERVAL, help="Intervalle en secondes entre les vérifications (défaut: 180s = 3 min).")
    parser.add_argument('--dry-run', action='store_true', help="Mode simulation : affiche les actions sans supprimer ni envoyer d'e-mails.")
    parser.add_argument('--auto-draft', action='store_true', help="Génère les brouillons dans Gmail sans bloquer pour une saisie interactive dans la console.")
    parser.add_argument('--port', type=int, default=int(os.getenv('PORT', '8080')), help="Port pour le serveur HTTP de santé.")
    args = parser.parse_args()

    # Variables d'environnement par défaut
    env_auto_draft = os.getenv('AUTO_DRAFT', '').lower() in ['true', '1', 'yes']
    env_run_once = os.getenv('RUN_ONCE', '').lower() in ['true', '1', 'yes']
    enable_healthcheck = os.getenv('ENABLE_HEALTHCHECK', 'true').lower() in ['true', '1', 'yes']

    is_auto_draft = args.auto_draft or env_auto_draft
    is_once = args.once or env_run_once

    print("=" * 75)
    print("       🚀 DÉMARRAGE DE L'AGENT GMAIL EXÉCUTIF & INTELLIGENT")
    print(f"       - Mode           : {'Exécution unique (--once)' if is_once else f'Surveillance continue 24/7 ({args.interval}s)'}")
    print(f"       - Simulation     : {'OUI (Dry Run)' if args.dry_run else 'NON (Actions réelles)'}")
    print(f"       - Mode Brouillons: {'Automatique sans blocage (--auto-draft)' if is_auto_draft else 'Interactif (validation console)'}")
    print(f"       - Utilisateur    : {USER_NAME}")
    print(f"       - Modèle IA      : gemini-2.5-flash ({'Actif' if GEMINI_API_KEY else 'Non configuré'})")
    print("=" * 75)

    # Démarrage du serveur de santé HTTP en mode continu si activé
    if not is_once and enable_healthcheck:
        start_healthcheck_server(port=args.port)

    logger.info("Connexion à l'API Gmail...")
    try:
        service = get_gmail_service()
        logger.info("✅ Authentification Gmail réussie !")
    except Exception as e:
        logger.critical(f"❌ Échec lors de l'authentification Gmail : {e}")
        sys.exit(1)

    if is_once:
        process_inbox(service, auto_draft=is_auto_draft, dry_run=args.dry_run)
        logger.info("Cycle terminé. Fin du programme.")
        return

    logger.info(f"Boucle de surveillance 24/7 active (vérification toutes les {args.interval} secondes).")
    try:
        while True:
            try:
                process_inbox(service, auto_draft=is_auto_draft, dry_run=args.dry_run)
            except Exception as e:
                logger.exception(f"Erreur durant le cycle de scan : {e}")
                AGENT_STATS["errors_count"] += 1
            logger.info(f"En attente pendant {args.interval} secondes avant le prochain scan...")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("\nArrêt de l'agent Gmail demandé par l'utilisateur. Au revoir !")


if __name__ == '__main__':
    main()

