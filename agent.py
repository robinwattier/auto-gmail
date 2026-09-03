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
import html
import base64
import signal
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

import requests  # type: ignore
from dotenv import load_dotenv  # type: ignore

# Google APIs
from google.auth.transport.requests import Request  # type: ignore
from google.oauth2.credentials import Credentials  # type: ignore
from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore
from googleapiclient.discovery import build  # type: ignore
from googleapiclient.errors import HttpError  # type: ignore

# Google GenAI SDK (Gemini)
try:
    from google import genai  # type: ignore
    from google.genai import types  # type: ignore
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

# Charger les variables d'environnement
load_dotenv()

# Forcer l'encodage UTF-8 pour Windows
if sys.platform.startswith('win'):
    try:
        reconfig_out = getattr(sys.stdout, 'reconfigure', None)
        if reconfig_out and getattr(sys.stdout, 'encoding', None) != 'utf-8':
            reconfig_out(encoding='utf-8', errors='replace')
        reconfig_err = getattr(sys.stderr, 'reconfigure', None)
        if reconfig_err and getattr(sys.stderr, 'encoding', None) != 'utf-8':
            reconfig_err(encoding='utf-8', errors='replace')
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

# Configuration des Notifications Mobiles & Push (Désactivées par défaut pour consultation paisible le matin)
ENABLE_NOTIFICATIONS = os.getenv('ENABLE_NOTIFICATIONS', 'false').lower() in ['true', '1', 'yes']
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '').strip()
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '').strip()
NTFY_TOPIC = os.getenv('NTFY_TOPIC', '').strip()
NTFY_SERVER = os.getenv('NTFY_SERVER', 'https://ntfy.sh').strip().rstrip('/')
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL', '').strip()
PUSHOVER_USER_KEY = os.getenv('PUSHOVER_USER_KEY', '').strip()
PUSHOVER_API_TOKEN = os.getenv('PUSHOVER_API_TOKEN', '').strip()
GENERIC_WEBHOOK_URL = os.getenv('GENERIC_WEBHOOK_URL', '').strip()
NOTIFY_ON_START = os.getenv('NOTIFY_ON_START', 'false').lower() in ['true', '1', 'yes']

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("GmailAgent")

# Statistiques d'exécution pour le Cloud & le Healthcheck
AGENT_STATS: Dict[str, Any] = {
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
    # Codes de vérification, validation et sécurité (2FA / OTP / PIN)
    r'code de v[ée]rification',
    r'code de validation',
    r'code de confirmation',
    r'code de s[ée]curit[ée]',
    r'code de connexion',
    r'code d[\'’]acc[èe]s',
    r'code [àa] \d+ chiffres',
    r'votre code (est|secret|temporaire|pin)?\b',
    r'verification code',
    r'validation code',
    r'confirmation code',
    r'security code',
    r'access code',
    r'login code',
    r'your code is',
    r'your verification code',
    r'one[- ]time password',
    r'mot de passe temporaire',
    r'mot de passe [àa] usage unique',
    r'\b2fa\b',
    r'\botp\b',
    r'\bpin\b',
    # Activation de compte, validation d'adresse email & inscription
    r'activation de (votre )?compte',
    r'activez votre compte',
    r'activer votre compte',
    r'account activation',
    r'activate your account',
    r'validez votre (compte|adresse|inscription|e[- ]?mail)',
    r'valider votre (compte|adresse|inscription|e[- ]?mail)',
    r'confirmez votre (compte|adresse|inscription|e[- ]?mail)',
    r'confirmer votre (compte|adresse|inscription|e[- ]?mail)',
    r'v[ée]rifiez votre (adresse|compte|e[- ]?mail)',
    r'v[ée]rifier votre (adresse|compte|e[- ]?mail)',
    r'verify your (email|account|address)',
    r'confirm your (email|account|address)',
    r'complete your registration',
    r'finalisez votre inscription',
    r'finaliser votre inscription',
    r'lien d[\'’]activation',
    r'activation link',
    r'lien de connexion',
    r'magic link',
    # Alertes de sécurité & connexions
    r'v[ée]rification de s[ée]curit[ée]',
    r'authentification [àa] deux facteurs',
    r'security alert',
    r'alerte de s[ée]curit[ée]',
    r'nouvelle connexion',
    r'connexion suspecte',
    r'sign[- ]in attempt',
    r'tentative de connexion',
    r'r[ée]initialisation de votre mot de passe',
    r'password reset',
    r'reset your password',
    r'r[ée]initialiser le mot de passe',
    # Réponses d'absence / automatiques
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

# 1.4 RECRUTEMENT, CANDIDATURES & TESTS D'ÉVALUATION (Elao, Forem, Plateformes ATS)
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
    # Plateformes de tests, évaluations & formation (Forem, Elao, etc.)
    r'@.*\.elao\.(com|be)',
    r'@.*\.forem\.be',
    r'@.*\.leforem\.be',
    r'@.*\.technocite\.be',
    r'@.*\.testgorilla\.com',
    r'@.*\.hackerrank\.com',
    r'@.*\.codility\.com',
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
    # Tests d'évaluation, langues & sélections (Elao, Forem, Technocité...)
    r'\belao\b',
    r'invitation.*(test|[ée]valuation|assessment)',
    r'test (de |d[\'’])?(langue|niveau|anglais|fran[çc]ais|comp[ée]tence|s[ée]lection|positionnement|technique)',
    r'[ée]valuation (de |d[\'’])?(langue|niveau|comp[ée]tence)',
    r'passer (un|votre) test',
    r'session de test',
    r'coup de poing p[ée]nurie',
    r'technocit[ée]',
    r'le forem\b',
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
    r'\bsummary of\b|\bmonthly summary\b|\bweekly summary\b',
    r'\banalytics summary\b|\bperformance summary\b',
    r'@.*\.metricool\.com',
    r'\bmetricool\b',
    r'news@',
    r'newsletters?@',
    r'updates?@',
]

# Motifs de spam flagrant / arnaques / escroqueries (pour purger sans risque les vrais indésirables des spams)
OBVIOUS_SPAM_PATTERNS = [
    # Scams financiers, cryptos, gains miracles
    r'bitcoin\s+(investment|profit|wallet|doubler|bonus)',
    r'cryptocurrency\s+(investment|giveaway|bonus)',
    r'gagnez\s+(de l\'argent|des millions|un salaire)',
    r'revenus?\s+(passifs?|garantis?|suppl[ée]mentaires?)',
    r'invest(ir|issement)\s+(crypto|rentable|sans risque)',
    r'loterie|lottery|jackpot|tirage au sort',
    r'f[ée]licitations,\s+vous avez gagn[ée]',
    r'you have won|congratulations you won',
    r'h[ée]ritage\s+(bloqu[ée]|l[ée]gataire)',
    r'fonds\s+bloqu[ée]s?\s+de\s+plusieurs\s+millions',
    # Arnaques santé / pharma / adultes / casino
    r'casino\s*(en ligne|bonus|free spins|sans d[ée]p[ôo]t)',
    r'poker\s*(bonus|en ligne)',
    r'viagra|cialis|levitra|pharmacie\s+en\s+ligne',
    r'rencontre\s+(coquine|adulte|discr[èe]te|sans lendemain)',
    r'sugar\s+daddy|sugar\s+mommy',
    # Hameçonnage / Phishing grossier
    r'votre compte est bloqu[ée].{0,40}(cliquez|v[ée]rifiez immédiatement)',
    r'votre colis est bloqu[ée].{0,40}(frais de port|r[ée]gler)',
    r'amende\s+impay[ée]e.{0,40}(antai|infraction)',
]


def is_obvious_spam(sender: str, subject: str, body: str) -> Tuple[bool, str]:
    """Détecte si un e-mail est un spam, scam, arnaque ou phishing évident."""
    combined = f"{sender} {subject} {body[:2000]}".lower()
    for pat in OBVIOUS_SPAM_PATTERNS:
        if re.search(pat, combined):
            return True, f"Motif de spam avéré ({pat})"
    return False, ""



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

    # Notifications futiles de réseaux sociaux et outils SaaS sans action requise
    social_senders = [
        r'@.*\.facebookmail\.com',
        r'@.*\.instagram\.com',
        r'@.*\.tiktok\.com',
        r'@.*\.pinterest\.com',
        r'@.*\.twitter\.com',
        r'@.*\.x\.com',
        r'@.*\.metricool\.com',
    ]
    sender_lower = sender.lower()
    for s_pat in social_senders:
        if re.search(s_pat, sender_lower):
            return True, f"Notification futile / SaaS automatisé ({s_pat})"

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


def rescue_message_from_spam(service, msg_id: str, dry_run: bool = False) -> bool:
    """
    Sauve un e-mail légitime ou important du dossier Spam et le replace dans la Boîte de réception principale (INBOX).
    """
    if dry_run:
        logger.info(f"   [DRY-RUN] Sauvetage du message {msg_id} : retrait de SPAM et ajout à INBOX.")
        return True

    try:
        service.users().messages().modify(
            userId='me',
            id=msg_id,
            body={
                'removeLabelIds': ['SPAM'],
                'addLabelIds': ['INBOX']
            }
        ).execute()
        logger.info(f"   🛡️ [Sauvetage Spam -> Boîte Principale] Message {msg_id} replacé avec succès dans la boîte de réception.")
        return True
    except HttpError as e:
        logger.error(f"   ⚠️ Erreur lors du sauvetage du message {msg_id} des spams: {e}")
        return False


def empty_trash(service, dry_run: bool = False):
    """
    Vide et purge définitivement les messages de la Corbeille (Trash) de Gmail.
    Le dossier Spam n'est plus vidé aveuglément : chaque message de spam est préalablement
    analysé individuellement pour sauver les faux-positifs.
    """
    try:
        res = service.users().messages().list(userId='me', q='in:trash', maxResults=500).execute()
        messages = res.get('messages', [])
        if not messages:
            return

        msg_ids = [m['id'] for m in messages]
        count = len(msg_ids)
        logger.info(f"🧹 [Vidage Corbeille] {count} message(s) trouvé(s) à purger définitivement.")

        if dry_run:
            logger.info(f"   [DRY-RUN] Purge de {count} message(s) dans la Corbeille.")
            return

        try:
            service.users().messages().batchDelete(userId='me', body={'ids': msg_ids}).execute()
            logger.info(f"   ✅ Corbeille entièrement vidée ({count} message(s) supprimé(s) définitivement).")
        except Exception:
            for mid in msg_ids:
                try:
                    service.users().messages().delete(userId='me', id=mid).execute()
                except Exception:
                    pass
            logger.info(f"   ✅ Corbeille vidée ({count} message(s)).")

    except Exception as e:
        logger.error(f"   Erreur lors du vidage de la Corbeille: {e}")



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

        env_model = os.getenv('GEMINI_MODEL', '').strip()
        models_to_try = [
            'gemini-3-flash-preview',
            'gemini-3.6-flash',
            'gemini-3.1-pro-preview',
            'gemini-3.1-flash-lite-preview',
            'gemini-3.1-flash-lite',
            'gemini-flash-latest',
            'gemini-2.5-flash',
            'gemini-2.0-flash',
            'gemini-1.5-flash'
        ]
        if env_model and env_model not in models_to_try:
            models_to_try.insert(0, env_model)
        elif env_model and env_model in models_to_try:
            models_to_try.remove(env_model)
            models_to_try.insert(0, env_model)

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
    # Vérifier si un brouillon existe déjà pour ce fil afin d'éviter les doublons
    thread_id = original_msg.get('threadId')
    if thread_id and not dry_run:
        try:
            thread_data = service.users().threads().get(userId='me', id=thread_id).execute()
            messages_in_thread = thread_data.get('messages', [])
            has_existing_draft = any('DRAFT' in m.get('labelIds', []) for m in messages_in_thread)
            if has_existing_draft:
                logger.info(f"   ℹ️ [Brouillon Gmail] Un brouillon existe déjà pour ce fil ({thread_id}). Doublon évité.")
                return None
        except Exception as e:
            logger.debug(f"Impossible de vérifier les brouillons existants pour le fil {thread_id}: {e}")

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
# NOTIFICATIONS MULTI-CANAL (TELEGRAM, NTFY.SH, DISCORD, PUSHOVER, WEBHOOK)
# ==============================================================================

def clean_text_snippet(text: str, max_length: int = 350) -> str:
    """Nettoie et tronque proprement le texte d'un e-mail reçu pour l'aperçu de notification."""
    if not text:
        return "(Aucun texte extrait)"
    cleaned = re.sub(r'[\r\n\t]+', ' ', text)
    cleaned = re.sub(r'\s{2,}', ' ', cleaned).strip()
    if len(cleaned) <= max_length:
        return cleaned
    return cleaned[:max_length].rstrip() + "..."


def send_telegram_notification(
    sender_display: str,
    sender_email: str,
    subject: str,
    snippet: str,
    draft_text: str,
    attachment_name: Optional[str] = None,
    draft_id: Optional[str] = None,
    thread_id: Optional[str] = None
) -> bool:
    """Envoie une notification push formatée via le Bot Telegram avec lien Gmail."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    gmail_drafts_url = "https://mail.google.com/mail/u/0/#drafts"

    # Tronquer proprement si trop long (limite Telegram 4096 car.)
    safe_draft = draft_text if len(draft_text) <= 2500 else draft_text[:2500] + "\n[... suite dans Gmail]"
    att_html = f"📎 <b>Pièce jointe :</b> {html.escape(attachment_name)}\n" if attachment_name else ""

    message_html = (
        f"📬 <b>Nouveau mail & Pré-réponse prête</b>\n\n"
        f"👤 <b>De :</b> {html.escape(sender_display)} (<code>{html.escape(sender_email)}</code>)\n"
        f"📌 <b>Objet :</b> {html.escape(subject)}\n\n"
        f"📩 <b>Extrait reçu :</b>\n"
        f"<i>« {html.escape(snippet)} »</i>\n\n"
        f"✍️ <b>Pré-réponse IA (Brouillon Gmail) :</b>\n"
        f"<blockquote>{html.escape(safe_draft)}</blockquote>\n"
        f"{att_html}\n"
        f"🔗 <a href=\"{gmail_drafts_url}\">Ouvrir les Brouillons dans Gmail</a>"
    )

    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message_html,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": {
            "inline_keyboard": [
                [{"text": "📬 Ouvrir Brouillons Gmail", "url": gmail_drafts_url}]
            ]
        }
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            logger.info("   📱 [Notification Telegram] Envoyée avec succès sur votre téléphone !")
            return True
        else:
            logger.warning(f"   ⚠️ Échec envoi Telegram HTML (Code {resp.status_code}): {resp.text}. Tentative en texte brut...")
            fallback_text = (
                f"📬 Nouveau mail & Pré-réponse prête\n\n"
                f"De : {sender_display} <{sender_email}>\n"
                f"Objet : {subject}\n\n"
                f"Extrait :\n{snippet}\n\n"
                f"Pré-réponse IA :\n{draft_text}\n\n"
                f"Lien : {gmail_drafts_url}"
            )
            fallback_payload = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": fallback_text[:4000],
                "disable_web_page_preview": True
            }
            fb_resp = requests.post(url, json=fallback_payload, timeout=10)
            return fb_resp.status_code == 200
    except Exception as e:
        logger.warning(f"   ⚠️ Erreur lors de l'envoi de la notification Telegram: {e}")
        return False


def send_ntfy_notification(
    sender_display: str,
    sender_email: str,
    subject: str,
    snippet: str,
    draft_text: str,
    attachment_name: Optional[str] = None
) -> bool:
    """Envoie une notification push instantanée gratuite via ntfy.sh (sans compte requis)."""
    if not NTFY_TOPIC:
        return False

    url = f"{NTFY_SERVER}/{NTFY_TOPIC}"
    gmail_drafts_url = "https://mail.google.com/mail/u/0/#drafts"

    body_content = (
        f"👤 De : {sender_display} <{sender_email}>\n"
        f"📌 Objet : {subject}\n\n"
        f"📩 Extrait reçu :\n{snippet}\n\n"
        f"✍️ Pré-réponse IA (Brouillon créé dans Gmail) :\n{draft_text}\n"
    )
    if attachment_name:
        body_content += f"\n📎 Pièce jointe : {attachment_name}"

    safe_subject = subject.encode('ascii', 'replace').decode('ascii')[:70]
    headers = {
        "Title": f"Mail: {safe_subject}".encode('ascii', 'ignore').decode('ascii'),
        "Priority": "high",
        "Tags": "envelope,sparkles,robot",
        "Click": gmail_drafts_url,
        "Actions": f"view, Ouvrir Gmail, {gmail_drafts_url}"
    }

    try:
        resp = requests.post(url, data=body_content.encode('utf-8'), headers=headers, timeout=10)
        if resp.status_code == 200:
            logger.info("   📱 [Notification ntfy.sh] Envoyée avec succès sur votre téléphone !")
            return True
        else:
            logger.warning(f"   ⚠️ Échec envoi ntfy.sh (Code {resp.status_code}): {resp.text}")
            return False
    except Exception as e:
        logger.warning(f"   ⚠️ Erreur lors de l'envoi de la notification ntfy: {e}")
        return False


def send_discord_notification(
    sender_display: str,
    sender_email: str,
    subject: str,
    snippet: str,
    draft_text: str,
    attachment_name: Optional[str] = None
) -> bool:
    """Envoie une alerte avec carte riche dans un salon Discord via Webhook."""
    if not DISCORD_WEBHOOK_URL:
        return False

    gmail_drafts_url = "https://mail.google.com/mail/u/0/#drafts"
    short_draft = draft_text if len(draft_text) <= 1000 else draft_text[:1000] + "..."

    embed = {
        "title": f"📬 {subject[:240]}",
        "description": "Un brouillon de réponse a été préparé automatiquement dans votre boîte Gmail.",
        "color": 3447003,  # Bleu
        "url": gmail_drafts_url,
        "fields": [
            {"name": "👤 De", "value": f"**{sender_display}** (`{sender_email}`)", "inline": False},
            {"name": "📩 Extrait du message", "value": f"> {snippet[:500]}" if snippet else "N/A", "inline": False},
            {"name": "✍️ Pré-réponse IA (Brouillon Gmail)", "value": f"```{short_draft}```", "inline": False}
        ],
        "footer": {"text": "Agent Gmail 24/7 • Gemini 2.5 Flash"}
    }
    if attachment_name:
        embed["fields"].append({"name": "📎 Pièce jointe", "value": attachment_name, "inline": True})

    payload = {
        "content": "🔔 **Nouvel e-mail reçu & Pré-réponse rédigée**",
        "embeds": [embed]
    }

    try:
        resp = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code in [200, 204]:
            logger.info("   📱 [Notification Discord] Envoyée avec succès !")
            return True
        else:
            logger.warning(f"   ⚠️ Échec envoi Discord (Code {resp.status_code}): {resp.text}")
            return False
    except Exception as e:
        logger.warning(f"   ⚠️ Erreur lors de l'envoi Discord: {e}")
        return False


def send_pushover_notification(
    sender_display: str,
    sender_email: str,
    subject: str,
    snippet: str,
    draft_text: str,
    attachment_name: Optional[str] = None
) -> bool:
    """Envoie une notification push via le service Pushover."""
    if not PUSHOVER_USER_KEY or not PUSHOVER_API_TOKEN:
        return False

    url = "https://api.pushover.net/1/messages.json"
    msg = f"De: {sender_display} <{sender_email}>\n\nExtrait:\n{snippet}\n\nPré-réponse IA:\n{draft_text}"
    if attachment_name:
        msg += f"\n\nPièce jointe: {attachment_name}"

    data = {
        "token": PUSHOVER_API_TOKEN,
        "user": PUSHOVER_USER_KEY,
        "title": f"📬 {subject[:100]}",
        "message": msg[:1024],
        "url": "https://mail.google.com/mail/u/0/#drafts",
        "url_title": "Ouvrir Brouillons Gmail"
    }

    try:
        resp = requests.post(url, data=data, timeout=10)
        if resp.status_code == 200:
            logger.info("   📱 [Notification Pushover] Envoyée avec succès !")
            return True
        else:
            logger.warning(f"   ⚠️ Échec Pushover (Code {resp.status_code}): {resp.text}")
            return False
    except Exception as e:
        logger.warning(f"   ⚠️ Erreur Pushover: {e}")
        return False


def send_generic_webhook(
    sender_display: str,
    sender_email: str,
    subject: str,
    snippet: str,
    draft_text: str,
    attachment_name: Optional[str] = None,
    draft_id: Optional[str] = None
) -> bool:
    """Envoie un événement JSON à une URL Webhook personnalisée."""
    if not GENERIC_WEBHOOK_URL:
        return False

    payload = {
        "event": "gmail.draft_created",
        "timestamp": time.time(),
        "sender_name": sender_display,
        "sender_email": sender_email,
        "subject": subject,
        "snippet": snippet,
        "draft_text": draft_text,
        "attachment": attachment_name,
        "draft_id": draft_id,
        "gmail_url": "https://mail.google.com/mail/u/0/#drafts"
    }

    try:
        resp = requests.post(GENERIC_WEBHOOK_URL, json=payload, timeout=10)
        return resp.status_code in [200, 201, 202, 204]
    except Exception as e:
        logger.warning(f"   ⚠️ Erreur Generic Webhook: {e}")
        return False


def dispatch_push_notifications(
    sender_name: str,
    sender_email: str,
    subject: str,
    original_body: str,
    draft_text: str,
    attachment_path: Optional[str] = None,
    draft_id: Optional[str] = None,
    msg_id: Optional[str] = None,
    thread_id: Optional[str] = None,
    dry_run: bool = False
) -> Dict[str, bool]:
    """
    Diffuse la notification sur tous les canaux configurés par l'utilisateur.
    """
    sender_display = sender_name if sender_name else sender_email
    attachment_name = os.path.basename(attachment_path) if attachment_path else None
    snippet = clean_text_snippet(original_body, max_length=350)

    if not ENABLE_NOTIFICATIONS:
        logger.debug("   ℹ️ [Notifications] Mode silencieux actif : aucune notification push envoyée.")
        return {}

    has_any_channel = bool(
        (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) or
        NTFY_TOPIC or
        DISCORD_WEBHOOK_URL or
        (PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN) or
        GENERIC_WEBHOOK_URL
    )

    if not has_any_channel:
        logger.info("   ℹ️ [Notifications] Aucun canal push configuré (Telegram / ntfy / Discord). Consultez DEPLOIEMENT.md pour recevoir des alertes sur votre téléphone quand l'ordi est éteint.")
        return {}

    if dry_run:
        logger.info(f"   [DRY-RUN] Simulation d'envoi de notification push pour '{subject}' de {sender_display}.")
        return {"dry_run": True}

    logger.info("   🚀 Diffusion de la notification push (Mobile / Chat)...")
    results = {}

    # 1. Telegram
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        results['telegram'] = send_telegram_notification(
            sender_display=sender_display,
            sender_email=sender_email,
            subject=subject,
            snippet=snippet,
            draft_text=draft_text,
            attachment_name=attachment_name,
            draft_id=draft_id,
            thread_id=thread_id
        )

    # 2. ntfy.sh
    if NTFY_TOPIC:
        results['ntfy'] = send_ntfy_notification(
            sender_display=sender_display,
            sender_email=sender_email,
            subject=subject,
            snippet=snippet,
            draft_text=draft_text,
            attachment_name=attachment_name
        )

    # 3. Discord
    if DISCORD_WEBHOOK_URL:
        results['discord'] = send_discord_notification(
            sender_display=sender_display,
            sender_email=sender_email,
            subject=subject,
            snippet=snippet,
            draft_text=draft_text,
            attachment_name=attachment_name
        )

    # 4. Pushover
    if PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN:
        results['pushover'] = send_pushover_notification(
            sender_display=sender_display,
            sender_email=sender_email,
            subject=subject,
            snippet=snippet,
            draft_text=draft_text,
            attachment_name=attachment_name
        )

    # 5. Webhook générique
    if GENERIC_WEBHOOK_URL:
        results['webhook'] = send_generic_webhook(
            sender_display=sender_display,
            sender_email=sender_email,
            subject=subject,
            snippet=snippet,
            draft_text=draft_text,
            attachment_name=attachment_name,
            draft_id=draft_id
        )

    return results


def send_startup_notification():
    """Envoie une notification de démarrage pour confirmer que l'agent 24/7 est bien actif dans le Cloud."""
    if not NOTIFY_ON_START or not ENABLE_NOTIFICATIONS:
        return

    msg = f"🚀 Agent Gmail 24/7 en ligne pour {USER_NAME} ! Surveillance active de votre boîte."
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg},
                timeout=5
            )
        except Exception:
            pass

    if NTFY_TOPIC:
        try:
            requests.post(f"{NTFY_SERVER}/{NTFY_TOPIC}", data=msg.encode('utf-8'), timeout=5)
        except Exception:
            pass

    if DISCORD_WEBHOOK_URL:
        try:
            requests.post(DISCORD_WEBHOOK_URL, json={"content": msg}, timeout=5)
        except Exception:
            pass


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
    body_text: str = "",
    auto_draft: bool = False,
    dry_run: bool = False
):
    """
    Affiche le format de validation obligatoire, diffuse la notification mobile et gère le choix.
    """
    # 1. Affichage du format strict
    validation_card = format_validation_display(sender_name, sender_email, subject, draft_text)
    print(validation_card)

    # 2. Création préventive du brouillon Gmail pour que Robin puisse le retrouver dans Gmail
    draft_id = create_gmail_draft(service, original_msg, draft_text, attachment_path=detected_cv_path, dry_run=dry_run)

    # 3. Notification push (désactivée par défaut pour consultation tranquille le matin)
    if ENABLE_NOTIFICATIONS:
        dispatch_push_notifications(
            sender_name=sender_name,
            sender_email=sender_email,
            subject=subject,
            original_body=body_text,
            draft_text=draft_text,
            attachment_path=detected_cv_path,
            draft_id=draft_id,
            msg_id=original_msg.get('id'),
            thread_id=original_msg.get('threadId'),
            dry_run=dry_run
        )

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

def process_single_message(
    service,
    msg_id: str,
    is_from_spam: bool = False,
    auto_draft: bool = False,
    dry_run: bool = False
):
    """
    Analyse et traite un message individuel (issu de la boîte principale ou des spams).
    Applique les règles de sécurité, le sauvetage depuis les spams si légitime,
    le nettoyage/désabonnement si pub/scam, et la pré-rédaction IA si actionnable.
    """
    try:
        msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    except HttpError as e:
        logger.error(f"Impossible de récupérer le message {msg_id}: {e}")
        return

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

    source_tag = "[Dossier SPAM]" if is_from_spam else "[Boîte Principale]"
    logger.info(f"\n--- {source_tag} Message {msg_id} ---")
    logger.info(f"De       : {from_header}")
    logger.info(f"Objet    : {subject}")
    logger.info(f"Date     : {date_str}")

    # ------------------------------------------------------------------
    # 1. RÈGLE DE SÉCURITÉ ABSOLUE : ANALYSE DES PROTECTIONS
    # ------------------------------------------------------------------
    is_protected, protect_reason = check_security_whitelist(from_header, subject, body, headers, payload)

    if is_from_spam:
        # === CAS PARTICULIER : MESSAGE SITUÉ DANS LES SPAMS ===
        if is_protected:
            logger.info(f"🛡️  [Sécurité Absolue / Sauvetage] E-mail important protégé détecté dans les spams : {protect_reason}.")
            rescue_message_from_spam(service, msg_id, dry_run=dry_run)
        else:
            # Vérifier si c'est une newsletter, une notification futile ou une arnaque avérée
            is_promo, promo_reason = is_newsletter_or_marketing(headers, label_ids, from_header, subject)
            is_futile, futile_reason = is_futile_notification(from_header, subject, headers, label_ids)
            is_scam, scam_reason = is_obvious_spam(from_header, subject, body)

            if is_promo or is_futile or is_scam:
                reason = promo_reason or futile_reason or scam_reason
                logger.info(f"🧹 [Nettoyage Spam Confirmé] Purge du courrier indésirable ({reason}).")
                if list_unsub and is_promo:
                    execute_http_unsubscribe(list_unsub, list_unsub_post)
                purge_message(service, msg_id, hard_delete=True, dry_run=dry_run)
                return
            else:
                # E-mail non promotionnel et non frauduleux : échange humain / contact légitime classé à tort par Gmail
                logger.info("🛡️  [Sauvetage Spam -> Boîte Principale] E-mail direct ou légitime sauvé des spams.")
                rescue_message_from_spam(service, msg_id, dry_run=dry_run)
                is_protected = True
                protect_reason = "E-mail légitime sauvé des spams"
    else:
        # === CAS STANDARD : MESSAGE DE LA BOÎTE PRINCIPALE ===
        if not is_protected:
            is_promo, promo_reason = is_newsletter_or_marketing(headers, label_ids, from_header, subject)
            if is_promo:
                logger.info(f"🧹 [Newsletters & Marketing] Détecté ({promo_reason}).")
                if list_unsub:
                    execute_http_unsubscribe(list_unsub, list_unsub_post)
                purge_message(service, msg_id, hard_delete=True, dry_run=dry_run)
                return

            # E-mails futiles / Notifications de basse valeur
            is_futile, futile_reason = is_futile_notification(from_header, subject, headers, label_ids)
            if is_futile:
                logger.info(f"🗑️  [Notification Futile] Mise en corbeille ({futile_reason}).")
                purge_message(service, msg_id, hard_delete=False, dry_run=dry_run)
                return

        if is_protected:
            logger.info(f"🛡️  [Sécurité Absolue] Message protégé : {protect_reason}.")

    # ------------------------------------------------------------------
    # 2. GESTION DES MESSAGES PROTÉGÉS & NON ACTIONNABLES (Absence, 2FA...)
    # ------------------------------------------------------------------
    # Réponses automatiques d'absence / Out of office (ne jamais répondre dessus)
    is_auto_reply = bool(re.search(r'r[ée]ponse automatique|automatic reply|auto[- ]reply|out of office|absent(e)? du bureau', subject.lower())) or get_header_value(headers, 'Auto-Submitted').lower() in ['auto-replied', 'auto-generated']
    if is_auto_reply:
        logger.info("   ℹ️ Réponse automatique / Absence du bureau détectée : laissé intact dans la boîte, aucune réponse générée.")
        return

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
        return

    # Expéditeurs automatisés / no-reply protégés (confirmations de commandes, factures reçues...)
    is_noreply_sender = bool(re.search(r'(no-reply|noreply|donotreply|notifications?@|mailer-daemon)', from_header.lower()))
    if is_noreply_sender and not get_header_value(headers, 'In-Reply-To'):
        logger.info("   ℹ️ Notification automatisée (no-reply) : laissé intact dans la boîte, aucune réponse requise.")
        return

    # ------------------------------------------------------------------
    # 3. E-MAILS IMPORTANTS & ACTIONNABLES (VRAIS CONTACTS & ÉCHANGES)
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
        body_text=body,
        auto_draft=auto_draft,
        dry_run=dry_run
    )

    # En mode auto-draft, marquer comme lu pour ne pas retraiter en boucle au cycle suivant
    if auto_draft and not dry_run:
        try:
            service.users().messages().modify(
                userId='me',
                id=msg_id,
                body={'removeLabelIds': ['UNREAD']}
            ).execute()
        except Exception as e:
            logger.debug(f"Impossible de retirer le statut UNREAD pour {msg_id}: {e}")


def process_inbox(service, auto_draft: bool = False, dry_run: bool = False):
    """
    Scanne les e-mails non lus dans la boîte de réception ET dans le dossier Spam.
    Sauve les e-mails importants des spams, élimine le superflu et pré-rédige les réponses.
    """
    AGENT_STATS["last_scan_time"] = time.strftime('%Y-%m-%d %H:%M:%S')  # type: ignore
    logger.info("Scan des e-mails (Boîte de réception & Spams)...")

    try:
        # 1. Traitement des e-mails non lus de la Boîte de Réception Principale
        inbox_res = service.users().messages().list(
            userId='me',
            q='is:unread in:inbox',
            maxResults=50
        ).execute()
        inbox_messages = inbox_res.get('messages', [])
        logger.info(f"📬 [Boîte Principale] {len(inbox_messages)} nouveau(x) message(s) non lu(s).")

        for msg_summary in inbox_messages:
            process_single_message(
                service=service,
                msg_id=msg_summary['id'],
                is_from_spam=False,
                auto_draft=auto_draft,
                dry_run=dry_run
            )

        # 2. Traitement et tri intelligent du dossier Spam (sauvetage des faux-positifs & élimination des vrais spams)
        spam_res = service.users().messages().list(
            userId='me',
            q='in:spam',
            maxResults=50
        ).execute()
        spam_messages = spam_res.get('messages', [])
        if spam_messages:
            logger.info(f"🛡️  [Dossier Spam] {len(spam_messages)} message(s) trouvé(s) en cours de tri et d'analyse de sécurité...")
            for msg_summary in spam_messages:
                process_single_message(
                    service=service,
                    msg_id=msg_summary['id'],
                    is_from_spam=True,
                    auto_draft=auto_draft,
                    dry_run=dry_run
                )
        else:
            logger.info("🛡️  [Dossier Spam] Aucun message à trier dans les spams.")

        # 3. Purge uniquement de la Corbeille
        empty_trash(service, dry_run=dry_run)

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
    active_model_name = os.getenv('GEMINI_MODEL', 'gemini-3-flash-preview')
    print(f"       - Modèle IA      : {active_model_name} ({'Actif' if GEMINI_API_KEY else 'Non configuré'})")
    print("=" * 75)

    # Démarrage du serveur de santé HTTP en mode continu si activé
    if not is_once and enable_healthcheck:
        start_healthcheck_server(port=args.port)

    # Notification de démarrage si configurée
    send_startup_notification()

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

    # Gestion des signaux de terminaison propres (SIGTERM pour Render / Docker)
    def sigterm_handler(signum, frame):
        logger.info("Signal d'arrêt reçu (SIGTERM). Arrêt propre de l'agent Gmail...")
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, sigterm_handler)
    except Exception:
        pass

    logger.info(f"Boucle de surveillance 24/7 active (vérification toutes les {args.interval} secondes).")
    try:
        while True:
            try:
                process_inbox(service, auto_draft=is_auto_draft, dry_run=args.dry_run)
            except HttpError as e:
                AGENT_STATS["errors_count"] += 1
                logger.error(f"Erreur API Gmail durant le cycle de scan: {e}")
                if getattr(e, 'resp', None) and getattr(e.resp, 'status', None) in [401, 403]:
                    logger.warning("🔄 Tentative de ré-authentification au service Gmail...")
                    try:
                        service = get_gmail_service()
                        logger.info("✅ Ré-authentification réussie.")
                    except Exception as re_err:
                        logger.error(f"❌ Échec de la ré-authentification : {re_err}")
            except Exception as e:
                logger.exception(f"Erreur durant le cycle de scan : {e}")
                AGENT_STATS["errors_count"] += 1
            logger.info(f"En attente pendant {args.interval} secondes avant le prochain scan...")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("\nArrêt de l'agent Gmail demandé par l'utilisateur. Au revoir !")


if __name__ == '__main__':
    main()

