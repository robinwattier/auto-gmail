#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test instantané pour les notifications mobiles de l'Agent Gmail.
Permet de vérifier la bonne réception des alertes push (Telegram, ntfy.sh, Discord, etc.)
sans avoir besoin d'attendre un vrai e-mail.
"""

import os
import sys
import argparse
from dotenv import load_dotenv  # type: ignore

# Charger l'environnement
load_dotenv()

# Importer les fonctions de notification depuis agent.py
from agent import (  # type: ignore
    dispatch_push_notifications,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    NTFY_TOPIC,
    NTFY_SERVER,
    DISCORD_WEBHOOK_URL,
    PUSHOVER_USER_KEY,
    PUSHOVER_API_TOKEN,
    GENERIC_WEBHOOK_URL,
    USER_NAME
)

def main():
    parser = argparse.ArgumentParser(description="Test des notifications mobiles pour l'Agent Gmail")
    parser.add_argument('--channel', choices=['telegram', 'ntfy', 'discord', 'pushover', 'webhook', 'all'], default='all',
                        help="Canal spécifique à tester (défaut: tous les canaux configurés)")
    args = parser.parse_args()

    print("=" * 70)
    print("       📱 TEST DES NOTIFICATIONS MOBILES - AGENT GMAIL")
    print("=" * 70)

    # État des canaux
    print("\n🔍 Statut des configurations détectées dans votre fichier .env :")
    print(f"  • Telegram : {'✅ Configuré' if (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) else '❌ Non configuré (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)'}")
    print(f"  • ntfy.sh  : {'✅ Configuré (Topic: ' + NTFY_TOPIC + ')' if NTFY_TOPIC else '❌ Non configuré (NTFY_TOPIC)'}")
    print(f"  • Discord  : {'✅ Configuré' if DISCORD_WEBHOOK_URL else '❌ Non configuré (DISCORD_WEBHOOK_URL)'}")
    print(f"  • Pushover : {'✅ Configuré' if (PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN) else '❌ Non configuré'}")
    print(f"  • Webhook  : {'✅ Configuré' if GENERIC_WEBHOOK_URL else '❌ Non configuré'}")

    has_any = bool((TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) or NTFY_TOPIC or DISCORD_WEBHOOK_URL or (PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN) or GENERIC_WEBHOOK_URL)

    if not has_any:
        print("\n" + "!" * 70)
        print("⚠️ AUCUN CANAL DE NOTIFICATION N'EST CONFIGURÉ DANS .env !")
        print("!" * 70)
        print("\n💡 Pour recevoir les notifications sur votre téléphone même PC éteint :")
        print("\n👉 OPTION A : ntfy.sh (Le plus rapide - 0 inscription requise)")
        print("   1. Installez l'application gratuite 'ntfy' sur votre smartphone (iOS / Android).")
        print("   2. Dans l'application, abonnez-vous au sujet : 'robin-gmail-alertes-1234'")
        print("   3. Ajoutez dans votre .env :")
        print("      NTFY_TOPIC=robin-gmail-alertes-1234")
        print("\n👉 OPTION B : Telegram (Recommandé pour un contrôle complet)")
        print("   1. Sur Telegram, cherchez @BotFather et tapez /newbot pour créer votre bot.")
        print("   2. Copiez le token fourni dans .env : TELEGRAM_BOT_TOKEN=...")
        print("   3. Démarrez une discussion avec votre bot (/start), puis cherchez @userinfobot pour obtenir votre Chat ID.")
        print("   4. Ajoutez dans votre .env : TELEGRAM_CHAT_ID=...")
        print("\nConsultez DEPLOIEMENT.md pour le tutoriel détaillé pas-à-pas.")
        sys.exit(0)

    # Données fictives pour le test
    test_sender_name = "Alexandre Dupont"
    test_sender_email = "alexandre.dupont@entreprise-partenaire.fr"
    test_subject = "Proposition de partenariat & échange de calendrier"
    test_body = """Bonjour Robin,

J'espère que vous allez bien. Suite à notre échange sur le projet d'automatisation, seriez-vous disponible ce jeudi à 14h30 pour un point rapide en visio ?

Pourriez-vous également me transmettre votre CV actualisé pour l'équipe technique ?

Bien cordialement,
Alexandre Dupont
Directeur Technique"""

    test_draft = f"""Bonjour Alexandre,

Je vous remercie pour votre message et pour l'intérêt que vous portez à nos projets d'automatisation.

Le créneau de ce jeudi à 14h30 me convient parfaitement pour notre échange en visio. Je vous laisse me faire parvenir le lien de connexion.

Comme convenu, vous trouverez ci-joint mon CV actualisé pour votre équipe technique.

Au plaisir d'échanger jeudi,

Bien cordialement,
{USER_NAME}"""

    print("\n🚀 Envoi d'une notification de test en cours...")
    results = dispatch_push_notifications(
        sender_name=test_sender_name,
        sender_email=test_sender_email,
        subject=test_subject,
        original_body=test_body,
        draft_text=test_draft,
        attachment_path="CV_Robin_Wattier.pdf",
        draft_id="draft_test_12345",
        msg_id="msg_test_12345",
        dry_run=False
    )

    print("\n📊 Résultats de l'envoi :")
    for channel, success in results.items():
        icon = "✅" if success else "❌"
        status = "Envoyé avec succès !" if success else "Échec de transmission"
        print(f"  • {channel.capitalize():<10} : {icon} {status}")

    print("\n💡 Vérifiez l'écran de votre smartphone pour vous assurer que la notification est bien arrivée.")

if __name__ == '__main__':
    main()
