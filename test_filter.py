#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test de validation pour le filtrage strict des e-mails.
Vérifie que :
1. Les notifications de mises à jour, CGU, digests, alertes de services connectés sont bien ignorées.
2. Les factures, 2FA et billets sont bien détectés comme ne nécessitant aucune réponse.
3. Les e-mails de vraies personnes demandant un échange ou un CV sont bien identifiés comme nécessitant une réponse.
"""

import sys
from typing import List, Dict, TypedDict
from agent import is_automated_or_service_notification, fallback_check_requires_reply


class TestCase(TypedDict, total=False):
    name: str
    headers: List[Dict[str, str]]
    sender: str
    subject: str
    body: str
    expect_automated: bool
    expect_human_reply: bool


def run_tests():
    test_cases: List[TestCase] = [
        # --- CAS DEVRAIENT ÊTRE IGNORÉS (AUTOMATIQUES, MISES À JOUR, SERVICES) ---
        {
            "name": "Mise à jour Notion (Nouveautés)",
            "headers": [{"name": "List-Unsubscribe", "value": "<https://notion.so/unsub>"}],
            "sender": "Notion <mail@notion.so>",
            "subject": "Quoi de neuf dans Notion : découvrez les nouvelles fonctionnalités",
            "body": "Bonjour, découvrez les nouveautés de ce mois-ci dans votre espace de travail.",
            "expect_automated": True
        },
        {
            "name": "Mise à jour CGU Google Cloud",
            "headers": [],
            "sender": "Google Cloud <google-cloud-compliance@google.com>",
            "subject": "Mise à jour des Conditions d'utilisation de Google Cloud",
            "body": "Nous mettons à jour nos conditions d'utilisation et notre politique de confidentialité.",
            "expect_automated": True
        },
        {
            "name": "GitHub Notification (PR merged)",
            "headers": [{"name": "X-GitHub-Reason", "value": "mention"}],
            "sender": "GitHub <notifications@github.com>",
            "subject": "[datanomade/auto-gmail] Pull request #12 merged",
            "body": "Robin, your pull request was merged into main.",
            "expect_automated": True
        },
        {
            "name": "Facture Stripe automatique",
            "headers": [],
            "sender": "Stripe <invoices@stripe.com>",
            "subject": "Votre facture Stripe n° INV-2026-001 est prête",
            "body": "Votre facture mensuelle est disponible au téléchargement.",
            "expect_automated": True
        },
        {
            "name": "Billet SNCF Connect",
            "headers": [],
            "sender": "SNCF Connect <confirmation@sncf-connect.com>",
            "subject": "Votre billet de train pour Paris Gare de Lyon",
            "body": "Retrouvez votre e-billet en pièce jointe.",
            "expect_automated": True
        },
        {
            "name": "Code de sécurité 2FA",
            "headers": [],
            "sender": "Microsoft <account-security-noreply@accountprotection.microsoft.com>",
            "subject": "Code de sécurité pour votre compte Microsoft",
            "body": "Votre code de sécurité à 6 chiffres est : 492810.",
            "expect_automated": True
        },
        {
            "name": "Slack Digest",
            "headers": [{"name": "Precedence", "value": "bulk"}],
            "sender": "Slack <notification@slack.com>",
            "subject": "Résumé hebdomadaire de votre espace de travail",
            "body": "Voici l'activité de votre équipe cette semaine.",
            "expect_automated": True
        },
        {
            "name": "Accusé de réception candidature WTTJ",
            "headers": [],
            "sender": "Welcome to the Jungle <no-reply@welcometothejungle.com>",
            "subject": "Accusé de réception de votre candidature",
            "body": "Nous avons bien reçu votre candidature et nous reviendrons vers vous.",
            "expect_automated": True
        },

        # --- CAS DEVRAIENT ÊTRE TRAITÉS COMME VRAIES PERSONNES (RÉPONSE REQUISE) ---
        {
            "name": "Client potentiel demandant un devis",
            "headers": [],
            "sender": "Sophie Laurent <sophie.laurent@agence-digitale.fr>",
            "subject": "Demande de devis pour un projet d'automatisation",
            "body": "Bonjour Robin, suite à notre discussion, pourriez-vous me faire parvenir un devis pour la mission ? Seriez-vous disponible demain à 10h ?",
            "expect_automated": False,
            "expect_human_reply": True
        },
        {
            "name": "Recruteur demandant un CV et un créneau d'appel",
            "headers": [],
            "sender": "Marc Valadier <m.valadier@tech-recrutement.com>",
            "subject": "Opportunité Senior Developer / Automatisation",
            "body": "Bonjour Robin, ton profil a retenu notre attention. Pourrais-tu me transmettre ton CV à jour et me donner tes disponibilités pour un rapide échange ?",
            "expect_automated": False,
            "expect_human_reply": True
        },
        {
            "name": "Collègue posant une question directe",
            "headers": [],
            "sender": "julien@mon-entreprise.com",
            "subject": "Question sur l'API Gmail",
            "body": "Salut Robin, est-ce que tu as pu regarder le bug d'authentification ? Qu'en penses-tu ?",
            "expect_automated": False,
            "expect_human_reply": True
        }
    ]

    print("=" * 70)
    print("       🧪 TEST DU FILTRE STRICT D'E-MAILS HUMAINS VS AUTOMATES")
    print("=" * 70)

    passed = 0
    total = len(test_cases)

    for case in test_cases:
        headers_val: List[Dict[str, str]] = case.get("headers", [])
        sender_val: str = case.get("sender", "")
        subject_val: str = case.get("subject", "")
        body_val: str = case.get("body", "")
        expect_auto: bool = case.get("expect_automated", False)
        expect_human: bool = case.get("expect_human_reply", True)

        is_auto, reason = is_automated_or_service_notification(
            headers=headers_val,
            sender=sender_val,
            subject=subject_val,
            body=body_val
        )

        if expect_auto:
            if is_auto:
                print(f"✅ [REJETÉ AUTO] {case.get('name', '')} -> Détecté comme automatique ({reason})")
                passed += 1
            else:
                print(f"❌ [ERREUR] {case.get('name', '')} aurait dû être détecté comme automatique !")
        else:
            if not is_auto:
                needs_reply, reply_reason = fallback_check_requires_reply(sender_val, subject_val, body_val)
                if needs_reply == expect_human:
                    print(f"✅ [ACCEPTÉ HUMAIN] {case.get('name', '')} -> Détecté comme personne humaine ({reply_reason})")
                    passed += 1
                else:
                    print(f"❌ [ERREUR] {case.get('name', '')} détection humaine échouée : {reply_reason}")
            else:
                print(f"❌ [ERREUR] {case.get('name', '')} a été faussement rejeté comme automatique : {reason}")

    print("=" * 70)
    print(f"Résultats : {passed}/{total} tests validés avec succès.")
    print("=" * 70)

    if passed == total:
        print("🎉 TOUS LES TESTS SONT AU VERT !")
    else:
        sys.exit(1)


if __name__ == '__main__':
    run_tests()
