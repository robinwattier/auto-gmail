# 📬 Que fait précisément l'agent dans votre boîte Gmail ?

Voici le récapitulatif complet, exact et à jour de toutes les actions que réalise l'agent pour sécuriser, trier, nettoyer votre boîte et pré-rédiger vos e-mails.

---

## 1. ⏱️ Surveillance continue (24h/24 & 7j/7)

* Il analyse automatiquement vos **nouveaux e-mails non lus** à intervalles réguliers (toutes les 3 minutes par défaut).
* Il fonctionne aussi bien sur votre ordinateur qu'hébergé dans le Cloud (Render, Railway...) grâce à son **serveur de santé HTTP intégré** (`/health`), vous alertant même lorsque votre ordinateur est éteint.

---

## 2. 🛡️ Protection absolue des e-mails indispensables (Règle d'or : Ne jamais supprimer)

Avant toute décision de tri ou de nettoyage, l'agent vérifie systématiquement si le message relève de l'un de vos domaines prioritaires. **Il sanctuarise et conserve obligatoirement :**

* **Vos vrais échanges humains** : tous les fils de discussion actifs avec vos contacts, clients, collègues ou proches (détection des en-têtes `In-Reply-To` et `References`).
* **Vos documents & pièces jointes utiles** : tout message contenant un fichier important (PDF, Word, Excel, PowerPoint, archives ZIP/RAR, rendez-vous d'agenda ICS, etc.).
* **Votre sécurité, accès & activations de compte** : codes de validation, codes de confirmation ou de sécurité (2FA / OTP / PIN), liens d'activation de compte, validation d'adresse e-mail, liens de connexion magiques (*magic links*), réinitialisations de mot de passe, alertes de sécurité et de connexion officielle (Google, Microsoft, Apple, GitHub, etc.). Ces e-mails ne sont **JAMAIS supprimés** et sont **immédiatement sortis des spams** s'ils y atterrissent.
* **Vos finances, factures & démarches légales** : notifications bancaires (BoursoBank, PayPal, Stripe, Revolut, etc.), avis des impôts ou de l'URSSAF, factures et reçus de paiement, devis, contrats et signatures électroniques (DocuSign, Yousign, Adobe Sign, etc.).
* **Vos voyages, déplacements & rendez-vous** : billets de train ou d'avion (SNCF Connect, Air France, Eurostar...), réservations d'hôtel (Booking, Airbnb...), transports (Uber, Bolt, BlaBlaCar...), rendez-vous médicaux ou d'agenda (Doctolib, Calendly...).
* **Vos candidatures, recrutements, formations & tests de sélection** :
  * Confirmations et retours de candidatures des plateformes d'emploi (Welcome to the Jungle, LinkedIn, Indeed, JobTeaser, Apec, etc.).
  * **Organismes officiels de formation & emploi** : e-mails du **Forem** (`@forem.be`), de **Technocité** (`@technocite.be`), programmes *Coup de Poing Pénurie*, etc.
  * **Invitations à des tests d'évaluation** : tests de langues (**Elao**), tests de positionnement, tests techniques et plateformes d'évaluation (TestGorilla, HackerRank, Codility...). **Ces e-mails ne sont JAMAIS supprimés.**

---

## 3. 🧹 Nettoyage du superflu, filtrage SaaS & tri intelligent des Spams

Pour garder une boîte propre sans jamais risquer de perdre un message important :

* **Tri intelligent & sauvetage des faux-positifs dans les Spams** : l'agent inspecte systématiquement le dossier *Spams* avec les mêmes règles rigoureuses de protection. Tout e-mail important (test d'évaluation **Elao**, formation **Forem**, contact professionnel, confirmation de candidature, facture, code de sécurité...) classé par erreur dans les spams par Gmail est **automatiquement sauvé, replacé dans la boîte de réception principale et traité** (avec pré-rédaction de brouillon si nécessaire).
* **Désabonnement HTTP officiel (List-Unsubscribe)** : si l'expéditeur fournit un lien ou un en-tête de désinscription conforme (RFC 8058 One-Click POST ou GET), l'agent active automatiquement la désinscription pour que vous ne receviez plus ces messages.
* **Suppression des newsletters, pubs et promotions** : mise à la corbeille immédiate des e-mails marketing et publicitaires.
* **Filtrage des bilans et notifications SaaS non sollicités** : détection et élimination des bilans statistiques automatiques ou récapitulatifs périodiques sans action requise (ex: rapports mensuels **Metricool**, résumés analytiques, notifications futiles de réseaux sociaux).
* **Vidage sécurisé de la Corbeille et des vrais spams confirmés** : seuls les spams avérés (scams, arnaques, arnaques crypto, loteries, casino) et les messages mis à la corbeille sont définitivement purgés après analyse.

---

## 4. ✍️ Rédaction intelligente de réponses avec l'IA (Google Gemini)

Lorsqu'un e-mail reçu est un vrai message demandant une attention ou une réponse humaine :

* **Respect strict de la langue de votre interlocuteur** :
  * Si l'e-mail est rédigé en anglais, l'agent rédige intégralement en anglais (salutation, corps et formule de politesse).
  * Si l'e-mail est en français, il répond en français impeccable.
  * Zéro mélange linguistique : formule de politesse et signature adaptées avec votre nom (**Robin**).
* **Détection automatique des demandes de CV** : si l'expéditeur demande votre CV, l'IA adapte le texte de la réponse pour l'indiquer et prépare automatiquement votre fichier CV (`CV_Robin_Wattier.pdf`) en pièce jointe.
* **Filtrage des messages non actionnables** : l'agent ne tente jamais de répondre aux messages automatiques d'absence (*« Out of office »*), aux adresses *no-reply*, ni aux accusés de réception purement informatifs.

---

## 5. 🎯 Enregistrement en brouillon dans Gmail (Zéro doublon & Contrôle total)

* **Brouillon officiel créé dans Gmail** : la réponse pré-rédigée est enregistrée directement dans votre dossier *Brouillons* Gmail, rattachée avec précision à la bonne conversation.
* **Système anti-doublon** : l'agent vérifie préalablement si un brouillon existe déjà sur ce fil de discussion. Si c'est le cas, aucun nouveau brouillon n'est créé pour éviter toute pollution de votre boîte.
* **Marquage comme traité** : une fois le brouillon préparé, l'e-mail d'origine est marqué comme lu pour ne pas être retraité indéfiniment à chaque cycle.
* **Vous gardez 100% du contrôle** : rien n'est envoyé sans votre accord. Vous pouvez relire, modifier ou envoyer le brouillon d'un simple clic depuis l'application Gmail sur votre téléphone ou votre ordinateur.

---

## 6. 🔕 Mode Silencieux & Tranquillité d'esprit (Zéro notification intempestive)

Pour vous laisser travailler ou vous reposer sans être interrompu par des alertes continues tout au long de la journée :

* **Aucune notification push intrusive** : l'agent travaille discrètement en arrière-plan. Il ne vous envoie aucune alerte intempestive sur votre téléphone (Telegram, push mobile, etc.).
* **Consultation paisible le matin** : tout le travail préparatoire (nettoyage des pubs, tri, protection de vos e-mails de formation/tests et pré-rédaction des réponses) est fait pour vous en amont. Le matin, à votre rythme, vous ouvrez simplement Gmail : vos brouillons prêts à l'envoi vous attendent sagement dans votre boîte, prêts à être validés ou ajustés en buvant votre café.
* **Optionnel à la demande** : si un jour vous souhaitez réactiver des notifications push instantanées en temps réel, le système reste disponible dans les réglages (`ENABLE_NOTIFICATIONS=true`).

---

### 💡 En résumé

> **L'agent agit comme un secrétaire particulier discret et efficace : il sanctuarise vos opportunités (candidatures, formations Forem, tests Elao, contrats, échanges réels), élimine le bruit (pubs, spams, newsletters, bilans Metricool), pré-rédige vos brouillons dans Gmail avec l'IA et vous laisse une boîte impeccable prête pour votre consultation tranquille le matin, sans jamais vous déranger.**
