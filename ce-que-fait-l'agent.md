# 📋 Guide Complet : Tout ce que fait exactement l'Agent Gmail

Ce document détaille avec une **précision chirurgicale** le fonctionnement exact de votre agent exécutif, étape par étape, selon ses **5 Piliers Fondamentaux**.

---

## 1. Le Sauvetage Prioritaire du dossier Spam (`in:spam`)

Google classe parfois par erreur des e-mails vitaux dans les spams. L'agent applique un protocole d'inspection chirurgical :

- **Vérification d'identité cryptographique (Anti-Usurpation)** : Avant de toucher à un e-mail dans les spams, il contrôle les signatures techniques (**SPF** et **DKIM** via `Authentication-Results` et `Received-SPF`). Si un spammeur usurpe l'adresse d'une banque ou d'un client (`spf=fail` ou `dkim=fail`), l'agent le détecte immédiatement et le laisse bloqué dans les spams.
- **Repêchage instantané vers la Boîte Principale (`INBOX`)** : Si le message est authentifié et provient d'une vraie personne (recruteur, client, opportunité) ou contient un document vital (facture, billet, code 2FA), il lui retire le label `SPAM` et le replace directement dans votre boîte de réception principale.
- **Traçabilité visuelle** : Il lui applique l'étiquette **`⚠️ Faux-Positif-Spam`** pour que vous sachiez instantanément qu'un message important a été sauvé des spams.
- **Prise en charge directe** : Si ce mail repêché attend une réponse, il génère immédiatement un brouillon (voir point 4).
- **Purge des arnaques réelles** : Les arnaques évidentes (phishing grossier, crypto, loteries) sont transférées directement à la corbeille Gmail.

---

## 2. L'Élimination Radicale du Superflu ("Bazarder")

L'agent désencombre votre boîte de réception sans intervention manuelle :

- **Détection du marketing et des newsletters** : Il identifie automatiquement les publicités, newsletters, soldes, webinaires et digests via les en-têtes techniques (`List-Unsubscribe`, `Precedence: bulk`) et les catégories Gmail (`Promotions`, `Social`).
- **Désabonnement propre (RFC 8058)** : Si l'expéditeur respecte la norme officielle en un clic (`List-Unsubscribe-Post: List-Unsubscribe=One-Click`), l'agent émet automatiquement la requête POST de désinscription technique pour couper le flux à la source.
- **Sécurité réseau (Zéro SSRF)** : Il refuse d'ouvrir à l'aveugle des liens arbitraires. Son bouclier anti-SSRF valide obligatoirement le protocole HTTPS et interdit toute résolution vers des adresses IP locales, privées (`127.0.0.1`, `10.x`, `192.168.x`) ou non sécurisées.
- **Mise en corbeille sécurisée** : Le message est déplacé dans la corbeille Gmail. Votre vue est immédiatement nettoyée, mais le message reste récupérable pendant 30 jours en cas de faux-pas.

---

## 3. La Préservation & l'Archivage Doux (Soft Archiving)

Vos documents administratifs et notifications essentielles ne sont jamais perdus, mais ils ne polluent plus votre boîte de réception principale :

- **Sanctuarisation absolue** : Interdiction totale de supprimer ou jeter les factures, reçus, billets de train/avion, réservations d'hôtel, alertes serveurs/GitHub/AWS et codes de sécurité 2FA.
- **Rangement automatique par étiquettes** : L'agent leur assigne automatiquement leur dossier dédié dans Gmail :
  - **`📂 Archives/Finances`** : Factures, reçus, banques, Stripe, PayPal, impôts, devis.
  - **`📂 Archives/Transports`** : SNCF Connect, billets d'avion, réservations Booking/Airbnb, courses Uber, rendez-vous Doctolib.
  - **`📂 Archives/Sécurité`** : Codes 2FA, OTP, alertes de connexion, réinitialisations de mot de passe.
  - **`📂 Archives/Dev`** : Alertes GitHub, GitLab, AWS, Google Cloud, Vercel, Supabase, Docker, Sentry, Datadog.
- **Désencombrement de l'Inbox** : Il retire l'étiquette `INBOX`. Ces e-mails n'apparaissent plus dans votre flux principal, mais restent parfaitement classés et consultables via la recherche ou dans leurs dossiers.
- **Respect du statut de lecture** : Il ne marque jamais ces e-mails comme "lus" à votre place. Si vous ne les avez pas ouverts, ils restent non lus.

---

## 4. Le Moteur de Réponse IA & Brouillons (Gemini)

Dès qu'un e-mail provient d'une vraie personne attendant un retour (qu'il vienne de l'Inbox ou d'un sauvetage Spam) :

- **Lecture du fil complet (Thread Context)** : L'IA ne lit pas le message de façon isolée ; elle analyse l'historique des 2 ou 3 échanges précédents pour comprendre tout le contexte de la conversation.
- **Bouclier Anti-Prompt Injection** : Le texte de l'e-mail est confiné dans des balises sécurisées `<untrusted_email_content>`. Un message hostile tentant de donner des contre-ordres à l'IA est totalement neutralisé.
- **Rédaction prête à l'envoi** :
  - Réponse rédigée à 100 % dans la langue de l'interlocuteur (salutations, corps et formule de politesse finale).
  - Ton naturel, chaleureux, professionnel et signé Robin.
  - **Zéro placeholder** : Aucun texte à trous du type `[Date]` ou `[Lien]`.
  - **Ajout automatique du CV** : Si l'expéditeur demande un CV, l'IA le détecte, mentionne la pièce jointe dans le texte et attache automatiquement votre PDF (`CV_Robin_Wattier.pdf`).
- **Brouillon Gmail officiel** : La réponse est enregistrée comme brouillon directement rattaché au fil de discussion existant. Rien n'est envoyé dans votre dos.
- **Signalement prioritaire** : L'e-mail reçoit l'étiquette **`🤖 Action-Requise`** pour sauter immédiatement aux yeux dans votre boîte.

---

## 5. L'Infrastructure Technique (Mémoire & Fiabilité)

Sous le capot, l'agent est blindé pour tourner sans bug 24h/24 :

- **Mémoire permanente sur disque (SQLite `agent_memory.db`)** : L'ancien cache temporaire qui s'effaçait à chaque redémarrage du conteneur Cloud est remplacé par une base locale persistante. L'agent sait exactement ce qu'il a déjà traité.
- **Garantie zéro doublon (Idempotence)** : Même si le script tourne deux fois par erreur sur le même message, il vérifie sa base de données et s'arrête net sans regénérer de brouillon ni consommer d'API inutilement.
- **Prêt pour le temps réel (Push Pub/Sub)** : Il intègre l'endpoint **`/webhook/gmail-pubsub`** prêt à recevoir les notifications instantanées de Google Cloud, éliminant la latence du scan toutes les 3 minutes.
- **Notifications smartphone** : Il peut envoyer une notification immédiate (*Telegram, Discord, ntfy*) contenant le lien direct vers le brouillon dès qu'un message requiert votre validation ou qu'un faux-positif a été repêché des spams.

---

## 📊 Résumé de votre quotidien avec cette version

Lorsque vous ouvrez Gmail :

1. Votre boîte principale est vide de tout spam et de toute pub.
2. Vos factures et billets sont déjà rangés dans leurs dossiers sans vous déranger.
3. Vous ne voyez que les e-mails humains importants (y compris ceux que Google avait mis dans les spams par erreur).
4. Chaque message important est marqué **`🤖 Action-Requise`** et possède déjà sa réponse rédigée en brouillon, prête à être relue et envoyée en un clic.
