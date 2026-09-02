# 🚀 Guide de Déploiement en Ligne 24h/24 : Agent Gmail

Ce guide vous explique pas à pas comment déployer et faire tourner votre agent Gmail **en continu 24h/24 sur le Cloud**, sans avoir besoin de laisser votre ordinateur allumé.

---

## 📋 Sommaire

1. [Étape 0 : Générer le token d'authentification pour le Cloud](#étape-0--générer-le-token-dauthentification-pour-le-cloud)
2. [Option 1 (Recommandée) : Déploiement sur Render (Web Service ou Worker)](#option-1-recommandée--déploiement-sur-render)
3. [Option 2 : Déploiement sur Railway](#option-2--déploiement-sur-railway)
4. [Option 3 (100% Gratuit & Sans Serveur) : GitHub Actions Cron](#option-3-100-gratuit--sans-serveur--github-actions-cron)
5. [Option 4 : Déploiement sur un VPS ou Serveur Linux (Docker / systemd)](#option-4--déploiement-sur-un-vps-ou-serveur-linux)

---

## Étape 0 : Générer le token d'authentification pour le Cloud

Dans le Cloud, l'agent ne peut pas ouvrir de navigateur pour vous demander d'autoriser Google. Vous devez donc générer le token une première fois en local.

1. Ouvrez votre terminal dans le dossier du projet :

   ```bash
   .venv\Scripts\python.exe auth_setup.py
   # ou sur Mac/Linux : python3 auth_setup.py
   ```

2. Votre navigateur s'ouvre : connectez-vous avec votre compte Gmail et accordez les autorisations.
3. Le script valide la connexion et affiche directement vos variables prêtes à copier :
   - `GMAIL_TOKEN_JSON` (votre token OAuth2)
   - `GMAIL_CREDENTIALS_JSON` (vos identifiants client)

---

## Option 1 (Recommandée) : Déploiement sur Render

Render est l'une des plateformes cloud les plus fiables et simples d'utilisation.

### Déploiement en 5 minutes

1. Créez un compte gratuit sur [render.com](https://render.com).
2. Poussez votre code sur un dépôt **GitHub** (privé de préférence).
3. Sur Render, cliquez sur **New +** > **Web Service** (ou **Background Worker**).
4. Connectez votre dépôt GitHub `auto-gmail`.
5. Configurez les paramètres :
   - **Environment** : `Python` (ou `Docker`)
   - **Build Command** : `pip install -r requirements.txt`
   - **Start Command** : `python agent.py --auto-draft`
6. Dans la section **Environment Variables**, ajoutez :

   | Clé | Valeur |
   | --- | --- |
   | `GEMINI_API_KEY` | Votre clé API Google AI Studio |
   | `USER_NAME` | `Robin` |
   | `CHECK_INTERVAL_SECONDS` | `180` |
   | `AUTO_DRAFT` | `true` |
   | `PORT` | `8080` |
   | `GMAIL_TOKEN_JSON` | Le contenu JSON obtenu à l'Étape 0 |
   | `GMAIL_CREDENTIALS_JSON` | Le contenu JSON de votre `credentials.json` |

7. Cliquez sur **Create Web Service**.

✅ Votre agent tourne désormais 24h/24 ! Render effectue un check de santé automatique sur `http://votre-app.onrender.com/health` pour s'assurer qu'il ne s'arrête jamais.

---

## Option 2 : Déploiement sur Railway

[Railway.app](https://railway.app) permet de déployer en 1 clic à partir de votre dépôt GitHub.

1. Connectez-vous sur [Railway](https://railway.app).
2. Cliquez sur **New Project** > **Deploy from GitHub repo**.
3. Sélectionnez votre dépôt `auto-gmail`.
4. Allez dans l'onglet **Variables** et ajoutez :
   - `GEMINI_API_KEY`
   - `GMAIL_TOKEN_JSON`
   - `GMAIL_CREDENTIALS_JSON`
   - `AUTO_DRAFT=true`
   - `USER_NAME=Robin`
5. Railway détecte automatiquement le `Dockerfile` ou le `Procfile` et démarre l'agent en continu.

---

## Option 3 (100% Gratuit & Sans Serveur) : GitHub Actions Cron

Si vous ne souhaitez pas héberger de serveur permanent, GitHub Actions peut exécuter le scan Gmail automatiquement **toutes les 10 minutes** gratuitement !

1. Poussez votre projet sur un dépôt GitHub **Privé**.
2. Allez sur votre dépôt GitHub > **Settings** > **Secrets and variables** > **Actions**.
3. Cliquez sur **New repository secret** et ajoutez :
   - `GEMINI_API_KEY` : Votre clé Gemini.
   - `GMAIL_TOKEN_JSON` : La valeur générée par `auth_setup.py`.
   - `GMAIL_CREDENTIALS_JSON` : La valeur de votre `credentials.json`.
   - `USER_NAME` : `Robin`.
4. Le fichier `.github/workflows/gmail-agent-cron.yml` déjà inclus dans le projet s'exécutera automatiquement toutes les 10 minutes !
5. Pour tester immédiatement : allez dans l'onglet **Actions** sur GitHub > **Gmail Agent Auto-Scan (Cron)** > **Run workflow**.

---

## Option 4 : Déploiement sur un VPS ou Serveur Linux

Si vous disposez d'un VPS (OVH, Hetzner, DigitalOcean, AWS EC2, etc.) :

### Méthode Docker Compose

1. Copiez les fichiers du projet sur votre serveur.
2. Créez votre fichier `.env` avec les clés.
3. Lancez le conteneur en arrière-plan :

   ```bash
   docker compose up -d --build
   ```

4. Pour voir les logs en temps réel :

   ```bash
   docker compose logs -f
   ```

### Méthode Service Linux (systemd)

Créez un service `/etc/systemd/system/gmail-agent.service` :

```ini
[Unit]
Description=Agent Gmail Intelligent 24/7
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/auto-gmail
ExecStart=/home/ubuntu/auto-gmail/.venv/bin/python agent.py --auto-draft
Restart=always
RestartSec=10
EnvironmentFile=/home/ubuntu/auto-gmail/.env

[Install]
WantedBy=multi-user.target
```

Activez et démarrez le service :

```bash
sudo systemctl daemon-reload
sudo systemctl enable gmail-agent
sudo systemctl start gmail-agent
sudo systemctl status gmail-agent
```

---

## 🔒 Sécurité & Bonnes Pratiques

- **Ne commitez jamais** vos fichiers `token.json`, `credentials.json` ou `.env` dans un dépôt GitHub public.
- Si le token OAuth2 expire ou est révoqué, réexécutez simplement `python auth_setup.py` sur votre ordinateur et mettez à jour la variable `GMAIL_TOKEN_JSON` sur votre hébergeur.
- Le mode `--auto-draft` pré-rédige les réponses directement dans votre boîte Gmail sans jamais envoyer d'e-mail sans votre validation humaine finale.
