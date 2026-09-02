# Image Python 3.11 légère et sécurisée
FROM python:3.11-slim

# Configuration de l'environnement Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Europe/Paris \
    PORT=8080 \
    AUTO_DRAFT=true

# Installation des certificats et fuseau horaire
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Répertoire de travail
WORKDIR /app

# Installation des dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code de l'application
COPY agent.py .
COPY *.pdf . 2>/dev/null || true

# Port exposé pour le serveur de santé HTTP (utilisé par Render, Railway, Cloud Run...)
EXPOSE 8080

# Commande de démarrage (Mode automatique 24h/24)
CMD ["python", "agent.py", "--auto-draft"]
