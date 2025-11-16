FROM node:18-alpine

# Arbeitsverzeichnis wie im Container: /usr/src/app
WORKDIR /usr/src/app

# Nur die Package-Dateien zuerst, damit Docker-Caching sauber funktioniert
COPY package*.json ./

# Dependencies für den Bot installieren (Production reicht)
RUN npm install --only=production

# Restlichen Code kopieren
COPY src ./src

# Bot hört (intern) auf Port 3000
EXPOSE 3000

# Startkommando
CMD ["node", "src/index.js"]
