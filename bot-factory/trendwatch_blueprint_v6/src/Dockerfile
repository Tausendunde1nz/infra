FROM node:18-alpine

# Arbeitsverzeichnis im Container
WORKDIR /usr/src/app

# Nur package.json kopieren (sauberes Caching)
COPY package*.json ./

# Dependencies installieren (Production)
RUN npm install --only=production

# Restlichen Code kopieren
COPY src ./src

# App-Port
EXPOSE 3000

# Startkommando
CMD ["node", "src/index.js"]
