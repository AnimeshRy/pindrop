# Deliberately insecure fixture for `pindrop scan`. Do not copy this.
#
# Expected Trivy misconfiguration findings:
#   AVD-DS-0002 no USER instruction, so the container runs as root
#   AVD-DS-0026 no HEALTHCHECK
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
