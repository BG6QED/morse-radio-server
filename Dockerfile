FROM node:20-slim
RUN addgroup --system --gid 999 nodejs
RUN adduser --system --uid 999 --gid 999 morseuser
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
RUN chown -R morseuser:nodejs /app
USER morseuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1
CMD ["node", "index.js"]
