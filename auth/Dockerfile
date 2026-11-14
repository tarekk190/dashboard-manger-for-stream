# Multi-stage production Node.js Dockerfile
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY package.json ./
RUN npm install --omit=dev

FROM node:20-alpine

WORKDIR /usr/src/app

# Security: Run as unprivileged node user
USER node

COPY --chown=node:node --from=builder /usr/src/app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node server.js ./

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/health || exit 1

CMD ["node", "server.js"]
