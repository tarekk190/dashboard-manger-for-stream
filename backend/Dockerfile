# ==============================================================================
# Unified Live Streaming Backend & FFmpeg Restreamer Dockerfile
# Based on Alpine Linux with Node.js 20 and FFmpeg
# ==============================================================================
FROM node:20-alpine

# Install FFmpeg, CA certificates, bash, and curl for healthchecks
RUN apk add --no-cache \
    ffmpeg \
    bash \
    curl \
    ca-certificates

WORKDIR /app

# Install production dependencies first (caching layer)
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Copy backend source code and public assets
COPY . .

# Ensure data directory exists for channel persistence
RUN mkdir -p /app/data /hls

# Expose default backend port
EXPOSE 3000

# Healthcheck probe
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:3000/api/health || exit 1

CMD ["node", "server.js"]
