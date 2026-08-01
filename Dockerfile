# EXENOM — Multi-stage Dockerfile
# Builds the Next.js web app + scan engine in a single image

# ─── Stage 1: Build ─────────────────────────────────────────────────────────
FROM oven/bun:1 AS builder

WORKDIR /app

# Copy package files
COPY package.json bun.lock ./

# Install dependencies
RUN bun install --frozen-lockfile

# Copy source code
COPY . .

# Build Next.js
RUN bun run build

# ─── Stage 2: Production ────────────────────────────────────────────────────
FROM oven/bun:1-slim

WORKDIR /app

# Copy built app + dependencies
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/next.config.ts ./next.config.ts
COPY --from=builder /app/tsconfig.json ./tsconfig.json
COPY --from=builder /app/src ./src
COPY --from=builder /app/cli ./cli
COPY --from=builder /app/mini-services ./mini-services
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/db ./db

# Expose ports
# 3000 = Next.js web app
# 3004 = EASM scan engine (WebSocket)
EXPOSE 3000 3004

# Environment
ENV NODE_ENV=production
ENV PORT=3000

# Start script: runs both the web app and scan engine
# Use a process manager or just run both in background
CMD ["sh", "-c", "bun run easm-service & sleep 2 && bun run start"]
