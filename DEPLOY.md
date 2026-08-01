# EXENOM Deployment Guide

This guide covers all the ways to deploy EXENOM so it's available for users.

---

## Option 1: Vercel (Free, Recommended)

Vercel is the easiest way to deploy Next.js apps. The free tier is sufficient for personal use.

### Steps:

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "EXENOM — External Attack Surface Management"
   git branch -M main
   git remote add origin https://github.com/yourusername/exenom.git
   git push -u origin main
   ```

2. **Deploy on Vercel**
   - Go to [vercel.com](https://vercel.com) and sign in with GitHub
   - Click "New Project" → Import your `exenom` repo
   - Vercel auto-detects Next.js — just click "Deploy"
   - Your app is live at `https://exenom.vercel.app`

3. **Set API keys (optional)**
   - In Vercel dashboard → Settings → Environment Variables
   - Add: `EASM_SHODAN_KEYS`, `EASM_VIRUSTOTAL_KEYS`, etc.

> **Note:** The scan engine (WebSocket service on port 3004) needs to run separately. On Vercel's free tier, you can use Vercel Functions or deploy the scan engine to a free service like Railway/Render.

---

## Option 2: Docker (Self-Host)

### Using Docker Compose (easiest)

```bash
# Clone the repo
git clone https://github.com/yourusername/exenom.git
cd exenom

# Start everything with one command
docker-compose up -d

# The app is now running at http://localhost:3000
```

### Using Docker directly

```bash
# Build the image
docker build -t exenom .

# Run the web app (port 3000)
docker run -d -p 3000:3000 --name exenom-web exenom

# Run the scan engine (port 3004) in another container
docker run -d -p 3004:3004 --name exenom-engine exenom bun run easm-service
```

### Environment variables in Docker

```bash
docker run -d -p 3000:3000 \
  -e EASM_SHODAN_KEYS="key1,key2" \
  -e EASM_VIRUSTOTAL_KEYS="key1" \
  --name exenom exenom
```

---

## Option 3: VPS / Self-Host (with Bun)

### Prerequisites
- A VPS (DigitalOcean, Linode, AWS EC2, etc.)
- Node.js 18+ or Bun installed

### Steps:

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/exenom.git
cd exenom

# 2. Install dependencies
bun install

# 3. Build for production
bun run build

# 4. Start the scan engine (port 3004) — use a process manager like pm2
bun run easm-service &

# 5. Start the web app (port 3000)
bun run start

# 6. Set up a reverse proxy (nginx/caddy) to expose ports 80/443
```

### Using PM2 (process manager)

```bash
npm install -g pm2

# Start both services
pm2 start "bun run easm-service" --name exenom-engine
pm2 start "bun run start" --name exenom-web

# Save & auto-restart on reboot
pm2 save
pm2 startup
```

---

## Option 4: Standalone Python CLI (No Server Needed)

The Python CLI requires **no server, no dependencies, no installation**. Just download and run:

```bash
# Download the single file
curl -O https://raw.githubusercontent.com/yourusername/exenom/main/download/easm.py

# Run it
python3 easm.py scan example.com
```

This is perfect for:
- Quick scans from any machine
- CI/CD pipelines
- Sharing with others who just want to scan

---

## Option 5: GitHub Releases

To distribute pre-built versions:

1. Tag a release:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. GitHub automatically creates a release page
3. Attach the standalone `easm.py` as a release asset
4. Users download it directly

---

## Port Reference

| Service | Port | Purpose |
|---------|------|---------|
| Next.js web app | 3000 | Web terminal UI |
| EASM scan engine | 3004 | WebSocket scan service |

---

## Troubleshooting

### "Port 3004 in use"
```bash
# Find and kill the process
fuser -k 3004/tcp
# or
lsof -i :3004 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

### WebSocket not connecting (web terminal shows "offline")
- The web terminal connects via the Caddy gateway on port 81
- Make sure both the Next.js app (3000) and scan engine (3004) are running
- If accessing directly (not through Caddy), use `http://localhost:81`

### API keys not working
- Check that environment variables are set correctly
- VirusTotal free tier has rate limits (4 requests/minute)
- Shodan DNS endpoint requires membership
