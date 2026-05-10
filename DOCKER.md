# Docker Guide — Cryptography Tool

Everything you need to build, run, and publish this app with Docker.

---

## Prerequisites

- **Docker Desktop** installed and running
  - Download: https://www.docker.com/products/docker-desktop/
  - After install, open Docker Desktop and wait for the whale icon to show "Engine running"
- You do **not** need Python installed — Docker handles everything

---

## Quick Start (two commands)

```bash
# 1. Build the image
docker build -t cryptography-tool .

# 2. Run it
docker run -p 8000:8000 cryptography-tool
```

Then open your browser at **http://localhost:8000**

Press `Ctrl+C` in the terminal to stop.

---

## Option A — docker run (manual)

```bash
# Build
docker build -t cryptography-tool .

# Run in foreground (see logs)
docker run -p 8000:8000 cryptography-tool

# Run in background (detached)
docker run -d -p 8000:8000 --name cryptography-tool cryptography-tool

# Stop the background container
docker stop cryptography-tool

# Remove the stopped container
docker rm cryptography-tool
```

---

## Option B — docker compose (recommended for repeated use)

```bash
# Build and start
docker compose up --build

# Start in background
docker compose up -d --build

# Stop
docker compose down

# View logs
docker compose logs -f
```

---

## Publishing to Docker Hub

### One-time setup

1. Create a free account at https://hub.docker.com
2. Log in from your terminal:

```bash
docker login
```

### Push your image

Replace `your-username` with your Docker Hub username.

```bash
# Tag the image with your Docker Hub username
docker tag cryptography-tool your-username/cryptography-tool:latest

# Push
docker push your-username/cryptography-tool:latest
```

### Pull and run from Docker Hub (on any machine)

```bash
docker run -p 8000:8000 your-username/cryptography-tool:latest
```

Then open **http://localhost:8000** — no Python, no pip, no setup needed.

---

## Useful commands

| Command | What it does |
| ------- | ------------ |
| `docker images` | List all images on your machine |
| `docker ps` | List running containers |
| `docker ps -a` | List all containers (including stopped) |
| `docker logs cryptography-tool` | View container output |
| `docker rm cryptography-tool` | Remove a stopped container |
| `docker rmi cryptography-tool` | Remove the image |
| `docker system prune` | Clean up unused images/containers |

---

## Troubleshooting

**Port already in use**
```bash
# Use a different host port (e.g. 8080)
docker run -p 8080:8000 cryptography-tool
# Then open http://localhost:8080
```

**Container exits immediately**
```bash
docker logs cryptography-tool
```
Check the output — usually a missing dependency or import error.

**Changes not reflected after rebuild**
```bash
docker compose up --build  
```

**Windows: "Docker daemon not running"**
Open Docker Desktop and wait for the engine to fully start before running commands.

---

## Port reference

| Port | Purpose |
| ---- | ------- |
| `8000` | Web app (FastAPI + Tailwind SPA) |
| `/api/...` | REST API endpoints |
| `/docs` | Auto-generated FastAPI docs |
