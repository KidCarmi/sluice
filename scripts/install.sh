#!/usr/bin/env bash
# Sluice CDR Engine — One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/KidCarmi/sluice/main/scripts/install.sh | bash
set -euo pipefail

INSTALL_DIR="/opt/sluice"
COMPOSE_URL="https://raw.githubusercontent.com/KidCarmi/sluice/main/scripts/docker-compose.yml"
CONFIG_URL="https://raw.githubusercontent.com/KidCarmi/sluice/main/config.example.yaml"
IMAGE="ghcr.io/kidcarmi/sluice:latest"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[sluice]${NC} $1"; }
ok()    { echo -e "${GREEN}[sluice]${NC} $1"; }
warn()  { echo -e "${YELLOW}[sluice]${NC} $1"; }
fail()  { echo -e "${RED}[sluice]${NC} $1"; exit 1; }

echo ""
echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║     Sluice CDR Engine Installer       ║"
echo "  ║     Content Disarm & Reconstruction   ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

# --- Preflight checks ---
info "Checking prerequisites..."

command -v docker >/dev/null 2>&1 || fail "Docker is not installed. Install it first: https://docs.docker.com/get-docker/"

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    fail "Docker Compose is not installed. Install it first: https://docs.docker.com/compose/install/"
fi

ok "Docker and Docker Compose found."

# --- Create install directory ---
info "Installing to ${INSTALL_DIR}..."
sudo mkdir -p "${INSTALL_DIR}"
sudo chown "$(id -u):$(id -g)" "${INSTALL_DIR}"

# --- Download compose file ---
info "Downloading compose file..."
curl -fsSL "${COMPOSE_URL}" -o "${INSTALL_DIR}/docker-compose.yml"

# --- Download default config ---
if [ ! -f "${INSTALL_DIR}/config.yaml" ]; then
    info "Creating default config..."
    curl -fsSL "${CONFIG_URL}" -o "${INSTALL_DIR}/config.yaml"
else
    warn "Config already exists, keeping current config.yaml"
fi

# --- Pull image ---
info "Pulling ${IMAGE}..."
docker pull "${IMAGE}" || warn "Could not pull image (will build on first run if needed)"

# --- Start ---
info "Starting Sluice..."
cd "${INSTALL_DIR}"
${COMPOSE} up -d

# --- Get IP ---
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo -e "${GREEN}  ╔═══════════════════════════════════════╗"
echo -e "  ║         Sluice is running!             ║"
echo -e "  ╚═══════════════════════════════════════╝${NC}"
echo ""
ok "Web GUI:    http://${LOCAL_IP}:8080"
ok "gRPC:       ${LOCAL_IP}:8443"
ok "Metrics:    http://${LOCAL_IP}:9090/metrics"
echo ""
info "Installed to: ${INSTALL_DIR}"
info "Config:       ${INSTALL_DIR}/config.yaml"
info "Logs:         ${COMPOSE} -f ${INSTALL_DIR}/docker-compose.yml logs -f"
info "Stop:         ${COMPOSE} -f ${INSTALL_DIR}/docker-compose.yml down"
info "Update:       docker pull ${IMAGE} && ${COMPOSE} -f ${INSTALL_DIR}/docker-compose.yml up -d"
echo ""
