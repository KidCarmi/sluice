#!/usr/bin/env bash
# install.sh — One-command Sluice CDR setup for a fresh Linux server.
#
# Usage (fresh server):
#   curl -fsSL https://raw.githubusercontent.com/KidCarmi/sluice/main/scripts/install.sh | bash
#
# Or if you already cloned:
#   bash scripts/install.sh
#
# What this script does:
#   1. Detects your Linux distro (Ubuntu, Debian, RHEL, CentOS, Fedora, Amazon Linux, Arch)
#   2. Installs Docker Engine + Compose v2 if not present
#   3. Adds the current user to the docker group
#   4. Clones Sluice (if not already in the repo)
#   5. Starts all services with docker compose up -d --build
#
# Supported distros:
#   Ubuntu 20.04+, Debian 11+, RHEL/CentOS/Rocky/Alma 8+, Fedora 38+,
#   Amazon Linux 2023+, Arch Linux
#
# Requirements: sudo access, internet connection

set -euo pipefail

###############################################################################
# Helpers
###############################################################################
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }
step()  { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

wait_for_apt_lock() {
  local waited=0
  local max=300
  while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || sudo fuser /var/lib/dpkg/lock          >/dev/null 2>&1 \
     || sudo fuser /var/lib/apt/lists/lock     >/dev/null 2>&1; do
    if (( waited == 0 )); then
      warn "Another apt/dpkg process is running (likely unattended-upgrades). Waiting..."
    fi
    sleep 3
    waited=$((waited + 3))
    if (( waited >= max )); then
      warn "Still waiting for apt lock after ${max}s. Trying anyway."
      break
    fi
  done
}

apt_install_with_repair() {
  local log
  log=$(mktemp 2>/dev/null || echo "/tmp/sluice-apt-$$.log")
  wait_for_apt_lock
  if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >"$log" 2>&1; then
    rm -f "$log"
    return 0
  fi
  warn "apt-get install failed. Last 30 lines:"
  tail -n 30 "$log" >&2 || true
  rm -f "$log"
  warn "Repairing dpkg state..."
  wait_for_apt_lock
  sudo dpkg --configure -a 2>&1 | tail -n 20 >&2 || true
  wait_for_apt_lock
  sudo apt-get install -f -y 2>&1 | tail -n 20 >&2 || true
  info "Retrying: $*"
  wait_for_apt_lock
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

dump_docker_diagnostics() {
  echo "" >&2
  warn "── docker.service status ──"
  sudo systemctl status docker.service --no-pager -l 2>&1 | sed 's/^/    /' >&2 || true
  echo "" >&2
  warn "── docker.service journal (last 30 lines) ──"
  sudo journalctl -xeu docker.service --no-pager -n 30 2>&1 | sed 's/^/    /' >&2 || true
  echo "" >&2
}

REPO_URL="https://github.com/KidCarmi/sluice.git"
INSTALL_DIR="${SLUICE_DIR:-$HOME/sluice}"

###############################################################################
# Detect distro family
###############################################################################
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID}"
    DISTRO_VERSION="${VERSION_ID:-}"
    DISTRO_CODENAME="${VERSION_CODENAME:-}"
    DISTRO_LIKE="${ID_LIKE:-}"
  else
    error "Cannot detect distro — /etc/os-release not found."
  fi

  case "$DISTRO_ID" in
    ubuntu|debian|linuxmint|pop)
      DISTRO_FAMILY="debian"
      if [[ "$DISTRO_ID" == "linuxmint" || "$DISTRO_ID" == "pop" ]]; then
        DISTRO_ID="ubuntu"
        DISTRO_CODENAME="${UBUNTU_CODENAME:-$DISTRO_CODENAME}"
      fi
      ;;
    rhel|centos|rocky|almalinux|ol)
      DISTRO_FAMILY="rhel"
      if [[ "$DISTRO_ID" != "rhel" ]]; then DISTRO_ID="centos"; fi
      ;;
    fedora)         DISTRO_FAMILY="fedora" ;;
    amzn)           DISTRO_FAMILY="amzn" ;;
    arch|manjaro|endeavouros) DISTRO_FAMILY="arch" ;;
    *)
      if [[ "$DISTRO_LIKE" == *"debian"* || "$DISTRO_LIKE" == *"ubuntu"* ]]; then
        DISTRO_FAMILY="debian"; DISTRO_ID="ubuntu"
      elif [[ "$DISTRO_LIKE" == *"rhel"* || "$DISTRO_LIKE" == *"centos"* || "$DISTRO_LIKE" == *"fedora"* ]]; then
        DISTRO_FAMILY="rhel"; DISTRO_ID="centos"
      else
        error "Unsupported distro: $DISTRO_ID. Supported: Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora, Amazon Linux, Arch."
      fi
      ;;
  esac
  info "Detected: $DISTRO_ID ($DISTRO_FAMILY family)"
}

###############################################################################
# Pre-flight checks
###############################################################################
step "Pre-flight checks"

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║     Sluice CDR Engine Installer       ║"
echo "  ║     Content Disarm & Reconstruction   ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

[[ "$(uname -s)" == "Linux" ]] || error "This script is for Linux only."

if ! sudo -n true 2>/dev/null; then
  warn "sudo access required. You may be prompted for your password."
fi

if curl -fsSL --connect-timeout 5 https://download.docker.com > /dev/null 2>&1 || \
   wget -q --timeout=5 -O /dev/null https://download.docker.com 2>/dev/null; then
  info "Internet connectivity OK"
else
  error "No internet connection. Cannot reach download.docker.com"
fi

if command -v free &>/dev/null; then
  TOTAL_MEM_MB=$(free -m | awk '/^Mem:/{print $2}')
  if [[ -n "$TOTAL_MEM_MB" && "$TOTAL_MEM_MB" -lt 512 ]]; then
    warn "Detected ${TOTAL_MEM_MB} MB RAM. Sluice wants ~512 MB to run comfortably."
  fi
fi

if command -v df &>/dev/null; then
  DISK_AVAIL_MB=$(df -m /var 2>/dev/null | awk 'NR==2 {print $4}')
  if [[ -n "$DISK_AVAIL_MB" && "$DISK_AVAIL_MB" =~ ^[0-9]+$ && "$DISK_AVAIL_MB" -lt 2000 ]]; then
    warn "Only ${DISK_AVAIL_MB} MB free in /var. Docker + Sluice image need ~2 GB."
  fi
fi

if [[ -n "${HTTPS_PROXY:-}${https_proxy:-}${HTTP_PROXY:-}${http_proxy:-}" ]]; then
  warn "HTTP/HTTPS proxy detected. Docker daemon may need separate proxy config."
  warn "See: https://docs.docker.com/engine/daemon/proxy/"
fi

detect_distro

###############################################################################
# 1. Install Docker Engine (if needed)
###############################################################################
step "Checking Docker"

if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
  info "Docker with Compose v2 already installed: $(docker --version)"
else
  step "Installing Docker Engine"
  case "$DISTRO_FAMILY" in
    debian)
      info "Installing from Docker's official apt repository..."
      sudo apt-get update -qq
      apt_install_with_repair ca-certificates curl gnupg
      sudo install -m 0755 -d /etc/apt/keyrings
      if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
        curl -fsSL "https://download.docker.com/linux/${DISTRO_ID}/gpg" | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
      fi
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO_ID} ${DISTRO_CODENAME} stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
      sudo apt-get update -qq
      apt_install_with_repair docker-ce docker-ce-cli containerd.io docker-compose-plugin
      ;;
    rhel)
      info "Installing from Docker's official yum/dnf repository..."
      sudo dnf install -y yum-utils 2>/dev/null || sudo yum install -y yum-utils 2>/dev/null
      sudo yum-config-manager --add-repo "https://download.docker.com/linux/${DISTRO_ID}/docker-ce.repo"
      sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin 2>/dev/null || \
        sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      ;;
    fedora)
      info "Installing from Docker's official dnf repository..."
      sudo dnf install -y dnf-plugins-core
      sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
      sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      ;;
    amzn)
      info "Installing Docker on Amazon Linux..."
      sudo yum install -y docker
      COMPOSE_VERSION=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
      sudo mkdir -p /usr/local/lib/docker/cli-plugins
      sudo curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" \
        -o /usr/local/lib/docker/cli-plugins/docker-compose
      sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
      ;;
    arch)
      info "Installing Docker via pacman..."
      sudo pacman -Sy --noconfirm docker docker-compose
      ;;
    *)
      error "Unsupported distro family: $DISTRO_FAMILY"
      ;;
  esac
  info "Docker installed: $(docker --version)"
fi

###############################################################################
# 2. Start Docker and add user to group
###############################################################################
step "Configuring Docker"

sudo systemctl daemon-reload >/dev/null 2>&1 || true
sudo systemctl enable containerd >/dev/null 2>&1 || true
sudo systemctl start containerd 2>/dev/null || true
sudo systemctl enable docker >/dev/null 2>&1 || true

if ! sudo systemctl start docker 2>/dev/null; then
  warn "Docker failed to start. Attempting recovery..."
  sudo systemctl daemon-reload || true
  sudo systemctl restart containerd 2>/dev/null || true
  sleep 2
  if ! sudo systemctl start docker 2>/dev/null; then
    dump_docker_diagnostics
    error "Docker daemon could not be started. See diagnostics above."
  fi
fi

CURRENT_USER="$(id -un)"
if [[ "$CURRENT_USER" != "root" ]]; then
  if ! groups "$CURRENT_USER" | grep -qw docker; then
    info "Adding '$CURRENT_USER' to the docker group..."
    sudo usermod -aG docker "$CURRENT_USER"
    warn "Group change takes effect after re-login. Using sudo for now."
  fi
fi

if sudo docker info &>/dev/null; then
  info "Docker engine is running"
else
  dump_docker_diagnostics
  error "Docker engine started but is not responding."
fi

###############################################################################
# 3. Install git if missing
###############################################################################
if ! command -v git &>/dev/null; then
  step "Installing git"
  case "$DISTRO_FAMILY" in
    debian) apt_install_with_repair git ;;
    rhel|fedora) sudo dnf install -y git 2>/dev/null || sudo yum install -y git ;;
    amzn) sudo yum install -y git ;;
    arch) sudo pacman -Sy --noconfirm git ;;
  esac
  info "git installed"
fi

###############################################################################
# 4. Clone Sluice (if not already in the repo)
###############################################################################
step "Setting up Sluice"

if [[ -f "./deploy/docker-compose.yml" ]] && grep -q "sluice" ./deploy/docker-compose.yml 2>/dev/null; then
  info "Already inside Sluice repo: $(pwd)"
  INSTALL_DIR="$(pwd)"
elif [[ -d "$INSTALL_DIR" ]] && [[ -f "$INSTALL_DIR/deploy/docker-compose.yml" ]]; then
  info "Sluice repo already exists at $INSTALL_DIR"
else
  info "Cloning Sluice..."
  git clone "$REPO_URL" "$INSTALL_DIR"
  info "Cloned to $INSTALL_DIR"
fi

cd "$INSTALL_DIR"

###############################################################################
# 5. Build and start
###############################################################################
step "Starting Sluice"

info "Building image and starting services (first run may take 1-2 minutes)..."

COMPOSE_FILE="deploy/docker-compose.yml"

if sudo docker compose -f "$COMPOSE_FILE" up -d --build --wait --wait-timeout 120 2>/dev/null; then
  : # success
elif sudo docker compose -f "$COMPOSE_FILE" up -d --build; then
  info "Waiting for Sluice to become healthy..."
  for i in $(seq 1 30); do
    if sudo docker compose -f "$COMPOSE_FILE" ps --format '{{.Health}}' 2>/dev/null | grep -qw healthy; then
      break
    fi
    if sudo docker compose -f "$COMPOSE_FILE" ps -a --format '{{.State}}' 2>/dev/null | grep -qw exited; then
      warn "Container exited unexpectedly."
      sudo docker compose -f "$COMPOSE_FILE" logs --tail=50 --no-color >&2 || true
      error "Sluice failed to start. See logs above."
    fi
    sleep 2
  done
else
  sudo docker compose -f "$COMPOSE_FILE" logs --tail=50 --no-color >&2 || true
  error "Sluice failed to start. See logs above."
fi

LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Sluice CDR Engine is running!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  Web GUI:  http://${LOCAL_IP}:8080"
echo "  gRPC:     ${LOCAL_IP}:8443"
echo "  Metrics:  http://${LOCAL_IP}:9090/metrics"
echo ""
echo "  Open the Web GUI and drop a file to sanitize it."
echo ""
echo "  Useful commands:"
echo "    cd $INSTALL_DIR"
echo "    docker compose -f deploy/docker-compose.yml logs -f"
echo "    docker compose -f deploy/docker-compose.yml ps"
echo "    docker compose -f deploy/docker-compose.yml down"
echo "    docker compose -f deploy/docker-compose.yml up -d --build  # rebuild"
echo ""
echo "  To integrate with Culvert, add Sluice as a CDR endpoint"
echo "  in Culvert's admin GUI: Integrations > Add CDR > ${LOCAL_IP}:8443"
echo ""
if [[ "$CURRENT_USER" != "root" ]] && ! groups "$CURRENT_USER" | grep -qw docker; then
  echo -e "${YELLOW}  NOTE: Log out and back in to use 'docker' without sudo.${NC}"
  echo ""
fi
