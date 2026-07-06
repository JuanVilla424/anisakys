#!/bin/bash
set -e

PROJECT_DIR="/opt/anisakys"
VENV_DIR="$PROJECT_DIR/venv"
SERVICE_USER="anisakys"
SHOT_SERVICE_USER="anisakys-shot"
PW_BROWSERS_DIR="$PROJECT_DIR/pw-browsers"

echo "=== Anisakys Installation ==="

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating user $SERVICE_USER..."
    sudo useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
else
    echo "User $SERVICE_USER already exists"
fi

# Create sandboxed screenshot-worker user -- deliberately separate from
# $SERVICE_USER and never granted access to $PROJECT_DIR/.env (see
# bin/anisakys-screenshot-worker.service).
if ! id "$SHOT_SERVICE_USER" &>/dev/null; then
    echo "Creating user $SHOT_SERVICE_USER..."
    sudo useradd --system --no-create-home --shell /bin/false "$SHOT_SERVICE_USER"
else
    echo "User $SHOT_SERVICE_USER already exists"
fi

# $SERVICE_USER needs to CONNECT to the worker's Unix socket (owned by
# $SHOT_SERVICE_USER, inside a 0750 RuntimeDirectory=) without making that
# socket world-accessible -- supplementary group membership, not a shared
# password/home/shell, is the only privilege $SERVICE_USER gains here.
echo "Adding $SERVICE_USER to the $SHOT_SERVICE_USER group (to reach the screenshot socket)..."
sudo usermod -aG "$SHOT_SERVICE_USER" "$SERVICE_USER"

# Create project directory
echo "Creating project directory at $PROJECT_DIR..."
sudo mkdir -p "$PROJECT_DIR"
sudo cp -r . "$PROJECT_DIR/"

# Create required directories
sudo mkdir -p "$PROJECT_DIR/logs"
sudo mkdir -p "$PROJECT_DIR/screenshots"
sudo mkdir -p "$PROJECT_DIR/data"

# Create virtual environment as root
echo "Creating Python virtual environment..."
sudo python3 -m venv "$VENV_DIR"

# Install dependencies
echo "Installing dependencies..."
sudo "$VENV_DIR/bin/pip" install --upgrade pip
sudo "$VENV_DIR/bin/pip" install -r "$PROJECT_DIR/requirements.txt"

# Set ownership after venv creation
echo "Setting ownership..."
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$PROJECT_DIR"

# Provision the sandboxed screenshot worker's own browser install -- it runs
# as $SHOT_SERVICE_USER (--no-create-home, no $HOME), so it can't rely on the
# usual ~/.cache/ms-playwright/ location; PLAYWRIGHT_BROWSERS_PATH points it
# at a dedicated directory it owns instead.
echo "Installing Playwright browser for the screenshot worker..."
sudo mkdir -p "$PW_BROWSERS_DIR"
sudo chown -R "$SHOT_SERVICE_USER:$SHOT_SERVICE_USER" "$PW_BROWSERS_DIR"
sudo -u "$SHOT_SERVICE_USER" env PLAYWRIGHT_BROWSERS_PATH="$PW_BROWSERS_DIR" \
    "$VENV_DIR/bin/playwright" install chromium

# Install systemd services
echo "Installing systemd services..."
sudo cp "$PROJECT_DIR/bin/anisakys-threads.service" /etc/systemd/system/
sudo cp "$PROJECT_DIR/bin/anisakys-api.service" /etc/systemd/system/
sudo cp "$PROJECT_DIR/bin/anisakys-scanner.service" /etc/systemd/system/
sudo cp "$PROJECT_DIR/bin/anisakys-screenshot-worker.service" /etc/systemd/system/

# The DNS resolver's own address commonly falls inside the private ranges
# IPAddressDeny= blocks (WSL, AWS VPC default resolvers, etc.) -- carve it
# out via a host-specific drop-in rather than hardcoding it in the tracked
# unit file. IPAddressAllow= always wins over IPAddressDeny= for a matching
# address (systemd.resource-control(5)), so this doesn't weaken the rest of
# the deny list.
RESOLVER_IPS=$(awk '/^nameserver/{print $2}' /etc/resolv.conf | tr '\n' ' ')
if [ -n "$RESOLVER_IPS" ]; then
    echo "Allow-listing DNS resolver(s) for the screenshot worker: $RESOLVER_IPS"
    sudo mkdir -p /etc/systemd/system/anisakys-screenshot-worker.service.d
    {
        echo "[Service]"
        for ip in $RESOLVER_IPS; do
            echo "IPAddressAllow=$ip/32"
        done
    } | sudo tee /etc/systemd/system/anisakys-screenshot-worker.service.d/resolver.conf >/dev/null
else
    echo "WARNING: could not determine DNS resolver from /etc/resolv.conf -- the" \
         "screenshot worker may be unable to resolve hostnames until an" \
         "IPAddressAllow= drop-in is added manually for its resolver."
fi

sudo systemctl daemon-reload

# Enable services (scanner is manual)
sudo systemctl enable anisakys-threads.service
sudo systemctl enable anisakys-api.service
sudo systemctl enable anisakys-screenshot-worker.service

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Configure /opt/anisakys/.env"
echo "  2. Start services:"
echo "     sudo systemctl start anisakys-threads"
echo "     sudo systemctl start anisakys-api"
echo "     sudo systemctl start anisakys-scanner"
echo "     sudo systemctl start anisakys-screenshot-worker"
echo "  3. To actually route screenshot capture through the sandboxed worker"
echo "     (recommended), set in /opt/anisakys/.env:"
echo "     SCREENSHOT_WORKER_SOCKET=/run/anisakys/screenshot-worker.sock"
echo "     Until set, anisakys-api/-threads capture screenshots in-process as before."
echo "  4. anisakys-api/-threads must be (re)started after step 3, or after this"
echo "     first install, to pick up the new supplementary group membership."
echo ""
echo "Check status:"
echo "  sudo systemctl status anisakys-threads"
echo "  sudo journalctl -u anisakys-threads -f"
echo "  sudo systemd-analyze security anisakys-screenshot-worker.service"
