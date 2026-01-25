#!/bin/bash
set -e

PROJECT_DIR="/opt/anisakys"
VENV_DIR="$PROJECT_DIR/venv"
SERVICE_USER="anisakys"

echo "=== Anisakys Installation ==="

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating user $SERVICE_USER..."
    sudo useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
else
    echo "User $SERVICE_USER already exists"
fi

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

# Install systemd services
echo "Installing systemd services..."
sudo cp "$PROJECT_DIR/bin/anisakys-threads.service" /etc/systemd/system/
sudo cp "$PROJECT_DIR/bin/anisakys-api.service" /etc/systemd/system/
sudo cp "$PROJECT_DIR/bin/anisakys-scanner.service" /etc/systemd/system/
sudo systemctl daemon-reload

# Enable services (scanner is manual)
sudo systemctl enable anisakys-threads.service
sudo systemctl enable anisakys-api.service

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Configure /opt/anisakys/.env"
echo "  2. Start services:"
echo "     sudo systemctl start anisakys-threads"
echo "     sudo systemctl start anisakys-api"
echo "     sudo systemctl start anisakys-scanner"
echo ""
echo "Check status:"
echo "  sudo systemctl status anisakys-threads"
echo "  sudo journalctl -u anisakys-threads -f"
