#!/bin/bash
set -e

PROJECT_DIR="/opt/anisakys"
VENV_DIR="$PROJECT_DIR/venv"

echo "Creating project directory at $PROJECT_DIR..."
sudo mkdir -p "$PROJECT_DIR"
sudo cp -r . "$PROJECT_DIR/"

echo "Creating Python virtual environment..."
sudo apt-get update && sudo apt-get install -y python3-venv
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "Installing dependencies..."
pip install -r "$PROJECT_DIR/requirements.txt"

echo "Setting up systemd service..."
sudo cp "$PROJECT_DIR/bin/anisakys.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable anisakys.service
sudo systemctl start anisakys.service

echo "Installation complete."
