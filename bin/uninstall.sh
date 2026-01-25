#!/bin/bash
set -e

SERVICE_USER="anisakys"

echo "=== Anisakys Uninstallation ==="

# Stop and disable services
echo "Stopping services..."
sudo systemctl stop anisakys-threads.service 2>/dev/null || true
sudo systemctl stop anisakys-api.service 2>/dev/null || true
sudo systemctl stop anisakys-scanner.service 2>/dev/null || true

sudo systemctl disable anisakys-threads.service 2>/dev/null || true
sudo systemctl disable anisakys-api.service 2>/dev/null || true
sudo systemctl disable anisakys-scanner.service 2>/dev/null || true

# Remove service files
echo "Removing service files..."
sudo rm -f /etc/systemd/system/anisakys-threads.service
sudo rm -f /etc/systemd/system/anisakys-api.service
sudo rm -f /etc/systemd/system/anisakys-scanner.service
sudo systemctl daemon-reload

# Remove project files
echo "Removing project files..."
sudo rm -rf /opt/anisakys

# Remove user
if id "$SERVICE_USER" &>/dev/null; then
    echo "Removing user $SERVICE_USER..."
    sudo userdel "$SERVICE_USER" 2>/dev/null || true
fi

echo ""
echo "=== Uninstallation complete ==="
