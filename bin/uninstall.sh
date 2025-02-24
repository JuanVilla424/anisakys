#!/bin/bash
set -e

echo "Stopping anisakys service..."
sudo systemctl stop anisakys.service
sudo systemctl disable anisakys.service
sudo rm /etc/systemd/system/anisakys.service
sudo systemctl daemon-reload

echo "Removing project files..."
sudo rm -rf /opt/anisakys

echo "Uninstallation complete."
