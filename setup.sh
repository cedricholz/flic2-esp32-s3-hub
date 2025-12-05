#!/bin/bash

set -e

echo "=== Flic2 ESP32-S3 Hub Setup ==="

echo "Installing Docker..."
if command -v docker &> /dev/null; then
    echo "Docker already installed"
else
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
fi

echo "Building Docker image..."
sudo docker build -t flic2-hub .

echo "Creating systemd service..."
sudo tee /etc/systemd/system/flic2-hub.service > /dev/null << EOF
[Unit]
Description=Flic2 ESP32-S3 Hub
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/docker stop flic2-hub
ExecStartPre=-/usr/bin/docker rm flic2-hub
ExecStart=/usr/bin/docker run --rm --name flic2-hub \\
  --network host \\
  --privileged \\
  -v /dev:/dev \\
  -v \$HOME/flic2-hub/firmware:/app/firmware \\
  flic2-hub
ExecStop=/usr/bin/docker stop flic2-hub

[Install]
WantedBy=multi-user.target
EOF


echo "Enabling service..."
sudo systemctl daemon-reload
sudo systemctl enable flic2-hub.service

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Commands:"
echo "  Start:   sudo systemctl start flic2-hub"
echo "  Stop:    sudo systemctl stop flic2-hub"
echo "  Status:  sudo systemctl status flic2-hub"
echo "  Logs:    sudo journalctl -fu flic2-hub"
echo ""
echo ""
echo "The hub will be available at http://localhost:5000"