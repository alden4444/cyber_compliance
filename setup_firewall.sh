#!/usr/bin/env bash
set -euo pipefail

# Require sudo
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run with sudo: sudo ./setup_firewall.sh"
    exit 1
fi

echo "Detecting package manager..."
if command -v pacman >/dev/null 2>&1; then
    echo "Configuring firewall for Arch Linux..."
    pacman -Sy --noconfirm ufw iptables
    ufw allow 22/tcp || true
    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
    systemctl enable --now ufw
    echo "Firewall status:"
    ufw status verbose
elif command -v apt-get >/dev/null 2>&1 || command -v apt >/dev/null 2>&1; then
    echo "Configuring firewall for Ubuntu/Debian..."
    apt-get update -qq
    apt-get install -y ufw
    ufw allow 22/tcp || true
    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
    systemctl enable --now ufw
    echo "Firewall status:"
    ufw status verbose
elif command -v dnf >/dev/null 2>&1; then
    echo "Configuring firewalld for Fedora / RHEL..."
    dnf install -y firewalld
    systemctl enable --now firewalld
    firewall-cmd --add-service=ssh --permanent || true
    firewall-cmd --set-default-zone=drop
    firewall-cmd --reload
    echo "Firewall status:"
    firewall-cmd --state
else
    echo "Using baseline iptables incoming drop rules with SSH allowed..."
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -P INPUT DROP
    echo "Firewall status:"
    iptables -S INPUT
fi
