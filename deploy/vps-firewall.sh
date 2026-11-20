#!/usr/bin/env bash
# PX League VPS firewall: 80/443 only from Cloudflare, 1935 only from localhost + PUSH_IPS, SSH open.
#
# Usage (as root, from the repo directory):
#   sudo SSH_PORT=22 PUSH_IPS="198.51.100.10 2001:db8::10" bash deploy/vps-firewall.sh
#
# Keep a SECOND SSH session open until you have checked you can still log in.
# Safe to re-run (e.g. monthly, to pick up Cloudflare range changes): the Docker block is replaced.
#
# Why two layers: Docker publishes ports with its own NAT rules, which bypass ufw's INPUT rules.
# ufw alone would leave 80/443/1935 open, so the same policy is also written into Docker's
# DOCKER-USER chain (via /etc/ufw/after.rules and after6.rules, so ufw reloads keep it).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }

SSH_PORT="${SSH_PORT:-22}"   # change if sshd listens elsewhere
PUSH_IPS="${PUSH_IPS:-}"     # public IPs allowed to push RTMP to :1935, space separated.
                             # Empty = no outside pushes (pull restreams inside Docker still work).

IFACE=$(ip -o route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
[ -n "$IFACE" ] || { echo "Could not detect the public interface"; exit 1; }
CF4=$(curl -fsS --max-time 15 https://www.cloudflare.com/ips-v4)
CF6=$(curl -fsS --max-time 15 https://www.cloudflare.com/ips-v6)
[ "$(echo "$CF4" | wc -l)" -ge 10 ] && [ "$(echo "$CF6" | wc -l)" -ge 5 ] || { echo "Cloudflare range download failed"; exit 1; }
PUSH4=$(for ip in $PUSH_IPS; do case $ip in *:*) ;; *) echo "$ip";; esac; done)
PUSH6=$(for ip in $PUSH_IPS; do case $ip in *:*) echo "$ip";; esac; done)
echo "Public interface: $IFACE | SSH port: $SSH_PORT | RTMP push IPs: ${PUSH_IPS:-none}"

command -v ufw >/dev/null || { apt-get update -qq && apt-get install -y -qq ufw; }

# ---------------------------------------------------------------------------
# 1. Host firewall (INPUT). SSH is allowed BEFORE ufw is enabled.
#    Also covers ports Docker exposes through docker-proxy on IPv6.
# ---------------------------------------------------------------------------
ufw allow "${SSH_PORT}/tcp" comment 'SSH'
ufw default deny incoming
ufw default allow outgoing
for ip in $CF4 $CF6; do
  ufw allow proto tcp from "$ip" to any port 80,443 comment 'Cloudflare' >/dev/null
done
for ip in $PUSH_IPS; do
  ufw allow proto tcp from "$ip" to any port 1935 comment 'RTMP push' >/dev/null
done

# ---------------------------------------------------------------------------
# 2. Docker-published ports (FORWARD -> DOCKER-USER). Only traffic arriving on the public
#    interface is filtered; replies and container-to-container traffic pass untouched.
#    --ctorigdstport = the port the client connected to (before Docker's DNAT).
# ---------------------------------------------------------------------------
docker_block() {   # $1 = Cloudflare ranges, $2 = push IPs
  echo "# BEGIN PXL DOCKER-USER"
  echo "*filter"
  echo ":DOCKER-USER - [0:0]"
  echo "-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
  echo "-A DOCKER-USER ! -i $IFACE -j RETURN"
  for ip in $1; do
    for port in 80 443; do
      echo "-A DOCKER-USER -p tcp -s $ip -m conntrack --ctorigdstport $port --ctdir ORIGINAL -j RETURN"
    done
  done
  for ip in $2; do
    echo "-A DOCKER-USER -p tcp -s $ip -m conntrack --ctorigdstport 1935 --ctdir ORIGINAL -j RETURN"
  done
  for port in 80 443 1935; do
    echo "-A DOCKER-USER -p tcp -m conntrack --ctorigdstport $port --ctdir ORIGINAL -j DROP"
    echo "-A DOCKER-USER -p udp -m conntrack --ctorigdstport $port --ctdir ORIGINAL -j DROP"
  done
  echo "-A DOCKER-USER -j RETURN"
  echo "COMMIT"
  echo "# END PXL DOCKER-USER"
}
for pair in "/etc/ufw/after.rules|$CF4|$PUSH4" "/etc/ufw/after6.rules|$CF6|$PUSH6"; do
  file=${pair%%|*}; rest=${pair#*|}; ranges=${rest%%|*}; push=${rest#*|}
  cp -a "$file" "$file.bak.$(date +%s)"
  sed -i '/^# BEGIN PXL DOCKER-USER$/,/^# END PXL DOCKER-USER$/d' "$file"
  docker_block "$ranges" "$push" >> "$file"
done

ufw --force enable
ufw reload
systemctl restart docker   # re-links DOCKER-USER into FORWARD; containers (restart: unless-stopped) come back

echo; ufw status verbose | head -n 20
echo; iptables -S DOCKER-USER | head -n 8; echo "... ($(iptables -S DOCKER-USER | wc -l) rules)"
