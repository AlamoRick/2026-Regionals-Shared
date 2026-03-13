#!/bin/bash
# =============================================================================
# ir.sh — Incident Response Toolkit
# San Antonio College — SWCCDC 2026
# Based on University of Tulsa's IR script pattern
#
# Quick tools for when Red Team hits. Each flag does one thing fast.
#
# Usage:
#   sudo ./ir.sh -b          # Basic system info (ports, users, connections)
#   sudo ./ir.sh -l          # Login activity (successful, failed)
#   sudo ./ir.sh -c          # Check for suspicious stuff
#   sudo ./ir.sh -bi [ip]    # Block an IP address
#   sudo ./ir.sh -k [user]   # Kick a user off the system
#   sudo ./ir.sh -t          # Full triage (paste output into AI)
#   sudo ./ir.sh -h          # Help
# =============================================================================

set -uo pipefail

G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; C='\033[1;36m'; B='\033[1m'; N='\033[0m'
header() { echo -e "\n${G}══════════════════════════════════════${N}"; echo -e "${G}  $1${N}"; echo -e "${G}══════════════════════════════════════${N}"; }
ok()   { echo -e "  ${G}✔${N} $1"; }
bad()  { echo -e "  ${R}✖${N} $1"; }
warn() { echo -e "  ${Y}⚠${N} $1"; }

if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi

LOG="/var/log/ir_$(date +%Y%m%d_%H%M%S).log"
log() { echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

# =========================================================================
# -b : Basic system info
# =========================================================================
cmd_basic() {
    header "System Info"
    uptime
    echo ""

    header "Active Users"
    w 2>/dev/null || who

    header "Listening Ports"
    ss -tulnp 2>/dev/null || netstat -tulnp

    header "Established Connections"
    ss -tunap state established 2>/dev/null || netstat -tunap 2>/dev/null | grep ESTABLISHED

    header "Top Processes by CPU"
    ps aux --sort=-%cpu 2>/dev/null | head -11

    header "Firewall Rules"
    iptables -L -n --line-numbers 2>/dev/null || nft list ruleset 2>/dev/null || ufw status 2>/dev/null
}

# =========================================================================
# -l : Login activity
# =========================================================================
cmd_logins() {
    header "Successful SSH Logins Today"
    today=$(date '+%b %d')
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u ssh -u sshd --no-pager 2>/dev/null | grep "$today" | grep -i "accepted" || warn "None found"
    elif [ -f /var/log/auth.log ]; then
        grep "Accepted" /var/log/auth.log | grep "$today" || warn "None found"
    fi

    header "Failed SSH Login Attempts Today"
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u ssh -u sshd --no-pager 2>/dev/null | grep "$today" | grep -i "failed\|invalid" || warn "None found"
    elif [ -f /var/log/auth.log ]; then
        grep "Failed password" /var/log/auth.log | grep "$today" || warn "None found"
    fi

    header "Recent Logins"
    last -20 2>/dev/null
}

# =========================================================================
# -c : Suspicious activity check
# =========================================================================
cmd_suspicious() {
    header "Suspicious Activity Check"

    echo -e "\n  ${B}1. Users with UID 0:${N}"
    awk -F: '$3 == 0 {print "    " $0}' /etc/passwd

    echo -e "\n  ${B}2. Authorized keys files:${N}"
    found=0
    for d in /root /home/*; do
        if [ -f "$d/.ssh/authorized_keys" ]; then
            found=1
            bad "FOUND: $d/.ssh/authorized_keys"
            awk '{print "      " $0}' "$d/.ssh/authorized_keys"
        fi
    done
    [ "$found" -eq 0 ] && ok "None found"

    echo -e "\n  ${B}3. SUID in unusual places:${N}"
    suid=$(find /home /tmp /var/tmp /opt /usr/local -maxdepth 5 -perm -4000 -type f 2>/dev/null)
    [ -n "$suid" ] && echo "$suid" | awk '{print "    " $0}' || ok "None found"

    echo -e "\n  ${B}4. Executables in /tmp:${N}"
    tmp=$(find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null)
    [ -n "$tmp" ] && bad "Found:" && echo "$tmp" | awk '{print "    " $0}' || ok "None"

    echo -e "\n  ${B}5. Recently modified /etc files (last 30 min):${N}"
    recent=$(find /etc -mmin -30 -type f 2>/dev/null)
    [ -n "$recent" ] && echo "$recent" | awk '{print "    " $0}' || ok "None"

    echo -e "\n  ${B}6. Cron jobs:${N}"
    for f in /etc/crontab /etc/cron.d/*; do
        [ -f "$f" ] && echo "    [$f]:" && grep -vE '^#|^$|PATH|SHELL' "$f" 2>/dev/null | awk '{print "      " $0}'
    done
    for uc in /var/spool/cron/crontabs/* /var/spool/cron/*; do
        [ -f "$uc" ] && echo "    [User: $(basename "$uc")]:" && grep -vE '^#|^$' "$uc" 2>/dev/null | awk '{print "      " $0}'
    done

    echo -e "\n  ${B}7. Listening on unusual ports (1025-32767):${N}"
    ss -tlnp 2>/dev/null | awk 'NR>1' | while read -r line; do
        port=$(echo "$line" | awk '{print $4}' | grep -oE '[0-9]+$')
        [ -n "$port" ] && [ "$port" -gt 1024 ] && [ "$port" -lt 32768 ] && echo "    $line"
    done

    echo -e "\n  ${B}8. Processes with deleted binaries:${N}"
    ls -l /proc/*/exe 2>/dev/null | grep deleted | head -10 || ok "None"

    echo -e "\n  ${B}9. FIM alerts (last hour):${N}"
    journalctl -t FIM --since "1 hour ago" --no-pager 2>/dev/null || echo "    No FIM alerts"
}

# =========================================================================
# -bi : Block an IP
# =========================================================================
cmd_block_ip() {
    local ip="${1:-}"
    [ -z "$ip" ] && echo -n "  Enter IP to block: " && read -r ip
    [ -z "$ip" ] && { bad "No IP provided"; return; }

    # Basic validation
    if ! echo "$ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'; then
        bad "Invalid IP: $ip"; return
    fi

    header "Blocking IP: $ip"
    log "Blocking IP: $ip"

    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT 1 -s "$ip" -j DROP && ok "Blocked $ip (iptables)"
    elif command -v nft >/dev/null 2>&1; then
        nft add rule inet filter input ip saddr "$ip" drop && ok "Blocked $ip (nft)"
    elif command -v ufw >/dev/null 2>&1; then
        ufw deny from "$ip" && ok "Blocked $ip (ufw)"
    else
        bad "No firewall tool found"
    fi
}

# =========================================================================
# -k : Kick a user
# =========================================================================
cmd_kick() {
    local user="${1:-}"
    [ -z "$user" ] && echo -n "  Enter username to kick: " && read -r user
    [ -z "$user" ] && return

    if [ "$user" = "$(whoami)" ]; then bad "Can't kick yourself"; return; fi

    header "Kicking user: $user"
    log "Kicking user: $user"

    pkill -KILL -u "$user" 2>/dev/null && ok "Killed all processes for $user" || warn "No processes found"

    echo -n "  Lock account? [y/N] "
    read -r yn
    if [ "$yn" = "y" ] || [ "$yn" = "Y" ]; then
        passwd -l "$user" 2>/dev/null && ok "Account locked" || bad "Failed to lock"
        log "Locked account: $user"
    fi
}

# =========================================================================
# -t : Full triage (for pasting into AI)
# =========================================================================
cmd_triage() {
    TRIAGE="/root/triage_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "========================================================"
        echo "INCIDENT TRIAGE — $(hostname) — $(date)"
        echo "========================================================"
        echo ""
        echo "=== ACTIVE CONNECTIONS ==="
        ss -tunap 2>/dev/null
        echo ""
        echo "=== LISTENING PORTS ==="
        ss -tulnp 2>/dev/null
        echo ""
        echo "=== LOGGED IN USERS ==="
        w 2>/dev/null
        echo ""
        echo "=== RECENT LOGINS ==="
        last -15 2>/dev/null
        echo ""
        echo "=== FAILED LOGINS ==="
        lastb 2>/dev/null | head -15
        echo ""
        echo "=== ALL PROCESSES ==="
        ps auxf 2>/dev/null | head -40
        echo ""
        echo "=== RECENTLY MODIFIED /etc (30 min) ==="
        find /etc -mmin -30 -type f 2>/dev/null
        echo ""
        echo "=== FILES IN /tmp ==="
        find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null
        echo ""
        echo "=== CRON JOBS ==="
        cat /etc/crontab 2>/dev/null
        for f in /etc/cron.d/*; do [ -f "$f" ] && echo "--- $f ---" && cat "$f"; done
        echo ""
        echo "=== AUTHORIZED KEYS ==="
        for d in /root /home/*; do [ -f "$d/.ssh/authorized_keys" ] && echo "$d:" && cat "$d/.ssh/authorized_keys"; done
        echo ""
        echo "=== /etc/passwd ==="
        cat /etc/passwd
        echo ""
        echo "=== BASH HISTORY (root) ==="
        tail -30 /root/.bash_history 2>/dev/null
        echo ""
        echo "=== JOURNAL (last 15 min) ==="
        journalctl --since "15 min ago" --no-pager 2>/dev/null | tail -40
        echo ""
        echo "=== FIM ALERTS ==="
        journalctl -t FIM --since "1 hour ago" --no-pager 2>/dev/null
    } 2>&1 | tee "$TRIAGE"

    echo ""
    ok "Triage saved to: $TRIAGE"
    echo ""
    echo "Paste this into Claude/ChatGPT with:"
    echo '  "I am in a CCDC competition. Red Team has hit this machine.'
    echo '   Analyze this triage output. Tell me:'
    echo '   1) What did the attacker do?'
    echo '   2) How do I contain it?'
    echo '   3) Help me write an incident report."'
}

# =========================================================================
# Usage
# =========================================================================
usage() {
    echo ""
    echo "ir.sh — Incident Response Toolkit"
    echo "San Antonio College — SWCCDC 2026"
    echo ""
    echo "Usage: sudo $0 [option] [arg]"
    echo ""
    echo "  -b          Basic info (ports, users, connections)"
    echo "  -l          Login activity (success + failed)"
    echo "  -c          Check for suspicious activity"
    echo "  -bi [ip]    Block an IP address"
    echo "  -k  [user]  Kick a user and optionally lock account"
    echo "  -t          Full triage dump (paste into AI for analysis)"
    echo "  -h          This help"
    echo ""
    exit 0
}

FLAG="${1:-}"
ARG="${2:-}"

case "$FLAG" in
    -b)  cmd_basic ;;
    -l)  cmd_logins ;;
    -c)  cmd_suspicious ;;
    -bi) cmd_block_ip "$ARG" ;;
    -k)  cmd_kick "$ARG" ;;
    -t)  cmd_triage ;;
    -h)  usage ;;
    *)   usage ;;
esac
