#!/usr/bin/vbash
# =============================================================================
# reference.sh — Router Command Reference
# San Antonio College — SWCCDC 2026
#
# SWCCDC typically uses VyOS, but always confirm at game start.
# This is a REFERENCE FILE — don't run it. Copy-paste commands as needed.
#
# HOW TO IDENTIFY YOUR ROUTER:
#   VyOS:    Login shows "vyos login:" or "Welcome to VyOS"
#   pfSense: Web UI on 443/80, FreeBSD console, numbered menu
#   Cisco:   Shows ">" prompt, "enable" for privileged mode
# =============================================================================

# ╔════════════════════════════════════════════════════════╗
# ║  VYOS — Most likely router at SWCCDC                  ║
# ╠════════════════════════════════════════════════════════╣
# ║  WORKFLOW: configure → make changes → commit → save   ║
# ║  ALWAYS commit AND save or changes are lost on reboot ║
# ╚════════════════════════════════════════════════════════╝

# --- FIRST 2 MINUTES ---

# Step 1: Recon — see what we're working with
show interfaces
show ip route
show system login
show service ssh
show service dns forwarding
show nat source rules
show firewall

# Step 2: Change password (do this IMMEDIATELY)
configure
set system login user vyos authentication plaintext-password "YOUR_NEW_PASS"
commit
save

# Step 3: Delete any users you don't recognize
# show system login       # see all users first
# delete system login user <SUSPICIOUS_USER>
# commit
# save

# Step 4: Backup config
show configuration > /tmp/router-backup.txt

# --- SSH HARDENING ---
configure
# Only listen on internal interfaces (get IPs from 'show interfaces')
set service ssh listen-address <INTERNAL_IP>
set service ssh port 22
delete service telnet 2>/dev/null
delete service http 2>/dev/null
commit
save

# --- DNS ---
configure
set service dns forwarding name-server 8.8.8.8
set service dns forwarding name-server 8.8.4.4
commit
save

# --- DISABLE CONNTRACK ABUSE ---
configure
delete system conntrack modules h323 2>/dev/null
delete system conntrack modules pptp 2>/dev/null
delete system conntrack modules sip 2>/dev/null
delete system conntrack modules sqlnet 2>/dev/null
delete system conntrack modules tftp 2>/dev/null
commit
save

# --- FIREWALL TEMPLATE ---
# Adapt this to YOUR network. Get IPs from 'show interfaces' and team packet.
configure

# Define your internal networks (figure these out from show interfaces)
# set firewall group network-group INTERNAL network 172.16.X.0/24

# Allow established connections through
set firewall ipv4 forward filter default-action drop
set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 state established
set firewall ipv4 forward filter rule 10 state related

# Drop invalid
set firewall ipv4 forward filter rule 20 action drop
set firewall ipv4 forward filter rule 20 state invalid

# Allow ICMP (scoring engine may ping)
set firewall ipv4 forward filter rule 30 action accept
set firewall ipv4 forward filter rule 30 protocol icmp

# SCORED SERVICES — Add one rule per service you find
# Figure these out from inventory.sh output on each machine
#
# set firewall ipv4 forward filter rule 1000 action accept
# set firewall ipv4 forward filter rule 1000 protocol tcp
# set firewall ipv4 forward filter rule 1000 destination address <SERVER_IP>
# set firewall ipv4 forward filter rule 1000 destination port <PORT>
#
# Repeat for each scored service...

# Allow outbound DNS, HTTP, NTP from servers
set firewall ipv4 forward filter rule 2000 action accept
set firewall ipv4 forward filter rule 2000 protocol udp
set firewall ipv4 forward filter rule 2000 destination port 53

set firewall ipv4 forward filter rule 2010 action accept
set firewall ipv4 forward filter rule 2010 protocol tcp
set firewall ipv4 forward filter rule 2010 destination port 80,443

set firewall ipv4 forward filter rule 2020 action accept
set firewall ipv4 forward filter rule 2020 protocol udp
set firewall ipv4 forward filter rule 2020 destination port 123

commit
save

# --- PROTECT THE ROUTER ITSELF ---
configure
set firewall ipv4 input filter default-action drop
set firewall ipv4 input filter rule 10 action accept
set firewall ipv4 input filter rule 10 state established
set firewall ipv4 input filter rule 10 state related

set firewall ipv4 input filter rule 20 action accept
set firewall ipv4 input filter rule 20 protocol icmp

# SSH from internal only
set firewall ipv4 input filter rule 30 action accept
set firewall ipv4 input filter rule 30 protocol tcp
set firewall ipv4 input filter rule 30 source group network-group INTERNAL
set firewall ipv4 input filter rule 30 destination port 22
commit
save

# --- BLOCK A RED TEAM IP (use during competition) ---
configure
set firewall group network-group BLOCKED-C2 network <BAD_IP>/32
# Then add a drop rule referencing this group, or:
set firewall ipv4 forward filter rule 25 action drop
set firewall ipv4 forward filter rule 25 source group network-group BLOCKED-C2
commit
save

# --- SYSLOG TO CENTRAL SERVER ---
# configure
# set system syslog host <LOG_SERVER_IP> facility all level info
# set system syslog host <LOG_SERVER_IP> port 514
# set system syslog host <LOG_SERVER_IP> protocol udp
# commit; save

# --- EMERGENCY: SCORING BREAKS? OPEN EVERYTHING ---
# configure
# delete firewall ipv4 forward filter
# delete firewall ipv4 input filter
# commit

# --- VERIFICATION ---
show firewall
show firewall statistics
show conntrack table ipv4 | head 30
show log | tail 20


# ╔════════════════════════════════════════════════════════╗
# ║  PFSENSE — if it's a web UI router                    ║
# ╠════════════════════════════════════════════════════════╣
# ║  Console: Option 3 = reset admin password             ║
# ║  Then use web UI for everything else                  ║
# ╚════════════════════════════════════════════════════════╝

# Console shortcuts:
# pfctl -sr              # show current rules
# pfctl -ss              # show state table
# pfctl -F states        # flush states (careful!)

# Web UI steps:
# 1. System > User Manager → change admin password, delete rogue users
# 2. Firewall > Rules → block suspicious IPs
# 3. System > Advanced → disable HTTP, HTTPS only
# 4. Status > System Logs → check activity


# ╔════════════════════════════════════════════════════════╗
# ║  CISCO ASA — if it's a CLI router with ">" prompt     ║
# ╠════════════════════════════════════════════════════════╣
# ║  enable → configure terminal                          ║
# ╚════════════════════════════════════════════════════════╝

# enable
# configure terminal
# enable password <NEWPASS>
# username admin password <NEWPASS> privilege 15
#
# show running-config
# show access-list
# show interface ip brief
# show route
# show conn all
#
# Block an IP:
# access-list OUTSIDE_IN line 1 extended deny ip host <BAD_IP> any log
#
# Save:
# write memory
