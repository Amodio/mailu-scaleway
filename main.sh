#!/bin/bash

# Copyright (c) 2022 Jacques Boscq <jacques@boscq.fr>. All rights reserved.
# This work is licensed under the terms of the MIT license.  

# main.sh: Get a Scaleway Debian (Stardust) instance, then run this script.
# It deploys Mailu dockerized with let's encrypt certificates (HTTPS&email).
# This will create a customized user and harden the system (SSHd w/ fail2ban).
#
# Useful command: docker-compose logs -f
#
# <---------------------> CONFIGURATION START <--------------------->
#
# TODO: Fix iptables replacing hostnames by their current IP once
#       This bug will affect you (reaching the server) if your IP changes

# Your IP/hostname used to access the server by SSH&HTTPS (blocked otherwise)
_YOUR_IP_='YOUR_HOME.IP'

# Your email domain name
_EMAIL_DOMAIN_='EXAMPLE.COM'

# User login (do not choose: debian, admin, abuse, postmaster or root)
_USERNAME_='USER'

# /!\                                            /!\
# /!\ You should not edit any value from now on. /!\
# /!\                                            /!\

# Web path to the admin mailu interface
_EMAIL_WEBPATH_='/mailu-admin'

# The timezone you want the server to be on
_TIMEZONE_='Europe/Paris'

# Your email sub-domain name
_EMAIL_SUBDOMAIN_='mail'

# Enable iptables logs?
_ENABLE_FW_LOGS_=0

# SSHd port
_SSH_PORT_=22222

# 16 bytes random secret key string
_SECRET_KEY_='' # Automatically set below but could be forced aswell.

#_IFACE_='ens2' # Automatically set below but could be forced aswell.

#
# <---------------------> CONFIGURATION  END  <--------------------->
#

# First things first: correct the timezone of the server.
timedatectl set-timezone "${_TIMEZONE_}"

START_TIME=$(date +%s)

# First things first: Check if we have the powers to run smoothly...
if [ "$(whoami)" != "root" ]; then
    echo "Aborting: run this script as root." > /dev/stderr
    exit 1
fi

# First things first: Check we got configured
if [ "${_USERNAME_}" = 'USER' -o "${_YOUR_IP_}" = 'YOUR_HOME.IP' -o "${_EMAIL_DOMAIN_}" = 'EXAMPLE.COM' ]; then
    echo "Aborting: please configure this script (3 variables)." > /dev/stderr
    exit 1
fi

# Start: if the user already exists, abort.
id "${_USERNAME_}" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Aborting: user ${_USERNAME_} already exists." > /dev/stderr
    exit 1
fi

# Start: fetch the network interface name
if [ -z "${_IFACE_}" ]; then
    _IFACE_="$(ip -o -4 route show to default|awk 'END {print $NF}')"
fi
# XXX: better check?
if [ -z "${_IFACE_}" ]; then
    echo "Aborting: unknown network interface, please set it manually." > /dev/stderr
    exit 1
fi

# Make sure being up to date
apt update; apt -y upgrade; apt -y autoremove; apt clean

# System configuration: install lsof, bzip2 & pwgen
DEBIAN_FRONTEND=noninteractive apt -y install lsof bzip2 pwgen
# System configuration: set mailu secret key if needed
if [ -z "${SECRET_KEY_}" ]; then
    _SECRET_KEY_="$(pwgen -c 16 1)"
    _SECRET_KEY_="${_SECRET_KEY_^^}"
fi
if [ ${#_SECRET_KEY_} -ne 16 ]; then
    echo "Aborting: invalid secret key ${_SECRET_KEY_}." > /dev/stderr
    exit 1
fi

# System configuration: user account: create our user account (with no password)
adduser --quiet --disabled-password --gecos "${_USERNAME_}" "${_USERNAME_}"
if [ $? -ne 0 ]; then
    echo "Aborting: cannot create user ${_USERNAME_}." > /dev/stderr
    exit 1
fi

# System configuration: user account: add our SSH pubkey into it
mkdir -p "/home/${_USERNAME_}/.ssh"
cp -f /root/.ssh/authorized_keys "/home/${_USERNAME_}/.ssh/"
chown "${_USERNAME_}:${_USERNAME_}" -R "/home/${_USERNAME_}/.ssh/"
chmod 700 "/home/${_USERNAME_}/.ssh/"
# System configuration: user account: delete the default user
deluser --quiet debian 2>/dev/null; rm -rf /home/debian/
# System configuration: user account: sudoers (overwrite the default user `debian`)
echo "${_USERNAME_} ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/90-cloud-init-users
# System configuration: user account: colored prompt
sed -i 's/^#force_color_prompt=yes/force_color_prompt=yes/' "/home/${_USERNAME_}/.bashrc"

# System configuration: root account: ls colored aliases in the prompt
sed -i 's/^# export LS_OPTIONS/export LS_OPTIONS/' /root/.bashrc
sed -i 's/^# eval /eval /' /root/.bashrc
sed -i 's/^# alias ls/alias ls/' /root/.bashrc
sed -i 's/^# alias ll/alias ll/' /root/.bashrc
sed -i 's/^# alias l=/alias l=/' /root/.bashrc

# System configuration: env vars
grep -q LESSHISTFILE /etc/profile 2>/dev/null
if [ $? -ne 0 ]; then
    sed -i "1 i\export LESSHISTFILE='/dev/null'" /etc/profile
fi

# System configuration: ls colored aliases
if [ ! -f '/etc/profile.d/aliases.sh' ]; then
    echo "alias ls='ls --color'
alias l='ls'
alias ll='ls -la'

alias grep='grep --color'

alias apt_='sudo apt update; sudo apt -y upgrade; sudo apt clean'" > /etc/profile.d/aliases.sh
fi
# System configuration: ViM configuration (no mouse nor viminfo, 4 spaces tabs)
echo 'set tabstop=4
set expandtab
set shiftwidth=4
set nobk
set mouse=
set ttymouse=
set viminfofile=NONE' >> /etc/vim/vimrc
# System configuration: empty the Message Of The Day file
echo -n '' > /etc/motd
# System configuration: ip{6}tables
DEBIAN_FRONTEND=noninteractive apt -y install iptables-persistent
# System configuration: ip{6}tables log file
touch /var/log/firewall.log
chmod 640 /var/log/firewall.log
chown root:adm /var/log/firewall.log
echo ':msg, contains, "iptables: " -/var/log/firewall.log
& stop
:msg, contains, "ip6tables: " -/var/log/firewall.log
& stop' > /etc/rsyslog.d/10-firewall.conf
# ip{6}tables log file: file rotation
echo '/var/log/firewall.log {
    rotate 8
    daily
    delaycompress
    compress
    maxsize 100M
    missingok
    notifempty
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}' > /etc/logrotate.d/firewall
service rsyslog force-reload
#ip6tables -F # Flush any previous rules
#ip6tables -X # Delete any previous rules
ip6tables -I INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -p udp --dport 53    -j ACCEPT # DNS
ip6tables -A OUTPUT -p udp --dport 123   -j ACCEPT # NTP
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED   -j ACCEPT
ip6tables -A INPUT -p icmpv6 -m conntrack ! --ctstate INVALID -j ACCEPT
if [ "${_ENABLE_FW_LOGS_}" -ne 0 ]; then
    ip6tables -A INPUT -j LOG --log-prefix "ip6tables: iDROP:"
fi
ip6tables -P INPUT DROP
ip6tables -A OUTPUT -p icmpv6 -m conntrack ! --ctstate INVALID -j ACCEPT
ip6tables -A OUTPUT -m conntrack ! --ctstate INVALID -j ACCEPT 
if [ "${_ENABLE_FW_LOGS_}" -ne 0 ]; then
    ip6tables -A OUTPUT -j LOG --log-prefix "ip6tables: oDROP:"
fi
ip6tables -P OUTPUT DROP
if [ "${_ENABLE_FW_LOGS_}" -ne 0 ]; then
    ip6tables -A FORWARD -j LOG --log-prefix "ip6tables: FWD:"
fi
ip6tables -P FORWARD DROP
ip6tables-save > /etc/iptables/rules.v6
# XXX: https://gist.github.com/azlux/6a70bd38bb7c525ab26efe7e3a7ea8ac
#iptables -F # Flush any previous rules
#iptables -X # Delete any previous rules
iptables -I INPUT -i lo -j ACCEPT
iptables -I INPUT -i "${_IFACE_}" -p udp -d 255.255.255.255 --sport 67 --dport 68 -j ACCEPT # dhclient
iptables -A INPUT -p tcp -i "${_IFACE_}" --dport "${_SSH_PORT_}" -s "${_YOUR_IP_}" -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport "${_SSH_PORT_}" -d "${_YOUR_IP_}" -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 53    -j ACCEPT # DNS
iptables -A OUTPUT -p udp --dport 123   -j ACCEPT # NTP
iptables -A INPUT  -p icmp --icmp-type echo-request    -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED   -j ACCEPT
if [ "${_ENABLE_FW_LOGS_}" -ne 0 ]; then
    iptables -A INPUT -j LOG --log-prefix "iptables: iDROP:"
fi
iptables -P INPUT DROP
iptables -A OUTPUT -p icmp -m conntrack ! --ctstate INVALID -j ACCEPT
iptables -A OUTPUT -m conntrack ! --ctstate INVALID -j ACCEPT 
if [ "${_ENABLE_FW_LOGS_}" -ne 0 ]; then
    iptables -A OUTPUT -j LOG --log-prefix "iptables: oDROP:"
fi
iptables -P OUTPUT DROP
if [ "${_ENABLE_FW_LOGS_}" -ne 0 ]; then
    iptables -A FORWARD -j LOG --log-prefix "iptables: FWD:"
fi
iptables -P FORWARD DROP
iptables-save > /etc/iptables/rules.v4

# SSHd hardening: install Fail2Ban
DEBIAN_FRONTEND=noninteractive apt -y install fail2ban
# SSHd hardening: configure Fail2Ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/^bantime[ ]*= 10m$/bantime = 1d/' /etc/fail2ban/jail.local
sed -i 's/^maxretry[ ]*= 5$/maxretry = 3/' /etc/fail2ban/jail.local
echo 'port    = '${_SSH_PORT_}'
logpath = %(sshd_log)s
backend = %(sshd_backend)s' >> /etc/fail2ban/jail.d/defaults-debian.conf
service fail2ban restart
# SSHd hardening: connection banner
echo '#############################################################################
# WARNING: Authorized Use Only. Transactions may be monitored.              #
# By continuing past this point, you expressly consent to this monitoring.  #
#############################################################################' > /etc/ssh/sshd_banner
# SSHd hardening: set _SSH_PORT_, banner, no root login and only ipv4 (no ipv6)
sed -i 's/^#Port 22$/Port "'${_SSH_PORT_}'"/' /etc/ssh/sshd_config
sed -i 's/^#Banner none$/Banner \/etc\/ssh\/sshd_banner/' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin .*$/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#AddressFamily any$/AddressFamily inet/' /etc/ssh/sshd_config
# SSHd hardening: check if password authentication is indeed disabled.
grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config
if [ $? -ne 0 ]; then
    echo 'ERROR: Press ENTER to set PasswordAuthentication to no in sshd_config' > /dev/stderr
    read tmp
    vi /etc/ssh/sshd_config
fi
# SSHd hardening: restart the daemon
service ssh restart

# Install docker, runnable by the user
DEBIAN_FRONTEND=noninteractive apt -y install docker-compose docker.io docker-doc
usermod -aG docker "${_USERNAME_}"

# Autostart: create a service for launching the docker-compose at boot
echo "[Unit]
Description=docker-compose systemd service.
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/docker-compose -f '/home/${_USERNAME_}/docker/docker-compose.yml' up -d

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/my-docker-compose.service
systemctl enable my-docker-compose.service

# iptables: forbid any HTTPS connection except for us
iptables -I DOCKER-USER -i "${_IFACE_}" -p tcp --dport 443 ! -s "${_YOUR_IP_}" -j DROP
iptables-save > /etc/iptables/rules.v4

# openssl ciphers -V 'ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA' | awk '{print $3}'|sort -u|tr '\n' ':'
# Harden openssl (remove TLS_AES_128_GCM_SHA256 TLSv1.3 cipher-suite support)
echo 'Ciphersuites = TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384' >> /etc/ssl/openssl.cnf

# Fail2Ban configuration files
cat << _EOF_ > /etc/fail2ban/filter.d/bad-auth.conf
[Definition]
failregex = .* client login failed: .+ client:\ <HOST>
ignoreregex =
journalmatch = CONTAINER_TAG=mailu-front
_EOF_
# 8 failed login attempts max in 1 day -> ban for 7 days
cat << _EOF_ > /etc/fail2ban/jail.d/bad-auth.conf
[bad-auth]
enabled = true
backend = systemd
filter = bad-auth
bantime = 604800
findtime = 86400
maxretry = 8
action = docker-action
_EOF_
cat << _EOF_ > /etc/fail2ban/action.d/docker-action.conf
[Definition]

actionstart = iptables -N f2b-bad-auth
              iptables -A f2b-bad-auth -j RETURN
              iptables -I FORWARD -p tcp -m multiport --dports 1:1024 -j f2b-bad-auth

actionstop = iptables -D FORWARD -p tcp -m multiport --dports 1:1024 -j f2b-bad-auth
             iptables -F f2b-bad-auth
             iptables -X f2b-bad-auth

actioncheck = iptables -n -L FORWARD | grep -q 'f2b-bad-auth[ \t]'

actionban = iptables -I f2b-bad-auth 1 -s <ip> -j DROP

actionunban = iptables -D f2b-bad-auth -s <ip> -j DROP
_EOF_
service fail2ban restart

# Fix docker flooding logs from health checks
cat << _EOF_ > /etc/rsyslog.d/01-blocklist.conf
if \$msg contains ".mount: Succeeded." then {
    stop
}
if \$programname == "mailu-front" and \$msg contains "GET /health " then {
    stop
}
if \$programname == "mailu-front" and \$msg contains " client 127.0.0.1 closed keepalive connection" then {
    stop
}
_EOF_
service rsyslog restart

# Deploy the save script in ~
cat << _EOF_ > "/home/${_USERNAME_}/save.sh"
#!/bin/bash
docker-compose -f "/home/${_USERNAME_}/docker/docker-compose.yml" down
time sudo tar cjvf "docker-\$(date '+%Y-%m-%d').tar.bz2" "/home/${_USERNAME_}/docker/"
docker-compose -f "/home/${_USERNAME_}/docker/docker-compose.yml" up -d
_EOF_
chmod +x "/home/${_USERNAME_}/save.sh"

# Try to restore a backup file from /root/
_DOCKER_BACKUP_="$(ls docker-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].tar.bz2 -1 2>/dev/null | tail -1)"
if [ -n "${_DOCKER_BACKUP_}" ]; then
    echo 'Restoring backup...'
    if [ -e "/home/${_USERNAME_}/docker" ]; then
        echo 'WARN: ~/docker already exists...'
        mv -f "/home/${_USERNAME_}/docker" "/home/${_USERNAME_}/docker_"
    fi
    tar xjf "${_DOCKER_BACKUP_}" -C "/home/${_USERNAME_}/"
fi

# Mailu configuration files: deploy initial ones if needed
if [ ! -d "/home/${_USERNAME_}/docker" ]; then
    if [ -e "/home/${_USERNAME_}/docker" ]; then
        echo 'WARN: ~/docker already exists and is not a directory...'
        mv -f "/home/${_USERNAME_}/docker" "/home/${_USERNAME_}/docker_"
    fi
    mkdir -p "/home/${_USERNAME_}/docker/"
    cat << _EOF_ > "/home/${_USERNAME_}/docker/docker-compose.yml"
version: '2.2'

services:
  # External dependencies
  redis:
    image: redis:alpine
    restart: always
    volumes:
      - "/home/${_USERNAME_}/docker/redis:/data"
    depends_on:
      - resolver
    dns:
      - 192.168.203.254

  # Core services
  front:
    image: \${DOCKER_ORG:-mailu}/\${DOCKER_PREFIX:-}nginx:\${MAILU_VERSION:-1.9}
    restart: always
    env_file: mailu.env
    logging:
      driver: journald
      options:
        tag: mailu-front
    ports:
      - "80:80"   # For the Let's Encrypt ACME server
      - "443:443" # For the Mailu web admin panel
      - "25:25"   # SMTP relay
      - "465:465" # SMTP over TLS, for email submission (587: StartTLS)
      - "993:993" # IMAPS
    volumes:
      - "/home/${_USERNAME_}/docker/certs:/certs"
      - "/home/${_USERNAME_}/docker/overrides/nginx:/overrides:ro"
    depends_on:
      - resolver
    dns:
      - 192.168.203.254

  resolver:
    image: \${DOCKER_ORG:-mailu}/\${DOCKER_PREFIX:-}unbound:\${MAILU_VERSION:-1.9}
    env_file: mailu.env
    restart: always
    networks:
      default:
        ipv4_address: 192.168.203.254

  admin:
    image: \${DOCKER_ORG:-mailu}/\${DOCKER_PREFIX:-}admin:\${MAILU_VERSION:-1.9}
    restart: always
    env_file: mailu.env
    volumes:
      - "/home/${_USERNAME_}/docker/data:/data"
      - "/home/${_USERNAME_}/docker/dkim:/dkim"
    depends_on:
      - redis
      - resolver
    dns:
      - 192.168.203.254

  imap:
    image: \${DOCKER_ORG:-mailu}/\${DOCKER_PREFIX:-}dovecot:\${MAILU_VERSION:-1.9}
    restart: always
    env_file: mailu.env
    volumes:
      - "/home/${_USERNAME_}/docker/mail:/mail"
      - "/home/${_USERNAME_}/docker/overrides/dovecot:/overrides:ro"
    depends_on:
      - front
      - resolver
    dns:
      - 192.168.203.254

  smtp:
    image: \${DOCKER_ORG:-mailu}/\${DOCKER_PREFIX:-}postfix:\${MAILU_VERSION:-1.9}
    restart: always
    env_file: mailu.env
    volumes:
      - "/home/${_USERNAME_}/docker/mailqueue:/queue"
      - "/home/${_USERNAME_}/docker/overrides/postfix:/overrides:ro"
    depends_on:
      - front
      - resolver
    dns:
      - 192.168.203.254

  antispam:
    image: \${DOCKER_ORG:-mailu}/\${DOCKER_PREFIX:-}rspamd:\${MAILU_VERSION:-1.9}
    hostname: antispam
    restart: always
    env_file: mailu.env
    volumes:
      - "/home/${_USERNAME_}/docker/filter:/var/lib/rspamd"
      - "/home/${_USERNAME_}/docker/overrides/rspamd:/etc/rspamd/override.d:ro"
    depends_on:
      - front
      - resolver
    dns:
      - 192.168.203.254

networks:
  default:
    enable_ipv6: false
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 192.168.203.0/24
_EOF_
    cat << _EOF_ > "/home/${_USERNAME_}/docker/mailu.env"
# Mailu main configuration file
# docker-compose exec admin flask mailu admin me example.net ASSWORD
#
# This file is autogenerated by the configuration management wizard for compose flavor.
# For a detailed list of configuration variables, see the documentation at
# https://mailu.io

###################################
# Common configuration variables
###################################

# Set to a randomly generated 16 bytes string
SECRET_KEY=${_SECRET_KEY_}

# Subnet of the docker network. This should not conflict with any networks to which your system is connected. (Internal and external!)
SUBNET=192.168.203.0/24

# Main mail domain
DOMAIN=${_EMAIL_DOMAIN_}

# Hostnames for this server, separated with comas
HOSTNAMES=${_EMAIL_SUBDOMAIN_}.${_EMAIL_DOMAIN_}

# Postmaster local part (will append the main mail domain)
POSTMASTER=admin

# Choose how secure connections will behave (value: letsencrypt, cert, notls, mail, mail-letsencrypt)
TLS_FLAVOR=letsencrypt

# Authentication rate limit per IP (per /24 on ipv4 and /56 on ipv6)
AUTH_RATELIMIT_IP=60/hour

# Authentication rate limit per user (regardless of the source-IP)
AUTH_RATELIMIT_USER=300/day

# Opt-out of statistics, replace with "True" to opt out
DISABLE_STATISTICS=True

###################################
# Optional features
###################################

# Expose the admin interface (value: true, false)
ADMIN=true

# Choose which webmail to run if any (values: roundcube, rainloop, none)
WEBMAIL=none

# Dav server implementation (value: radicale, none)
WEBDAV=none

# Antivirus solution (value: clamav, none)
ANTIVIRUS=none

###################################
# Mail settings
###################################

# Message size limit in bytes
# Default: accept messages up to 50MB
# Max attachment size will be 33% smaller
MESSAGE_SIZE_LIMIT=100000000

# Message rate limit (per user)
MESSAGE_RATELIMIT=200/day

# Networks granted relay permissions
# Use this with care, all hosts in this networks will be able to send mail without authentication!
RELAYNETS=

# Will relay all outgoing mails if configured
RELAYHOST=

# Fetchmail delay
FETCHMAIL_DELAY=600

# Recipient delimiter, character used to delimiter localpart from custom address part
RECIPIENT_DELIMITER=+

# DMARC rua and ruf email
DMARC_RUA=admin
DMARC_RUF=admin

# Welcome email, enable and set a topic and body if you wish to send welcome
# emails to all users.
WELCOME=false
WELCOME_SUBJECT=Welcome to your new email account
WELCOME_BODY=Welcome to your new email account, if you can read this, then it is configured properly!

# Maildir Compression
# choose compression-method, default: none (value: bz2, gz)
COMPRESSION=gz
# change compression-level, default: 6 (value: 1-9)
COMPRESSION_LEVEL=

# IMAP full-text search is enabled by default. Set the following variable to off in order to disable the feature.
# FULL_TEXT_SEARCH=off

###################################
# Web settings
###################################

# Path to redirect / to
WEBROOT_REDIRECT=

# Path to the admin interface if enabled
WEB_ADMIN=${_EMAIL_WEBPATH_}

# Path to the webmail if enabled
WEB_WEBMAIL=

# Website name
SITENAME=Mailu

# Linked Website URL
WEBSITE=https://${_EMAIL_SUBDOMAIN_}.${_EMAIL_DOMAIN_}



###################################
# Advanced settings
###################################

# Log driver for front service. Possible values:
# json-file (default)
# journald (On systemd platforms, useful for Fail2Ban integration)
# syslog (Non systemd platforms, Fail2Ban integration. Disables \`docker-compose log\` for front!)
# LOG_DRIVER=json-file

# Docker-compose project name, this will prepended to containers names.
COMPOSE_PROJECT_NAME=mailu

# Number of rounds used by the password hashing scheme
CREDENTIAL_ROUNDS=12

# Header to take the real ip from
REAL_IP_HEADER=

# IPs for nginx set_real_ip_from (CIDR list separated by commas)
REAL_IP_FROM=

# choose wether mailu bounces (no) or rejects (yes) mail when recipient is unknown (value: yes, no)
REJECT_UNLISTED_RECIPIENT=

# Log level threshold in start.py (value: CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET)
LOG_LEVEL=WARNING

# Timezone for the Mailu containers. See this link for all possible values https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
TZ=${_TIMEZONE_}

###################################
# Database settings
###################################
DB_FLAVOR=sqlite
_EOF_

    chown "${_USERNAME_}:${_USERNAME_}" -R "/home/${_USERNAME_}/docker/"

    docker-compose -f "/home/${_USERNAME_}/docker/docker-compose.yml" up -d
    sleep 15 # Wait for the containers to initialize

    # mailu-admin: Create the email domain
    docker-compose -f "/home/${_USERNAME_}/docker/docker-compose.yml" exec admin flask mailu domain "${_EMAIL_DOMAIN_}"
    # mailu-admin: No quota (i.e. infinite: user number, user aliases, mailbox size)
    docker-compose -f "/home/${_USERNAME_}/docker/docker-compose.yml" exec admin flask mailu setlimits "${_EMAIL_DOMAIN_}" -- -1 -1 0
    # mailu-admin: Create the admin user
    _MAILU_ADMIN_PW_="$(pwgen -c 32 1)"
    docker-compose -f "/home/${_USERNAME_}/docker/docker-compose.yml" exec admin flask mailu admin "${_USERNAME_}" "${_EMAIL_DOMAIN_}" "${_MAILU_ADMIN_PW_}"
    # mailu-admin: Configure some default aliases to redirect emails to the admin
    for i in admin abuse postmaster root; do
        docker-compose -f "/home/${_USERNAME_}/docker/docker-compose.yml" exec admin flask mailu alias "$i" "${_EMAIL_DOMAIN_}" "${_USERNAME_}@${_EMAIL_DOMAIN_}"
    done
else
    docker-compose -f "/home/${_USERNAME_}/docker/docker-compose.yml" up -d
fi

# Finally: clean packages and remove this file
apt -y autoremove; apt clean; rm -f -- "$0"

echo
echo -n '<-------------------------+ Elapsed: '
printf "%02dm%02ds. +------------------------>\n\n" $(expr \( $(date +%s) - $START_TIME \) \/ 60) $(expr \( $(date +%s) - $START_TIME \) % 60)

# Finally: print the secrets (for a fresh install)
if [ -n "${_MAILU_ADMIN_PW_}" ]; then
    echo "Please NOTE your creds for https://${_EMAIL_SUBDOMAIN_}.${_EMAIL_DOMAIN_}${_EMAIL_WEBPATH_}"
    echo "${_USERNAME_}@${_EMAIL_DOMAIN_} / ${_MAILU_ADMIN_PW_}"
    echo
    echo "Generate (DKIM&DMARC) keys + set your DNS records accordingly"
    echo "from: https://${_EMAIL_SUBDOMAIN_}.${_EMAIL_DOMAIN_}${_EMAIL_WEBPATH_}/domain/details/${_EMAIL_DOMAIN_}"
    echo
    echo "Then configure your email client(s) according to:"
    echo "https://${_EMAIL_SUBDOMAIN_}.${_EMAIL_DOMAIN_}${_EMAIL_WEBPATH_}/client"
    echo
fi

echo 'Now press ENTER to reboot (or Ctrl+c to skip). Enjoy!'
read tmp
docker-compose -f "/home/${_USERNAME_}/docker/docker-compose.yml" down
reboot
