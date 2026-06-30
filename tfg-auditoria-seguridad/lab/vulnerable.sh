#!/usr/bin/env bash
# vulnerable.sh — Aprovisionamiento del escenario base vulnerable
#
# Introduce una desviación controlada por cada una de las 43 reglas del catálogo
# (categorías SRV, NET, SSH, ACC, PERM, LOG, UPD). El script es idempotente,
# requiere privilegios de root y debe ejecutarse con el adaptador NAT activo
# (para instalar paquetes), ANTES de capturar la instantánea baseline-vulnerable.
#
# ADVERTENCIA: degrada deliberadamente la seguridad del sistema. Ejecutar solo en
# una máquina virtual desechable, nunca en un sistema de producción.

set -uo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Este script debe ejecutarse como root (usa: sudo $0)." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
log() { echo -e "\n[vulnerable.sh] $*"; }

log "Actualizando índice de paquetes"
apt-get update -y

# ── SRV — Servicios y puertos activos (5 reglas) ────────────────────────────
log "Configurando desviaciones SRV"

# SRV-001  Telnet (23/tcp): se instala y se activa su entrada en inetd
apt-get install -y telnetd
sed -i 's/^#<off>#\s*telnet/telnet/' /etc/inetd.conf
systemctl enable --now inetutils-inetd

# SRV-002  FTP (21/tcp)
apt-get install -y vsftpd
systemctl enable --now vsftpd

# SRV-003  rsh / rlogin / rexec (513-514/tcp)
apt-get install -y rsh-redone-server
systemctl restart inetutils-inetd

# SRV-004  avahi-daemon, descubrimiento mDNS (5353/udp)
apt-get install -y avahi-daemon
systemctl enable --now avahi-daemon

# SRV-005  CUPS, servicio de impresión (631/tcp)
apt-get install -y cups
systemctl enable --now cups

# ── NET — Configuración de red (9 reglas) ───────────────────────────────────
log "Configurando desviaciones NET"

# NET-001..007  Parámetros del núcleo inseguros, aplicados en caliente y de forma
# persistente para que sobrevivan al reinicio.
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.accept_redirects=1
sysctl -w net.ipv4.conf.all.send_redirects=1
sysctl -w net.ipv4.tcp_syncookies=0
sysctl -w net.ipv4.conf.all.accept_source_route=1
sysctl -w net.ipv4.conf.all.log_martians=0
sysctl -w net.ipv4.conf.all.rp_filter=0
cat > /etc/sysctl.d/99-vulnerable.conf << 'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.tcp_syncookies = 0
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.all.rp_filter = 0
EOF

# NET-008  ufw inactivo   y   NET-009  política de entrada permisiva (ACCEPT)
apt-get install -y ufw
ufw --force reset
ufw default allow incoming
ufw default allow outgoing
ufw disable

# ── SSH — Acceso remoto (12 reglas) ─────────────────────────────────────────
log "Configurando desviaciones SSH"

# Drop-in con prefijo 00 para ganar precedencia sobre 50-cloud-init
# (sshd aplica el primer valor leído).
cat > /etc/ssh/sshd_config.d/00-vulnerable.conf << 'EOF'
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
X11Forwarding yes
AllowTcpForwarding yes
AllowAgentForwarding yes
MaxAuthTries 10
LoginGraceTime 120
Banner none
LogLevel QUIET
Ciphers aes128-cbc,3des-cbc,aes256-cbc
MACs hmac-md5,hmac-sha1
EOF
systemctl restart ssh

# ── ACC — Cuentas de usuario (3 reglas) ─────────────────────────────────────
log "Configurando desviaciones ACC"

# ACC-001  Caducidad de contraseña excesiva
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/' /etc/login.defs

# ACC-002  Complejidad insuficiente (minlen=6, por debajo del mínimo CIS de 14)
apt-get install -y libpam-pwquality
sed -i '/pam_pwquality/d' /etc/pam.d/common-password
sed -i '/pam_unix/i password requisite pam_pwquality.so retry=3 minlen=6' /etc/pam.d/common-password

# ACC-003  Sin bloqueo por intentos fallidos (pam_faillock ausente)
sed -i '/pam_faillock/d' /etc/pam.d/common-auth

# ── PERM — Permisos de ficheros (8 reglas) ──────────────────────────────────
log "Configurando desviaciones PERM"

chmod 0666 /etc/passwd       # PERM-001  world-writable
chmod 0644 /etc/shadow       # PERM-002  legible por otros
chmod 0644 /etc/gshadow      # PERM-003  legible por otros
chmod 0666 /etc/group        # PERM-004  world-writable
# PERM-005  /etc/ssh/sshd_config ya viene en 644 por defecto (CIS pide 600);
#           no requiere acción de aprovisionamiento.
chmod 0777 /var/log          # PERM-006  world-writable
chmod 0644 /etc/crontab      # PERM-007  legible por otros (CIS pide 600)
chmod 0644 /etc/sudoers      # PERM-008  legible por otros (CIS pide 440)

# ── LOG — Registro de eventos (3 reglas) ────────────────────────────────────
log "Configurando desviaciones LOG"

# LOG-001  auditd inactivo (se desinstala)
systemctl stop auditd 2>/dev/null || true
systemctl disable auditd 2>/dev/null || true
apt-get remove -y auditd 2>/dev/null || true

# LOG-002  journald sin persistencia
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/00-vulnerable.conf << 'EOF'
[Journal]
Storage=volatile
EOF
systemctl restart systemd-journald

# LOG-003  rsyslog inactivo
systemctl stop rsyslog 2>/dev/null || true
systemctl disable rsyslog 2>/dev/null || true

# ── UPD — Actualizaciones (3 reglas) ────────────────────────────────────────
log "Configurando desviaciones UPD"

# UPD-001  Actualizaciones pendientes: NO se ejecuta `apt upgrade` de forma
# deliberada, porque las actualizaciones pendientes son, en sí mismas, la
# vulnerabilidad que la regla evalúa.
log "UPD-001: actualizaciones pendientes preservadas (no se ejecuta upgrade)"

# UPD-002  Actualizaciones automáticas deshabilitadas
apt-get install -y unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF

# UPD-003  Instalación de paquetes sin autenticar permitida
cat > /etc/apt/apt.conf.d/99-vulnerable << 'EOF'
APT::Get::AllowUnauthenticated "true";
EOF

log "vulnerable.sh completado — 43 desviaciones aplicadas"
