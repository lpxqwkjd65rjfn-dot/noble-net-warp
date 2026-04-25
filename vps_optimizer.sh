#!/bin/bash
# shellcheck disable=SC2059

# ==============================================================================
# VPS Global Optimization Script (v6.1 PHOENIX - HUMAN PROFILE EDITION)
# ------------------------------------------------------------------------------
#  - Adaptive TCP/UDP buffers (BDP-aware, scales with RAM)
#  - Robust BBR/BBR2/BBR3 detection (no blind modprobe)
#  - Correct RPS/RFS bitmask for >32 cores
#  - LRO disabled (critical for forwarding/proxy use-cases)
#  - File descriptor limits actually applied (limits.conf + nr_open)
#  - ZRAM tuned with vm.swappiness=180 / page-cluster=0
#  - Persistent RPS via systemd unit (survives reboots)
#  - Stealth iOS noise: realistic UA pool, HTTP/3 + HTTP/2, TLS 1.3,
#    iOS service endpoints (apple, icloud, mzstatic, push), human-like
#    burst/idle timing, optional curl-impersonate-safari for full JA3.
#  - RU human profile: Yandex/Mail.ru/Max.ru email + news sites with
#    configurable session intervals (recommended OR fully custom).
#  - Phantom APT activity: periodic apt-get update + .deb downloads of
#    libraries and OS images that are immediately discarded — looks like
#    a normal Ubuntu host running unattended-upgrades.
#  - All noise parameters externalised to /etc/vps-noise.conf and editable.
# ==============================================================================

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

SYSCTL_CONF="/etc/sysctl.d/99-vps-optimizer.conf"
LIMITS_CONF="/etc/security/limits.d/99-vps-limits.conf"
NOISE_GEN_SCRIPT="/usr/local/bin/vps_noise_gen.sh"
NOISE_GEN_SERVICE="/etc/systemd/system/vps-noise.service"
RPS_BOOT_SCRIPT="/usr/local/sbin/vps_rps_boot.sh"
RPS_BOOT_SERVICE="/etc/systemd/system/vps-rps.service"
EXP_CONF="/etc/sysctl.d/99-vps-experimental.conf"
SYSCTL_BACKUP="/etc/sysctl.d/.99-vps-optimizer.bak"
NOISE_CONF="/etc/vps-noise.conf"

print_header() {
    clear
    echo -e "${MAGENTA}${BOLD}"
    echo "================================================================="
    echo "     ULTRA VPS ACCELERATOR v6.1 (PHOENIX / HUMAN PROFILE)      "
    echo "================================================================="
    echo -e "  Adaptive Buffers | RPS/RFS | ZRAM | iOS+RU Stealth | APT Phantom"
    echo -e "=================================================================${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Запустите от имени root.${NC}"
        exit 1
    fi
}

# Доступен ли указанный congestion control в ядре?
has_cong_ctl() {
    local algo="$1"
    grep -qw "$algo" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null
}

# Корректно строим bitmask CPU для rps_cpus, формат группами по 32 бита,
# разделёнными запятыми (старшие биты слева). Работает для >32 ядер.
build_cpu_mask() {
    local n=$1
    if [ "$n" -le 0 ]; then echo "0"; return; fi
    local groups=$(( (n + 31) / 32 ))
    local last_bits=$(( n - (groups - 1) * 32 ))
    local first
    if [ "$last_bits" -ge 32 ]; then
        first="ffffffff"
    else
        first=$(printf '%x' $(( (1 << last_bits) - 1 )))
    fi
    local rest=""
    local i
    for ((i=1; i<groups; i++)); do
        rest=",ffffffff${rest}"
    done
    echo "${first}${rest}"
}

run_benchmark() {
    clear
    echo -e "${CYAN}${BOLD}=== ТЕСТ ЗАДЕРЖКИ (BENCHMARK) ===${NC}"
    echo "Замеряем средний пинг до глобальных узлов..."

    local targets=("www.google.com" "www.apple.com" "1.1.1.1" "www.cloudflare.com")
    local target ping_res
    for target in "${targets[@]}"; do
        echo -n "Тест $target: "
        ping_res=$(ping -c 4 -W 2 "$target" 2>/dev/null | awk -F '/' 'END {if ($5) print $5; else print ""}')
        if [ -z "$ping_res" ]; then
            echo -e "${RED}ОШИБКА (Timeout)${NC}"
        else
            echo -e "${GREEN}${ping_res} ms${NC}"
        fi
    done

    echo ""
    echo -e "${CYAN}Текущий congestion control:${NC} $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    echo -e "${CYAN}Текущий qdisc по умолчанию:${NC}  $(sysctl -n net.core.default_qdisc 2>/dev/null)"
    echo -e "${CYAN}Доступные алгоритмы:${NC}        $(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)"
    echo ""
    read -r -p "Нажмите Enter..."
}

install_dependencies() {
    echo -e "${YELLOW}[*] Установка компонентов Phoenix...${NC}"
    apt-get update -y
    apt-get install -y --no-install-recommends \
        curl ca-certificates ethtool iproute2 iputils-ping \
        dnsmasq util-linux bc zram-tools jq nano \
        apt-utils dpkg-dev >/dev/null 2>&1

    # Локальный DNS-кэш (dnsmasq) — резко снижает RTT на повторные запросы
    cat > /etc/dnsmasq.d/vps-speed.conf <<EOF
listen-address=127.0.0.1
bind-interfaces
cache-size=10000
no-resolv
no-negcache
neg-ttl=60
min-cache-ttl=60
server=1.1.1.1
server=1.0.0.1
server=8.8.8.8
server=8.8.4.4
EOF
    systemctl restart dnsmasq >/dev/null 2>&1 || true

    echo -e "${GREEN}[+] Базовые компоненты установлены.${NC}"
    echo -e "${YELLOW}[i] Опционально: curl-impersonate-safari даёт TLS/JA3 как у iOS.${NC}"
    echo -e "${YELLOW}    https://github.com/lwthiker/curl-impersonate (release binaries)${NC}"
    sleep 1
}

apply_optimizations() {
    echo -e "${YELLOW}[*] Глобальный тюнинг системы v6.1 PHOENIX...${NC}"

    # Сохраняем оригинал, если уже был наш конфиг
    if [ -f "$SYSCTL_CONF" ] && [ ! -f "$SYSCTL_BACKUP" ]; then
        cp "$SYSCTL_CONF" "$SYSCTL_BACKUP"
    fi

    # 1. RPS/RFS — раздаём softirq по всем ядрам
    local interfaces cpu_cores rps_mask iface
    interfaces=$(ip -o link show | awk -F': ' '$2 !~ /^(lo|virbr|docker|veth|wg|tun|tap|gre|ppp|br-|cilium|kube)/ {print $2}')
    cpu_cores=$(nproc)
    rps_mask=$(build_cpu_mask "$cpu_cores")

    for iface in $interfaces; do
        echo -e "${YELLOW}[*] RPS/RFS тюнинг: $iface (Маска: $rps_mask)${NC}"
        local f
        for f in /sys/class/net/"$iface"/queues/rx-*/rps_cpus; do
            if [ -e "$f" ]; then echo "$rps_mask" > "$f" 2>/dev/null || true; fi
        done
        echo "32768" > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
        for f in /sys/class/net/"$iface"/queues/rx-*/rps_flow_cnt; do
            if [ -e "$f" ]; then echo "4096" > "$f" 2>/dev/null || true; fi
        done

        # Аппаратное ускорение. ВАЖНО: LRO выключаем — он ломает форвардинг
        # (а именно ради проксирования/туннелей этот скрипт и используют).
        ethtool -K "$iface" rx on tx on sg on tso on gso on gro on lro off >/dev/null 2>&1 || true

        # Поднимаем ring buffers до максимума, если железо разрешает
        local ring_max_rx ring_max_tx
        ring_max_rx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^RX:/{print $2; exit}')
        ring_max_tx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^TX:/{print $2; exit}')
        if [ -n "$ring_max_rx" ] && [ -n "$ring_max_tx" ]; then
            ethtool -G "$iface" rx "$ring_max_rx" tx "$ring_max_tx" >/dev/null 2>&1 || true
        fi

        # Адаптивная коалесценция прерываний — лучше для смешанной нагрузки
        ethtool -C "$iface" adaptive-rx on adaptive-tx on >/dev/null 2>&1 || \
            ethtool -C "$iface" rx-usecs 8 tx-usecs 8 >/dev/null 2>&1 || true
    done

    # Делаем RPS-настройки персистентными (через systemd) — без этого
    # настройки очередей сбрасываются при ребуте.
    cat > "$RPS_BOOT_SCRIPT" <<'RPS_EOF'
#!/bin/bash
set -e
build_cpu_mask() {
    local n=$1
    if [ "$n" -le 0 ]; then echo "0"; return; fi
    local groups=$(( (n + 31) / 32 ))
    local last_bits=$(( n - (groups - 1) * 32 ))
    local first
    if [ "$last_bits" -ge 32 ]; then
        first="ffffffff"
    else
        first=$(printf '%x' $(( (1 << last_bits) - 1 )))
    fi
    local rest="" i
    for ((i=1; i<groups; i++)); do rest=",ffffffff${rest}"; done
    echo "${first}${rest}"
}
MASK=$(build_cpu_mask "$(nproc)")
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
for IFACE in $(ip -o link show | awk -F': ' '$2 !~ /^(lo|virbr|docker|veth|wg|tun|tap|gre|ppp|br-|cilium|kube)/ {print $2}'); do
    for f in /sys/class/net/"$IFACE"/queues/rx-*/rps_cpus; do
        [ -e "$f" ] && echo "$MASK" > "$f" 2>/dev/null || true
    done
    for f in /sys/class/net/"$IFACE"/queues/rx-*/rps_flow_cnt; do
        [ -e "$f" ] && echo 4096 > "$f" 2>/dev/null || true
    done
    ethtool -K "$IFACE" lro off >/dev/null 2>&1 || true
done
RPS_EOF
    chmod +x "$RPS_BOOT_SCRIPT"
    cat > "$RPS_BOOT_SERVICE" <<EOF
[Unit]
Description=VPS RPS/RFS persistent tuning
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$RPS_BOOT_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now vps-rps.service >/dev/null 2>&1 || true

    # 2. ZRAM
    if modprobe zram 2>/dev/null; then
        echo -e "${YELLOW}[*] Активация ZRAM акселератора...${NC}"
        swapoff /dev/zram0 2>/dev/null || true
        zramctl --reset /dev/zram0 2>/dev/null || true

        local mem_total zram_size
        mem_total=$(free -m | awk '/Mem:/{print $2}')
        # Сжатый swap размером ~50% RAM (zstd ~3x сжатие → ~1.5x эффективной RAM).
        zram_size=$(( mem_total / 2 ))
        if [ "$zram_size" -lt 256 ]; then zram_size=256; fi

        zramctl --find --size "${zram_size}M" --algorithm zstd >/dev/null 2>&1 || \
            zramctl --find --size "${zram_size}M" --algorithm lz4 >/dev/null 2>&1
        mkswap /dev/zram0 >/dev/null 2>&1
        swapon /dev/zram0 -p 100 2>/dev/null || true
        echo -e "${GREEN}[+] ZRAM активен (${zram_size}MB).${NC}"
    else
        echo -e "${RED}[!] ZRAM не поддерживается ядром.${NC}"
    fi

    # 3. Подбираем лучший congestion control из реально доступных
    local best_bbr="cubic"
    if has_cong_ctl bbr3; then best_bbr="bbr3"
    elif has_cong_ctl bbr2; then best_bbr="bbr2"
    elif has_cong_ctl bbr;  then best_bbr="bbr"
    fi

    # Лучший qdisc: cake (умный, AQM), fq (BBR-friendly), fq_codel (fallback)
    local best_qdisc="fq_codel"
    if modprobe sch_cake 2>/dev/null; then best_qdisc="cake"
    elif modprobe sch_fq 2>/dev/null;   then best_qdisc="fq"
    fi
    # BBR любит именно fq — если он есть, оставляем fq
    if [ "$best_bbr" != "cubic" ] && modprobe sch_fq 2>/dev/null; then
        best_qdisc="fq"
    fi

    # 4. Адаптивные буферы. BDP для 1Gbps×100ms ≈ 12MB,
    # для 10Gbps×100ms ≈ 125MB. Берём 128MB как разумный максимум,
    # на жирной RAM поднимаем до 256MB. UDP отдельно — критично для QUIC/Reality.
    local mem_mb buf_max=134217728
    mem_mb=$(free -m | awk '/Mem:/{print $2}')
    if [ "$mem_mb" -ge 8192 ]; then buf_max=268435456; fi
    if [ "$mem_mb" -ge 16384 ]; then buf_max=536870912; fi

    cat > "$SYSCTL_CONF" <<EOF
# === Phoenix Performance ===
fs.file-max = 2000000
fs.nr_open = 2000000
kernel.pid_max = 4194304

# --- Networking core ---
net.core.default_qdisc = $best_qdisc
net.ipv4.tcp_congestion_control = $best_bbr
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
net.core.netdev_max_backlog = 500000
net.core.somaxconn = 65535
net.core.busy_poll = 50
net.core.busy_read = 50
net.core.optmem_max = 4194304
net.core.rps_sock_flow_entries = 32768

# --- TCP buffers (BDP-tuned, scales with RAM) ---
net.core.rmem_max = $buf_max
net.core.wmem_max = $buf_max
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.ipv4.tcp_rmem = 4096 2097152 $buf_max
net.ipv4.tcp_wmem = 4096 2097152 $buf_max
net.ipv4.tcp_mem = 786432 1048576 1572864
net.ipv4.tcp_adv_win_scale = -2
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_notsent_lowat = 131072

# --- UDP buffers (важно для QUIC/Reality/XHTTP) ---
net.ipv4.udp_rmem_min = 131072
net.ipv4.udp_wmem_min = 131072
net.ipv4.udp_mem = 786432 1048576 1572864

# --- TCP behavior ---
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 0
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.ipv4.ip_local_port_range = 10000 65535

# --- Stealth / маскировка стека под обычный десктоп ---
# TTL=64 — стандартное значение Linux (а не «64 минус N» как у тоннелей).
# Это убирает явный признак, что трафик вышел из-под VPN/прокси.
net.ipv4.ip_default_ttl = 64

# --- Security ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

# --- IPv6 mirror ---
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0

# --- VM/ZRAM tuning ---
vm.swappiness = 180
vm.page-cluster = 0
vm.vfs_cache_pressure = 50
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
vm.min_free_kbytes = 65536
EOF

    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true

    # 5. Лимиты файловых дескрипторов — раньше переменная LIMITS_CONF
    # объявлялась, но никогда не использовалась. Это критично для
    # высоконагруженных прокси (xray, sing-box, haproxy).
    cat > "$LIMITS_CONF" <<EOF
*       soft    nofile  1048576
*       hard    nofile  1048576
root    soft    nofile  1048576
root    hard    nofile  1048576
*       soft    nproc   unlimited
*       hard    nproc   unlimited
EOF
    # systemd unit-files игнорируют limits.conf — ставим лимиты и для них.
    mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
    cat > /etc/systemd/system.conf.d/99-vps-limits.conf <<EOF
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=infinity
EOF
    cat > /etc/systemd/user.conf.d/99-vps-limits.conf <<EOF
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=infinity
EOF
    systemctl daemon-reexec >/dev/null 2>&1 || true

    echo -e "${GREEN}[+] Phoenix v6.1: BBR=${best_bbr}, qdisc=${best_qdisc}, buf_max=${buf_max}.${NC}"
    echo ""
    read -r -p "Нажмите Enter..."
}

#
# ----- Конфиг шумогенератора (рекомендованные значения) -----
#
# Что задаём в /etc/vps-noise.conf:
#   PROFILE             — какие домены крутить: ru | global | mixed
#   ENABLE_IOS_BURST    — фоновые «листания» iOS Safari (apple/icloud)
#   ENABLE_APNS         — TCP-keepalive на courier.push.apple.com:5223
#   ENABLE_EMAIL        — заходы на почту (Яндекс/Mail.ru/Max.ru)
#   ENABLE_NEWS         — новостные сайты + соцсети РФ
#   ENABLE_APT_PHANTOM  — фантомные APT-загрузки (пакеты + образы ОС)
#   *_INTERVAL_MIN/MAX  — диапазон случайной паузы между сессиями
#   APT_PHANTOM_PACKAGES — какие .deb качать и сразу выкидывать
#
# Рекомендованные значения подобраны так, чтобы суточная активность
# совпадала с поведением реального человека в РФ: ~10 проверок почты
# в день, ~25–40 заглядываний в новости, ~1–4 «обновления системы».
#
write_default_noise_conf() {
    cat > "$NOISE_CONF" <<'CONF_EOF'
# ============================================================
#  Конфиг VPS Noise Generator (Phoenix v6.1)
#  Все интервалы — в МИНУТАХ. Безопасно редактируется руками,
#  затем: systemctl restart vps-noise
# ============================================================

# Профиль доменов: ru | global | mixed
PROFILE="ru"

# --- Что включено ---
ENABLE_IOS_BURST=1        # фон iOS Safari (apple.com / icloud.com / ...)
ENABLE_APNS=1             # TCP-keepalive courier.push.apple.com:5223
ENABLE_EMAIL=1            # заходы в Яндекс.Почту / Mail.ru / Max.ru
ENABLE_NEWS=1             # новостные сайты + соцсети РФ
ENABLE_APT_PHANTOM=1      # фантомные APT-загрузки (libs + OS images)

# --- iOS бёрсты (рекомендованные: каждые 1–6 минут днём) ---
IOS_BURST_INTERVAL_MIN=1
IOS_BURST_INTERVAL_MAX=6

# --- Email-сессии (рекомендованные: каждые 45–180 минут) ---
# Реальный человек открывает почту 5–10 раз в день, по 1–3 минуты.
EMAIL_INTERVAL_MIN=45
EMAIL_INTERVAL_MAX=180

# --- News-сессии (рекомендованные: каждые 20–90 минут) ---
# Чтение новостей/соцсетей: ~25–40 коротких сессий за день.
NEWS_INTERVAL_MIN=20
NEWS_INTERVAL_MAX=90

# --- APT phantom (рекомендованные: каждые 6–24 часа = 360–1440 мин) ---
# unattended-upgrades в Ubuntu тикает раз в сутки, плюс пользователь
# часто руками вызывает apt update / apt install ~раз в несколько дней.
APT_PHANTOM_INTERVAL_MIN=360
APT_PHANTOM_INTERVAL_MAX=1440

# Сколько пакетов качать за один проход (1..N)
APT_PHANTOM_PKG_MIN=1
APT_PHANTOM_PKG_MAX=3

# Список «обычных» пакетов — они есть в стандартных репах Ubuntu,
# их регулярно тянут реальные админы. Можно дополнять.
APT_PHANTOM_PACKAGES="curl wget vim htop git tmux build-essential nginx \
ca-certificates net-tools iputils-ping rsync unzip zip jq python3-pip \
nodejs npm postgresql-client redis-tools mariadb-client tcpdump"

# Иногда (с этим шансом, 0..100) вместо обычной библиотеки качаем
# тяжёлый «образ ОС» — ядро, ubuntu-server, linux-headers. Это даёт
# редкие, но крупные всплески трафика, как при апгрейде дистрибутива.
APT_PHANTOM_OS_CHANCE=20
APT_PHANTOM_OS_PACKAGES="linux-image-generic linux-headers-generic \
ubuntu-server ubuntu-minimal cloud-init systemd"

# Если =1, вообще ничего не сохраняем на диск (всё уходит в /dev/null
# через --print-uris + curl). Если =0 — используется apt-get download
# во временный каталог с моментальным rm.
APT_PHANTOM_BLACKHOLE=1

# Глобальный rate-limit для curl (KB/s, диапазон min..max).
RATE_KB_MIN=500
RATE_KB_MAX=3500

# Окна суток (часы 0..23). Изменив их, можно подвинуть «график дня».
NIGHT_HOUR_FROM=1
NIGHT_HOUR_TO=6
PEAK_MORNING_FROM=7
PEAK_MORNING_TO=9
PEAK_EVENING_FROM=18
PEAK_EVENING_TO=23
CONF_EOF
}

# Показать текущий конфиг
show_noise_conf() {
    if [ -f "$NOISE_CONF" ]; then
        echo -e "${CYAN}--- $NOISE_CONF ---${NC}"
        cat "$NOISE_CONF"
    else
        echo -e "${YELLOW}[i] Конфиг ещё не создан.${NC}"
    fi
}

# Интерактивный ввод. Enter — оставить рекомендуемое значение.
prompt_custom_noise_conf() {
    [ -f "$NOISE_CONF" ] || write_default_noise_conf
    # shellcheck disable=SC1090
    source "$NOISE_CONF"

    echo -e "${CYAN}${BOLD}=== Кастомизация шумогенератора ===${NC}"
    echo -e "${YELLOW}Enter — оставить рекомендованное значение.${NC}"
    echo ""

    local v
    read -r -p "Профиль (ru/global/mixed) [${PROFILE}]: " v;             PROFILE="${v:-$PROFILE}"
    read -r -p "iOS-бёрсты (1=да/0=нет) [${ENABLE_IOS_BURST}]: " v;      ENABLE_IOS_BURST="${v:-$ENABLE_IOS_BURST}"
    read -r -p "APNs keepalive (1/0) [${ENABLE_APNS}]: " v;              ENABLE_APNS="${v:-$ENABLE_APNS}"
    read -r -p "Заходы в почту (1/0) [${ENABLE_EMAIL}]: " v;             ENABLE_EMAIL="${v:-$ENABLE_EMAIL}"
    read -r -p "Новости/соц.сети РФ (1/0) [${ENABLE_NEWS}]: " v;         ENABLE_NEWS="${v:-$ENABLE_NEWS}"
    read -r -p "APT-фантом (1/0) [${ENABLE_APT_PHANTOM}]: " v;           ENABLE_APT_PHANTOM="${v:-$ENABLE_APT_PHANTOM}"

    echo ""
    echo -e "${CYAN}-- Email-сессии --${NC}"
    echo -e "${YELLOW}Рекомендуется: 45..180 минут (≈10 проверок в день).${NC}"
    read -r -p "EMAIL_INTERVAL_MIN [мин, ${EMAIL_INTERVAL_MIN}]: " v;    EMAIL_INTERVAL_MIN="${v:-$EMAIL_INTERVAL_MIN}"
    read -r -p "EMAIL_INTERVAL_MAX [мин, ${EMAIL_INTERVAL_MAX}]: " v;    EMAIL_INTERVAL_MAX="${v:-$EMAIL_INTERVAL_MAX}"

    echo ""
    echo -e "${CYAN}-- News-сессии --${NC}"
    echo -e "${YELLOW}Рекомендуется: 20..90 минут.${NC}"
    read -r -p "NEWS_INTERVAL_MIN [мин, ${NEWS_INTERVAL_MIN}]: " v;      NEWS_INTERVAL_MIN="${v:-$NEWS_INTERVAL_MIN}"
    read -r -p "NEWS_INTERVAL_MAX [мин, ${NEWS_INTERVAL_MAX}]: " v;      NEWS_INTERVAL_MAX="${v:-$NEWS_INTERVAL_MAX}"

    echo ""
    echo -e "${CYAN}-- APT-фантом --${NC}"
    echo -e "${YELLOW}Рекомендуется: 360..1440 минут (раз в 6–24 ч).${NC}"
    read -r -p "APT_PHANTOM_INTERVAL_MIN [мин, ${APT_PHANTOM_INTERVAL_MIN}]: " v
    APT_PHANTOM_INTERVAL_MIN="${v:-$APT_PHANTOM_INTERVAL_MIN}"
    read -r -p "APT_PHANTOM_INTERVAL_MAX [мин, ${APT_PHANTOM_INTERVAL_MAX}]: " v
    APT_PHANTOM_INTERVAL_MAX="${v:-$APT_PHANTOM_INTERVAL_MAX}"
    read -r -p "Шанс качнуть «образ ОС» вместо библиотеки (0..100) [${APT_PHANTOM_OS_CHANCE}]: " v
    APT_PHANTOM_OS_CHANCE="${v:-$APT_PHANTOM_OS_CHANCE}"
    read -r -p "Сразу в /dev/null без сохранения (1/0) [${APT_PHANTOM_BLACKHOLE}]: " v
    APT_PHANTOM_BLACKHOLE="${v:-$APT_PHANTOM_BLACKHOLE}"

    # Перезаписываем конфиг
    cat > "$NOISE_CONF" <<EOF
# vps-noise.conf (custom, $(date -u +%FT%TZ))
PROFILE="$PROFILE"

ENABLE_IOS_BURST=$ENABLE_IOS_BURST
ENABLE_APNS=$ENABLE_APNS
ENABLE_EMAIL=$ENABLE_EMAIL
ENABLE_NEWS=$ENABLE_NEWS
ENABLE_APT_PHANTOM=$ENABLE_APT_PHANTOM

IOS_BURST_INTERVAL_MIN=${IOS_BURST_INTERVAL_MIN}
IOS_BURST_INTERVAL_MAX=${IOS_BURST_INTERVAL_MAX}

EMAIL_INTERVAL_MIN=$EMAIL_INTERVAL_MIN
EMAIL_INTERVAL_MAX=$EMAIL_INTERVAL_MAX

NEWS_INTERVAL_MIN=$NEWS_INTERVAL_MIN
NEWS_INTERVAL_MAX=$NEWS_INTERVAL_MAX

APT_PHANTOM_INTERVAL_MIN=$APT_PHANTOM_INTERVAL_MIN
APT_PHANTOM_INTERVAL_MAX=$APT_PHANTOM_INTERVAL_MAX
APT_PHANTOM_PKG_MIN=${APT_PHANTOM_PKG_MIN}
APT_PHANTOM_PKG_MAX=${APT_PHANTOM_PKG_MAX}
APT_PHANTOM_PACKAGES="${APT_PHANTOM_PACKAGES}"
APT_PHANTOM_OS_CHANCE=$APT_PHANTOM_OS_CHANCE
APT_PHANTOM_OS_PACKAGES="${APT_PHANTOM_OS_PACKAGES}"
APT_PHANTOM_BLACKHOLE=$APT_PHANTOM_BLACKHOLE

RATE_KB_MIN=${RATE_KB_MIN}
RATE_KB_MAX=${RATE_KB_MAX}
NIGHT_HOUR_FROM=${NIGHT_HOUR_FROM}
NIGHT_HOUR_TO=${NIGHT_HOUR_TO}
PEAK_MORNING_FROM=${PEAK_MORNING_FROM}
PEAK_MORNING_TO=${PEAK_MORNING_TO}
PEAK_EVENING_FROM=${PEAK_EVENING_FROM}
PEAK_EVENING_TO=${PEAK_EVENING_TO}
EOF
    echo -e "${GREEN}[+] Конфиг сохранён в $NOISE_CONF${NC}"
}

manage_noise_generator() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}=== STEALTH NOISE GENERATOR (Phoenix v6.1) ===${NC}"
        local status
        if systemctl is-active --quiet vps-noise; then
            status="${GREEN}ВКЛЮЧЕН${NC}"
        else
            status="${RED}ОТКЛЮЧЕН${NC}"
        fi
        echo -e "Статус: $status"
        if [ -f "$NOISE_CONF" ]; then
            local p
            p=$(awk -F'"' '/^PROFILE=/{print $2}' "$NOISE_CONF")
            echo -e "Профиль: ${CYAN}${p:-?}${NC}    Конфиг: $NOISE_CONF"
        fi
        echo ""
        echo -e "  ${GREEN}[1]${NC} Запустить с ${BOLD}рекомендованными${NC} настройками"
        echo -e "  ${GREEN}[2]${NC} Запустить с ${BOLD}кастомными${NC} интервалами (мастер)"
        echo -e "  ${CYAN}[3]${NC} Открыть конфиг в редакторе (${EDITOR:-nano})"
        echo -e "  ${CYAN}[4]${NC} Показать текущий конфиг"
        echo -e "  ${YELLOW}[5]${NC} Перезапустить сервис (применить изменённый конфиг)"
        echo -e "  ${RED}[6]${NC} Выключить генератор"
        echo -e "  ${CYAN}[0]${NC} Назад"
        echo ""
        read -r -p "Выбор: " nchoice
        case $nchoice in
            1)
                write_default_noise_conf
                deploy_noise_generator
                echo -e "${GREEN}[+] Шум запущен с рекомендованными настройками.${NC}"
                sleep 2
                ;;
            2)
                prompt_custom_noise_conf
                deploy_noise_generator
                echo -e "${GREEN}[+] Шум запущен с кастомным конфигом.${NC}"
                sleep 2
                ;;
            3)
                [ -f "$NOISE_CONF" ] || write_default_noise_conf
                "${EDITOR:-nano}" "$NOISE_CONF"
                ;;
            4)
                clear
                show_noise_conf
                echo ""
                read -r -p "Нажмите Enter..."
                ;;
            5)
                systemctl restart vps-noise && echo -e "${GREEN}[+] Перезапущен.${NC}"
                sleep 1
                ;;
            6)
                systemctl stop vps-noise 2>/dev/null
                systemctl disable vps-noise 2>/dev/null
                sleep 1
                ;;
            0) return ;;
        esac
    done
}

# Раскладывает скрипт + systemd-юнит и (пере)запускает сервис.
deploy_noise_generator() {
    [ -f "$NOISE_CONF" ] || write_default_noise_conf
    cat > "$NOISE_GEN_SCRIPT" <<'NOISE_EOF'
#!/bin/bash
# vps-noise.sh — Phoenix v6.1 multi-profile noise generator.
# Полностью управляется через /etc/vps-noise.conf. Один процесс
# параллельно крутит несколько независимых сценариев активности:
#   - iOS Safari/CFNetwork бёрсты
#   - APNs keepalive
#   - Заходы в почту (Yandex/Mail.ru/Max.ru) — короткие сессии
#   - Чтение новостных сайтов и соцсетей РФ
#   - Фантомные APT-загрузки (.deb пакетов и тяжёлых ОС-образов)

set -u
umask 077

CONF="/etc/vps-noise.conf"
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"

# --- Дефолты на случай, если конфига нет / параметр забыли ---
PROFILE="${PROFILE:-ru}"
ENABLE_IOS_BURST="${ENABLE_IOS_BURST:-1}"
ENABLE_APNS="${ENABLE_APNS:-1}"
ENABLE_EMAIL="${ENABLE_EMAIL:-1}"
ENABLE_NEWS="${ENABLE_NEWS:-1}"
ENABLE_APT_PHANTOM="${ENABLE_APT_PHANTOM:-1}"

IOS_BURST_INTERVAL_MIN="${IOS_BURST_INTERVAL_MIN:-1}"
IOS_BURST_INTERVAL_MAX="${IOS_BURST_INTERVAL_MAX:-6}"
EMAIL_INTERVAL_MIN="${EMAIL_INTERVAL_MIN:-45}"
EMAIL_INTERVAL_MAX="${EMAIL_INTERVAL_MAX:-180}"
NEWS_INTERVAL_MIN="${NEWS_INTERVAL_MIN:-20}"
NEWS_INTERVAL_MAX="${NEWS_INTERVAL_MAX:-90}"
APT_PHANTOM_INTERVAL_MIN="${APT_PHANTOM_INTERVAL_MIN:-360}"
APT_PHANTOM_INTERVAL_MAX="${APT_PHANTOM_INTERVAL_MAX:-1440}"
APT_PHANTOM_PKG_MIN="${APT_PHANTOM_PKG_MIN:-1}"
APT_PHANTOM_PKG_MAX="${APT_PHANTOM_PKG_MAX:-3}"
APT_PHANTOM_OS_CHANCE="${APT_PHANTOM_OS_CHANCE:-20}"
APT_PHANTOM_BLACKHOLE="${APT_PHANTOM_BLACKHOLE:-1}"
APT_PHANTOM_PACKAGES="${APT_PHANTOM_PACKAGES:-curl wget vim htop git tmux nginx ca-certificates}"
APT_PHANTOM_OS_PACKAGES="${APT_PHANTOM_OS_PACKAGES:-linux-image-generic linux-headers-generic ubuntu-server}"
RATE_KB_MIN="${RATE_KB_MIN:-500}"
RATE_KB_MAX="${RATE_KB_MAX:-3500}"
NIGHT_HOUR_FROM="${NIGHT_HOUR_FROM:-1}"
NIGHT_HOUR_TO="${NIGHT_HOUR_TO:-6}"
PEAK_MORNING_FROM="${PEAK_MORNING_FROM:-7}"
PEAK_MORNING_TO="${PEAK_MORNING_TO:-9}"
PEAK_EVENING_FROM="${PEAK_EVENING_FROM:-18}"
PEAK_EVENING_TO="${PEAK_EVENING_TO:-23}"

# ===== UA-пулы =====
UA_IOS=(
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
"AppleCoreMedia/1.0.0.21F90 (iPhone; U; CPU OS 17_5 like Mac OS X; en_us)"
"itunesstored/1.0 iOS/17.5.1 model/iPhone15,3 hwp/t8120 build/21F90 (6; dt:248)"
"com.apple.WebKit.Networking/8617.2.4.0.6 CFNetwork/1492.0.1 Darwin/23.3.0"
)

# Десктоп — для почты/новостей/соцсетей это естественнее, чем iOS Safari
UA_DESKTOP=(
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 YaBrowser/24.4.0.0 Safari/537.36"
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
)

UA_MOBILE_RU=(
"Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
"Mozilla/5.0 (Linux; arm_64; Android 13; RMX3771) AppleWebKit/537.36 (KHTML, like Gecko) YaBrowser/24.4.0 Mobile Safari/537.36"
)

# ===== URL-пулы =====
URLS_IOS=(
"https://www.apple.com/" "https://www.apple.com/iphone/"
"https://www.apple.com/shop/buy-iphone" "https://support.apple.com/"
"https://www.icloud.com/" "https://apps.apple.com/"
"https://itunes.apple.com/lookup?id=284910350"
"https://configuration.apple.com/configurations/internetservices/safari/ContentBlockerLists.plist.signed"
"https://gateway.icloud.com/" "https://mesu.apple.com/assets/"
"https://swcdn.apple.com/" "https://updates.cdn-apple.com/"
"https://is1-ssl.mzstatic.com/" "https://gs-loc.apple.com/"
)
URLS_CAPTIVE=(
"https://captive.apple.com/hotspot-detect.html"
"https://www.apple.com/library/test/success.html"
"https://gsp64-ssl.ls.apple.com/"
)

# Yandex / Mail.ru / Max.ru — то, куда заходит реальный пользователь в РФ
# shellcheck disable=SC2034
URLS_EMAIL_YANDEX=(
"https://mail.yandex.ru/" "https://mail.yandex.ru/lite/"
"https://passport.yandex.ru/auth?origin=mail&from=mail"
"https://yandex.ru/" "https://disk.yandex.ru/"
"https://360.yandex.ru/mail/"
)
# shellcheck disable=SC2034
URLS_EMAIL_MAILRU=(
"https://mail.ru/" "https://e.mail.ru/inbox/" "https://e.mail.ru/login"
"https://account.mail.ru/login" "https://my.mail.ru/" "https://cloud.mail.ru/"
)
# shellcheck disable=SC2034
URLS_EMAIL_MAX=(
"https://max.ru/" "https://web.max.ru/" "https://max.ru/about"
)

URLS_NEWS_RU=(
"https://lenta.ru/" "https://ria.ru/" "https://www.rbc.ru/"
"https://tass.ru/" "https://www.kommersant.ru/" "https://www.vedomosti.ru/"
"https://www.gazeta.ru/" "https://rg.ru/" "https://iz.ru/"
"https://www.interfax.ru/" "https://www.kp.ru/"
"https://dzen.ru/news" "https://www.fontanka.ru/" "https://www.mk.ru/"
"https://meduza.io/"
)
URLS_SOCIAL_RU=(
"https://vk.com/" "https://ok.ru/" "https://dzen.ru/"
"https://t.me/s/durov" "https://www.wildberries.ru/" "https://www.ozon.ru/"
"https://www.avito.ru/" "https://hh.ru/"
)
URLS_SEARCH_RU=(
"https://yandex.ru/" "https://ya.ru/" "https://www.google.com/"
)

# shellcheck disable=SC2034
URLS_GLOBAL=(
"https://www.bing.com/" "https://duckduckgo.com/"
"https://www.wikipedia.org/" "https://www.reddit.com/"
"https://news.ycombinator.com/" "https://www.bbc.com/"
"https://www.cnn.com/" "https://www.nytimes.com/"
)

ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
ACCEPT_LANG_RU="ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
ACCEPT_LANG_EN="en-US,en;q=0.9"
ACCEPT_ENC="gzip, deflate, br"

# ===== Бинарь curl =====
pick_curl() {
    if command -v curl_safari17_4 >/dev/null 2>&1; then echo curl_safari17_4
    elif command -v curl_safari16_5 >/dev/null 2>&1; then echo curl_safari16_5
    elif command -v curl-impersonate-safari >/dev/null 2>&1; then echo curl-impersonate-safari
    else echo curl
    fi
}
CURL_BIN=$(pick_curl)

COOKIE_JAR_DIR="/tmp/.vps_noise"
mkdir -p "$COOKIE_JAR_DIR"
chmod 700 "$COOKIE_JAR_DIR"

# Случайное число в диапазоне [a, b]
rrange() { echo $(( RANDOM % ($2 - $1 + 1) + $1 )); }

# Случайный rate-limit
rand_rate() { echo $(( RANDOM % (RATE_KB_MAX - RATE_KB_MIN + 1) + RATE_KB_MIN )); }

# ===== Один HTTP-запрос =====
# Аргументы: $1 — URL, $2 — UA-pool name (ios|desktop|mobile_ru), $3 — lang (ru|en), $4 — cookie tag
http_request() {
    local url="$1" ua_kind="${2:-ios}" lang="${3:-en}" tag="${4:-default}"
    local ua jar="$COOKIE_JAR_DIR/${tag}.jar"
    case "$ua_kind" in
        ios)        ua="${UA_IOS[$RANDOM % ${#UA_IOS[@]}]}" ;;
        desktop)    ua="${UA_DESKTOP[$RANDOM % ${#UA_DESKTOP[@]}]}" ;;
        mobile_ru)  ua="${UA_MOBILE_RU[$RANDOM % ${#UA_MOBILE_RU[@]}]}" ;;
        *)          ua="${UA_DESKTOP[$RANDOM % ${#UA_DESKTOP[@]}]}" ;;
    esac
    local accept_lang="$ACCEPT_LANG_EN"
    [ "$lang" = "ru" ] && accept_lang="$ACCEPT_LANG_RU"

    touch "$jar"

    local rate
    rate=$(rand_rate)
    local args=(
        -s -o /dev/null
        --max-time 25 --connect-timeout 8
        --tls-max 1.3 --tlsv1.2
        --compressed
        --cookie-jar "$jar" --cookie "$jar"
        -A "$ua"
        -H "Accept: $ACCEPT"
        -H "Accept-Language: $accept_lang"
        -H "Accept-Encoding: $ACCEPT_ENC"
        -H "Sec-Fetch-Dest: document"
        -H "Sec-Fetch-Mode: navigate"
        -H "Sec-Fetch-Site: none"
        -H "Upgrade-Insecure-Requests: 1"
        -H "Priority: u=0, i"
        --limit-rate "${rate}K"
    )
    if [ "$CURL_BIN" = "curl" ]; then
        if (( RANDOM % 3 == 0 )) && curl --help all 2>/dev/null | grep -q -- '--http3'; then
            args+=(--http3)
        else
            args+=(--http2)
        fi
    fi
    "$CURL_BIN" "${args[@]}" "$url" 2>/dev/null || true
}

# ===== APNs keepalive =====
apns_keepalive() {
    timeout 6 bash -c 'exec 3<>/dev/tcp/courier.push.apple.com/5223 && sleep 3' 2>/dev/null || true
}

# ===== iOS Safari бёрст =====
ios_burst() {
    local n url
    n=$(rrange 3 8)
    http_request "${URLS_IOS[$RANDOM % ${#URLS_IOS[@]}]}" ios en ios_session
    sleep "$(rrange 1 4)"
    local i
    for ((i=1; i<n; i++)); do
        url="${URLS_IOS[$RANDOM % ${#URLS_IOS[@]}]}"
        http_request "$url" ios en ios_session
        sleep "$(rrange 1 6)"
    done
    # Иногда — captive check
    if (( RANDOM % 5 == 0 )); then
        http_request "${URLS_CAPTIVE[$RANDOM % ${#URLS_CAPTIVE[@]}]}" ios en ios_captive
    fi
}

# ===== Email session =====
# Поведение: открыть главную почты → 2-5 переходов внутри → пауза.
# Чередуется между Яндексом, Mail.ru и Max.ru.
email_session() {
    local provider=$(( RANDOM % 3 ))
    local urls_var url n i
    case $provider in
        0) urls_var=URLS_EMAIL_YANDEX ;;
        1) urls_var=URLS_EMAIL_MAILRU ;;
        2) urls_var=URLS_EMAIL_MAX ;;
    esac
    # bash 4.3+ nameref — чисто и без eval
    local -n arr="$urls_var"
    n=$(rrange 2 5)
    for ((i=0; i<n; i++)); do
        url="${arr[$RANDOM % ${#arr[@]}]}"
        # 70% десктоп, 30% мобильный РФ-браузер
        if (( RANDOM % 10 < 7 )); then
            http_request "$url" desktop ru email
        else
            http_request "$url" mobile_ru ru email
        fi
        sleep "$(rrange 4 25)"
    done
}

# ===== News session =====
news_session() {
    local n url i
    # Стартовая точка — поисковик или прямой заход на новостник
    if (( RANDOM % 3 == 0 )); then
        http_request "${URLS_SEARCH_RU[$RANDOM % ${#URLS_SEARCH_RU[@]}]}" desktop ru news
        sleep "$(rrange 2 7)"
    fi
    n=$(rrange 3 9)
    for ((i=0; i<n; i++)); do
        if (( RANDOM % 4 == 0 )); then
            url="${URLS_SOCIAL_RU[$RANDOM % ${#URLS_SOCIAL_RU[@]}]}"
        else
            url="${URLS_NEWS_RU[$RANDOM % ${#URLS_NEWS_RU[@]}]}"
        fi
        if (( RANDOM % 10 < 6 )); then
            http_request "$url" desktop ru news
        else
            http_request "$url" mobile_ru ru news
        fi
        sleep "$(rrange 6 40)"
    done
}

# ===== APT phantom =====
# Настоящий unattended-upgrades регулярно делает `apt-get update` и
# подкачивает .deb. Мы делаем то же самое, но всё, что скачали —
# мгновенно отправляем в /dev/null. Системе не наносится никакого
# вреда: ни пакеты не ставятся, ни кэш не пухнет.
apt_phantom_run() {
    # apt-get update — это нормальная операция, она и так бы выполнялась.
    apt-get -qq -o Acquire::Languages=none update >/dev/null 2>&1 || true

    # APT_PHANTOM_PACKAGES — список через пробел, словосплит здесь намеренный
    # shellcheck disable=SC2206
    local pkgs=( $APT_PHANTOM_PACKAGES )
    # shellcheck disable=SC2206
    local os_pkgs=( $APT_PHANTOM_OS_PACKAGES )

    local n
    n=$(rrange "$APT_PHANTOM_PKG_MIN" "$APT_PHANTOM_PKG_MAX")

    local i pkg use_os tmpd
    for ((i=0; i<n; i++)); do
        use_os=0
        if (( RANDOM % 100 < APT_PHANTOM_OS_CHANCE )); then
            use_os=1
            pkg="${os_pkgs[$RANDOM % ${#os_pkgs[@]}]}"
        else
            pkg="${pkgs[$RANDOM % ${#pkgs[@]}]}"
        fi

        if [ "$APT_PHANTOM_BLACKHOLE" = "1" ]; then
            # Получаем список URI и тащим curl-ом прямо в /dev/null —
            # на диск ничего не пишется вообще.
            local uri_list
            uri_list=$(apt-get -y -qq --print-uris install --reinstall "$pkg" 2>/dev/null \
                       | awk -F"'" '/^'\''http/{print $2}')
            [ -z "$uri_list" ] && uri_list=$(apt-get -y -qq --print-uris download "$pkg" 2>/dev/null \
                       | awk -F"'" '/^'\''http/{print $2}')
            local u rate
            rate=$(rand_rate)
            for u in $uri_list; do
                curl -s -L --max-time 120 --connect-timeout 10 \
                    --limit-rate "${rate}K" \
                    -A "Debian APT-HTTP/1.3 (2.7.14) Ubuntu/24.04" \
                    "$u" -o /dev/null 2>/dev/null || true
            done
        else
            # Сохраняем .deb в tmpfs / временный каталог и сразу же rm.
            tmpd=$(mktemp -d /tmp/.apt_phantom.XXXXXX)
            ( cd "$tmpd" && apt-get -qq download "$pkg" >/dev/null 2>&1 || true )
            rm -rf "$tmpd"
        fi
        sleep "$(rrange 5 30)"

        # Ослабленный шум: «пользователь смотрит, что ставится» — реже
        # листает страницу пакета.
        if (( RANDOM % 3 == 0 )); then
            http_request "https://packages.ubuntu.com/noble/$pkg" desktop en apt
        fi
        # Иногда ОС-обновление сопровождается одним заходом на release-notes
        if [ "$use_os" = "1" ] && (( RANDOM % 2 == 0 )); then
            http_request "https://wiki.ubuntu.com/NobleNumbat/ReleaseNotes" desktop en apt
        fi
    done
}

# ===== Профиль времени суток (множитель пауз) =====
# Возвращает целочисленный множитель (в процентах) к базовому интервалу.
hour_factor() {
    local h
    h=$(date +%H); h=$((10#$h))
    if (( h >= NIGHT_HOUR_FROM && h <= NIGHT_HOUR_TO )); then
        echo 250                  # ночь — паузы в 2.5 раза длиннее
    elif (( h >= PEAK_MORNING_FROM && h <= PEAK_MORNING_TO )); then
        echo 60                   # утренний пик — короче
    elif (( h >= PEAK_EVENING_FROM && h <= PEAK_EVENING_TO )); then
        echo 70                   # вечерний пик
    else
        echo 100                  # день
    fi
}

# Случайная пауза в МИНУТАХ с учётом времени суток
sleep_minutes() {
    local mn=$1 mx=$2 base factor minutes
    base=$(rrange "$mn" "$mx")
    factor=$(hour_factor)
    minutes=$(( base * factor / 100 ))
    [ "$minutes" -lt 1 ] && minutes=1
    sleep "$((minutes * 60))"
}

# ===== Параллельные циклы =====
loop_ios() {
    while true; do
        ios_burst
        sleep_minutes "$IOS_BURST_INTERVAL_MIN" "$IOS_BURST_INTERVAL_MAX"
    done
}
loop_apns() {
    while true; do
        apns_keepalive
        sleep "$(rrange 1500 2400)"   # ~25–40 мин
    done
}
loop_email() {
    while true; do
        sleep_minutes "$EMAIL_INTERVAL_MIN" "$EMAIL_INTERVAL_MAX"
        email_session
    done
}
loop_news() {
    while true; do
        sleep_minutes "$NEWS_INTERVAL_MIN" "$NEWS_INTERVAL_MAX"
        news_session
    done
}
loop_apt() {
    while true; do
        sleep_minutes "$APT_PHANTOM_INTERVAL_MIN" "$APT_PHANTOM_INTERVAL_MAX"
        apt_phantom_run
    done
}

# Старт включённых модулей в фоне
PIDS=()
[ "$ENABLE_IOS_BURST"   = "1" ] && { loop_ios   & PIDS+=($!); }
[ "$ENABLE_APNS"        = "1" ] && { loop_apns  & PIDS+=($!); }
[ "$ENABLE_EMAIL"       = "1" ] && { loop_email & PIDS+=($!); }
[ "$ENABLE_NEWS"        = "1" ] && { loop_news  & PIDS+=($!); }
[ "$ENABLE_APT_PHANTOM" = "1" ] && command -v apt-get >/dev/null 2>&1 && { loop_apt & PIDS+=($!); }

# Если ни один модуль не включён — спим, чтобы systemd не считал крах.
if [ "${#PIDS[@]}" -eq 0 ]; then
    while :; do sleep 3600; done
fi

# Если упадёт хоть один цикл — останавливаем сервис целиком, systemd
# его перезапустит (Restart=always), все циклы стартуют заново.
trap 'kill "${PIDS[@]}" 2>/dev/null; exit 0' TERM INT
wait -n
kill "${PIDS[@]}" 2>/dev/null || true
exit 1
NOISE_EOF
    chmod +x "$NOISE_GEN_SCRIPT"

    cat > "$NOISE_GEN_SERVICE" <<EOF
[Unit]
Description=VPS Phoenix Stealth Noise (iOS + RU human profile + APT phantom)
After=network-online.target dnsmasq.service
Wants=network-online.target

[Service]
ExecStart=$NOISE_GEN_SCRIPT
EnvironmentFile=-$NOISE_CONF
Restart=always
RestartSec=15
Nice=15
IOSchedulingClass=idle
CPUWeight=20
MemoryHigh=128M
MemoryMax=256M
StandardOutput=null
StandardError=null
PrivateTmp=yes
ProtectSystem=full
NoNewPrivileges=yes
ReadWritePaths=/tmp /var/cache/apt /var/lib/apt

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable vps-noise >/dev/null 2>&1
    systemctl restart vps-noise
}


manage_swap() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}=== УПРАВЛЕНИЕ ПОДКАЧКОЙ (SWAP & ZRAM) ===${NC}"
        echo -e "Текущая подкачка:"
        swapon --show || true
        echo ""
        echo -e "  ${GREEN}[1]${NC} Создать/Пересоздать SWAP-файл (в ГИГАБАЙТАХ)"
        echo -e "  ${YELLOW}[2]${NC} Активировать ZRAM (Сжатие в RAM)"
        echo -e "  ${RED}[3]${NC} Удалить SWAP-файл (/swapfile)"
        echo -e "  ${RED}[4]${NC} Отключить ZRAM (/dev/zram0)"
        echo -e "  ${CYAN}[0]${NC} Назад"
        echo ""
        read -r -p "Выбор: " schoice
        case $schoice in
            1)
                read -r -p "Введите желаемый размер SWAP в Гб (например, 2 или 4): " SWAP_GB
                if [[ ! "$SWAP_GB" =~ ^[0-9]+$ ]] || [ "$SWAP_GB" -le 0 ]; then
                    echo -e "${RED}[!] Ошибка: введите положительное целое число.${NC}"
                    sleep 2
                    continue
                fi

                echo -e "${YELLOW}[*] Подготовка файла подкачки на ${SWAP_GB}GB...${NC}"
                swapoff /swapfile 2>/dev/null || true
                rm -f /swapfile

                if ! fallocate -l "${SWAP_GB}G" /swapfile 2>/dev/null; then
                    echo -e "${YELLOW}[*] fallocate не удался, использую dd...${NC}"
                    dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_GB * 1024)) status=progress
                fi

                chmod 600 /swapfile
                mkswap /swapfile >/dev/null
                swapon /swapfile

                if ! grep -q "/swapfile" /etc/fstab; then
                    echo "/swapfile none swap sw 0 0" >> /etc/fstab
                fi
                echo -e "${GREEN}[+] SWAP-файл на ${SWAP_GB}GB активирован.${NC}"
                sleep 2
                ;;
            2)
                if modprobe zram 2>/dev/null; then
                    swapoff /dev/zram0 2>/dev/null || true
                    zramctl --reset /dev/zram0 2>/dev/null || true
                    local mem_total
                    mem_total=$(free -m | awk '/Mem:/{print $2}')
                    zramctl --find --size "$(( mem_total / 2 ))M" --algorithm zstd >/dev/null 2>&1 || \
                        zramctl --find --size "$(( mem_total / 2 ))M" --algorithm lz4 >/dev/null 2>&1
                    mkswap /dev/zram0 >/dev/null
                    swapon /dev/zram0 -p 100
                    echo -e "${GREEN}[+] ZRAM активирован.${NC}"
                else
                    echo -e "${RED}[!] ZRAM не поддерживается ядром.${NC}"
                fi
                sleep 2
                ;;
            3)
                echo -e "${YELLOW}[*] Удаление SWAP-файла...${NC}"
                swapoff /swapfile 2>/dev/null || true
                rm -f /swapfile
                sed -i '/\/swapfile/d' /etc/fstab
                echo -e "${GREEN}[+] SWAP-файл удалён.${NC}"
                sleep 2
                ;;
            4)
                echo -e "${YELLOW}[*] Отключение ZRAM...${NC}"
                swapoff /dev/zram0 2>/dev/null || true
                zramctl --reset /dev/zram0 2>/dev/null || true
                echo -e "${GREEN}[+] ZRAM отключён.${NC}"
                sleep 2
                ;;
            0) return ;;
        esac
    done
}

experimental_menu() {
    clear
    echo -e "${CYAN}${BOLD}=== ЭКСПЕРИМЕНТАЛЬНЫЕ ОПЦИИ ===${NC}"
    echo "1. TCP Fast Open: $(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null)"
    echo "2. ECN:           $(sysctl -n net.ipv4.tcp_ecn 2>/dev/null)"
    echo "3. busy_poll/read: $(sysctl -n net.core.busy_poll 2>/dev/null) / $(sysctl -n net.core.busy_read 2>/dev/null)"
    read -r -p "1/2/3 переключить, 0 назад: " e_choice
    case "$e_choice" in
        1) sysctl -w net.ipv4.tcp_fastopen=3 ;;
        2) sysctl -w net.ipv4.tcp_ecn=1 ;;
        3) sysctl -w net.core.busy_poll=50 net.core.busy_read=50 ;;
    esac
}

reset_all() {
    echo -e "${YELLOW}[*] Полный откат...${NC}"
    swapoff -a 2>/dev/null || true
    rm -f /swapfile
    sed -i '/\/swapfile/d' /etc/fstab
    zramctl --reset /dev/zram0 2>/dev/null || true
    rm -f "$SYSCTL_CONF" "$LIMITS_CONF" "$EXP_CONF" "$NOISE_CONF" \
          /etc/dnsmasq.d/vps-speed.conf \
          /etc/systemd/system.conf.d/99-vps-limits.conf \
          /etc/systemd/user.conf.d/99-vps-limits.conf
    systemctl stop vps-noise vps-rps dnsmasq >/dev/null 2>&1 || true
    systemctl disable vps-noise vps-rps >/dev/null 2>&1 || true
    rm -f "$NOISE_GEN_SCRIPT" "$NOISE_GEN_SERVICE" "$RPS_BOOT_SCRIPT" "$RPS_BOOT_SERVICE"
    rm -rf /tmp/.vps_noise
    systemctl daemon-reload >/dev/null 2>&1 || true
    sysctl --system >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] Сброс выполнен.${NC}"
    sleep 2
}

main_menu() {
    while true; do
        print_header
        echo -e "Выберите действие:"
        echo -e "  ${GREEN}[1]${NC} Подготовка: Компоненты Phoenix"
        echo -e "  ${CYAN}[2]${NC} УСКОРЕНИЕ: v6.1 (Adaptive Buffers + RPS + ZRAM)"
        echo -e "  ${CYAN}[3]${NC} Stealth: генератор шума (iOS + RU email/news + APT phantom)"
        echo -e "  ${CYAN}[4]${NC} Подкачка: SWAP & ZRAM (Ручная настройка)"
        echo -e "  ${CYAN}[5]${NC} Тест: Запустить Бенчмарк (Пинг)"
        echo -e "  ${YELLOW}[12]${NC} Экспериментально: TFO / ECN / busy_poll"
        echo -e "  ${RED}[8]${NC} Полный откат всех изменений"
        echo -e "  ${GREEN}[0]${NC} Выход"
        echo ""
        read -r -p "Ваш выбор: " choice
        case $choice in
            1)  install_dependencies ;;
            2)  apply_optimizations ;;
            3)  manage_noise_generator ;;
            4)  manage_swap ;;
            5)  run_benchmark ;;
            12) experimental_menu ;;
            8)  reset_all ;;
            0)  exit 0 ;;
            *)  echo -e "${RED}[!] Неверный выбор.${NC}"; sleep 1 ;;
        esac
    done
}

check_root
main_menu
