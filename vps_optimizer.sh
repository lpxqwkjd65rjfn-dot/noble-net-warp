#!/bin/bash
# shellcheck disable=SC2059

# ==============================================================================
# VPS Global Optimization Script (v6.0 PHOENIX - DEEP TUNED EDITION)
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

print_header() {
    clear
    echo -e "${MAGENTA}${BOLD}"
    echo "================================================================="
    echo "     ULTRA VPS ACCELERATOR v6.0 (PHOENIX EDITION)              "
    echo "================================================================="
    echo -e "  Adaptive Buffers | RPS/RFS | ZRAM | iOS Stealth | Bench"
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
        dnsmasq util-linux bc zram-tools jq >/dev/null 2>&1

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
    echo -e "${YELLOW}[*] Глобальный тюнинг системы v6.0 PHOENIX...${NC}"

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

    echo -e "${GREEN}[+] Phoenix v6.0: BBR=${best_bbr}, qdisc=${best_qdisc}, buf_max=${buf_max}.${NC}"
    echo ""
    read -r -p "Нажмите Enter..."
}

manage_noise_generator() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}=== iOS STEALTH NOISE GENERATOR (Phoenix) ===${NC}"
        local status
        if systemctl is-active --quiet vps-noise; then
            status="${GREEN}ВКЛЮЧЕН${NC}"
        else
            status="${RED}ОТКЛЮЧЕН${NC}"
        fi
        echo -e "Статус: $status"
        echo ""
        echo -e "  ${GREEN}[1]${NC} Включить генератор (iOS Safari mimic + APNs keepalive)"
        echo -e "  ${RED}[2]${NC} Выключить генератор"
        echo -e "  ${CYAN}[0]${NC} Назад"
        echo ""
        read -r -p "Выбор: " nchoice
        case $nchoice in
            1)
                cat > "$NOISE_GEN_SCRIPT" <<'NOISE_EOF'
#!/bin/bash
# iOS Stealth Noise Generator — Phoenix edition.
# Имитирует фоновую активность iPhone/iPad: Safari, App Store, iCloud,
# APNs keepalive. Если в системе есть curl-impersonate-safari, он
# используется автоматически — это даёт корректный JA3/ALPN отпечаток iOS.

set -u

# --- Пул реальных iOS User-Agent (Safari + native CFNetwork) ---
UA_POOL=(
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
"AppleCoreMedia/1.0.0.21F90 (iPhone; U; CPU OS 17_5 like Mac OS X; en_us)"
"itunesstored/1.0 iOS/17.5.1 model/iPhone15,3 hwp/t8120 build/21F90 (6; dt:248)"
"com.apple.WebKit.Networking/8617.2.4.0.6 CFNetwork/1492.0.1 Darwin/23.3.0"
)

# --- Реальные домены, к которым обращается iOS в фоне ---
BROWSE_URLS=(
"https://www.apple.com/"
"https://www.apple.com/iphone/"
"https://www.apple.com/shop/buy-iphone"
"https://support.apple.com/"
"https://www.icloud.com/"
"https://apps.apple.com/"
"https://apps.apple.com/us/genre/ios/id36"
"https://itunes.apple.com/lookup?id=284910350"
"https://configuration.apple.com/configurations/internetservices/safari/ContentBlockerLists.plist.signed"
"https://gs-loc.apple.com/"
"https://gateway.icloud.com/"
"https://mesu.apple.com/assets/"
"https://swcdn.apple.com/"
"https://updates.cdn-apple.com/"
"https://is1-ssl.mzstatic.com/image/thumb/Purple221/v4/"
"https://www.bing.com/"
"https://duckduckgo.com/"
"https://yandex.ru/"
"https://www.google.com/"
)

# Лёгкие "пинги" (как captive-portal/connectivity check у iOS)
CAPTIVE_URLS=(
"https://captive.apple.com/hotspot-detect.html"
"https://www.apple.com/library/test/success.html"
"https://gsp64-ssl.ls.apple.com/"
)

# --- Заголовки, повторяющие порядок Safari iOS ---
ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ACCEPT_LANG_POOL=("en-US,en;q=0.9" "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7" "en-GB,en;q=0.9")
ACCEPT_ENC="gzip, deflate, br"

# Выбираем curl-impersonate-safari, если он есть
pick_curl() {
    if command -v curl_safari17_4 >/dev/null 2>&1; then
        echo "curl_safari17_4"
    elif command -v curl_safari16_5 >/dev/null 2>&1; then
        echo "curl_safari16_5"
    elif command -v curl-impersonate-safari >/dev/null 2>&1; then
        echo "curl-impersonate-safari"
    else
        echo "curl"
    fi
}

CURL_BIN=$(pick_curl)
COOKIE_JAR="/tmp/.ios_noise_cookies"
touch "$COOKIE_JAR"

# Случайное число в диапазоне [a, b]
rrange() { echo $(( RANDOM % ($2 - $1 + 1) + $1 )); }

# --- Один запрос «как из Safari/iOS» ---
do_request() {
    local url="$1"
    local ua="${UA_POOL[$RANDOM % ${#UA_POOL[@]}]}"
    local lang="${ACCEPT_LANG_POOL[$RANDOM % ${#ACCEPT_LANG_POOL[@]}]}"
    local rate=$(( RANDOM % 3000 + 500 ))   # 500–3500 KB/s — мобильный канал

    # Базовый набор флагов, валидный для всех вариантов curl
    local args=(
        -s -o /dev/null
        --max-time 25
        --connect-timeout 8
        --tls-max 1.3 --tlsv1.2
        --compressed
        --cookie-jar "$COOKIE_JAR" --cookie "$COOKIE_JAR"
        -A "$ua"
        -H "Accept: $ACCEPT"
        -H "Accept-Language: $lang"
        -H "Accept-Encoding: $ACCEPT_ENC"
        -H "Sec-Fetch-Dest: document"
        -H "Sec-Fetch-Mode: navigate"
        -H "Sec-Fetch-Site: none"
        -H "Upgrade-Insecure-Requests: 1"
        -H "Priority: u=0, i"
        --limit-rate "${rate}K"
    )

    # У стандартного curl пробуем HTTP/3, если не вышло — HTTP/2.
    # У curl-impersonate-safari ALPN зашит в бинарник.
    if [ "$CURL_BIN" = "curl" ]; then
        if (( RANDOM % 3 == 0 )) && curl --help all 2>/dev/null | grep -q -- '--http3'; then
            args+=(--http3)
        else
            args+=(--http2)
        fi
    fi

    "$CURL_BIN" "${args[@]}" "$url" 2>/dev/null || true
}

# --- APNs keepalive: TCP-коннект на courier.push.apple.com:5223 ---
# Реальный iPhone постоянно держит этот сокет; даже короткий connect раз
# в 20–40 минут добавляет правдоподобия фоновому профилю трафика.
apns_keepalive() {
    local host="courier.push.apple.com"
    if command -v timeout >/dev/null 2>&1; then
        timeout 6 bash -c "exec 3<>/dev/tcp/${host}/5223 && sleep 3" 2>/dev/null || true
    fi
}

# --- Сессионный «бёрст»: 3–8 запросов как при просмотре ленты ---
browse_burst() {
    local n
    n=$(rrange 3 8)
    local i url
    # Первый запрос — корневой ресурс
    do_request "${BROWSE_URLS[$RANDOM % ${#BROWSE_URLS[@]}]}"
    sleep "$(rrange 1 4)"
    for ((i=1; i<n; i++)); do
        url="${BROWSE_URLS[$RANDOM % ${#BROWSE_URLS[@]}]}"
        do_request "$url"
        sleep "$(rrange 1 6)"
    done
}

# --- Главный цикл с реалистичной кривой активности ---
LAST_APNS=0
while true; do
    HOUR=$(date +%H)
    NOW=$(date +%s)

    # APNs keepalive ~ каждые 25–35 минут
    if (( NOW - LAST_APNS > 1500 + RANDOM % 600 )); then
        apns_keepalive
        LAST_APNS=$NOW
    fi

    if (( 10#$HOUR >= 1 && 10#$HOUR <= 6 )); then
        # Ночь — редкие captive-проверки и единичные сессии
        do_request "${CAPTIVE_URLS[$RANDOM % ${#CAPTIVE_URLS[@]}]}"
        sleep "$(rrange 600 1500)"
        if (( RANDOM % 4 == 0 )); then
            browse_burst
        fi
        sleep "$(rrange 900 2400)"
    elif (( 10#$HOUR >= 7 && 10#$HOUR <= 9 )) || (( 10#$HOUR >= 18 && 10#$HOUR <= 23 )); then
        # Утренний и вечерний пики — частые бёрсты
        browse_burst
        sleep "$(rrange 30 180)"
    else
        # День — умеренная активность
        browse_burst
        sleep "$(rrange 90 360)"
    fi
done
NOISE_EOF
                chmod +x "$NOISE_GEN_SCRIPT"

                # Без жёсткой привязки к одному ядру — иначе пакеты
                # шума всегда летят с одного и того же CPU и легко
                # отделимы по таймингу. Оставляем планировщику.
                cat > "$NOISE_GEN_SERVICE" <<EOF
[Unit]
Description=VPS iOS Phoenix Stealth Noise
After=network-online.target dnsmasq.service
Wants=network-online.target

[Service]
ExecStart=$NOISE_GEN_SCRIPT
Restart=always
RestartSec=15
Nice=15
IOSchedulingClass=idle
CPUWeight=20
MemoryHigh=64M
MemoryMax=128M
StandardOutput=null
StandardError=null
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/tmp
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable vps-noise >/dev/null 2>&1
                systemctl restart vps-noise
                echo -e "${GREEN}[+] iOS-шум запущен (CFNetwork + APNs).${NC}"
                sleep 1
                ;;
            2)
                systemctl stop vps-noise 2>/dev/null
                systemctl disable vps-noise 2>/dev/null
                sleep 1
                ;;
            0) return ;;
        esac
    done
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
    rm -f "$SYSCTL_CONF" "$LIMITS_CONF" "$EXP_CONF" \
          /etc/dnsmasq.d/vps-speed.conf \
          /etc/systemd/system.conf.d/99-vps-limits.conf \
          /etc/systemd/user.conf.d/99-vps-limits.conf
    systemctl stop vps-noise vps-rps dnsmasq >/dev/null 2>&1 || true
    systemctl disable vps-noise vps-rps >/dev/null 2>&1 || true
    rm -f "$NOISE_GEN_SCRIPT" "$NOISE_GEN_SERVICE" "$RPS_BOOT_SCRIPT" "$RPS_BOOT_SERVICE"
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
        echo -e "  ${CYAN}[2]${NC} УСКОРЕНИЕ: v6.0 (Adaptive Buffers + RPS + ZRAM)"
        echo -e "  ${CYAN}[3]${NC} Stealth: iOS-генератор шума (Safari + APNs)"
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
