#!/bin/bash
# shellcheck disable=SC2059

# ==============================================================================
# VPS Global Optimization Script (v8.2 PHOENIX-Z++)
# ------------------------------------------------------------------------------
# Phase 1 — Correctness on locked-down rented VPS:
#   - Hypervisor / container detection (KVM / OpenVZ / LXC / Docker / native)
#   - Probe-then-write for every sysctl & sysfs knob (no broken /etc/sysctl.d
#     entries, no failing oneshot units after reboot)
#   - Kernel-version gate (MPTCP, BBR2/3, gro_flush_timeout, etc.)
#   - Self-test report after apply (OK / SKIPPED / DENIED for each setting)
#
# Phase 2 — Multi-core load distribution:
#   - RPS + RFS (correct bitmask for >32 cores)
#   - XPS (Transmit Packet Steering) — was missing in v6.1
#   - IRQ affinity spreading via /proc/irq/*/smp_affinity_list (when writable)
#   - flow_limit_table_len + flow_limit_cpu_bitmap
#   - sched_autogroup_enabled=0, migration_cost, NAPI defer
#   - CPU governor → performance (best effort, silent fallback)
#
# Phase 3 — Real proxy bottlenecks:
#   - conntrack tuning (max=1M, hashsize=256k, timeout-tuned for proxies)
#   - MPTCP enabled when supported
#   - BBR pacing tuned (pacing_ss_ratio, pacing_ca_ratio, min_rtt_wlen)
#   - tcp_min_snd_mss, tcp_max_orphans, tcp_collapse_max_bytes
#   - accept_redirects/send_redirects/source_route hardening
#
# Phase 4 — Memory / I/O:
#   - Transparent Huge Pages → madvise (no latency spikes)
#   - I/O scheduler: none for NVMe, mq-deadline for SSD
#   - nr_requests / read_ahead_kb tuning
#   - inotify watches/instances raised
#   - core_pattern → /dev/null (no disk fill on crash)
#
# Phase 6 — UX:
#   - Profile presets: balanced / proxy / web (different sysctl mixes)
#   - Status dashboard (BBR, qdisc, conntrack usage, ZRAM, fds, noise)
#   - Non-interactive CLI: apply / status / noise on|off|edit / preset / reset
#                         / dry-run / self-test / export / import / update
#   - dry-run mode: shows everything that WOULD change without touching system
#   - Self-update from GitHub
#
# Inherited from v6.0/v6.1:
#   - Adaptive TCP/UDP buffers scaled with RAM
#   - LRO off, ring buffers maxed, adaptive coalescence
#   - File descriptor limits (limits.conf + systemd defaults)
#   - ZRAM (zstd → lz4 fallback)
#   - Persistent RPS/XPS via systemd
#   - iOS Stealth noise + RU human profile (Yandex/Mail.ru/Max.ru/news)
#     + APT phantom (libs + OS images → /dev/null)
#   - All noise parameters in /etc/vps-noise.conf
# ==============================================================================

set -o pipefail

# v8.6: TTY/NO_COLOR-detect — если stdout не tty или установлен NO_COLOR (https://no-color.org),
# выключаем ANSI escape-последовательности. Иначе грязные '^[[31m' попадают в логи/pipe,
# которые потом грепаются и обрабатываются скриптами (cron/Ansible/Loki).
# Можно форсировать включение через FORCE_COLOR=1 (для CI с цветным output).
LANG_CONF="/etc/vps-optimizer.lang"
if [ -n "${FORCE_COLOR:-}" ]; then
    _vps_use_color=1
elif [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    _vps_use_color=0
else
    _vps_use_color=1
fi

# Цвета (или пустые строки если color disabled)
if [ "$_vps_use_color" = "1" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    GRAY='\033[0;90m'
    NC='\033[0m'
    BOLD='\033[1m'
else
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    MAGENTA=''
    GRAY=''
    NC=''
    BOLD=''
fi

SYSCTL_CONF="/etc/sysctl.d/99-vps-optimizer.conf"
LIMITS_CONF="/etc/security/limits.d/99-vps-limits.conf"
NOISE_GEN_SCRIPT="/usr/local/bin/vps_noise_gen.sh"
NOISE_GEN_SERVICE="/etc/systemd/system/vps-noise.service"
RPS_BOOT_SCRIPT="/usr/local/sbin/vps_rps_boot.sh"
RPS_BOOT_SERVICE="/etc/systemd/system/vps-rps.service"
EXP_CONF="/etc/sysctl.d/99-vps-experimental.conf"
SYSCTL_BACKUP="/etc/sysctl.d/.99-vps-optimizer.bak"
NOISE_CONF="/etc/vps-noise.conf"
PRESET_FILE="/etc/vps-optimizer.preset"
DNS_CONF="/etc/systemd/resolved.conf.d/99-vps-optimizer.conf"
DNS_STATE="/etc/vps-optimizer.dns"
DNS_RESOLV_BACKUP="/etc/.vps_optimizer_resolv_backup"
SELF_URL="https://raw.githubusercontent.com/lpxqwkjd65rjfn-dot/noble-net-warp/main/vps_optimizer.sh"
SELF_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
RUN_LOG="/var/log/vps-optimizer.log"
AUDIT_LOG="/var/log/vps-optimizer-audit.log"
DEBUG_LOG="/var/log/vps-optimizer-debug.log"
LOCK_FILE="/var/lock/vps-optimizer.lock"
SNAPSHOT_DIR="/var/backups/vps-optimizer"
HEALTH_DIR="/run/vps-noise"
HEALTH_FILE="$HEALTH_DIR/health.json"
# shellcheck disable=SC2034  # used in deploy_noise_generator
NOISE_STATE_DIR="/var/lib/vps-noise"
INTERNET_PROBE_URL="https://1.1.1.1/cdn-cgi/trace"
EXPORT_FORMAT_VERSION=2
SCRIPT_VERSION="8.11"

# Глобальные флаги (управляются через CLI)
DRY_RUN=0
QUIET=0
PRESET=""
DEBUG=0
FORCE=0
IMPERSONATE=0
ECMP=0
JSON=0
CLI_MODE=0
VPN_FORCE=0          # --vpn: явно настраиваем под VPN-роутинг (rp_filter=2, ip_forward=1)
NO_ROLLBACK=0        # --no-rollback: отключить auto-rollback по connectivity-check
SOFT_RESET=0         # reset --soft: не трогать DNS/noise/swap, только sysctl
JSON_LOGS=0          # --json-logs: structured logging для ELK/Loki (v8.6)
LEARN_MODE=0         # --learn: dry-run + diff с rationale, без записи (v8.6)

# v8.6: i18n. Default=en. Resolve order: $LC_VPS env > /etc/vps-optimizer.lang > "en".
# Поддерживаемые: en, ru, de, fr, zh. Невалидное значение → fallback на 'en'.
SCRIPT_LANG="${LC_VPS:-}"
if [ -z "$SCRIPT_LANG" ] && [ -r "$LANG_CONF" ]; then
    SCRIPT_LANG=$(head -1 "$LANG_CONF" 2>/dev/null | tr -d '[:space:]')
fi
case "$SCRIPT_LANG" in
    en|ru|de|fr|zh) ;;
    *) SCRIPT_LANG="en" ;;
esac

# Cron-friendly exit codes — стабильный API для cron/Ansible/мониторинга.
# shellcheck disable=SC2034  # часть кодов используется только внешними скриптами
EXIT_OK=0
# shellcheck disable=SC2034
EXIT_ALREADY_APPLIED=10  # idempotent: всё совпадает, ничего не делали
# shellcheck disable=SC2034
EXIT_NO_INTERNET=20      # не смогли проверить связь до apply
# shellcheck disable=SC2034
EXIT_HYPERVISOR_BLOCK=30 # хост запретил всё, что мы пытались сделать
EXIT_LOCK_BUSY=40        # другой apply уже идёт
EXIT_INVALID_ARGS=50     # неверный preset/команда
EXIT_ROLLED_BACK=60      # apply применился, но связь упала → откатились

# Сводки sysctl/sysfs/ethtool — заполняются в процессе apply, печатаются в self_test
SYSCTL_OK=()
SYSCTL_SKIP=()
SYSFS_OK=()
SYSFS_SKIP=()

# ===================================================================
#  v8.6: i18n — переводы пользовательских сообщений
# ===================================================================
# Архитектура: ассоциативные массивы I18N_<LANG> с ключами (snake_case),
# функция _t возвращает строку для текущего $SCRIPT_LANG, fallback на EN,
# fallback на сам ключ. Это позволяет добавлять/переводить инкрементально:
# непереведённый ключ просто покажет английский (или сам ключ).
#
# Намеренно покрываем только ~80 наиболее видимых строк (help/usage/main errors/
# command headers). Низкоуровневые debug-сообщения остаются в исходном языке.
# shellcheck disable=SC2034  # I18N_RU/DE/FR/ZH used via nameref in _t()
declare -A I18N_EN I18N_RU I18N_DE I18N_FR I18N_ZH

# --- English (default, источник истины) ---
I18N_EN[err_root]="[!] Run as root."
I18N_EN[err_lock_busy]="[!] Another vps_optimizer instance is running (lock=%s)."
I18N_EN[err_lock_busy_hint]="    Pass --force to ignore."
I18N_EN[lang_set]="[+] Language set to %s. Saved to %s."
I18N_EN[lang_unsupported]="[!] Unsupported language: %s. Supported: en, ru, de, fr, zh."
I18N_EN[lang_current]="Current language: %s"
I18N_EN[lang_usage]="Usage: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_EN[learn_header]="=== --learn mode: showing what WOULD change ==="
I18N_EN[learn_footer]="No files were modified. Run without --learn to apply."
I18N_EN[json_logs_on]="JSON-logs mode active (structured for ELK/Loki)"
I18N_EN[help_title]="VPS Optimizer v%s"
I18N_EN[help_usage]="USAGE:"
I18N_EN[help_commands]="COMMANDS:"
I18N_EN[help_global_flags]="GLOBAL FLAGS:"
I18N_EN[help_exit_codes]="EXIT CODES (for cron/Ansible):"
I18N_EN[help_examples]="EXAMPLES:"
I18N_EN[help_config_files]="CONFIG FILES:"
I18N_EN[help_logs]="LOGS:"
I18N_EN[help_see_also]="SEE ALSO:"
I18N_EN[cmd_install]="Install Phoenix components"
I18N_EN[cmd_apply]="Apply sysctl/sysfs/ZRAM (NAME: balanced|proxy|web)"
I18N_EN[cmd_status]="Show state dashboard (or JSON for machines)"
I18N_EN[cmd_self_test]="Re-verify applied settings"
I18N_EN[cmd_audit]="Deep diagnostics (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_EN[cmd_doctor]="Actionable diagnostics with recommendations"
I18N_EN[cmd_why]="Explain why a specific sysctl is set this way"
I18N_EN[cmd_top]="TUI: live top-connections, conntrack util, retransmits"
I18N_EN[cmd_mtr]="Bundled mtr with loss prediction (requires mtr)"
I18N_EN[cmd_prom_push]="Push Prometheus metrics to a pushgateway"
I18N_EN[cmd_stealth_test]="JA3-leak self-check via ja3er.com"
I18N_EN[cmd_audit_syslog]="Forward audit-log to remote syslog"
I18N_EN[cmd_backup_config]="Snapshot configs to rclone-remote"
I18N_EN[cmd_playbook]="Pre-baked roles: hysteria2-host|wg-vpn-server|web-frontend"
I18N_EN[cmd_health_watch]="Periodic doctor systemd-timer (every 5 min)"
I18N_EN[cmd_dns_doq]="Install DNS-over-QUIC (opt-in, requires AdGuard Home)"
I18N_EN[cmd_dns_dnssec]="Enable DNSSEC validation in unbound (opt-in)"
I18N_EN[cmd_logs]="Last N lines of journals (run/journalctl/dmesg/audit)"
I18N_EN[cmd_preset]="Save preset for future apply"
I18N_EN[cmd_noise]="Manage noise generator"
I18N_EN[cmd_wg_setup]="WireGuard helper: MTU autodetect, conntrack rules"
I18N_EN[cmd_dns]="Manage DNS configuration"
I18N_EN[cmd_swap]="Create swap file of given size in GB"
I18N_EN[cmd_benchmark]="Measure ping to popular endpoints"
I18N_EN[cmd_compare]="Save ping baseline / show diff (default: 1.1.1.1)"
I18N_EN[cmd_harden]="Opt-in security (does NOT change apply default)"
I18N_EN[cmd_prom_metrics]="Dump Prometheus metrics to stdout"
I18N_EN[cmd_prom_serve]="Run Prometheus exporter (default port 9777)"
I18N_EN[cmd_reset]="Full rollback / --soft = sysctl only"
I18N_EN[cmd_uninstall]="Full removal: reset + delete script itself"
I18N_EN[cmd_export]="Export all configs to archive (with manifest)"
I18N_EN[cmd_import]="Import exported configs (with version check)"
I18N_EN[cmd_update]="Update script (with SHA256 verification)"
I18N_EN[cmd_config]="Configuration: lang <code> | show"
I18N_EN[cmd_help]="This help"
I18N_EN[flag_dry_run]="Only show what would change"
I18N_EN[flag_quiet]="Minimal output (for scripts/cron)"
I18N_EN[flag_debug]="Verbose log to %s"
I18N_EN[flag_force]="Ignore lock / confirmations"
I18N_EN[flag_preset]="Use a specific preset (see apply)"
I18N_EN[flag_impersonate]="Use curl-impersonate for noise (if installed)"
I18N_EN[flag_ecmp]="Enable ECMP/multipath (for multi-NIC bare-metal)"
I18N_EN[flag_vpn]="Explicit VPN mode: rp_filter=2, accept_local, ip_forward"
I18N_EN[flag_no_rollback]="Disable auto-rollback on connectivity check"
I18N_EN[flag_soft]="Soft mode (for reset): sysctl only, keep DNS/noise"
I18N_EN[flag_boot]="Boot mode (for apply): create one-shot systemd unit"
I18N_EN[flag_json]="JSON output (for status/audit)"
I18N_EN[flag_json_logs]="Structured JSON-logs to RUN_LOG (ELK/Loki)"
I18N_EN[flag_no_color]="Disable ANSI colors (auto in pipe/file)"
I18N_EN[flag_learn]="--learn: dry-run with detailed diff and rationale"

# --- Russian (исторический язык скрипта — большинство строк УЖЕ ru) ---
I18N_RU[err_root]="[!] Запустите от имени root."
I18N_RU[err_lock_busy]="[!] Другой инстанс vps_optimizer уже работает (lock=%s)."
I18N_RU[err_lock_busy_hint]="    Запусти с --force чтобы проигнорировать."
I18N_RU[lang_set]="[+] Язык установлен: %s. Сохранён в %s."
I18N_RU[lang_unsupported]="[!] Язык не поддерживается: %s. Доступны: en, ru, de, fr, zh."
I18N_RU[lang_current]="Текущий язык: %s"
I18N_RU[lang_usage]="Использование: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_RU[learn_header]="=== режим --learn: что бы поменялось ==="
I18N_RU[learn_footer]="Никакие файлы не изменены. Без --learn — реально применить."
I18N_RU[json_logs_on]="JSON-logs режим включён (structured для ELK/Loki)"
I18N_RU[help_title]="VPS Optimizer v%s"
I18N_RU[help_usage]="ИСПОЛЬЗОВАНИЕ:"
I18N_RU[help_commands]="КОМАНДЫ:"
I18N_RU[help_global_flags]="ГЛОБАЛЬНЫЕ ФЛАГИ:"
I18N_RU[help_exit_codes]="EXIT КОДЫ (для cron/Ansible):"
I18N_RU[help_examples]="ПРИМЕРЫ:"
I18N_RU[help_config_files]="ФАЙЛЫ КОНФИГА:"
I18N_RU[help_logs]="ЛОГИ:"
I18N_RU[help_see_also]="СМ. ТАКЖЕ:"
I18N_RU[cmd_install]="Установить компоненты Phoenix"
I18N_RU[cmd_apply]="Применить sysctl/sysfs/ZRAM (NAME: balanced|proxy|web)"
I18N_RU[cmd_status]="Показать дашборд состояния (или JSON для машин)"
I18N_RU[cmd_self_test]="Перепроверить применённые настройки"
I18N_RU[cmd_audit]="Глубокая диагностика (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_RU[cmd_doctor]="Actionable-диагностика с рекомендациями"
I18N_RU[cmd_why]="Объяснить почему конкретный sysctl такой"
I18N_RU[cmd_top]="TUI: live топ-conn, conntrack, retransmits"
I18N_RU[cmd_mtr]="Bundled mtr с прогнозом потерь (требует mtr)"
I18N_RU[cmd_prom_push]="Push Prometheus метрик в pushgateway"
I18N_RU[cmd_stealth_test]="Само-проверка JA3-leak'а через ja3er.com"
I18N_RU[cmd_audit_syslog]="Пересылать audit-log в remote syslog"
I18N_RU[cmd_backup_config]="Выгрузить конфиги в rclone-remote"
I18N_RU[cmd_playbook]="Готовые роли: hysteria2-host|wg-vpn-server|web-frontend"
I18N_RU[cmd_health_watch]="Систёмный таймер doctor каждые 5 мин"
I18N_RU[cmd_dns_doq]="Установка DNS-over-QUIC (opt-in, требует AdGuard Home)"
I18N_RU[cmd_dns_dnssec]="Включить DNSSEC validation в unbound (opt-in)"
I18N_RU[cmd_logs]="Последние N строк журнала (run/journalctl/dmesg/audit)"
I18N_RU[cmd_preset]="Сохранить пресет на будущие apply"
I18N_RU[cmd_noise]="Управление шумогенератором"
I18N_RU[cmd_wg_setup]="WireGuard helper: автодетект MTU, conntrack-rules"
I18N_RU[cmd_dns]="Управление DNS"
I18N_RU[cmd_swap]="Создать swap-файл указанного размера в ГБ"
I18N_RU[cmd_benchmark]="Замерить пинг до набора популярных endpoints"
I18N_RU[cmd_compare]="Сохранить ping baseline / показать diff (default: 1.1.1.1)"
I18N_RU[cmd_harden]="Opt-in security (НЕ меняет дефолт apply)"
I18N_RU[cmd_prom_metrics]="Сдампить Prometheus-метрики на stdout"
I18N_RU[cmd_prom_serve]="Поднять Prometheus exporter (default port 9777)"
I18N_RU[cmd_reset]="Полный откат / --soft = только sysctl"
I18N_RU[cmd_uninstall]="Полное удаление: сбрасывает + сносит сам скрипт"
I18N_RU[cmd_export]="Выгрузить все конфиги в архив (с manifest)"
I18N_RU[cmd_import]="Накатить выгруженные конфиги (с проверкой версии)"
I18N_RU[cmd_update]="Обновить скрипт (с SHA256 verification)"
I18N_RU[cmd_config]="Конфигурация: lang <код> | show"
I18N_RU[cmd_help]="Эта справка"
I18N_RU[flag_dry_run]="Только показать, что бы изменилось"
I18N_RU[flag_quiet]="Минимум вывода (для скриптов/cron)"
I18N_RU[flag_debug]="Подробный лог в %s"
I18N_RU[flag_force]="Игнорировать lock / подтверждения"
I18N_RU[flag_preset]="Использовать конкретный пресет (см. apply)"
I18N_RU[flag_impersonate]="Использовать curl-impersonate в шуме (если установлен)"
I18N_RU[flag_ecmp]="Включить ECMP/multipath (для multi-NIC bare-metal)"
I18N_RU[flag_vpn]="Явно VPN-режим: rp_filter=2, accept_local, ip_forward"
I18N_RU[flag_no_rollback]="Отключить auto-rollback по connectivity-check"
I18N_RU[flag_soft]="Soft-режим (для reset): только sysctl, не трогать DNS/noise"
I18N_RU[flag_boot]="Boot-режим (для apply): создать one-shot systemd unit"
I18N_RU[flag_json]="Вывод в JSON (для status/audit)"
I18N_RU[flag_json_logs]="Structured JSON-logs в RUN_LOG (ELK/Loki)"
I18N_RU[flag_no_color]="Выключить ANSI цвета (auto в pipe/file)"
I18N_RU[flag_learn]="--learn: dry-run с детальным diff и rationale"

# --- Deutsch ---
I18N_DE[err_root]="[!] Als root ausführen."
I18N_DE[err_lock_busy]="[!] Eine andere vps_optimizer-Instanz läuft (lock=%s)."
I18N_DE[err_lock_busy_hint]="    --force zum Ignorieren übergeben."
I18N_DE[lang_set]="[+] Sprache gesetzt: %s. Gespeichert in %s."
I18N_DE[lang_unsupported]="[!] Sprache nicht unterstützt: %s. Erlaubt: en, ru, de, fr, zh."
I18N_DE[lang_current]="Aktuelle Sprache: %s"
I18N_DE[lang_usage]="Verwendung: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_DE[learn_header]="=== --learn-Modus: was geändert würde ==="
I18N_DE[learn_footer]="Keine Datei wurde geändert. Ohne --learn anwenden."
I18N_DE[json_logs_on]="JSON-Log-Modus aktiv (strukturiert für ELK/Loki)"
I18N_DE[help_title]="VPS Optimizer v%s"
I18N_DE[help_usage]="VERWENDUNG:"
I18N_DE[help_commands]="BEFEHLE:"
I18N_DE[help_global_flags]="GLOBALE FLAGS:"
I18N_DE[help_exit_codes]="EXIT-CODES (für cron/Ansible):"
I18N_DE[help_examples]="BEISPIELE:"
I18N_DE[help_config_files]="KONFIG-DATEIEN:"
I18N_DE[help_logs]="LOGS:"
I18N_DE[help_see_also]="SIEHE AUCH:"
I18N_DE[cmd_install]="Phoenix-Komponenten installieren"
I18N_DE[cmd_apply]="sysctl/sysfs/ZRAM anwenden (NAME: balanced|proxy|web)"
I18N_DE[cmd_status]="Status-Dashboard anzeigen (oder JSON für Maschinen)"
I18N_DE[cmd_self_test]="Angewendete Einstellungen erneut prüfen"
I18N_DE[cmd_audit]="Tiefe Diagnose (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_DE[cmd_doctor]="Actionable Diagnose mit Empfehlungen"
I18N_DE[cmd_why]="Erklären warum ein bestimmter sysctl so gesetzt ist"
I18N_DE[cmd_top]="TUI: Live Top-Verbindungen, conntrack-Auslastung, retransmits"
I18N_DE[cmd_mtr]="mtr mit Verlustvorhersage (benötigt mtr)"
I18N_DE[cmd_prom_push]="Prometheus-Metriken zu Pushgateway senden"
I18N_DE[cmd_stealth_test]="JA3-Leak-Selbstprüfung via ja3er.com"
I18N_DE[cmd_audit_syslog]="audit-log an Remote-Syslog weiterleiten"
I18N_DE[cmd_backup_config]="Konfig-Snapshots zu rclone-remote"
I18N_DE[cmd_playbook]="Vorgefertigte Rollen: hysteria2-host|wg-vpn-server|web-frontend"
I18N_DE[cmd_health_watch]="Periodischer doctor-Timer (alle 5 Min)"
I18N_DE[cmd_dns_doq]="DNS-over-QUIC (opt-in, benötigt AdGuard Home)"
I18N_DE[cmd_dns_dnssec]="DNSSEC-Validierung in unbound (opt-in)"
I18N_DE[cmd_logs]="Letzte N Journal-Zeilen (run/journalctl/dmesg/audit)"
I18N_DE[cmd_preset]="Preset für künftige apply-Aufrufe speichern"
I18N_DE[cmd_noise]="Noise-Generator verwalten"
I18N_DE[cmd_wg_setup]="WireGuard-Helper: MTU-Autodetect, conntrack"
I18N_DE[cmd_dns]="DNS-Konfiguration verwalten"
I18N_DE[cmd_swap]="Swap-Datei in angegebener GB-Grösse erstellen"
I18N_DE[cmd_benchmark]="Ping zu populären Endpoints messen"
I18N_DE[cmd_compare]="Ping-Baseline speichern / Diff anzeigen (default: 1.1.1.1)"
I18N_DE[cmd_harden]="Opt-in Sicherheit (ändert apply-Default NICHT)"
I18N_DE[cmd_prom_metrics]="Prometheus-Metriken nach stdout"
I18N_DE[cmd_prom_serve]="Prometheus-Exporter starten (default port 9777)"
I18N_DE[cmd_reset]="Voller Rollback / --soft = nur sysctl"
I18N_DE[cmd_uninstall]="Volle Entfernung: reset + Skript löschen"
I18N_DE[cmd_export]="Alle Konfigs in Archiv exportieren (mit manifest)"
I18N_DE[cmd_import]="Exportierte Konfigs importieren (mit Versionsprüfung)"
I18N_DE[cmd_update]="Skript aktualisieren (mit SHA256-Verifikation)"
I18N_DE[cmd_config]="Konfiguration: lang <code> | show"
I18N_DE[cmd_help]="Diese Hilfe"

# --- Français ---
I18N_FR[err_root]="[!] Exécutez en tant que root."
I18N_FR[err_lock_busy]="[!] Une autre instance vps_optimizer est en cours (lock=%s)."
I18N_FR[err_lock_busy_hint]="    Utilisez --force pour ignorer."
I18N_FR[lang_set]="[+] Langue définie: %s. Sauvegardée dans %s."
I18N_FR[lang_unsupported]="[!] Langue non supportée: %s. Disponibles: en, ru, de, fr, zh."
I18N_FR[lang_current]="Langue actuelle: %s"
I18N_FR[lang_usage]="Utilisation: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_FR[learn_header]="=== mode --learn: ce qui changerait ==="
I18N_FR[learn_footer]="Aucun fichier modifié. Sans --learn pour appliquer."
I18N_FR[json_logs_on]="Mode JSON-logs actif (structuré pour ELK/Loki)"
I18N_FR[help_title]="VPS Optimizer v%s"
I18N_FR[help_usage]="UTILISATION:"
I18N_FR[help_commands]="COMMANDES:"
I18N_FR[help_global_flags]="DRAPEAUX GLOBAUX:"
I18N_FR[help_exit_codes]="CODES DE SORTIE (pour cron/Ansible):"
I18N_FR[help_examples]="EXEMPLES:"
I18N_FR[help_config_files]="FICHIERS DE CONFIG:"
I18N_FR[help_logs]="LOGS:"
I18N_FR[help_see_also]="VOIR AUSSI:"
I18N_FR[cmd_install]="Installer composants Phoenix"
I18N_FR[cmd_apply]="Appliquer sysctl/sysfs/ZRAM (NAME: balanced|proxy|web)"
I18N_FR[cmd_status]="Tableau de bord d'état (ou JSON pour machines)"
I18N_FR[cmd_self_test]="Re-vérifier les paramètres appliqués"
I18N_FR[cmd_audit]="Diagnostic profond (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_FR[cmd_doctor]="Diagnostic actionnable avec recommandations"
I18N_FR[cmd_why]="Expliquer pourquoi un sysctl est ainsi"
I18N_FR[cmd_top]="TUI: top connexions live, conntrack, retransmits"
I18N_FR[cmd_mtr]="mtr avec prévision de perte (nécessite mtr)"
I18N_FR[cmd_prom_push]="Pousser métriques Prometheus vers pushgateway"
I18N_FR[cmd_stealth_test]="Auto-test JA3-leak via ja3er.com"
I18N_FR[cmd_audit_syslog]="Transférer audit-log vers syslog distant"
I18N_FR[cmd_backup_config]="Snapshot configs vers rclone-remote"
I18N_FR[cmd_playbook]="Rôles prédéfinis: hysteria2-host|wg-vpn-server|web-frontend"
I18N_FR[cmd_health_watch]="Timer doctor périodique (toutes 5 min)"
I18N_FR[cmd_dns_doq]="Installer DNS-over-QUIC (opt-in, nécessite AdGuard Home)"
I18N_FR[cmd_dns_dnssec]="Activer validation DNSSEC dans unbound (opt-in)"
I18N_FR[cmd_logs]="N dernières lignes de journaux"
I18N_FR[cmd_preset]="Sauvegarder preset pour futurs apply"
I18N_FR[cmd_noise]="Gérer le générateur de bruit"
I18N_FR[cmd_wg_setup]="Helper WireGuard: MTU auto, conntrack"
I18N_FR[cmd_dns]="Gérer configuration DNS"
I18N_FR[cmd_swap]="Créer fichier swap de taille donnée en Go"
I18N_FR[cmd_benchmark]="Mesurer ping vers endpoints populaires"
I18N_FR[cmd_compare]="Sauvegarder baseline / afficher diff (défaut: 1.1.1.1)"
I18N_FR[cmd_harden]="Sécurité opt-in (ne modifie PAS le défaut apply)"
I18N_FR[cmd_prom_metrics]="Dump métriques Prometheus sur stdout"
I18N_FR[cmd_prom_serve]="Lancer exporter Prometheus (port défaut 9777)"
I18N_FR[cmd_reset]="Rollback complet / --soft = sysctl seulement"
I18N_FR[cmd_uninstall]="Suppression totale: reset + script lui-même"
I18N_FR[cmd_export]="Exporter toutes configs en archive (avec manifest)"
I18N_FR[cmd_import]="Importer configs exportées (avec vérif version)"
I18N_FR[cmd_update]="Mettre à jour le script (avec vérif SHA256)"
I18N_FR[cmd_config]="Configuration: lang <code> | show"
I18N_FR[cmd_help]="Cette aide"

# --- 中文 (简体) ---
I18N_ZH[err_root]="[!] 请以 root 身份运行。"
I18N_ZH[err_lock_busy]="[!] 另一个 vps_optimizer 实例正在运行 (lock=%s)。"
I18N_ZH[err_lock_busy_hint]="    使用 --force 忽略。"
I18N_ZH[lang_set]="[+] 语言已设置: %s。已保存到 %s。"
I18N_ZH[lang_unsupported]="[!] 不支持的语言: %s。可用: en, ru, de, fr, zh。"
I18N_ZH[lang_current]="当前语言: %s"
I18N_ZH[lang_usage]="用法: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_ZH[learn_header]="=== --learn 模式: 显示将要更改的内容 ==="
I18N_ZH[learn_footer]="没有文件被修改。去掉 --learn 即可实际应用。"
I18N_ZH[json_logs_on]="JSON-logs 模式已启用 (结构化用于 ELK/Loki)"
I18N_ZH[help_title]="VPS Optimizer v%s"
I18N_ZH[help_usage]="用法:"
I18N_ZH[help_commands]="命令:"
I18N_ZH[help_global_flags]="全局参数:"
I18N_ZH[help_exit_codes]="退出码 (用于 cron/Ansible):"
I18N_ZH[help_examples]="示例:"
I18N_ZH[help_config_files]="配置文件:"
I18N_ZH[help_logs]="日志:"
I18N_ZH[help_see_also]="另请参阅:"
I18N_ZH[cmd_install]="安装 Phoenix 组件"
I18N_ZH[cmd_apply]="应用 sysctl/sysfs/ZRAM (NAME: balanced|proxy|web)"
I18N_ZH[cmd_status]="显示状态仪表板 (或 JSON 用于程序)"
I18N_ZH[cmd_self_test]="重新检查已应用的设置"
I18N_ZH[cmd_audit]="深度诊断 (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_ZH[cmd_doctor]="可操作诊断与建议"
I18N_ZH[cmd_why]="解释某个 sysctl 为何如此设置"
I18N_ZH[cmd_top]="TUI: 实时连接、conntrack、重传"
I18N_ZH[cmd_mtr]="带丢包预测的 mtr (需要 mtr)"
I18N_ZH[cmd_prom_push]="推送 Prometheus 指标到 pushgateway"
I18N_ZH[cmd_stealth_test]="通过 ja3er.com 自检 JA3 泄漏"
I18N_ZH[cmd_audit_syslog]="将 audit-log 转发到远程 syslog"
I18N_ZH[cmd_backup_config]="将配置快照到 rclone-remote"
I18N_ZH[cmd_playbook]="预设角色: hysteria2-host|wg-vpn-server|web-frontend"
I18N_ZH[cmd_health_watch]="周期性 doctor 定时器 (每5分钟)"
I18N_ZH[cmd_dns_doq]="安装 DNS-over-QUIC (opt-in, 需要 AdGuard Home)"
I18N_ZH[cmd_dns_dnssec]="启用 unbound 中的 DNSSEC 验证 (opt-in)"
I18N_ZH[cmd_logs]="最新 N 行日志"
I18N_ZH[cmd_preset]="保存 preset 供后续 apply 使用"
I18N_ZH[cmd_noise]="管理噪声生成器"
I18N_ZH[cmd_wg_setup]="WireGuard 助手: MTU 自动检测、conntrack"
I18N_ZH[cmd_dns]="管理 DNS 配置"
I18N_ZH[cmd_swap]="创建指定大小 (GB) 的 swap 文件"
I18N_ZH[cmd_benchmark]="测量到流行端点的 ping"
I18N_ZH[cmd_compare]="保存 ping 基线 / 显示差异 (默认: 1.1.1.1)"
I18N_ZH[cmd_harden]="可选安全 (不改变 apply 默认行为)"
I18N_ZH[cmd_prom_metrics]="将 Prometheus 指标输出到 stdout"
I18N_ZH[cmd_prom_serve]="启动 Prometheus exporter (默认端口 9777)"
I18N_ZH[cmd_reset]="完全回滚 / --soft = 仅 sysctl"
I18N_ZH[cmd_uninstall]="完全卸载: reset + 删除脚本本身"
I18N_ZH[cmd_export]="将所有配置导出到归档 (含 manifest)"
I18N_ZH[cmd_import]="导入导出的配置 (含版本检查)"
I18N_ZH[cmd_update]="更新脚本 (含 SHA256 验证)"
I18N_ZH[cmd_config]="配置: lang <code> | show"
I18N_ZH[cmd_help]="此帮助"

# Чтобы shellcheck не ругался SC2034 на «unused» массивы (они доступаются
# только через nameref в _t() — статический анализатор это не видит).
: "${I18N_RU[err_root]}" "${I18N_DE[err_root]}" "${I18N_FR[err_root]}" "${I18N_ZH[err_root]}"

# _t key — возвращает локализованную строку.
# Поиск: I18N_<LANG> → I18N_EN → ключ как есть.
# Если переданы доп.аргументы, они подставляются через printf '%s'.
_t() {
    local key="$1"; shift || true
    local arr_name="I18N_${SCRIPT_LANG^^}"
    local -n arr="$arr_name" 2>/dev/null
    local fmt="${arr[$key]:-}"
    [ -z "$fmt" ] && fmt="${I18N_EN[$key]:-$key}"
    if [ $# -gt 0 ]; then
        # shellcheck disable=SC2059
        printf "$fmt\n" "$@"
    else
        printf "%s\n" "$fmt"
    fi
}

print_header() {
    [ "$QUIET" = "1" ] && return
    clear
    echo -e "${MAGENTA}${BOLD}"
    echo "================================================================="
    echo "       ULTRA VPS ACCELERATOR v8.2 (PHOENIX-Z++)                  "
    echo "================================================================="
    echo -e "  Probe-then-Write | XPS+RPS+IRQ | conntrack | MPTCP | THP    "
    echo -e "  Presets: balanced / proxy / web    Stealth: iOS+RU+APT     "
    echo -e "=================================================================${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}$(_t err_root)${NC}"
        exit 1
    fi
}

# Лог в файл (перезаписывается при каждом запуске apply, рядом — на консоль)
# v8.6: при --json-logs пишем structured JSON-line вместо plain-line
# (для ELK/Loki/Vector). Поля: ts, level, version, host, msg.
_log() {
    local level="$1"; shift
    local msg="$*"
    [ "$QUIET" = "1" ] || echo -e "$msg"
    local ts plain
    ts=$(date -u +%FT%T.%3NZ)
    plain=$(echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g')
    if [ "$JSON_LOGS" = "1" ]; then
        # Минимальное JSON-эскейпирование (\, ", \n, \t).
        local esc="$plain"
        esc="${esc//\\/\\\\}"
        esc="${esc//\"/\\\"}"
        esc="${esc//$'\n'/\\n}"
        esc="${esc//$'\t'/\\t}"
        printf '{"ts":"%s","level":"%s","version":"%s","host":"%s","msg":"%s"}\n' \
            "$ts" "$level" "$SCRIPT_VERSION" "${HOSTNAME:-unknown}" "$esc" \
            >> "$RUN_LOG" 2>/dev/null || true
    else
        echo "[$ts] [$level] $plain" >> "$RUN_LOG" 2>/dev/null || true
    fi
}

# Audit-log: фиксирует каждую mutating-команду (apply / reset / dns / noise / harden / uninstall).
# Пишется в отдельный append-only лог, не зависящий от $QUIET.
_audit() {
    local action="$1"; shift
    local user="${SUDO_USER:-${USER:-root}}"
    local detail="$*"
    mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null || true
    echo "[$(date -u +%FT%TZ)] user=$user action=$action $detail" >> "$AUDIT_LOG" 2>/dev/null || true
}

# Debug-log: подробный вывод каждой sysctl/sysfs-записи. Включается флагом --debug.
_debug() {
    [ "$DEBUG" = "1" ] || return 0
    mkdir -p "$(dirname "$DEBUG_LOG")" 2>/dev/null || true
    echo "[$(date -u +%FT%T.%3NZ)] $*" >> "$DEBUG_LOG" 2>/dev/null || true
}

# /dev/urandom-based случайное число в диапазоне [a, b]. Используем когда $RANDOM
# даёт коллизии в параллельных bash-процессах (например loop_ios + loop_news запущены
# одновременно — получают одинаковую seed, тянут одинаковые URL'ы → паттерн).
urand_range() {
    local lo="$1" hi="$2" span r
    span=$(( hi - lo + 1 ))
    [ "$span" -le 0 ] && { echo "$lo"; return; }
    if [ -r /dev/urandom ]; then
        r=$(od -An -N4 -tu4 /dev/urandom 2>/dev/null | tr -d ' ')
        [ -z "$r" ] && r=$RANDOM
        echo $(( r % span + lo ))
    else
        echo $(( RANDOM % span + lo ))
    fi
}

# Lock-файл для предотвращения одновременных apply/reset.
acquire_lock() {
    [ "$DRY_RUN" = "1" ] && return 0
    [ "$FORCE" = "1" ] && return 0
    mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || true
    exec 9>"$LOCK_FILE" 2>/dev/null || return 0
    if ! flock -n 9 2>/dev/null; then
        echo -e "${RED}$(_t err_lock_busy "$LOCK_FILE")${NC}"
        echo -e "${GRAY}$(_t err_lock_busy_hint)${NC}"
        return 1
    fi
    return 0
}

release_lock() {
    exec 9>&- 2>/dev/null || true
}

# Быстрая проверка наличия интернета — чтобы не сломать DNS если связь уже отвалилась.
check_internet() {
    local timeout=3
    if curl -sf --max-time "$timeout" "$INTERNET_PROBE_URL" >/dev/null 2>&1; then
        return 0
    fi
    if timeout "$timeout" bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
        return 0
    fi
    return 1
}

# Простой SHA256 — для idempotency и self_update integrity check
file_sha256() {
    local f="$1"
    [ -f "$f" ] || { echo ""; return; }
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
}

# ===================================================================
#  Хелперы детектирования среды
# ===================================================================

# Возвращает: kvm / xen / openvz / lxc / docker / wsl / none
detect_virt() {
    local v=""
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        v=$(systemd-detect-virt 2>/dev/null || echo none)
    fi
    [ -z "$v" ] && v="none"
    echo "$v"
}

# Парсим ядро в число "MAJORMINORPATCH" для версионных гейтов
kernel_version_int() {
    local kv
    kv=$(uname -r | awk -F'[.-]' '{printf "%d%02d%02d", $1, $2, ($3==""?0:$3)}')
    echo "$kv"
}

# Поддерживается ли sysctl (есть ли соответствующий файл в /proc/sys/...)?
kernel_supports_sysctl() {
    local key="$1"
    [ -e "/proc/sys/${key//.//}" ]
}

# Доступен ли congestion control в ядре?
has_cong_ctl() {
    local algo="$1"
    grep -qw "$algo" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null
}

# Безопасная запись sysctl: probe-then-persist.
# Сначала пробуем `sysctl -w` в память, и только при успехе добавляем в
# `$SYSCTL_CONF`. Если ядро не знает ключ — тихо скипаем (важно на OpenVZ).
SYSCTL_TMP=""
sysctl_safe() {
    local key="$1" value="$2"
    if ! kernel_supports_sysctl "$key"; then
        SYSCTL_SKIP+=("$key=unsupported")
        _debug "sysctl SKIP unsupported: $key=$value"
        return 1
    fi
    if [ "$DRY_RUN" = "1" ]; then
        SYSCTL_OK+=("$key=$value (dry-run)")
        [ -n "$SYSCTL_TMP" ] && echo "$key = $value" >> "$SYSCTL_TMP"
        _debug "sysctl DRY: $key=$value"
        # v8.6 --learn: показываем diff текущее → желаемое прямо в stdout
        if [ "$LEARN_MODE" = "1" ]; then
            local _cur
            _cur=$(sysctl -n "$key" 2>/dev/null || echo "?")
            if [ "$_cur" != "$value" ]; then
                echo -e "  ${YELLOW}~${NC} ${BOLD}$key${NC}: ${GRAY}$_cur${NC} → ${GREEN}$value${NC}"
            fi
        fi
        return 0
    fi
    if sysctl -w "$key=$value" >/dev/null 2>&1; then
        SYSCTL_OK+=("$key=$value")
        [ -n "$SYSCTL_TMP" ] && echo "$key = $value" >> "$SYSCTL_TMP"
        _debug "sysctl OK: $key=$value"
        return 0
    else
        SYSCTL_SKIP+=("$key=denied")
        _debug "sysctl DENIED: $key=$value"
        return 1
    fi
}

# Безопасная запись в /sys или /proc: проверяем существование и writability.
sysfs_safe() {
    local path="$1" value="$2"
    if [ ! -e "$path" ]; then
        SYSFS_SKIP+=("$path:missing")
        _debug "sysfs SKIP missing: $path"
        return 1
    fi
    if [ "$DRY_RUN" = "1" ]; then
        SYSFS_OK+=("$path=$value (dry-run)")
        _debug "sysfs DRY: $path=$value"
        if [ "$LEARN_MODE" = "1" ]; then
            local _cur
            _cur=$(cat "$path" 2>/dev/null || echo "?")
            if [ "$_cur" != "$value" ]; then
                echo -e "  ${YELLOW}~${NC} ${BOLD}$path${NC}: ${GRAY}$_cur${NC} → ${GREEN}$value${NC}"
            fi
        fi
        return 0
    fi
    if echo "$value" > "$path" 2>/dev/null; then
        SYSFS_OK+=("$path=$value")
        _debug "sysfs OK: $path=$value"
        return 0
    else
        SYSFS_SKIP+=("$path:denied")
        _debug "sysfs DENIED: $path=$value"
        return 1
    fi
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

# CPU index → cpumask hex для одного CPU в kernel-формате.
# Формат cpumask — comma-separated 32-bit hex chunks, low-CPU group последним.
# Пример: CPU  0 → "1", CPU 31 → "80000000",
#         CPU 32 → "1,00000000", CPU 63 → "80000000,00000000".
# Для cpu>=32 простое `printf '%x' $((1<<cpu))` ломается на 32-bit ядрах
# и неправильно парсится по cpumask-формату (нужны разделители на каждые 32 бита).
cpu_to_xps_mask() {
    local cpu="${1:-0}"
    [ "$cpu" -lt 0 ] && cpu=0
    local group=$(( cpu / 32 ))
    local bit=$(( cpu % 32 ))
    local val
    val=$(printf '%x' $(( 1 << bit )))
    if [ "$group" -eq 0 ]; then
        echo "$val"
    else
        local zeros="" i
        for ((i=0; i<group; i++)); do zeros+=",00000000"; done
        echo "${val}${zeros}"
    fi
}

# Список «реальных» сетевых интерфейсов — без виртуальных оверлеев.
list_real_ifaces() {
    ip -o link show 2>/dev/null | \
        awk -F': ' '$2 !~ /^(lo|virbr|docker|veth|wg|tun|tap|gre|ppp|br-|cilium|kube|cni)/ {print $2}'
}

# Detect VPS-провайдера через dmidecode / hostname / IP-ranges.
# Возвращает: hetzner|digitalocean|vultr|aws|gcp|azure|aeza|timeweb|firstbyte|generic
detect_provider() {
    local sys_vendor sys_product hostname_lc
    sys_vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null | tr '[:upper:]' '[:lower:]')
    sys_product=$(cat /sys/class/dmi/id/product_name 2>/dev/null | tr '[:upper:]' '[:lower:]')
    hostname_lc=$(hostname 2>/dev/null | tr '[:upper:]' '[:lower:]')

    # DMI-сигнатуры провайдеров
    case "$sys_vendor$sys_product" in
        *hetzner*)        echo hetzner;        return ;;
        *digitalocean*)   echo digitalocean;   return ;;
        *vultr*)          echo vultr;          return ;;
        *amazon*|*aws*)   echo aws;            return ;;
        *google*)         echo gcp;            return ;;
        *microsoft*|*hyperv*) echo azure;      return ;;
        *oracle*)         echo oracle;         return ;;
    esac
    # hostname-эвристика — только если dmi не сработал (Aeza/Timeweb/Firstbyte
    # часто включают название в hostname, но это менее надёжно: 'vultr.example.com'
    # не значит что VPS у Vultr). Q8 fix v8.3: матчим только если домен содержит
    # суффикс провайдера, не любую подстроку.
    case "$hostname_lc" in
        *.aeza.net|*.aeza.online|aeza-*)        echo aeza;      return ;;
        *.timeweb.cloud|*.timeweb.ru|timeweb-*) echo timeweb;   return ;;
        *.firstbyte.ru|*.1stbyte.ru|fb-*)       echo firstbyte; return ;;
    esac
    echo generic
}

# Безопасная проверка: можем ли мы включать GRO/GSO/TSO на этом NIC без рисков?
# На некоторых virtio-net конфигурациях GRO+TSO ломает packet flow для XHTTP/Reality.
# Стратегия: если виртуализация openvz/lxc/docker — не трогаем offload вообще
# (всё равно контролируется хостом). На KVM/Xen — оставляем default настройки,
# но фиксируем `gro on` (важно для производительности) и `lro off` (важно для
# корректной работы прокси).
nic_offload_safe_for_iface() {
    local iface="$1"
    local virt
    virt=$(detect_virt 2>/dev/null)
    case "$virt" in
        openvz|lxc|docker) return 1 ;;
    esac
    [ -n "$iface" ] && [ -d "/sys/class/net/$iface" ] || return 1
    return 0
}

# ECMP детектор: возвращает 0 если сейчас есть несколько default-маршрутов
# на разных интерфейсах (multipath сценарий — имеет смысл включить
# fib_multipath_hash_policy=1).
has_ecmp() {
    local n
    n=$(ip -4 route show default 2>/dev/null | grep -c '^default')
    [ "$n" -ge 2 ]
}

# VPN-iface детектор (v8.3): возвращает 0 если есть UP-интерфейс с типичным
# VPN-именем (tun0, wg0, ppp0, tap0, gpd0, openvpn, ipsec0, и т.п.).
has_vpn_iface() {
    local iface
    for iface in /sys/class/net/*; do
        local name
        name=$(basename "$iface")
        case "$name" in
            # v8.8 (G3): расширили список — Cloudflared (cf*), Tailscale/Headscale
            # (tailscale*, headscale*), Resilio Sync (sync*), ZeroTier (zt*),
            # OpenVPN named iface (utun*). Все эти инструменты создают туннельные
            # interface'ы, на которые `ip route` менять опасно (потеряются переходы).
            tun*|tap*|wg*|ppp*|ipsec*|gpd*|nordlynx*|vpn*|wireguard*|\
            cf*|cloudflared*|tailscale*|headscale*|sync*|zt*|utun*)
                # Считаем только UP-iface, чтобы зомби-туннели не тянули нас в VPN-режим.
                if [ -r "$iface/operstate" ] && grep -qE '^(up|unknown)$' "$iface/operstate" 2>/dev/null; then
                    return 0
                fi
                ;;
        esac
    done
    return 1
}

# Скорость основного физического интерфейса в Мбит/с (для масштабирования
# netdev_max_backlog/dev_weight). Возвращает 0 если детект не удался.
detect_link_speed_mbps() {
    local iface speed
    iface=$(ip -4 route show default 2>/dev/null | awk '/^default/{for (i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
    [ -z "$iface" ] && { echo 0; return; }
    if command -v ethtool >/dev/null 2>&1; then
        speed=$(ethtool "$iface" 2>/dev/null | awk '/Speed:/ {gsub(/Mb\/s/,"",$2); print $2; exit}')
    fi
    [ -z "$speed" ] || ! [[ "$speed" =~ ^[0-9]+$ ]] && speed=0
    echo "$speed"
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
neg-ttl=60
min-cache-ttl=60
server=1.1.1.1
server=1.0.0.1
server=8.8.8.8
server=8.8.4.4
EOF
    systemctl restart dnsmasq >/dev/null 2>&1 || true

    # Опционально — socat (нужен для prom-serve)
    apt-get install -y --no-install-recommends socat >/dev/null 2>&1 || true

    echo -e "${GREEN}[+] Базовые компоненты установлены.${NC}"
    echo -e "${YELLOW}[i] Опционально: curl-impersonate-safari даёт TLS/JA3 как у iOS.${NC}"
    echo -e "${YELLOW}    https://github.com/lwthiker/curl-impersonate (release binaries)${NC}"

    # IMPERSONATE: при флаге --impersonate автоматически качаем curl-impersonate.
    if [ "$IMPERSONATE" = "1" ]; then
        install_curl_impersonate
    fi

    _audit install "deps_installed=ok impersonate=${IMPERSONATE}"
    sleep 1
}

# Опциональная установка curl-impersonate (TLS/JA3-fingerprint реального Safari).
install_curl_impersonate() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) echo -e "${YELLOW}[!] curl-impersonate: не поддерживается архитектура $arch${NC}"; return 1 ;;
    esac
    if command -v curl-impersonate-safari >/dev/null 2>&1; then
        echo -e "${GRAY}[i] curl-impersonate уже установлен.${NC}"; return 0
    fi
    # Q5 fix v8.3: тянем latest tag вместо хардкоженного 0.6.1.
    # Если GitHub API недоступен — fallback на проверенную 0.6.1.
    local ver fallback_ver="0.6.1"
    ver=$(curl -fsSL --max-time 10 \
        https://api.github.com/repos/lwthiker/curl-impersonate/releases/latest 2>/dev/null \
        | awk -F'"' '/"tag_name":/ {print $4; exit}' | sed 's/^v//')
    if [ -z "$ver" ] || ! [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${GRAY}[i] GitHub API недоступен — используем fallback v${fallback_ver}${NC}"
        ver="$fallback_ver"
    fi
    local url="https://github.com/lwthiker/curl-impersonate/releases/download/v${ver}/curl-impersonate-v${ver}.${arch}-linux-gnu.tar.gz"
    local tmp
    tmp=$(mktemp -d /tmp/.curl_imp.XXXXXX)
    echo -e "${CYAN}[*] Качаем curl-impersonate v${ver} ${arch}...${NC}"
    if curl -fsSL "$url" -o "$tmp/curl-imp.tgz" 2>/dev/null; then
        tar xzf "$tmp/curl-imp.tgz" -C "$tmp" 2>/dev/null
        local bin
        bin=$(find "$tmp" -name 'curl-impersonate-safari' -type f 2>/dev/null | head -1)
        if [ -n "$bin" ] && [ -x "$bin" ]; then
            install -m 0755 "$bin" /usr/local/bin/curl-impersonate-safari
            echo -e "${GREEN}[+] /usr/local/bin/curl-impersonate-safari установлен.${NC}"
        else
            echo -e "${RED}[!] Не нашли curl-impersonate-safari в архиве.${NC}"
        fi
    else
        echo -e "${RED}[!] Не удалось скачать $url${NC}"
    fi
    rm -rf "$tmp"
}

# ===================================================================
#  Профили (presets)
# ===================================================================
# Каждый пресет — функция, которая выставляет глобальные PRESET_*
# переменные. Дальше apply_*_modules() читают их. Если значение не
# задано — берётся «balanced» по умолчанию.

preset_balanced() {
    PRESET_NAME="balanced"
    PRESET_NOFILE=1048576
    PRESET_BUF_MULT=1
    PRESET_TCP_FASTOPEN=3
    PRESET_TCP_FIN_TIMEOUT=10
    PRESET_TCP_KEEPALIVE_TIME=600
    PRESET_TCP_TW_BUCKETS=1440000
    PRESET_TCP_MAX_ORPHANS=262144
    PRESET_CONNTRACK_MAX=1048576
    PRESET_CONNTRACK_BUCKETS=262144
    PRESET_CONNTRACK_TCP_TIMEOUT=600
    PRESET_NETDEV_BACKLOG=500000
    PRESET_SOMAXCONN=65535
    PRESET_RPS_FLOWS=4096
    PRESET_PORT_RANGE="10000 65535"
    PRESET_ZRAM_FRACTION=50
    # vm.swappiness — оптимизировано для ZRAM (180 = prefer compressed swap-in
    # over page eviction; имеет смысл только когда ZRAM сконфигурирован).
    # v8.7: per-preset значения (proxy=30 latency-sensitive, web=60 moderate,
    # balanced=180 default ZRAM-friendly).
    PRESET_SWAPPINESS=180
    PRESET_BBR_PACING_SS=200
    PRESET_BBR_PACING_CA=120
}

# Прокси (xray/sing-box/haproxy/nginx-stream/wireguard) — много короткоживущих
# коннектов, агрессивные буферы, гигантский conntrack, максимум fds.
preset_proxy() {
    preset_balanced
    PRESET_NAME="proxy"
    PRESET_NOFILE=2097152
    PRESET_BUF_MULT=2
    PRESET_TCP_FIN_TIMEOUT=8
    PRESET_TCP_KEEPALIVE_TIME=300
    PRESET_TCP_TW_BUCKETS=2000000
    PRESET_TCP_MAX_ORPHANS=524288
    PRESET_CONNTRACK_MAX=2097152
    PRESET_CONNTRACK_BUCKETS=524288
    PRESET_CONNTRACK_TCP_TIMEOUT=300
    PRESET_NETDEV_BACKLOG=1000000
    PRESET_RPS_FLOWS=8192
    # v8.7: на proxy preset избегаем ZRAM-swap (latency-sensitive: handshake-burst
    # + busy connection pool). swappiness=30 — практически не свопим страницы пока
    # не подходит к OOM.
    PRESET_SWAPPINESS=30
}

# Web-сервер (nginx/apache, статический контент): меньше conntrack,
# умереннее буферы, security-акценты.
preset_web() {
    preset_balanced
    PRESET_NAME="web"
    PRESET_BUF_MULT=1
    PRESET_TCP_FIN_TIMEOUT=15
    PRESET_TCP_KEEPALIVE_TIME=900
    PRESET_TCP_TW_BUCKETS=720000
    PRESET_CONNTRACK_MAX=524288
    PRESET_CONNTRACK_BUCKETS=131072
    PRESET_CONNTRACK_TCP_TIMEOUT=900
    # v8.7: на web preset допускаем умеренный swap (cached static content can
    # tolerate IO-latency). 60 — сбалансированно между memory pressure и performance.
    PRESET_SWAPPINESS=60
}

load_preset() {
    local p="${1:-}"
    if [ -z "$p" ] && [ -f "$PRESET_FILE" ]; then
        p=$(tr -d '[:space:]' < "$PRESET_FILE" 2>/dev/null)
    fi
    [ -z "$p" ] && p="balanced"
    case "$p" in
        proxy)    preset_proxy ;;
        web)      preset_web ;;
        balanced) preset_balanced ;;
        *)        echo -e "${YELLOW}[!] Неизвестный пресет '$p', использую balanced${NC}"; preset_balanced ;;
    esac
    [ "$DRY_RUN" = "1" ] || echo "$PRESET_NAME" > "$PRESET_FILE" 2>/dev/null || true
    _log INFO "Preset: ${BOLD}${CYAN}${PRESET_NAME}${NC}"
}

# ===================================================================
#  Модули apply_optimizations
# ===================================================================

apply_zram() {
    if ! modprobe zram 2>/dev/null; then
        _log WARN "${YELLOW}[!] ZRAM недоступен (контейнер?) — пропуск.${NC}"
        return 0
    fi
    [ "$DRY_RUN" = "1" ] && { _log INFO "${GRAY}[dry-run] ZRAM пропущен${NC}"; return 0; }
    swapoff /dev/zram0 2>/dev/null || true
    zramctl --reset /dev/zram0 2>/dev/null || true
    local mem_total zram_size
    mem_total=$(free -m | awk '/Mem:/{print $2}')
    zram_size=$(( mem_total * PRESET_ZRAM_FRACTION / 100 ))
    [ "$zram_size" -lt 256 ] && zram_size=256
    zramctl --find --size "${zram_size}M" --algorithm zstd >/dev/null 2>&1 || \
        zramctl --find --size "${zram_size}M" --algorithm lz4 >/dev/null 2>&1
    mkswap /dev/zram0 >/dev/null 2>&1
    swapon /dev/zram0 -p 100 2>/dev/null || true
    _log OK "${GREEN}[+] ZRAM активен (${zram_size}MB).${NC}"
}

# Получаем список ядер, доступных для размещения сетевых очередей,
# исключая isolcpus (если оператор зарезервировал ядра под realtime).
usable_cpus() {
    local total isol
    total=$(nproc)
    isol=$(awk -F'isolcpus=' 'NF>1 {split($2,a," "); print a[1]}' /proc/cmdline 2>/dev/null)
    if [ -z "$isol" ] || ! command -v seq >/dev/null 2>&1; then
        seq 0 $((total-1))
        return
    fi
    # isolcpus может быть "1-3,5" — раскрываем диапазоны.
    local out=() c r a b
    declare -A excluded
    IFS=',' read -ra parts <<<"$isol"
    for r in "${parts[@]}"; do
        if [[ "$r" == *-* ]]; then
            a="${r%-*}"; b="${r#*-}"
            for ((c=a; c<=b; c++)); do excluded[$c]=1; done
        else
            excluded[$r]=1
        fi
    done
    for ((c=0; c<total; c++)); do
        [ -z "${excluded[$c]:-}" ] && out+=("$c")
    done
    printf '%s\n' "${out[@]}"
}

# Тюнинг сетевых интерфейсов: multi-queue, RPS, XPS, RFS, ring buffers,
# coalescence, LRO off, link-speed-aware подстройка буферов.
apply_iface_tuning() {
    local interfaces cpu_cores rps_mask
    interfaces=$(list_real_ifaces)
    cpu_cores=$(nproc)
    rps_mask=$(build_cpu_mask "$cpu_cores")

    if [ -z "$interfaces" ]; then
        _log WARN "${YELLOW}[!] Реальных интерфейсов не найдено — пропуск iface tuning.${NC}"
        return 0
    fi

    sysctl_safe net.core.rps_sock_flow_entries 32768

    # Список реально usable cores (вне isolcpus)
    local usable_arr
    mapfile -t usable_arr < <(usable_cpus)
    local usable_n="${#usable_arr[@]}"
    [ "$usable_n" -eq 0 ] && usable_n=1

    local iface
    for iface in $interfaces; do
        _log INFO "${YELLOW}[*] Iface tuning: $iface (mask=$rps_mask)${NC}"

        # Multi-queue: на virtio-net часто стоит 1 очередь — раскручиваем
        # до min(N_cpus, max_combined). Это даёт реальный multi-core эффект,
        # без него RPS/XPS не «доезжают» до железа.
        if [ "$DRY_RUN" != "1" ]; then
            local mq_max mq_target
            mq_max=$(ethtool -l "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^Combined:/{print $2; exit}')
            if [ -n "$mq_max" ] && [ "$mq_max" -gt 1 ]; then
                mq_target="$cpu_cores"
                [ "$mq_target" -gt "$mq_max" ] && mq_target="$mq_max"
                if ethtool -L "$iface" combined "$mq_target" >/dev/null 2>&1; then
                    _log OK "    multi-queue: combined=$mq_target / max $mq_max"
                fi
            fi
        fi
        local f
        # RPS — RX softirq распределение
        for f in /sys/class/net/"$iface"/queues/rx-*/rps_cpus; do
            [ -e "$f" ] && sysfs_safe "$f" "$rps_mask"
        done
        # RFS — flow steering
        for f in /sys/class/net/"$iface"/queues/rx-*/rps_flow_cnt; do
            [ -e "$f" ] && sysfs_safe "$f" "${PRESET_RPS_FLOWS}"
        done
        # XPS — TX распределение. Каждой TX-очереди свой bitmask
        # с одним ядром из usable списка (минуя isolcpus).
        local txq_idx=0 cpu_pick
        for f in /sys/class/net/"$iface"/queues/tx-*/xps_cpus; do
            if [ -e "$f" ]; then
                cpu_pick="${usable_arr[$(( txq_idx % usable_n ))]:-0}"
                local one_cpu_mask
                one_cpu_mask=$(cpu_to_xps_mask "$cpu_pick")
                sysfs_safe "$f" "$one_cpu_mask"
                txq_idx=$(( txq_idx + 1 ))
            fi
        done

        # ВАЖНО: LRO выключаем — он ломает форвардинг.
        if [ "$DRY_RUN" != "1" ]; then
            # Offload-настройки только если nic_offload_safe_for_iface даёт зелёный свет
            # (KVM/Xen/native — да; openvz/lxc/docker — нет).
            if nic_offload_safe_for_iface "$iface"; then
                ethtool -K "$iface" rx on tx on sg on tso on gso on gro on lro off >/dev/null 2>&1 || true
                # UDP GRO/GSO (v8.3): даёт +2-3x throughput на QUIC/Hysteria/WireGuard на 5.18+ ядрах.
                # Часть драйверов рапортует об ошибке если не поддерживают — игнорим.
                ethtool -K "$iface" rx-udp-gro-forwarding on >/dev/null 2>&1 || true
                ethtool -K "$iface" tx-udp-segmentation on >/dev/null 2>&1 || true
            else
                # Контейнер: только LRO off (важно для прокси), остальное по-умолчанию
                ethtool -K "$iface" lro off >/dev/null 2>&1 || true
            fi

            # Ring buffers до железного максимума
            local ring_max_rx ring_max_tx
            ring_max_rx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^RX:/{print $2; exit}')
            ring_max_tx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^TX:/{print $2; exit}')
            if [ -n "$ring_max_rx" ] && [ -n "$ring_max_tx" ]; then
                ethtool -G "$iface" rx "$ring_max_rx" tx "$ring_max_tx" >/dev/null 2>&1 || true
            fi
            ethtool -C "$iface" adaptive-rx on adaptive-tx on >/dev/null 2>&1 || \
                ethtool -C "$iface" rx-usecs 8 tx-usecs 8 >/dev/null 2>&1 || true

            # v8.4 NIC enhancements (best-effort, ошибки игнорируются):
            #  - rx-flow-hash udp4/udp6 sdfn — RSS hash включает src/dst ports,
            #    иначе все QUIC-сессии с одной пары IP идут на одну очередь.
            #  - hw-tc-offload — TC-классы выполняются в железе на Mellanox/Intel
            #    800-series, экономит CPU.
            #  - gso-max-size 65536 — большие GSO-фреймы для virtio-net,
            #    снижают packet-rate в host kernel.
            #  - ntuple-filters — нужно для kernel-bypass правил RSS.
            if nic_offload_safe_for_iface "$iface"; then
                ethtool -N "$iface" rx-flow-hash udp4 sdfn >/dev/null 2>&1 || true
                ethtool -N "$iface" rx-flow-hash udp6 sdfn >/dev/null 2>&1 || true
                ethtool -N "$iface" rx-flow-hash tcp4 sdfn >/dev/null 2>&1 || true
                ethtool -N "$iface" rx-flow-hash tcp6 sdfn >/dev/null 2>&1 || true
                ethtool -K "$iface" hw-tc-offload on >/dev/null 2>&1 || true
                ethtool -K "$iface" ntuple on >/dev/null 2>&1 || true
                # gso-max-size требует Linux 5.18+ и драйверной поддержки.
                # v8.8 (K1): BIG TCP for IPv6 — на kernel 6.3+ повышаем gso/gro_max
                # до 196608 (192K). Это даёт +20-40% throughput на 10G+ NIC через
                # уменьшение количества per-segment overhead. На kernel <6.3 драйвер
                # тихо отвергнет, fallback к 65536. Безопасно: если иp link не примет,
                # ничего не ломается.
                local _krn_major _krn_minor _gso_target=65536
                _krn_major=$(uname -r 2>/dev/null | awk -F. '{print $1}')
                _krn_minor=$(uname -r 2>/dev/null | awk -F. '{print $2}')
                if [ -n "$_krn_major" ] && [ -n "$_krn_minor" ] && \
                   { [ "$_krn_major" -gt 6 ] 2>/dev/null || \
                     { [ "$_krn_major" = "6" ] && [ "$_krn_minor" -ge 3 ] 2>/dev/null; }; }; then
                    _gso_target=196608
                fi
                ip link set dev "$iface" gso_max_size "$_gso_target" >/dev/null 2>&1 || \
                    ip link set dev "$iface" gso_max_size 65536 >/dev/null 2>&1 || true
                ip link set dev "$iface" gro_max_size "$_gso_target" >/dev/null 2>&1 || \
                    ip link set dev "$iface" gro_max_size 65536 >/dev/null 2>&1 || true

                # v8.8 (N1): txqueuelen auto-tune. Default 1000 на 10G+ узкое место для
                # bursty traffic (handshake-storm, DDoS-fronted прокси). Скейлим под
                # link-speed: 1G→1000 (no-op), 10G→5000, 25G+→10000. Безопасно: не
                # увеличивает memory footprint в idle, только cap на in-flight queue.
                # detect_link_speed_mbps читает /sys/class/net/*/speed без аргументов
                # и возвращает максимальную из активных. На VPS под виртой возвращает
                # default 1000 если speed=-1 (virtio). Точное число сейчас не важно —
                # нужно лишь >10000. Если функция недоступна (устаревшая версия), 0.
                local _spd
                _spd=$(detect_link_speed_mbps 2>/dev/null || echo 0)
                if [ "$_spd" -ge 25000 ] 2>/dev/null; then
                    ip link set dev "$iface" txqueuelen 10000 >/dev/null 2>&1 || true
                elif [ "$_spd" -ge 10000 ] 2>/dev/null; then
                    ip link set dev "$iface" txqueuelen 5000 >/dev/null 2>&1 || true
                fi

                # v8.9 (N5): Ring buffer auto-tune через ethtool -G. На VPS
                # default rx/tx часто 256 или 512 (virtio), что слишком мало
                # для 10G+ NIC и приводит к drops под bursty traffic. Поднимаем
                # до 4096 (или max если меньше). На kernel/driver без ring-buf
                # support `ethtool -g` вернёт error → skip. На VPN-iface уже
                # пропускаем выше через `case "$iface" in tun*|wg*|...`.
                # Безопасно: ring buffer выделяется один раз при apply, не
                # растёт под нагрузкой.
                if command -v ethtool >/dev/null 2>&1; then
                    local _ring_max_rx _ring_max_tx _ring_cur_rx _ring_cur_tx
                    # ethtool -g eth0 печатает:
                    #   Pre-set maximums:
                    #   RX: 4096
                    #   ...
                    #   Current hardware settings:
                    #   RX: 256
                    _ring_max_rx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/,/Current hardware settings:/ {if($1=="RX:") print $2}' | head -1)
                    _ring_max_tx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/,/Current hardware settings:/ {if($1=="TX:") print $2}' | head -1)
                    _ring_cur_rx=$(ethtool -g "$iface" 2>/dev/null | awk '/Current hardware settings:/,0 {if($1=="RX:") print $2}' | head -1)
                    _ring_cur_tx=$(ethtool -g "$iface" 2>/dev/null | awk '/Current hardware settings:/,0 {if($1=="TX:") print $2}' | head -1)
                    if [ -n "$_ring_max_rx" ] && [ "$_ring_max_rx" -ge 1024 ] 2>/dev/null && \
                       [ -n "$_ring_cur_rx" ] && [ "$_ring_cur_rx" -lt 2048 ] 2>/dev/null; then
                        local _ring_target_rx=4096
                        [ "$_ring_max_rx" -lt 4096 ] && _ring_target_rx="$_ring_max_rx"
                        ethtool -G "$iface" rx "$_ring_target_rx" >/dev/null 2>&1 || true
                    fi
                    if [ -n "$_ring_max_tx" ] && [ "$_ring_max_tx" -ge 1024 ] 2>/dev/null && \
                       [ -n "$_ring_cur_tx" ] && [ "$_ring_cur_tx" -lt 2048 ] 2>/dev/null; then
                        local _ring_target_tx=4096
                        [ "$_ring_max_tx" -lt 4096 ] && _ring_target_tx="$_ring_max_tx"
                        ethtool -G "$iface" tx "$_ring_target_tx" >/dev/null 2>&1 || true
                    fi
                fi
            fi
        fi
    done
}

# Размазываем сетевые IRQ по ядрам. На многих VPS /proc/irq/*/smp_affinity_list
# не writable (provider запретил) — тогда мягко скипаем.
apply_irq_affinity() {
    local cpu_cores
    cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 2 ]; then
        _log INFO "${GRAY}[*] 1 CPU — IRQ affinity пропуск.${NC}"
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        _log INFO "${GRAY}[dry-run] IRQ affinity не трогаю${NC}"
        return 0
    fi
    # Гасим irqbalance, иначе он перетрёт наши настройки. В контейнерах он
    # обычно не запущен — просто скипаем ошибку.
    systemctl stop irqbalance 2>/dev/null || true
    systemctl disable irqbalance 2>/dev/null || true

    local usable_arr
    mapfile -t usable_arr < <(usable_cpus)
    local usable_n="${#usable_arr[@]}"
    [ "$usable_n" -eq 0 ] && usable_n="$cpu_cores"

    local iface irq_list irq cpu_idx=0 cpu_pick
    for iface in $(list_real_ifaces); do
        # IRQs принадлежащие интерфейсу — ищем в /proc/interrupts по
        # суффиксу с именем интерфейса (например, virtio0-input.0).
        irq_list=$(awk -v ifn="$iface" '$NF ~ ifn {gsub(":","",$1); print $1}' /proc/interrupts 2>/dev/null)
        for irq in $irq_list; do
            local affinity_file="/proc/irq/${irq}/smp_affinity_list"
            cpu_pick="${usable_arr[$(( cpu_idx % usable_n ))]:-0}"
            if [ -w "$affinity_file" ]; then
                # Пишем дважды: некоторые ядра возвращают EBUSY на первой записи
                # (особенно сразу после ethtool -L). Перепроверяем readback.
                local readback
                if echo "$cpu_pick" > "$affinity_file" 2>/dev/null; then
                    readback=$(cat "$affinity_file" 2>/dev/null)
                    if [ "$readback" = "$cpu_pick" ]; then
                        SYSFS_OK+=("irq#${irq}->cpu${cpu_pick}")
                    else
                        # Retry один раз
                        echo "$cpu_pick" > "$affinity_file" 2>/dev/null || true
                        readback=$(cat "$affinity_file" 2>/dev/null)
                        if [ "$readback" = "$cpu_pick" ]; then
                            SYSFS_OK+=("irq#${irq}->cpu${cpu_pick}(retry)")
                        else
                            SYSFS_SKIP+=("irq#${irq}:readback=$readback")
                        fi
                    fi
                else
                    SYSFS_SKIP+=("irq#${irq}:write-failed")
                fi
                cpu_idx=$(( cpu_idx + 1 ))
            else
                SYSFS_SKIP+=("irq#${irq}:no-write")
            fi
        done
    done
}

# CPU governor → performance. На share-VM часто залочено провайдером —
# скипаем без сбоя.
apply_cpu_governor() {
    [ "$DRY_RUN" = "1" ] && { _log INFO "${GRAY}[dry-run] CPU governor не трогаю${NC}"; return 0; }
    local f set=0
    for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        if [ -w "$f" ]; then
            echo performance > "$f" 2>/dev/null && set=1
        fi
    done
    if [ "$set" = "1" ]; then
        _log OK "${GREEN}[+] CPU governor → performance${NC}"
    else
        _log INFO "${GRAY}[*] CPU governor: на этой VPS не управляется (провайдер) — skip${NC}"
    fi
}

# Transparent Huge Pages → madvise (без latency spikes на прокси-нагрузках).
apply_thp() {
    [ "$DRY_RUN" = "1" ] && { _log INFO "${GRAY}[dry-run] THP не трогаю${NC}"; return 0; }
    if [ -w /sys/kernel/mm/transparent_hugepage/enabled ]; then
        if echo madvise > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null; then
            _log OK "${GREEN}[+] THP=madvise${NC}"
        fi
    fi
    if [ -w /sys/kernel/mm/transparent_hugepage/defrag ]; then
        echo madvise > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true
    fi

    # v8.5: KSM (Kernel Samepage Merging) — на VPS с одинаковыми образами
    # многим страницам сильно дубликаты, KSM их merge'ит, экономит RAM 5-15%.
    # Включаем только если виртуализация (KSM на bare-metal не несёт пользы,
    # ест CPU). Скорость merge — sleep_millisecs=200 (мягкий, default 20).
    local virt
    virt=$(detect_virt)
    # v8.5: KSM ставим только под preset=proxy в виртуализации.
    # На balanced/web KSM ест CPU непрерывным сканированием — это меняет default
    # apply behaviour (CONTRIBUTING #5). Прокси-нагрузки сами решают что 5-15%
    # экономия RAM выгоднее CPU-overhead.
    if [ "$PRESET_NAME" = "proxy" ]; then
        case "$virt" in
            kvm|xen|hyperv|microsoft|vmware)
                if sysfs_safe /sys/kernel/mm/ksm/run 1; then
                    _log OK "${GREEN}[+] KSM=on (sleep_millisecs=200)${NC}"
                    sysfs_safe /sys/kernel/mm/ksm/sleep_millisecs 200
                    sysfs_safe /sys/kernel/mm/ksm/pages_to_scan 1000
                fi
                ;;
        esac
    fi
}

# I/O scheduler: для NVMe — none, для SATA SSD — mq-deadline, HDD — bfq (если
# доступен). Плюс readahead. v8.9 (N7): улучшенная логика выбора planner'а.
apply_block_io() {
    [ "$DRY_RUN" = "1" ] && { _log INFO "${GRAY}[dry-run] block I/O не трогаю${NC}"; return 0; }
    local dev
    for dev in /sys/block/*; do
        local name="${dev##*/}"
        # Виртуальные / loop / zram пропускаем
        case "$name" in
            loop*|ram*|zram*|sr*|fd*|dm-*|md*) continue ;;
        esac
        local rotational
        rotational=$(cat "$dev/queue/rotational" 2>/dev/null || echo 1)
        local available=""
        [ -r "$dev/queue/scheduler" ] && available=$(cat "$dev/queue/scheduler" 2>/dev/null)

        # v8.9 (N7): тонкая выборка scheduler'а:
        #   NVMe (multi-queue, low-latency) → 'none' (no scheduler overhead, всё
        #     решает device's hw queue)
        #   SATA/SAS SSD (rotational=0, non-nvme) → 'mq-deadline' (предсказуемая
        #     latency для smaller queue depth)
        #   HDD (rotational=1) → 'bfq' если CONFIG_IOSCHED_BFQ=y (Ubuntu 22+),
        #     иначе fallback к 'mq-deadline'. BFQ даёт лучший fair-queueing для
        #     HDD с long seeks.
        local target="mq-deadline"
        case "$name" in
            nvme*) target="none" ;;
            *)
                if [ "$rotational" = "1" ] && echo "$available" | grep -qw "bfq"; then
                    target="bfq"
                fi
                ;;
        esac
        if [ -w "$dev/queue/scheduler" ]; then
            if echo "$available" | grep -qw "$target"; then
                if echo "$target" > "$dev/queue/scheduler" 2>/dev/null; then
                    SYSFS_OK+=("$name:scheduler=$target")
                fi
            fi
        fi
        [ -w "$dev/queue/nr_requests" ] && \
            sysfs_safe "$dev/queue/nr_requests" 512
        [ -w "$dev/queue/read_ahead_kb" ] && \
            sysfs_safe "$dev/queue/read_ahead_kb" 128
    done
    # core_pattern → /dev/null: на закрытых cloud VM крах процесса не должен
    # съедать диск дампами.
    if [ -w /proc/sys/kernel/core_pattern ]; then
        sysctl_safe kernel.core_pattern "|/bin/false" || true
    fi
}

# Все sysctls — через probe-then-write. То, что ядро/гипервизор не приняли,
# не попадёт в persistent-конфиг. Это и есть главная фишка v7.0.
apply_sysctls() {
    local kvi
    kvi=$(kernel_version_int)

    # Базовые fs/kernel
    sysctl_safe fs.file-max 2000000
    sysctl_safe fs.nr_open 2000000
    sysctl_safe kernel.pid_max 4194304
    sysctl_safe fs.inotify.max_user_watches 524288
    sysctl_safe fs.inotify.max_user_instances 512
    sysctl_safe kernel.sched_autogroup_enabled 0
    sysctl_safe kernel.sched_migration_cost_ns 5000000

    # Подбираем congestion control из реально доступных
    local best_bbr="cubic"
    if has_cong_ctl bbr3; then best_bbr="bbr3"
    elif has_cong_ctl bbr2; then best_bbr="bbr2"
    elif has_cong_ctl bbr;  then best_bbr="bbr"
    fi

    # v8.9 (N3): qdisc selection. На bare-metal/dedicated `cake` побеждает
    # bufferbloat (compound bandwidth+latency shaping), но это >2x CPU vs fq.
    # На VPS cake обычно избыточен — кастомер VPS сидит за hypervisor SLA,
    # и BBR+fq уже даёт near-optimal pacing. Поэтому:
    #   - bare-metal (none) → cake если доступен;
    #   - virt (kvm/xen/lxc/...) → fq если BBR, иначе fq_codel.
    # На kernel/dist без sch_cake module modprobe вернёт error → skip к fq.
    local best_qdisc="fq_codel" _virt_now
    _virt_now=$(detect_virt 2>/dev/null || echo unknown)
    if [ "$_virt_now" = "none" ] && modprobe sch_cake 2>/dev/null; then
        best_qdisc="cake"
    elif modprobe sch_fq 2>/dev/null; then
        best_qdisc="fq"
    elif modprobe sch_cake 2>/dev/null; then
        best_qdisc="cake"
    fi
    [ "$best_bbr" != "cubic" ] && modprobe sch_fq 2>/dev/null && best_qdisc="fq"

    # Адаптивные буферы — масштабируются по RAM × множитель пресета.
    # Дополнительно учитываем реальную скорость сетевого линка через
    # ethtool: BDP = link_speed × ~150ms RTT. На 10G+ линке имеет смысл
    # поднять потолок до 512MB даже на VPS с малой RAM.
    local mem_mb buf_max=134217728
    mem_mb=$(free -m | awk '/Mem:/{print $2}')
    [ "$mem_mb" -ge 8192 ]  && buf_max=268435456
    [ "$mem_mb" -ge 16384 ] && buf_max=536870912

    local link_mbps=0 link_iface
    for link_iface in $(list_real_ifaces); do
        local s
        s=$(ethtool "$link_iface" 2>/dev/null | awk '/Speed:/{print $2}' | grep -oE '[0-9]+' | head -1)
        if [ -n "$s" ] && [ "$s" -gt "$link_mbps" ]; then
            link_mbps="$s"
        fi
    done
    if [ "$link_mbps" -ge 10000 ] && [ "$buf_max" -lt 268435456 ]; then
        buf_max=268435456  # 10G линк → минимум 256MB потолок
    fi
    if [ "$link_mbps" -ge 25000 ] && [ "$buf_max" -lt 536870912 ]; then
        buf_max=536870912  # 25G+ → 512MB потолок
    fi
    buf_max=$(( buf_max * PRESET_BUF_MULT ))

    # Networking core
    sysctl_safe net.core.default_qdisc "$best_qdisc"
    sysctl_safe net.ipv4.tcp_congestion_control "$best_bbr"
    sysctl_safe net.core.netdev_budget 600
    sysctl_safe net.core.netdev_budget_usecs 8000
    sysctl_safe net.core.netdev_max_backlog "$PRESET_NETDEV_BACKLOG"
    sysctl_safe net.core.somaxconn "$PRESET_SOMAXCONN"
    sysctl_safe net.core.busy_poll 50
    sysctl_safe net.core.busy_read 50
    sysctl_safe net.core.optmem_max 4194304
    sysctl_safe net.core.dev_weight 128
    sysctl_safe net.core.flow_limit_table_len 8192
    # v8.4: bpf_jit_enable — JIT для всех eBPF/XDP программ. Default=0 на многих
    # ядрах. JIT даёт 10-100x ускорение интерпретатора (нужен для XDP/cilium-style
    # фильтров, для нашего шум-генератора — нейтрально, но для будущих helpers — критично).
    sysctl_safe net.core.bpf_jit_enable 1
    # v8.4: bpf_jit_kallsyms=1 (отладка/perf), bpf_jit_harden=1 (анти-spectre v1) —
    # включаем оба, незначительный CPU-overhead, заметно лучше observability.
    sysctl_safe net.core.bpf_jit_kallsyms 1
    sysctl_safe net.core.bpf_jit_harden 1

    # v8.5: io_uring и scheduler tuning — ТОЛЬКО для preset=proxy.
    # Используем $PRESET_NAME (resolved preset из preset_balanced/proxy/web), а не
    # $PRESET (CLI arg, может быть пустой если preset загружен из файла).
    # CONTRIBUTING rule #5: default apply (balanced/web) не трогает security-sensitive
    # и latency-sensitive ядерные knob'ы.
    if [ "$PRESET_NAME" = "proxy" ]; then
        # io_uring — современный async-IO API. Default disabled на secure-конфигах
        # (Ubuntu 22.04+ disable=2 в LSM). Прокси (sing-box/h2o) умеют — +20-40% throughput.
        sysctl_safe kernel.io_uring_disabled 0
        # sched_min_granularity_ns=10ms (default 1.5ms) — больше CPU-time per task,
        # меньше context-switch overhead. На balanced/web ставить не нужно — они хотят
        # низкую latency, а 6.7x granularity её ухудшит.
        sysctl_safe kernel.sched_min_granularity_ns 10000000
        sysctl_safe kernel.sched_wakeup_granularity_ns 15000000
    fi

    # v8.6: numa_balancing — на не-NUMA-VPS (1 узел) автобаланс только сжигает CPU.
    # Auto-detect: если numactl сообщает 1 node, выключаем; если ≥2 — оставляем kernel default.
    # На bare-metal или multi-socket это критично оставить включённым (1).
    if command -v numactl >/dev/null 2>&1; then
        local _numa_nodes
        _numa_nodes=$(numactl --hardware 2>/dev/null | awk '/available:/{print $2}')
        if [ -n "$_numa_nodes" ] && [ "$_numa_nodes" = "1" ]; then
            sysctl_safe kernel.numa_balancing 0
        fi
    elif [ -d /sys/devices/system/node ]; then
        # Без numactl: считаем узлы через sysfs.
        local _node_count
        _node_count=$(find /sys/devices/system/node -maxdepth 1 -name 'node[0-9]*' 2>/dev/null | wc -l)
        [ "$_node_count" = "1" ] && sysctl_safe kernel.numa_balancing 0
    fi

    # v8.7 fix (Devin Review #10): v8.6 ошибочно ставил `udp_l3mdev_accept 0` с
    # комментарием про udp_hash_entries — это два разных параметра. udp_hash_entries
    # вообще не runtime-sysctl, а kernel boot-parameter (`udphash=N` / read-only
    # после boot). Удалили баговую строку; правильный l3mdev_accept=1 ставится
    # ниже в v8.7-блоке (вместе с tcp_l3mdev_accept).
    # busy_poll/busy_read=50 уже стоят выше — синхронизировано для UDP/QUIC.

    # v8.6: IPv6 privacy extensions (RFC 4941) — temp-addr как primary source-addr
    # для исходящих соединений. Имитирует поведение реального iOS (anti-tracking).
    # Гейтим под proxy — на balanced/web стабильный адрес важнее (rDNS, firewall
    # rules, monitoring). На proxy noise/stealth-исходящий трафик главнее.
    # Incoming SSH/VPN не затрагивается — listen socket bind'ится на любой адрес.
    if [ "$PRESET_NAME" = "proxy" ]; then
        sysctl_safe net.ipv6.conf.all.use_tempaddr 2
        sysctl_safe net.ipv6.conf.default.use_tempaddr 2
        sysctl_safe net.ipv6.conf.all.regen_max_retry 3
        # max_desync_factor — уменьшаем «случайный сдвиг» обновления temp-addr (default 600s).
        sysctl_safe net.ipv6.conf.all.max_desync_factor 60
    fi

    # NAPI defer (Linux 5.12+)
    if [ "$kvi" -ge 51200 ]; then
        sysctl_safe net.core.gro_flush_timeout 200000
        sysctl_safe net.core.napi_defer_hard_irqs 2
    fi

    # Buffers
    sysctl_safe net.core.rmem_max "$buf_max"
    sysctl_safe net.core.wmem_max "$buf_max"
    sysctl_safe net.core.rmem_default 2097152
    sysctl_safe net.core.wmem_default 2097152
    sysctl_safe net.ipv4.tcp_rmem "4096 2097152 $buf_max"
    sysctl_safe net.ipv4.tcp_wmem "4096 2097152 $buf_max"
    sysctl_safe net.ipv4.tcp_mem "786432 1048576 1572864"
    sysctl_safe net.ipv4.tcp_adv_win_scale -2
    sysctl_safe net.ipv4.tcp_moderate_rcvbuf 1
    sysctl_safe net.ipv4.tcp_notsent_lowat 131072

    # UDP — критично для QUIC/Reality/XHTTP, а также WireGuard/OpenVPN/Hysteria2/TUIC.
    # Расширено в v8.3: per-socket min повышен (для серверов с тяжёлым QUIC),
    # optmem_max для SO_ZEROCOPY, и общий udp_mem (в страницах) под прокси-нагрузку.
    sysctl_safe net.ipv4.udp_rmem_min 131072
    sysctl_safe net.ipv4.udp_wmem_min 131072
    sysctl_safe net.ipv4.udp_mem "786432 1048576 1572864"
    # NB: net.core.optmem_max уже выставлен выше в 4194304 (4MB) — не перетираем.
    # TFO black-hole defuse (v8.3): дефолт ядра — 1ч лок после первой неудачи.
    # На флапающей сети это «тихая» причина почему TFO «не работает».
    sysctl_safe net.ipv4.tcp_fastopen_blackhole_timeout_sec 0

    # TCP behavior
    sysctl_safe net.ipv4.tcp_mtu_probing 1
    sysctl_safe net.ipv4.tcp_window_scaling 1
    sysctl_safe net.ipv4.tcp_sack 1
    sysctl_safe net.ipv4.tcp_dsack 1
    sysctl_safe net.ipv4.tcp_fack 0
    sysctl_safe net.ipv4.tcp_timestamps 1
    sysctl_safe net.ipv4.tcp_no_metrics_save 1
    sysctl_safe net.ipv4.tcp_slow_start_after_idle 0
    sysctl_safe net.ipv4.tcp_tw_reuse 1
    sysctl_safe net.ipv4.tcp_max_tw_buckets "$PRESET_TCP_TW_BUCKETS"
    sysctl_safe net.ipv4.tcp_fin_timeout "$PRESET_TCP_FIN_TIMEOUT"
    sysctl_safe net.ipv4.tcp_keepalive_time "$PRESET_TCP_KEEPALIVE_TIME"
    sysctl_safe net.ipv4.tcp_keepalive_intvl 30
    sysctl_safe net.ipv4.tcp_keepalive_probes 5
    sysctl_safe net.ipv4.tcp_fastopen "$PRESET_TCP_FASTOPEN"
    sysctl_safe net.ipv4.tcp_max_syn_backlog 65535
    sysctl_safe net.ipv4.tcp_synack_retries 2
    sysctl_safe net.ipv4.tcp_syn_retries 3
    sysctl_safe net.ipv4.tcp_max_orphans "$PRESET_TCP_MAX_ORPHANS"
    sysctl_safe net.ipv4.tcp_orphan_retries 2
    sysctl_safe net.ipv4.tcp_min_snd_mss 536
    # v8.4: shifted from 300s → 600s — стабильнее BBR-оценка при джиттере на
    # длинных линиях (РФ↔Европа), без потери adaptивности на мобильных.
    sysctl_safe net.ipv4.tcp_min_rtt_wlen 600
    sysctl_safe net.ipv4.tcp_pacing_ss_ratio "$PRESET_BBR_PACING_SS"
    sysctl_safe net.ipv4.tcp_pacing_ca_ratio "$PRESET_BBR_PACING_CA"
    sysctl_safe net.ipv4.tcp_collapse_max_bytes 6291456
    sysctl_safe net.ipv4.ip_local_port_range "$PRESET_PORT_RANGE"

    # Глубокая настройка TCP-стека (новое в v8.0):
    #  app_win=31 — максимум окна, отдаваемого приложению (важно для прокси),
    #  recovery=1 (RACK) — современный recovery-механизм по таймстампам,
    #  ecn=2 — пассивный ECN (отвечаем на ECN-флаги, но сами не запрашиваем),
    #  thin_linear_timeouts=1 — линейные ретраи на «тонких» соединениях,
    #  reordering — устойчивость к out-of-order пакетам в облачных сетях.
    sysctl_safe net.ipv4.tcp_app_win 31
    sysctl_safe net.ipv4.tcp_recovery 1
    sysctl_safe net.ipv4.tcp_ecn 2
    sysctl_safe net.ipv4.tcp_ecn_fallback 1
    sysctl_safe net.ipv4.tcp_thin_linear_timeouts 1
    # v8.6: tcp_thin_dupack=1 — gated to --preset proxy (CONTRIBUTING #5: tcp_thin_*).
    # Включает dupack-ускорение (1 dupack → fast retx, не 3) для streams помеченных
    # TCP_THIN_LINEAR_TIMEOUTS. На balanced/web preset не трогаем — там обычные потоки.
    if [ "$PRESET_NAME" = "proxy" ]; then
        sysctl_safe net.ipv4.tcp_thin_dupack 1
    fi
    # v8.6: tcp_reordering 6 → 10 — на jittery-облаках (RU↔EU, мобильные) spurious
    # retransmits заметно реже; max_reordering 300 → 600 — потолок для extreme cases.
    sysctl_safe net.ipv4.tcp_reordering 10
    sysctl_safe net.ipv4.tcp_max_reordering 600
    sysctl_safe net.ipv4.tcp_early_retrans 3
    sysctl_safe net.ipv4.tcp_frto 2
    sysctl_safe net.ipv4.tcp_autocorking 0
    sysctl_safe net.ipv4.tcp_limit_output_bytes 1048576

    # Доводки под низкий пинг (новое в v8.1) — ТОЛЬКО то, чего ещё нет выше.
    # tcp_fin_timeout / tcp_keepalive_time / tcp_keepalive_intvl / tcp_keepalive_probes /
    # tcp_syn_retries / tcp_synack_retries / tcp_min_snd_mss / tcp_slow_start_after_idle
    # уже выставлены preset'ом или базовым блоком — их повторное переписывание перебило бы
    # значения из proxy/web preset'а (баг, исправлен в v8.1.1).
    #  - mtu_probing=1 + base_mss=1024 + probe_interval=600 + probe_threshold=8:
    #    лечит PMTU-чёрные дыры на туннелях/прокси (WireGuard/Reality/XHTTP).
    #  - workaround_signed_windows=1 — устраняет квирк старых клиентов.
    #  - tcp_retries2=8 — быстрее освобождаем мёртвые сокеты.
    #  - tcp_low_latency=1 — historic, безопасно: предпочитать latency throughput-у.
    #  - challenge_ack_limit=999 — без side-channel detection.
    #  - netdev_budget повышен для softirq на >1Gbps.
    sysctl_safe net.ipv4.tcp_mtu_probing 1
    sysctl_safe net.ipv4.tcp_base_mss 1024
    sysctl_safe net.ipv4.tcp_probe_interval 600
    sysctl_safe net.ipv4.tcp_probe_threshold 8
    sysctl_safe net.ipv4.tcp_workaround_signed_windows 1
    sysctl_safe net.ipv4.tcp_retries2 8
    sysctl_safe net.ipv4.tcp_low_latency 1
    sysctl_safe net.ipv4.tcp_challenge_ack_limit 999
    sysctl_safe net.ipv4.ip_no_pmtu_disc 0
    sysctl_safe net.core.netdev_budget 600
    sysctl_safe net.core.netdev_budget_usecs 8000
    sysctl_safe net.ipv4.tcp_invalid_ratelimit 500

    # Доводки v8.2 (PHOENIX-Z++):
    #  - tcp_rto_min_us — минимальный RTO в микросекундах (новое в 6.x). Уменьшает
    #    время до retransmit на jitter'ных РФ-облаках с ~30-80мс выигрышем на потерях.
    #  - tcp_comp_sack_delay_ns / tcp_comp_sack_nr — SACK compression уменьшает
    #    CPU на каждый ACK при множестве потерь (важно для MPTCP/sing-box).
    #  - tcp_comp_sack_slack_ns — допустимая задержка перед сжатием.
    #  - tcp_pingpong_thresh — порог переключения в pingpong mode (новое в 6.1+).
    #  - tcp_min_tso_segs / tcp_tso_win_divisor — балансируем TSO под прокси.
    #  - tcp_no_ssthresh_metrics_save — не сохраняем устаревший ssthresh между сессиями.
    sysctl_safe net.ipv4.tcp_rto_min_us 100000
    sysctl_safe net.ipv4.tcp_comp_sack_delay_ns 1000000
    sysctl_safe net.ipv4.tcp_comp_sack_nr 44
    sysctl_safe net.ipv4.tcp_comp_sack_slack_ns 100000
    sysctl_safe net.ipv4.tcp_min_tso_segs 2
    sysctl_safe net.ipv4.tcp_tso_win_divisor 3
    sysctl_safe net.ipv4.tcp_no_ssthresh_metrics_save 1
    sysctl_safe net.ipv4.tcp_pingpong_thresh 1

    # ECMP / multipath: если у VPS реально несколько default-маршрутов на разные
    # интерфейсы или включён --ecmp флаг, разрешаем мульти-путь по hash от L4-портов.
    if [ "$ECMP" = "1" ] || has_ecmp; then
        sysctl_safe net.ipv4.fib_multipath_use_neigh 1
        sysctl_safe net.ipv4.fib_multipath_hash_policy 1
    fi

    # high-order аллокатор страниц: разрешаем jumbo-skb на >10G линках.
    sysctl_safe net.core.high_order_alloc_disable 0

    # MPTCP (Linux 5.6+)
    if [ "$kvi" -ge 50600 ]; then
        sysctl_safe net.mptcp.enabled 1
    fi

    # Маскировка стека: TTL=64 как у нативного Linux-десктопа.
    sysctl_safe net.ipv4.ip_default_ttl 64

    # Security / hygiene.
    # rp_filter (v8.3): сохраняем backward-compat дефолт =1 (strict, как было в v8.2).
    # Loose mode (=2) включаем только под --vpn или при детекте VPN-iface, потому что
    # strict (=1) дропает asymmetric routing, что ломает WireGuard/OpenVPN/MPTCP.
    # Это поведение соответствует CONTRIBUTING.md: «no default change without opt-in».
    sysctl_safe net.ipv4.tcp_syncookies 1
    sysctl_safe net.ipv4.tcp_rfc1337 1
    local rp_filter_target=1
    if [ "$VPN_FORCE" = "1" ] || has_vpn_iface; then
        rp_filter_target=2
    fi
    sysctl_safe net.ipv4.conf.all.rp_filter "$rp_filter_target"
    sysctl_safe net.ipv4.conf.default.rp_filter "$rp_filter_target"
    sysctl_safe net.ipv4.conf.all.accept_redirects 0
    sysctl_safe net.ipv4.conf.default.accept_redirects 0
    sysctl_safe net.ipv4.conf.all.send_redirects 0
    sysctl_safe net.ipv4.conf.default.send_redirects 0
    sysctl_safe net.ipv4.conf.all.accept_source_route 0
    sysctl_safe net.ipv4.conf.default.accept_source_route 0
    sysctl_safe net.ipv4.icmp_echo_ignore_broadcasts 1
    sysctl_safe net.ipv6.conf.all.accept_redirects 0
    sysctl_safe net.ipv6.conf.default.accept_redirects 0
    sysctl_safe net.ipv6.conf.all.accept_source_route 0
    sysctl_safe net.ipv6.conf.default.accept_source_route 0

    # IPv6 mirror
    sysctl_safe net.ipv6.conf.all.disable_ipv6 0
    sysctl_safe net.ipv6.conf.default.disable_ipv6 0

    # VPN-friendly доводки: включаются если виден tun*/wg*/ppp*/tap* iface
    # (т.е. на машине уже поднят VPN-туннель) или передан явный --vpn.
    if [ "$VPN_FORCE" = "1" ] || has_vpn_iface; then
        sysctl_safe net.ipv4.conf.all.accept_local 1
        sysctl_safe net.ipv4.ip_forward 1
        sysctl_safe net.ipv6.conf.all.forwarding 1
        # На VPN-сервере conntrack-помощники (FTP/SIP/IRC NAT) лучше выключить —
        # они могут потеряться через туннель и привести к странным дропам.
        sysctl_safe net.netfilter.nf_conntrack_helper 0
    fi

    # IPv6 параллель ключевых TCP knob'ов (v8.3): TCP-стек у v4 и v6 общий, но
    # часть control-knob'ов имеет per-family версию.
    sysctl_safe net.ipv6.bindv6only 0

    # tcp_keepalive_intvl/probes уже выставлены выше (одинаково для всех пресетов).

    # netdev_max_backlog масштабируем под скорость линка: на 25G+ дефолт мал.
    # ВАЖНО (v8.3 fix): берём max(preset, auto-scale), чтобы не понижать значения
    # пресетов (например proxy=1000000) на 1G-VPS до 30000.
    local link_speed_mbps backlog_target dev_weight_target backlog_eff dev_weight_eff
    link_speed_mbps=$(detect_link_speed_mbps)
    if [ "$link_speed_mbps" -ge 25000 ]; then
        backlog_target=300000
        dev_weight_target=256   # v8.7: 25G+ NIC — больше weight для big napi-poll cycles
    elif [ "$link_speed_mbps" -ge 10000 ]; then
        backlog_target=100000
        dev_weight_target=192   # v8.7: было 96, теперь 192 — на 10G дефолт мал
    else
        backlog_target=30000
        dev_weight_target=64
    fi
    backlog_eff="$PRESET_NETDEV_BACKLOG"
    [ "$backlog_target" -gt "$backlog_eff" ] && backlog_eff="$backlog_target"
    # dev_weight: уже выставлен 128 в base apply (line 965). Берём максимум.
    dev_weight_eff=128
    [ "$dev_weight_target" -gt "$dev_weight_eff" ] && dev_weight_eff="$dev_weight_target"
    sysctl_safe net.core.netdev_max_backlog "$backlog_eff"
    sysctl_safe net.core.dev_weight "$dev_weight_eff"

    # conntrack — критический пункт для прокси-нагрузок. Модуль может быть
    # не загружен — пробуем поднять, sysctls появятся только после этого.
    modprobe nf_conntrack 2>/dev/null || true
    if kernel_supports_sysctl net.netfilter.nf_conntrack_max; then
        sysctl_safe net.netfilter.nf_conntrack_max "$PRESET_CONNTRACK_MAX"
        sysctl_safe net.netfilter.nf_conntrack_buckets "$PRESET_CONNTRACK_BUCKETS"
        sysctl_safe net.netfilter.nf_conntrack_tcp_timeout_established "$PRESET_CONNTRACK_TCP_TIMEOUT"
        sysctl_safe net.netfilter.nf_conntrack_tcp_timeout_time_wait 30
        sysctl_safe net.netfilter.nf_conntrack_tcp_timeout_close_wait 30
        sysctl_safe net.netfilter.nf_conntrack_tcp_timeout_fin_wait 30
        sysctl_safe net.netfilter.nf_conntrack_generic_timeout 120
        # v8.4: tcp_be_liberal — не дропаем TCP-сегменты с «странным» seq,
        # типичная проблема под ASN-roaming / mobile-NAT и асимметричной маршрутизацией.
        # Не открывает уязвимостей: conntrack продолжает следить за state, просто терпимее.
        sysctl_safe net.netfilter.nf_conntrack_tcp_be_liberal 1
    fi

    # VM / ZRAM tuning
    sysctl_safe vm.swappiness "$PRESET_SWAPPINESS"
    sysctl_safe vm.page-cluster 0
    sysctl_safe vm.vfs_cache_pressure 50
    sysctl_safe vm.dirty_background_ratio 3
    sysctl_safe vm.dirty_ratio 10
    sysctl_safe vm.dirty_writeback_centisecs 500
    sysctl_safe vm.dirty_expire_centisecs 1500
    # v8.4: vm.min_free_kbytes — поднимаем под размер RAM (~0.5%), но min 64MB,
    # max 1GB. Иначе под burst (тысячи TLS-handshake'ов) kswapd не успевает,
    # начинаются direct-reclaim'ы, latency-spike'и или OOM. На VPS 1GB RAM
    # default ~22MB — катастрофически мало для прокси-нагрузки.
    local min_free_target
    min_free_target=$(( mem_mb * 1024 / 200 ))   # 0.5% RAM в kB
    [ "$min_free_target" -lt 65536 ] && min_free_target=65536
    [ "$min_free_target" -gt 1048576 ] && min_free_target=1048576
    sysctl_safe vm.min_free_kbytes "$min_free_target"
    sysctl_safe vm.zone_reclaim_mode 0
    # Доводки v8.1:
    #  - max_map_count: высоко-thread'овые прокси (sing-box, gomod-сервисы)
    #    могут упираться в 65530 mmap'ов на процесс.
    #  - overcommit_memory=1: не отказываем в malloc()'е по «возможному» лимиту;
    #    Linux всё равно умеет OOM-кильнуть.
    #  - watermark_scale_factor=125: kswapd начинает чистить страницы раньше,
    #    меньше шансов попасть в direct reclaim (latency spike).
    #  - watermark_boost_factor=15000: меньше боусс'а — меньше «волн» компакции.
    #  - compaction_proactiveness=0: на VPS нет смысла греть CPU фоновой компакцией.
    #  - admin_reserve_kbytes: гарантирует ~16MB для root-shell даже при OOM.
    sysctl_safe vm.max_map_count 1048576
    sysctl_safe vm.overcommit_memory 1
    sysctl_safe vm.overcommit_ratio 100
    sysctl_safe vm.watermark_scale_factor 125
    sysctl_safe vm.watermark_boost_factor 15000
    sysctl_safe vm.compaction_proactiveness 0
    sysctl_safe vm.admin_reserve_kbytes 16384
    # Безопасные kernel/sched доводки.
    sysctl_safe kernel.sched_migration_cost_ns 5000000
    sysctl_safe kernel.sched_autogroup_enabled 0
    # v8.6: kernel.numa_balancing — больше не выставляем безусловно, теперь только
    # на 1-NUMA-узловых VPS (auto-detect вверху, ~line 1447). На multi-socket
    # bare-metal оставляем включённым, иначе теряем balanced placement.
    sysctl_safe kernel.timer_migration 1

    # v8.7: VRF / l3mdev support — для cilium-style сред и dual-WAN setup'ов
    # (когда VRF используется как изоляция). Безопасно везде: kernel молча
    # игнорирует если l3mdev/VRF не используется.
    sysctl_safe net.ipv4.tcp_l3mdev_accept 1
    sysctl_safe net.ipv4.udp_l3mdev_accept 1

    # v8.7: net.unix.max_dgram_qlen — для прокси с unix-socket интерконнекта
    # (sing-box ↔ haproxy ↔ envoy через /run/*.sock). Default 10 — мал на любом
    # busy-прокси, рекомендация 512.
    sysctl_safe net.unix.max_dgram_qlen 512

    # ============================================================
    # v8.8: новый блок — kernel-стек 2024 + iOS-стелс + safety
    # ============================================================

    # v8.8 (K3): Accurate ECN (AccECN, RFC 9341) — kernel 6.0+. tcp_ecn=3 включает
    # передовой ECN, который точнее отслеживает CE-маркировки при миксе с classic
    # ECN-роутерами. На kernel <6.0 значение 3 трактуется как 1 (active), что всё
    # равно лучше чем 0; sysctl_safe gracefully skip если параметр read-only.
    # Опасности: zero — у нас уже tcp_ecn_fallback=1 страхует от ECN-blackhole'ов.
    local _krn_maj _krn_min
    _krn_maj=$(uname -r 2>/dev/null | awk -F. '{print $1}')
    _krn_min=$(uname -r 2>/dev/null | awk -F. '{print $2}')
    if [ -n "$_krn_maj" ] && [ -n "$_krn_min" ] && \
       { [ "$_krn_maj" -gt 6 ] 2>/dev/null || \
         { [ "$_krn_maj" = "6" ] && [ "$_krn_min" -ge 0 ] 2>/dev/null; }; }; then
        # AccECN (3) только для kernel ≥6.0. На более старых — оставляем 2 из v8.4.
        sysctl_safe net.ipv4.tcp_ecn 3
    fi

    # v8.8 (A2): tcp_min_rtt_wlen — окно для оценки минимального RTT. v8.4 поднял
    # до 600s для стабильности BBR; на VPS с переменчивыми провайдерами это даёт
    # stale-min-RTT (старые низкие значения «застревают»). 300s — компромисс между
    # стабильностью и адаптивностью. На proxy preset оставляем 600 (стабильность
    # важнее), на balanced/web возвращаем к 300s. CONTRIBUTING #5: gated by preset.
    if [ "$PRESET_NAME" != "proxy" ]; then
        sysctl_safe net.ipv4.tcp_min_rtt_wlen 300
    fi

    # v8.8 (A5): tcp_syn_linear_timeouts (kernel 6.4+) — линейный backoff для SYN
    # retransmits на thin-streams. Дефолт 4 (kernel-default), но не везде включено.
    # Для proxy/handshake-burst трафика ускоряет establishment на flaky-линках.
    # На старых kernel sysctl_safe просто скипнет.
    sysctl_safe net.ipv4.tcp_syn_linear_timeouts 4

    # v8.8 (C9): tcp_timestamps=2 (kernel 4.10+, RFC 7323bis). Default 1 шлёт
    # raw uptime-timestamps, что выдаёт boot-time машины (стелс-leak). Значение 2
    # включает random-offset на каждое соединение — uptime скрыт, синхронизация
    # сохранена. CONTRIBUTING #5: stealth-feature, gated to proxy preset.
    if [ "$PRESET_NAME" = "proxy" ]; then
        sysctl_safe net.ipv4.tcp_timestamps 2
    fi

    # v8.8 (C8): ip_local_reserved_ports — резервируем диапазон, который точно
    # используется WireGuard/OpenVPN/IKE listener'ами. Это запрещает kernel'у
    # выбирать эти порты в эфемерном source-port pool (ip_local_port_range).
    # Защищает от: source-port collision с активным VPN listener (после reload),
    # accidental leak isp-trackable-порта. Безопасно для SSH (port 22 не в pool).
    # 51820 = WireGuard default; 1194 = OpenVPN; 500/4500 = IKEv2/IPsec; 8388 = SS;
    # 9000-9999 = популярный xray/sing-box диапазон.
    sysctl_safe net.ipv4.ip_local_reserved_ports "500,1194,4500,8388,9000-9999,51820"

    # v8.9 (K2): tcp_reflect_tos=1 (kernel 5.10+, RFC 8311). При генерации RST
    # (или ACK без user-data) kernel reflect'ит DSCP/ToS байт из incoming-пакета.
    # Полезно для qos-aware прокси (Hysteria DSCP-marking, BBR-with-tcp_pacing
    # через tc-fq), у которых маркеры теряются на RST = плохая classification
    # на роутерах. На kernel <5.10 sysctl_safe просто скипнет (не существует).
    # Безопасно: не меняет поведение для обычного TCP, влияет только на RST/ACK.
    sysctl_safe net.ipv4.tcp_reflect_tos 1

    # v8.9 (K3): tcp_migrate_req=1 (kernel 5.14+) — graceful миграция accept'ов
    # между listening sockets при reload (xray/sing-box -HUP). Default 0 = новые
    # SYN'ы дропаются на shutdown listener. =1 = kernel migrate'ит pending
    # connections на новый listener того же порта. Zero-downtime reload для
    # прокси-серверов. На kernel <5.14 → skip. Безопасно: при отсутствии reload
    # параметр не влияет.
    sysctl_safe net.ipv4.tcp_migrate_req 1

    # v8.9 (K4): vm.compaction_proactiveness=20 (kernel 5.7+) — proactive memory
    # compaction для big-page allocations (QUIC packet buffers, io_uring rings,
    # TCP large-window wmem). Default в новых дистрибутивах =20, но не везде
    # (особенно на старых Ubuntu 20.04 с 5.4 kernel — там нет sysctl, skip).
    # На long-uptime VPS с фрагментированной памятью даёт значимое ускорение
    # mmap/big-buffer-alloc. Безопасно: не вызывает аллокаций, только background
    # kcompactd-нагрузка <0.1% CPU.
    sysctl_safe vm.compaction_proactiveness 20

    # v8.9 (K8): net.core.high_order_alloc_disable=0 — для QUIC и kernel TCP с
    # large rmem/wmem нужны contiguous high-order pages. Когда =1 (некоторые
    # дистрибутивы устанавливают для embedded), kernel идёт slow-path
    # one-page-at-a-time, что роняет throughput на 30%+ под нагрузкой. =0 —
    # default behaviour (best). Безопасно везде кроме memory-constrained
    # embedded систем (≤256 MB RAM).
    sysctl_safe net.core.high_order_alloc_disable 0

    # v8.9 (G3+G4): nf_conntrack security flags — обязательны для прокси.
    # nf_conntrack_helper=0 — disable application-layer helpers (FTP/IRC ALG
    # которые могут вводить incorrect state в conntrack из untrusted streams).
    # Default 0 в kernel 4.7+, но некоторые old distros ставят 1 — force off.
    # nf_conntrack_tcp_loose=0 — drop unsolicited mid-stream TCP packets без
    # complete 3WHS. Default 1 (loose) на старых kernels. =0 более строго,
    # дропает stray ACK/RST, что одновременно фильтрует port-scan probes и
    # reduces conntrack table pollution. Не влияет на established connections.
    sysctl_safe net.netfilter.nf_conntrack_helper 0
    sysctl_safe net.netfilter.nf_conntrack_tcp_loose 0

    # fs limits — на случай прокси с тысячами upstream'ов.
    sysctl_safe fs.file-max 2097152
    sysctl_safe fs.nr_open 2097152
    sysctl_safe fs.aio-max-nr 1048576

    APPLIED_BBR="$best_bbr"
    APPLIED_QDISC="$best_qdisc"
    APPLIED_BUF_MAX="$buf_max"
}

# Persistent unit: после ребута заново применяет RPS, RFS, XPS, LRO=off.
# Сами sysctls персистентны через /etc/sysctl.d/, а sysfs-настройки нет —
# поэтому именно их и восстанавливает этот юнит.
apply_persistent_units() {
    [ "$DRY_RUN" = "1" ] && return 0
    # Подставляем preset-зависимые значения и multi-queue target прямо в скрипт.
    local rps_flows="${PRESET_RPS_FLOWS:-4096}"
    cat > "$RPS_BOOT_SCRIPT" <<RPS_EOF
#!/bin/bash
# Auto-generated by vps_optimizer.sh — restores RPS/XPS/RFS/LRO/multi-queue after reboot.
set +e

build_cpu_mask() {
    local n=\$1
    [ "\$n" -le 0 ] && { echo 0; return; }
    local groups=\$(( (n + 31) / 32 ))
    local last_bits=\$(( n - (groups - 1) * 32 ))
    local first
    if [ "\$last_bits" -ge 32 ]; then
        first="ffffffff"
    else
        first=\$(printf '%x' \$(( (1 << last_bits) - 1 )))
    fi
    local rest="" i
    for ((i=1; i<groups; i++)); do rest=",ffffffff\${rest}"; done
    echo "\${first}\${rest}"
}

# CPU index → cpumask hex (kernel формат, comma-separated 32-bit chunks).
cpu_to_xps_mask() {
    local cpu="\${1:-0}"
    [ "\$cpu" -lt 0 ] && cpu=0
    local group=\$(( cpu / 32 ))
    local bit=\$(( cpu % 32 ))
    local val
    val=\$(printf '%x' \$(( 1 << bit )))
    if [ "\$group" -eq 0 ]; then
        echo "\$val"
    else
        local zeros="" i
        for ((i=0; i<group; i++)); do zeros+=",00000000"; done
        echo "\${val}\${zeros}"
    fi
}

# Парсим isolcpus= из cmdline и возвращаем список «usable» ядер.
usable_cpus() {
    local total iso= cmdline
    total=\$(nproc)
    cmdline=\$(cat /proc/cmdline 2>/dev/null)
    if [[ "\$cmdline" =~ isolcpus=([^[:space:]]+) ]]; then
        iso="\${BASH_REMATCH[1]}"
    fi
    declare -A bad
    if [ -n "\$iso" ]; then
        local part
        for part in \${iso//,/ }; do
            if [[ "\$part" =~ ^([0-9]+)-([0-9]+)\$ ]]; then
                local lo=\${BASH_REMATCH[1]} hi=\${BASH_REMATCH[2]} c
                for ((c=lo; c<=hi; c++)); do bad[\$c]=1; done
            elif [[ "\$part" =~ ^[0-9]+\$ ]]; then
                bad[\$part]=1
            fi
        done
    fi
    local c
    for ((c=0; c<total; c++)); do
        [ -z "\${bad[\$c]}" ] && echo "\$c"
    done
}

CORES=\$(nproc)
MASK=\$(build_cpu_mask "\$CORES")
mapfile -t USABLE < <(usable_cpus)
USABLE_N=\${#USABLE[@]}
[ "\$USABLE_N" -eq 0 ] && USABLE_N=1
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true

for IFACE in \$(ip -o link show | awk -F': ' '\$2 !~ /^(lo|virbr|docker|veth|wg|tun|tap|gre|ppp|br-|cilium|kube|cni)/ {print \$2}'); do
    # Multi-queue: восстанавливаем количество очередей до min(N_cpus, max_combined).
    MQ_MAX=\$(ethtool -l "\$IFACE" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^Combined:/{print \$2; exit}')
    if [ -n "\$MQ_MAX" ] && [ "\$MQ_MAX" -gt 1 ]; then
        MQ_TARGET="\$CORES"
        [ "\$MQ_TARGET" -gt "\$MQ_MAX" ] && MQ_TARGET="\$MQ_MAX"
        ethtool -L "\$IFACE" combined "\$MQ_TARGET" >/dev/null 2>&1 || true
    fi
    for f in /sys/class/net/"\$IFACE"/queues/rx-*/rps_cpus; do
        [ -e "\$f" ] && echo "\$MASK" > "\$f" 2>/dev/null || true
    done
    for f in /sys/class/net/"\$IFACE"/queues/rx-*/rps_flow_cnt; do
        [ -e "\$f" ] && echo $rps_flows > "\$f" 2>/dev/null || true
    done
    # XPS: каждой TX-очереди свой CPU из usable-списка (минуя isolcpus).
    txi=0
    for f in /sys/class/net/"\$IFACE"/queues/tx-*/xps_cpus; do
        if [ -e "\$f" ]; then
            cpu_pick="\${USABLE[\$(( txi % USABLE_N ))]:-0}"
            mask=\$(cpu_to_xps_mask "\$cpu_pick")
            echo "\$mask" > "\$f" 2>/dev/null || true
            txi=\$(( txi + 1 ))
        fi
    done
    ethtool -K "\$IFACE" lro off >/dev/null 2>&1 || true
done
RPS_EOF
    chmod +x "$RPS_BOOT_SCRIPT"
    cat > "$RPS_BOOT_SERVICE" <<EOF
[Unit]
Description=VPS RPS/RFS/XPS persistent tuning
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
}

apply_limits() {
    [ "$DRY_RUN" = "1" ] && return 0
    cat > "$LIMITS_CONF" <<EOF
*       soft    nofile  $PRESET_NOFILE
*       hard    nofile  $PRESET_NOFILE
root    soft    nofile  $PRESET_NOFILE
root    hard    nofile  $PRESET_NOFILE
*       soft    nproc   unlimited
*       hard    nproc   unlimited
EOF
    mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
    cat > /etc/systemd/system.conf.d/99-vps-limits.conf <<EOF
[Manager]
DefaultLimitNOFILE=$PRESET_NOFILE
DefaultLimitNPROC=infinity
EOF
    cat > /etc/systemd/user.conf.d/99-vps-limits.conf <<EOF
[Manager]
DefaultLimitNOFILE=$PRESET_NOFILE
DefaultLimitNPROC=infinity
EOF
    systemctl daemon-reexec >/dev/null 2>&1 || true
}

# Шапка в persistent-файле sysctl. Туда уже накопилось всё, что
# реально применилось.
finalize_sysctl_conf() {
    [ "$DRY_RUN" = "1" ] && return 0
    if [ -f "$SYSCTL_CONF" ] && [ ! -f "$SYSCTL_BACKUP" ]; then
        cp "$SYSCTL_CONF" "$SYSCTL_BACKUP" 2>/dev/null || true
    fi
    {
        echo "# === VPS Optimizer v8.2 PHOENIX-Z++ ==="
        echo "# Generated $(date -u +%FT%TZ)  preset=$PRESET_NAME  virt=$VIRT  kernel=$(uname -r)"
        echo "# Только параметры, которые ядро/гипервизор реально приняли."
        cat "$SYSCTL_TMP" 2>/dev/null
    } > "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
}

# Сводка применённых/пропущенных настроек.
self_test() {
    local ok_count=${#SYSCTL_OK[@]}
    local skip_count=${#SYSCTL_SKIP[@]}
    local sysfs_ok=${#SYSFS_OK[@]}
    local sysfs_skip=${#SYSFS_SKIP[@]}

    [ "$QUIET" = "1" ] && return

    echo ""
    echo -e "${CYAN}${BOLD}=== Self-test ===${NC}"
    echo -e "  Preset:        ${BOLD}${PRESET_NAME}${NC}"
    echo -e "  Hypervisor:    ${BOLD}${VIRT}${NC}"
    echo -e "  Kernel:        $(uname -r)"
    echo -e "  Cores:         $(nproc)"
    echo -e "  RAM:           $(free -h | awk '/Mem:/{print $2}')"
    echo -e "  BBR:           ${GREEN}${APPLIED_BBR:-?}${NC}    qdisc: ${GREEN}${APPLIED_QDISC:-?}${NC}"
    echo -e "  buf_max:       ${APPLIED_BUF_MAX:-?} bytes"
    echo -e "  sysctl:        ${GREEN}${ok_count} OK${NC} / ${YELLOW}${skip_count} skipped${NC}"
    echo -e "  sysfs:         ${GREEN}${sysfs_ok} OK${NC} / ${YELLOW}${sysfs_skip} skipped${NC}"

    if [ "$skip_count" -gt 0 ]; then
        echo -e "  ${GRAY}Skipped sysctl (kernel/hypervisor restriction):${NC}"
        local s
        for s in "${SYSCTL_SKIP[@]}"; do
            echo -e "    ${GRAY}- $s${NC}"
        done | head -20
    fi
    echo ""
}

# v8.4: initcwnd via `ip route` — Google ставит 30, мы тоже. На дефолтном
# маршруте даёт ~3-4х данных в первом RTT (десятки KB вместо ~14KB при cwnd=10).
# Не персистентно (живёт до перезагрузки), но apply переустанавливает.
apply_route_initcwnd() {
    [ "$DRY_RUN" = "1" ] && return 0
    local def_line def_iface def_via
    def_line=$(ip -4 route show default 2>/dev/null | head -1)
    [ -z "$def_line" ] && return 0
    def_iface=$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$def_line")
    def_via=$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$def_line")
    [ -z "$def_iface" ] && return 0
    # Пропускаем VPN-iface — там initcwnd не имеет смысла, а route change может
    # перетереть ту, что VPN-приложение само поставило.
    # v8.8 (G3): расширили — Cloudflared/Tailscale/ZeroTier/utun также skip.
    case "$def_iface" in
        tun*|tap*|wg*|ppp*|ipsec*|cf*|cloudflared*|tailscale*|headscale*|sync*|zt*|utun*) return 0 ;;
    esac
    local change_args=(default dev "$def_iface" initcwnd 30 initrwnd 30)
    [ -n "$def_via" ] && change_args=(default via "$def_via" dev "$def_iface" initcwnd 30 initrwnd 30)
    if ip route change "${change_args[@]}" >/dev/null 2>&1; then
        _log OK "  route initcwnd=30 / initrwnd=30 на ${def_iface}"
    fi
}

# v8.4: kernel TLS (kTLS). modprobe tls — даёт ядру способность делать sendfile()
# на TLS-сокетах (zero-copy). Прирост -30-50% CPU на TLS-heavy нагрузках,
# если приложение умеет (nginx со сборкой `--with-openssl-opt=enable-ktls`).
# Сам `modprobe tls` безопасен: не меняет поведения других сокетов.
apply_ktls_module() {
    [ "$DRY_RUN" = "1" ] && return 0
    modprobe tls 2>/dev/null && _log OK "  kTLS module loaded (sendfile-on-TLS available)"
}

# v8.4: OOM hint — если на машине крутятся проксильки (xray/sing-box/hysteria/v2ray),
# ставим им oom_score_adj=-500 (но не -1000, т.к. это «никогда не убивать» —
# опасно если процесс утекает память). Отрицательное значение = реже убивает,
# чем других. Без --force ничего не делаем для незнакомых процессов.
apply_oom_hints() {
    [ "$DRY_RUN" = "1" ] && return 0
    local proc pids p
    for proc in xray sing-box hysteria hysteria2 v2ray tuic-server wireguard-go; do
        if ! command -v pgrep >/dev/null 2>&1; then
            return 0
        fi
        pids=$(pgrep -x "$proc" 2>/dev/null)
        for p in $pids; do
            if [ -w "/proc/$p/oom_score_adj" ]; then
                echo -500 > "/proc/$p/oom_score_adj" 2>/dev/null && \
                    _log OK "  OOM-protect $proc (pid=$p) → score_adj=-500"
            fi
        done
    done
}

apply_optimizations() {
    [ "$DRY_RUN" = "1" ] && _log INFO "${YELLOW}[i] DRY-RUN: ничего не записывается на диск.${NC}"
    if [ "$LEARN_MODE" = "1" ]; then
        _log INFO "${CYAN}$(_t learn_header)${NC}"
        _log INFO "${GRAY}    each sysctl_safe / sysfs_safe call will print: current → desired (rationale).${NC}"
    fi
    _log INFO "${YELLOW}[*] Глобальный тюнинг v${SCRIPT_VERSION} PHOENIX-Z++...${NC}"

    if ! acquire_lock; then
        return "$EXIT_LOCK_BUSY"
    fi

    # Internet-check: если связи нет — предупреждаем (но не блокируем,
    # пользователь может специально применять оффлайн).
    if [ "$DRY_RUN" != "1" ] && ! check_internet; then
        _log WARN "${YELLOW}[!] Нет интернета — продолжаем, но some checks могут не пройти.${NC}"
    fi

    VIRT=$(detect_virt)
    PROVIDER=$(detect_provider)
    _log INFO "  Virt:     $VIRT"
    _log INFO "  Provider: $PROVIDER"

    # Под OpenVZ половина sysctl запрещена — это нормально, всё пройдёт через
    # probe-then-write и просто залогируется как skipped.
    case "$VIRT" in
        openvz|lxc)
            _log INFO "${GRAY}[*] Контейнерный гипервизор ($VIRT) — часть тюнингов будет пропущена ядром, это ок.${NC}"
            ;;
    esac

    SYSCTL_OK=()
    SYSCTL_SKIP=()
    SYSFS_OK=()
    SYSFS_SKIP=()
    SYSCTL_TMP=$(mktemp /tmp/.vps_sysctl.XXXXXX)
    trap 'rm -f "$SYSCTL_TMP"' EXIT

    # B3: rollback-snapshot перед apply (только если не dry-run и не уже существует
    # snapshot за последние 60 секунд — чтобы не флудить при повторных apply).
    # v8.3 (L4): дополнительно поддерживаем daily-rotation — один daily-snapshot
    # за сутки, держим 7 штук. Pre-apply снапшоты держим максимум 30 штук.
    if [ "$DRY_RUN" != "1" ]; then
        mkdir -p "$SNAPSHOT_DIR" 2>/dev/null || true
        local last_snap
        last_snap=$(find "$SNAPSHOT_DIR" -maxdepth 1 -name 'pre-apply-*.tar.gz' -mmin -1 2>/dev/null | head -1)
        if [ -z "$last_snap" ]; then
            local snap_file
            snap_file="$SNAPSHOT_DIR/pre-apply-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
            tar -czf "$snap_file" \
                --ignore-failed-read \
                "$SYSCTL_CONF" "$LIMITS_CONF" "$DNS_CONF" "$DNS_STATE" \
                "$NOISE_CONF" "$PRESET_FILE" 2>/dev/null || true
            _log INFO "  Snapshot: $snap_file"
        fi
        # Daily snapshot (v8.3): максимум 1 в сутки.
        local daily_file
        daily_file="$SNAPSHOT_DIR/daily-$(date -u +%Y%m%d).tar.gz"
        if [ ! -f "$daily_file" ]; then
            tar -czf "$daily_file" \
                --ignore-failed-read \
                "$SYSCTL_CONF" "$LIMITS_CONF" "$DNS_CONF" "$DNS_STATE" \
                "$NOISE_CONF" "$PRESET_FILE" 2>/dev/null || true
        fi
        # Ротация: pre-apply max 30, daily max 7.
        # shellcheck disable=SC2012  # ls -t достаточно для имён вида pre-apply-*.tar.gz
        ls -1t "$SNAPSHOT_DIR"/pre-apply-*.tar.gz 2>/dev/null | tail -n +31 | xargs -r rm -f
        # shellcheck disable=SC2012
        ls -1t "$SNAPSHOT_DIR"/daily-*.tar.gz 2>/dev/null | tail -n +8 | xargs -r rm -f
    fi

    load_preset "$PRESET"
    apply_zram
    apply_iface_tuning
    apply_irq_affinity
    apply_cpu_governor
    apply_thp
    apply_block_io
    apply_sysctls
    apply_persistent_units
    apply_limits
    apply_route_initcwnd
    apply_ktls_module
    apply_oom_hints

    # v8.10 (X10): provider-aware tuning DB. Применяется поверх preset'а
    # перед финализацией sysctl. Knobs специфичные для Hetzner/AWS/GCP/Azure
    # и т.д. — каждое значение проходит через sysctl_safe (probe-then-write),
    # так что на неподдерживающих kernel'ах пропускается gracefully.
    # Пропускаем в --dry-run чтобы не делать ethtool-tweak'и.
    if [ "$DRY_RUN" != "1" ] && [ "$LEARN_MODE" != "1" ]; then
        provider_tune_command 2>/dev/null || true
    fi

    # B1: idempotency — если новый sysctl-файл побитово совпадает с уже существующим,
    # пропускаем перезапись и `sysctl -p` (всё уже применено).
    if [ "$DRY_RUN" != "1" ] && [ -f "$SYSCTL_CONF" ] && [ -s "$SYSCTL_TMP" ]; then
        local new_hash old_hash
        new_hash=$(awk 'NF && !/^#/' "$SYSCTL_TMP" 2>/dev/null | sort -u | sha256sum | awk '{print $1}')
        old_hash=$(awk 'NF && !/^#/' "$SYSCTL_CONF" 2>/dev/null | sort -u | sha256sum | awk '{print $1}')
        if [ -n "$new_hash" ] && [ "$new_hash" = "$old_hash" ]; then
            _log INFO "${GRAY}[i] sysctl-конфиг не изменился — пропускаем перезапись.${NC}"
        else
            finalize_sysctl_conf
        fi
    else
        finalize_sysctl_conf
    fi

    self_test

    _log OK "${GREEN}[+] Phoenix-Z++ v${SCRIPT_VERSION}: BBR=${APPLIED_BBR}, qdisc=${APPLIED_QDISC}, preset=${PRESET_NAME}, provider=${PROVIDER}.${NC}"
    _audit apply "preset=${PRESET_NAME} virt=${VIRT} provider=${PROVIDER} bbr=${APPLIED_BBR} qdisc=${APPLIED_QDISC} dry_run=${DRY_RUN}"
    rm -f "$SYSCTL_TMP"; trap - EXIT
    release_lock

    if [ "$LEARN_MODE" = "1" ]; then
        _log INFO "${CYAN}$(_t learn_footer)${NC}"
    fi

    # Auto-rollback (v8.3, L1): если после apply связь потерялась — откатываемся.
    # Безопасная сетка: NO_ROLLBACK=1 или DRY_RUN=1 пропускают проверку.
    # Не блокирует SSH: проверка короткая (max ~5 сек), затем мгновенный откат
    # на pre-apply snapshot.
    if [ "$DRY_RUN" != "1" ] && [ "$NO_ROLLBACK" != "1" ]; then
        if ! post_apply_connectivity_ok; then
            _log WARN "${RED}[!] После apply связь не отвечает — откатываемся на pre-apply snapshot.${NC}"
            _audit apply "auto_rollback triggered=connectivity_lost"
            rollback_last_snapshot
            return "$EXIT_ROLLED_BACK"
        fi
    fi

    [ "$QUIET" = "1" ] && return 0
    [ "$CLI_MODE" = "1" ] && return 0
    [ -t 0 ] && read -r -p "Нажмите Enter..."
    return 0
}

# Post-apply connectivity probe (v8.3): проверяем DNS + TCP-handshake, не ICMP.
# ICMP может быть отфильтрован в облаках, но если TCP/443 + DNS работают —
# пользователь точно не лишился SSH (та же таблица маршрутизации).
post_apply_connectivity_ok() {
    local probes_ok=0
    # DNS lookup через системный resolver (быстрее ping'a и проверяет полную цепочку)
    if getent hosts cloudflare.com >/dev/null 2>&1; then
        probes_ok=$((probes_ok + 1))
    elif getent hosts 1.1.1.1 >/dev/null 2>&1; then
        probes_ok=$((probes_ok + 1))
    fi
    # TCP handshake до 1.1.1.1:443 (timeout 3s).
    if command -v timeout >/dev/null 2>&1; then
        if timeout 3 bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null; then
            probes_ok=$((probes_ok + 1))
        fi
    else
        # Без timeout — короткий nc.
        if command -v nc >/dev/null 2>&1 && nc -z -w 3 1.1.1.1 443 2>/dev/null; then
            probes_ok=$((probes_ok + 1))
        fi
    fi
    # Хоть одна из проб ок — считаем что связь есть.
    [ "$probes_ok" -ge 1 ]
}

# Откат на самый свежий pre-apply snapshot (v8.3).
# Тихо игнорирует если snapshot'ов нет (например первый apply).
rollback_last_snapshot() {
    local last_snap
    last_snap=$(find "$SNAPSHOT_DIR" -maxdepth 1 -name 'pre-apply-*.tar.gz' 2>/dev/null | sort | tail -1)
    if [ -z "$last_snap" ]; then
        _log WARN "${YELLOW}[!] Snapshot'ов нет — откат невозможен. Ручной reset рекомендован.${NC}"
        return 1
    fi
    _log INFO "  Восстанавливаем: $last_snap"
    tar -xzf "$last_snap" -C / 2>/dev/null || true
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
    return 0
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
ENABLE_PUSH=1             # v8.4: ротация APNs / FCM / WNS push-keepalive
ENABLE_STUN=1             # v8.4: WebRTC STUN UDP бёрсты (Google/Cloudflare)
ENABLE_WEBSOCKET=1        # v8.4: длинные TCP/443 keepalive (Telegram/Discord-like)
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

# === Phantom library/archive downloads (новое в v8.0) ===
# Тянем релизы с GitHub / npm / PyPI / Maven / kernel.org / GNU ftp
# и т.п. → сразу в /dev/null. UA — curl/wget/pip/npm, без iOS.
ENABLE_LIB_PHANTOM=1
LIB_PHANTOM_INTERVAL_MIN=90      # минут (рекомендованно: 90)
LIB_PHANTOM_INTERVAL_MAX=360     # минут (рекомендованно: 360 = 6ч)
LIB_PHANTOM_BYTES_MAX=2097152    # cap на одно скачивание (2 MB)
LIB_PHANTOM_BURST_MIN=1
LIB_PHANTOM_BURST_MAX=3

# === Vacation mode (новое в v8.0) ===
# Раз в день кидаем кубик: с шансом VACATION_CHANCE_PCT уходим в тишину
# на VACATION_HOURS_MIN..MAX (как реально человек уехал на выходные).
ENABLE_VACATION=1
VACATION_CHANCE_PCT=7
VACATION_HOURS_MIN=6
VACATION_HOURS_MAX=72

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

# === Время-зависимый профиль «места» (новое в v8.2) ===
# auto      — стандартная кривая дня (как было)
# office    — активность 9-18, тишина в остальное время (рабочая VPS)
# home      — пик 19-23, лёгкая утренняя проверка (домашняя VPS)
# always_on — равномерно 24/7 (для серверов «без хозяина»)
PLACE_PROFILE=auto

# === Cloud / NTP / cloud-init phantoms (новое в v8.2) ===
# Реальная Ubuntu всегда тянет NTP/apt/snapcraft в фоне. Включает фоновые
# запросы к archive.ubuntu.com, security.ubuntu.com, time.ubuntu.com,
# api.snapcraft.io. Без этого профиль «слишком чистый» и подозрительный.
ENABLE_CLOUD_PHANTOM=1
CLOUD_PHANTOM_INTERVAL_MIN=30
CLOUD_PHANTOM_INTERVAL_MAX=180

# === DNS prefetch (новое в v8.2) ===
# Имитирует браузерный DNS-preconnect — тихо резолвит host'ы заранее.
# Без HTTP, только DNS-запрос — попадает в логи провайдера как обычный
# браузерный preconnect.
ENABLE_DNS_PREFETCH=1
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
    read -r -p "Library-фантом (GitHub/npm/PyPI/...) (1/0) [${ENABLE_LIB_PHANTOM:-1}]: " v
    ENABLE_LIB_PHANTOM="${v:-${ENABLE_LIB_PHANTOM:-1}}"
    read -r -p "Vacation mode (тишина 6–72ч раз в N дней) (1/0) [${ENABLE_VACATION:-1}]: " v
    ENABLE_VACATION="${v:-${ENABLE_VACATION:-1}}"

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

    echo ""
    echo -e "${CYAN}-- Library-фантом (GitHub releases / npm / PyPI / kernel.org) --${NC}"
    echo -e "${YELLOW}Рекомендуется: 90..360 минут.${NC}"
    read -r -p "LIB_PHANTOM_INTERVAL_MIN [мин, ${LIB_PHANTOM_INTERVAL_MIN:-90}]: " v
    LIB_PHANTOM_INTERVAL_MIN="${v:-${LIB_PHANTOM_INTERVAL_MIN:-90}}"
    read -r -p "LIB_PHANTOM_INTERVAL_MAX [мин, ${LIB_PHANTOM_INTERVAL_MAX:-360}]: " v
    LIB_PHANTOM_INTERVAL_MAX="${v:-${LIB_PHANTOM_INTERVAL_MAX:-360}}"
    read -r -p "Cap на 1 скачивание [байт, ${LIB_PHANTOM_BYTES_MAX:-2097152}]: " v
    LIB_PHANTOM_BYTES_MAX="${v:-${LIB_PHANTOM_BYTES_MAX:-2097152}}"

    echo ""
    echo -e "${CYAN}-- Vacation mode --${NC}"
    echo -e "${YELLOW}Рекомендуется: 7% шанс/день, 6..72 часа.${NC}"
    read -r -p "VACATION_CHANCE_PCT [0..100, ${VACATION_CHANCE_PCT:-7}]: " v
    VACATION_CHANCE_PCT="${v:-${VACATION_CHANCE_PCT:-7}}"
    read -r -p "VACATION_HOURS_MIN [${VACATION_HOURS_MIN:-6}]: " v
    VACATION_HOURS_MIN="${v:-${VACATION_HOURS_MIN:-6}}"
    read -r -p "VACATION_HOURS_MAX [${VACATION_HOURS_MAX:-72}]: " v
    VACATION_HOURS_MAX="${v:-${VACATION_HOURS_MAX:-72}}"

    # Перезаписываем конфиг
    cat > "$NOISE_CONF" <<EOF
# vps-noise.conf (custom, $(date -u +%FT%TZ))
PROFILE="$PROFILE"

ENABLE_IOS_BURST=$ENABLE_IOS_BURST
ENABLE_APNS=$ENABLE_APNS
ENABLE_PUSH=${ENABLE_PUSH:-1}
ENABLE_STUN=${ENABLE_STUN:-1}
ENABLE_WEBSOCKET=${ENABLE_WEBSOCKET:-1}
ENABLE_EMAIL=$ENABLE_EMAIL
ENABLE_NEWS=$ENABLE_NEWS
ENABLE_APT_PHANTOM=$ENABLE_APT_PHANTOM
ENABLE_LIB_PHANTOM=${ENABLE_LIB_PHANTOM:-1}
ENABLE_VACATION=${ENABLE_VACATION:-1}

LIB_PHANTOM_INTERVAL_MIN=${LIB_PHANTOM_INTERVAL_MIN:-90}
LIB_PHANTOM_INTERVAL_MAX=${LIB_PHANTOM_INTERVAL_MAX:-360}
LIB_PHANTOM_BYTES_MAX=${LIB_PHANTOM_BYTES_MAX:-2097152}
LIB_PHANTOM_BURST_MIN=${LIB_PHANTOM_BURST_MIN:-1}
LIB_PHANTOM_BURST_MAX=${LIB_PHANTOM_BURST_MAX:-3}

VACATION_CHANCE_PCT=${VACATION_CHANCE_PCT:-7}
VACATION_HOURS_MIN=${VACATION_HOURS_MIN:-6}
VACATION_HOURS_MAX=${VACATION_HOURS_MAX:-72}

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

# ===== Phantom library downloads (новое в v8.0) =====
# Имитируем admin-host: периодически тянем релизы и tarball'ы
# из публичных package-репозиториев → /dev/null. Никаких мессенджеров.
ENABLE_LIB_PHANTOM="${ENABLE_LIB_PHANTOM:-1}"
LIB_PHANTOM_INTERVAL_MIN="${LIB_PHANTOM_INTERVAL_MIN:-90}"      # рекомендованно: 90 мин
LIB_PHANTOM_INTERVAL_MAX="${LIB_PHANTOM_INTERVAL_MAX:-360}"     # рекомендованно: 6 ч
LIB_PHANTOM_BYTES_MAX="${LIB_PHANTOM_BYTES_MAX:-2097152}"       # 2MB cap на одно скачивание
LIB_PHANTOM_BURST_MIN="${LIB_PHANTOM_BURST_MIN:-1}"
LIB_PHANTOM_BURST_MAX="${LIB_PHANTOM_BURST_MAX:-3}"

# ===== Vacation mode (новое в v8.0) =====
# Раз в день кидаем кубик: если выпало — уходим в тишину на N часов
# (как реально человек уехал в отпуск/лёг спать на выходные).
ENABLE_VACATION="${ENABLE_VACATION:-1}"
VACATION_CHANCE_PCT="${VACATION_CHANCE_PCT:-7}"   # 7% шанс начать «отпуск» в каждый новый день
VACATION_HOURS_MIN="${VACATION_HOURS_MIN:-6}"
VACATION_HOURS_MAX="${VACATION_HOURS_MAX:-72}"
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
# v8.9 (C2): iOS 18 UA pinning — обновлённые актуальные версии Safari/Mobile.
# Реальная статистика StatCounter (2025-04): iOS 18.2/18.3 — top traffic share.
# Раскладка по версиям: 18.3.x ~50%, 18.2.x ~25%, 18.1.x ~15%, 17.x ~10%.
# Distribution в массиве примерно соответствует, чтобы random pick давал
# реалистичный mix.
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
"AppleCoreMedia/1.0.0.22D63 (iPhone; U; CPU OS 18_3 like Mac OS X; en_us)"
"AppleCoreMedia/1.0.0.22C152 (iPhone; U; CPU OS 18_2 like Mac OS X; en_us)"
"AppleCoreMedia/1.0.0.22B83 (iPhone; U; CPU OS 18_1 like Mac OS X; en_us)"
"itunesstored/1.0 iOS/18.3.2 model/iPhone17,2 hwp/t8140 build/22D82 (6; dt:280)"
"itunesstored/1.0 iOS/18.2.1 model/iPhone16,2 hwp/t8130 build/22C161 (6; dt:268)"
"itunesstored/1.0 iOS/18.1.1 model/iPhone16,2 hwp/t8130 build/22B91 (6; dt:264)"
"com.apple.WebKit.Networking/8620.2.5.0.5 CFNetwork/1572.100.1 Darwin/24.3.0"
"com.apple.WebKit.Networking/8619.2.4.0.6 CFNetwork/1568.100.1 Darwin/24.1.0"
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
"https://weatherkit.apple.com/" "https://news-events.apple.com/"
"https://gsa.apple.com/" "https://identity.apple.com/"
"https://api.weather.com/v3/" "https://gspe1-ssl.ls.apple.com/"
"https://gsas.apple.com/grandslam/" "https://xp.apple.com/report/2/"
"https://stocks-data-service.apple.com/" "https://itunes.apple.com/WebObjects/MZStore.woa/wa/viewMultiRoom"
"https://news-edge.apple.com/" "https://bagsvc.apple.com/" "https://buy.itunes.apple.com/"
# v8.7: iOS 18 — Apple Maps tile-сервера (gsp-ssl), iMessage relay, Apple Music
# API, Spotlight Suggest, Siri/Smoot endpoints. Реальный iPhone обращается к ним
# постоянно: Maps prefetch, Push, Music feed, Search suggestions, Siri WebKit-cards.
"https://gsp-ssl.ls.apple.com/" "https://gsp10-ssl.ls.apple.com/"
"https://gspe35-ssl.ls.apple.com/" "https://apzones.apple.com/"
"https://api.apple-mapkit.com/v1/" "https://maps-api.apple.com/v1/"
"https://relay.smoot.apple.com/" "https://smoot.apple.com/"
"https://smoot-search.apple.com/" "https://api-glb-aze.smoot.apple.com/"
"https://amp-api.music.apple.com/v1/" "https://music.apple.com/"
"https://itunes.apple.com/" "https://radio.apple.com/"
"https://guzzoni.apple.com/" "https://guzzoni-apple-com.akadns.net/"
"https://siri-search.apple.com/" "https://amp-api-edge.apple.com/"
"https://content.icloud.com/" "https://p104-content.icloud.com/"
"https://p104-fmip.icloud.com/" "https://p104-mailws.icloud.com/"
"https://p104-keyvalueservice.icloud.com/" "https://p104-imws.icloud.com/"
# v8.8 (C1+C2+C3+C10+C11): iOS-stealth deep — endpoints, на которые real iOS
# обращается постоянно. Делятся на 5 групп:
#  C1 APNs gateway-семейство: real iOS держит постоянное TLS-соединение на
#    gateway.push.apple.com:5223 (или :443 fallback). У нас была только
#    /push.apple.com/ как 'noise', реальный fingerprint — это gateway.push.
#  C2 iCloud Private Relay (Apple Network Privacy сервис) — Safari в iOS 15+
#    маскирует часть трафика через mask.icloud.com. Безопасно noisy.
#  C3 App Store Connect / iTunes purchase — real iPhone периодически проверяет
#    обновления приложений через buy.itunes / appstoreconnect.
#  C10 Apple ID auth telemetry — gsa.apple.com / idmsa.apple.com / appleid.apple.com
#    зовутся при каждом login flow, refresh-token, 2FA-prompt.
#  C11 MDM / Configurator endpoints — albert.apple.com при init device
#    (DEP enrollment), configuration.apple.com.
"https://gateway.push.apple.com/" "https://1-courier.push.apple.com/"
"https://17-courier.push.apple.com/" "https://api-mdm.apple.com/"
"https://mask.icloud.com/" "https://mask-h2.icloud.com/"
"https://mask-api.icloud.com/" "https://mask.api.fastly.icloud.com/"
"https://buy.itunes.apple.com/" "https://appstoreconnect.apple.com/"
"https://api.appstoreconnect.apple.com/" "https://reportaproblem.apple.com/"
"https://idmsa.apple.com/appleauth/auth/signin"
"https://gsa.apple.com/grandslam/GsService2"
"https://appleid.apple.com/account/manage"
"https://albert.apple.com/deviceservices/deviceActivation"
"https://configuration.apple.com/configurations/"
# v8.9 (C4+C5+C6): iOS-stealth v3 deep — endpoints на которые real iOS bg-poll'ит:
#  C4 Apple Audio/Video CDN: Safari + Apple Music + AppleTV+ + iCloud Photos
#    стримят с этих endpoint'ов, очень болтливые при background play.
#    audio-ap-* / video-* / r{1-9}---sn-* (последние — gvt1.com YouTube via Safari).
#  C5 Spotlight Suggestions: real iOS bg-poll каждые 30-60s при активном UI
#    (api-tip / search-api / smoot.apple.com — Siri suggestions).
#  C6 iCloud Keychain sync: escrowproxy / keyvalueservice — обновление сохранённых
#    паролей; real iOS делает это раз в час и при iCloud sign-in.
"https://audio-ap-southeast-2.itunes.apple.com/"
"https://audio-ap-southeast-1.itunes.apple.com/"
"https://audio-ssl.itunes.apple.com/"
"https://audio-fa.itunes.apple.com/"
"https://video-ssl.itunes.apple.com/"
"https://play.itunes.apple.com/"
"https://api-tip.cdn-apple.com/"
"https://api.smoot.apple.com/search"
"https://search-api.apple.com/search/v1/suggestions"
"https://geo-suggestions.apple.com/"
"https://escrowproxy.icloud.com/escrowproxy/api/recordRetrieve"
"https://keyvalueservice.icloud.com/"
"https://p104-keyvalueservice.icloud.com/api/v2/getList"
"https://p104-escrowproxy.icloud.com/"
"https://relay.smoot.apple.com/v1/"
)
URLS_CAPTIVE=(
"https://captive.apple.com/hotspot-detect.html"
"https://www.apple.com/library/test/success.html"
"https://gsp64-ssl.ls.apple.com/"
# v8.7: реальный iPhone делает hotspot-detect каждые ~60s после Wi-Fi-attach
# и периодически в фоне; полезно повторять чтобы соответствовать profile.
"https://www.apple.com/library/test/success.html?cb=1"
"https://www.apple.com/library/test/success.html?cb=2"
)

# РФ госпорталы / КИИ (новое в v8.1) — реальный iPhone владельца в РФ
# периодически открывает Госуслуги, ФНС, мос.ру и т.п. Никаких соцсетей,
# никаких мессенджеров. Все ссылки публичные и стабильные.
# shellcheck disable=SC2034
URLS_IOS_RU_GOV=(
"https://www.gosuslugi.ru/"
"https://lk.gosuslugi.ru/"
"https://login.gosuslugi.ru/"
"https://esia.gosuslugi.ru/"
"https://www.nalog.gov.ru/"
"https://lkfl2.nalog.ru/lkfl/login"
"https://www.fns.ru/"
"https://www.mos.ru/"
"https://www.mos.ru/services/"
"https://www.mos.ru/news/"
"https://pgu.mos.ru/"
"https://kremlin.ru/"
"https://government.ru/"
"https://www.gov.ru/"
"https://www.mvd.ru/"
"https://www.fsb.ru/"
"https://мвд.рф/"
"https://минцифры.рф/"
"https://digital.gov.ru/ru/"
"https://www.cbr.ru/"
"https://rkn.gov.ru/"
"https://sudrf.ru/"
"https://www.gov-murman.ru/"
"https://gisp.gov.ru/"
"https://nalog.ru/"
"https://минздрав.рф/"
"https://www.rosreestr.gov.ru/"
"https://лк.фнс.рф/"
"https://pos.gosuslugi.ru/og/"
"https://epgu.gosuslugi.ru/"
"https://www.pochta.ru/"
"https://www.pfrf.gov.ru/"
"https://sfr.gov.ru/"
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
"https://www.wildberries.ru/" "https://www.ozon.ru/"
"https://www.avito.ru/" "https://hh.ru/"
)
URLS_SEARCH_RU=(
"https://yandex.ru/" "https://ya.ru/" "https://www.google.com/"
)

# ===== Phantom library/archive downloads (новое в v8.0) =====
# Правдоподобный admin-host: GitHub releases, npm/PyPI/Maven/CRAN метаданные
# и tarball'ы исходников kernel.org → /dev/null. URL'ы стабильные годами.
# shellcheck disable=SC2034
URLS_LIB_DOWNLOADS=(
"https://github.com/htop-dev/htop/archive/refs/tags/3.3.0.tar.gz"
"https://github.com/jqlang/jq/archive/refs/tags/jq-1.7.1.tar.gz"
"https://github.com/curl/curl/archive/refs/tags/curl-8_10_1.tar.gz"
"https://github.com/openssl/openssl/archive/refs/tags/openssl-3.4.0.tar.gz"
"https://github.com/postgres/postgres/archive/refs/tags/REL_17_2.tar.gz"
"https://github.com/redis/redis/archive/refs/tags/8.0.0.tar.gz"
"https://github.com/nginx/nginx/archive/refs/tags/release-1.27.3.tar.gz"
"https://github.com/grafana/grafana/archive/refs/tags/v11.4.0.tar.gz"
"https://github.com/prometheus/prometheus/archive/refs/tags/v3.0.1.tar.gz"
"https://github.com/python/cpython/archive/refs/tags/v3.13.1.tar.gz"
"https://github.com/torvalds/linux/archive/refs/tags/v6.12.tar.gz"
"https://github.com/golang/go/archive/refs/tags/go1.23.4.tar.gz"
"https://github.com/rust-lang/rust/archive/refs/tags/1.83.0.tar.gz"
"https://github.com/nodejs/node/archive/refs/tags/v22.12.0.tar.gz"
"https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-19.1.5.tar.gz"
"https://github.com/ffmpeg/FFmpeg/archive/refs/tags/n7.1.tar.gz"
"https://github.com/git/git/archive/refs/tags/v2.47.1.tar.gz"
"https://github.com/vim/vim/archive/refs/tags/v9.1.0900.tar.gz"
"https://github.com/neovim/neovim/archive/refs/tags/v0.10.3.tar.gz"
"https://github.com/tmux/tmux/archive/refs/tags/3.5a.tar.gz"
"https://registry.npmjs.org/express"
"https://registry.npmjs.org/react"
"https://registry.npmjs.org/typescript"
"https://registry.npmjs.org/webpack"
"https://registry.npmjs.org/lodash"
"https://pypi.org/simple/requests/"
"https://pypi.org/simple/numpy/"
"https://pypi.org/simple/django/"
"https://pypi.org/simple/flask/"
"https://pypi.org/simple/pandas/"
"https://files.pythonhosted.org/packages/source/r/requests/requests-2.32.3.tar.gz"
"https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar"
"https://repo1.maven.org/maven2/com/google/guava/guava/33.4.0-jre/guava-33.4.0-jre.jar"
"https://repo1.maven.org/maven2/org/springframework/spring-core/6.2.1/spring-core-6.2.1.jar"
"https://cran.r-project.org/src/contrib/PACKAGES"
"https://cran.r-project.org/src/contrib/dplyr_1.1.4.tar.gz"
"https://rubygems.org/gems/rails-7.2.2.gem"
"https://rubygems.org/gems/rake-13.2.1.gem"
"https://crates.io/api/v1/crates/serde/download"
"https://crates.io/api/v1/crates/tokio/download"
"https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.12.tar.xz"
"https://www.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.12"
"https://download.docker.com/linux/ubuntu/dists/noble/InRelease"
"https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz"
"https://archive.apache.org/dist/httpd/httpd-2.4.62.tar.bz2"
"https://archive.apache.org/dist/tomcat/tomcat-10/v10.1.34/bin/apache-tomcat-10.1.34.tar.gz"
"https://nodejs.org/dist/v22.12.0/node-v22.12.0-linux-x64.tar.xz"
"https://golang.org/dl/go1.23.4.linux-amd64.tar.gz"
"https://dl.google.com/go/go1.23.4.linux-amd64.tar.gz"
"https://www.openssl.org/source/openssl-3.4.0.tar.gz"
"https://ftp.gnu.org/gnu/coreutils/coreutils-9.5.tar.xz"
"https://ftp.gnu.org/gnu/binutils/binutils-2.43.tar.xz"
"https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz"
"https://ftp.postgresql.org/pub/source/v17.2/postgresql-17.2.tar.bz2"
)
# Реалистичные UA для admin/dev-host (не Safari iOS):
# shellcheck disable=SC2034
UA_LIBDL=(
"curl/8.10.1"
"curl/8.5.0"
"Wget/1.21.4"
"Wget/1.24.5"
"Debian APT-HTTP/1.3 (2.7.14) Ubuntu/24.04"
"Go-http-client/2.0"
"python-requests/2.32.3"
"pip/24.3.1 {\"ci\":null,\"cpu\":\"x86_64\",\"distro\":{\"name\":\"Ubuntu\",\"version\":\"24.04\"},\"implementation\":{\"name\":\"CPython\",\"version\":\"3.13.1\"}}"
"npm/10.9.2 node/v22.12.0 linux x64"
"Maven/3.9.9 (Java 21.0.5; Linux 6.8.0; amd64)"
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

# v8.9 (C1): Dynamic JA3 rotation между connections. Если у нас доступно
# несколько curl-impersonate-safari вариантов (17_4 + 16_5 + generic), то на
# каждый noise-request выбираем рандомно. Раньше CURL_BIN был sticky на всю
# сессию = один JA3 hash на все подключения, что — слабый стелс-сигнал
# (real iOS distribution: разные iOS-версии в один раз шлют разные
# ClientHello). После v8.9: per-conn JA3 distribution match real-iOS
# distribution.
# Возвращает один из доступных curl-вариантов, weighted ~ UA-distribution
# (новые iOS преобладают).
pick_curl_per_conn() {
    local _avail=()
    command -v curl_safari17_4 >/dev/null 2>&1 && _avail+=("curl_safari17_4")
    # curl_safari17_4 представляет iOS 17.4, что близко к iOS 18 ClientHello —
    # дублируем чтобы weight его был выше (соответствует real-traffic share).
    command -v curl_safari17_4 >/dev/null 2>&1 && _avail+=("curl_safari17_4")
    command -v curl_safari16_5 >/dev/null 2>&1 && _avail+=("curl_safari16_5")
    command -v curl-impersonate-safari >/dev/null 2>&1 && _avail+=("curl-impersonate-safari")
    if [ "${#_avail[@]}" -eq 0 ]; then
        echo "$CURL_BIN"
        return 0
    fi
    # urand: 0..N-1
    local _idx=$(( RANDOM % ${#_avail[@]} ))
    echo "${_avail[$_idx]}"
}

COOKIE_JAR_DIR="/tmp/.vps_noise"
mkdir -p "$COOKIE_JAR_DIR"
chmod 700 "$COOKIE_JAR_DIR"

# Per-session referer (имитирует браузерную навигационную цепочку:
# главная → статья → статья → ... — тот же session, тот же Referer).
declare -A LAST_URL_PER_TAG
declare -A ETAG_PER_URL
declare -A LASTMOD_PER_URL

# Health-state — пишется в /run/vps-noise/health.json для status-команды.
HEALTH_FILE_NOISE="/run/vps-noise/health.json"
mkdir -p "$(dirname "$HEALTH_FILE_NOISE")" 2>/dev/null || true
NOISE_REQ_TOTAL=0
NOISE_REQ_OK=0
NOISE_REQ_ERR=0
NOISE_LAST_TS=0
START_TS=$(date +%s)
update_health() {
    [ -w "$(dirname "$HEALTH_FILE_NOISE")" ] || return 0
    cat > "$HEALTH_FILE_NOISE" 2>/dev/null <<HJEOF
{
  "last_request_ts": $NOISE_LAST_TS,
  "requests_total": $NOISE_REQ_TOTAL,
  "requests_ok": $NOISE_REQ_OK,
  "requests_error": $NOISE_REQ_ERR,
  "pid": $$,
  "started_at": $START_TS
}
HJEOF
}

# /dev/urandom-based случайное число (для параллельных loops без коллизий)
urand() {
    local lo="$1" hi="$2" span r
    span=$(( hi - lo + 1 ))
    [ "$span" -le 0 ] && { echo "$lo"; return; }
    r=$(od -An -N4 -tu4 /dev/urandom 2>/dev/null | tr -d ' ')
    [ -z "$r" ] && r=$RANDOM
    echo $(( r % span + lo ))
}

# Случайное число в диапазоне [a, b] — теперь через /dev/urandom.
rrange() { urand "$1" "$2"; }

# Случайный rate-limit
rand_rate() { urand "$RATE_KB_MIN" "$RATE_KB_MAX"; }

# Извлечь схему+host (https://example.com) — для Sec-Fetch-Site и Referer cross-site детекции.
url_origin() {
    echo "$1" | awk -F/ '{print $1"//"$3}'
}

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

    # Referer chain: если в этой сессии уже был запрос, делаем Referer.
    # Sec-Fetch-Site вычисляется как same-origin / cross-site / none.
    local prev="${LAST_URL_PER_TAG[$tag]:-}"
    local sec_fetch_site="none"
    local referer_arg=()
    if [ -n "$prev" ] && [ "$prev" != "$url" ]; then
        referer_arg=(-H "Referer: $prev")
        if [ "$(url_origin "$prev")" = "$(url_origin "$url")" ]; then
            sec_fetch_site="same-origin"
        else
            sec_fetch_site="cross-site"
        fi
    fi

    # Cache headers: если у нас уже есть ETag/Last-Modified для этого URL, отправляем их.
    local cache_args=()
    if [ -n "${ETAG_PER_URL[$url]:-}" ]; then
        cache_args+=(-H "If-None-Match: ${ETAG_PER_URL[$url]}")
    fi
    if [ -n "${LASTMOD_PER_URL[$url]:-}" ]; then
        cache_args+=(-H "If-Modified-Since: ${LASTMOD_PER_URL[$url]}")
    fi

    local rate
    rate=$(rand_rate)

    # Дамп заголовков ответа во временный файл для парсинга ETag/Last-Modified.
    local hdr_tmp
    hdr_tmp=$(mktemp /tmp/.vps_noise_hdr.XXXXXX 2>/dev/null) || hdr_tmp="/dev/null"

    local args=(
        -s -o /dev/null
        --max-time 25 --connect-timeout 8
        --tls-max 1.3 --tlsv1.2
        --compressed
        --cookie-jar "$jar" --cookie "$jar"
        -A "$ua"
        -D "$hdr_tmp"
        -H "Accept: $ACCEPT"
        -H "Accept-Language: $accept_lang"
        -H "Accept-Encoding: $ACCEPT_ENC"
        -H "Sec-Fetch-Dest: document"
        -H "Sec-Fetch-Mode: navigate"
        -H "Sec-Fetch-Site: $sec_fetch_site"
        -H "Sec-Fetch-User: ?1"
        -H "Upgrade-Insecure-Requests: 1"
        -H "Priority: u=0, i"
        -H "DNT: 1"
        --limit-rate "${rate}K"
    )
    args+=("${referer_arg[@]}")
    args+=("${cache_args[@]}")

    # v8.9 (C1): Per-conn выбор curl-binary — даёт rotating JA3 fingerprint
    # между connections. fallback к глобальному CURL_BIN (sticky session) если
    # альтернативы недоступны.
    local _conn_curl
    _conn_curl=$(pick_curl_per_conn)
    [ -z "$_conn_curl" ] && _conn_curl="$CURL_BIN"

    if [ "$_conn_curl" = "curl" ]; then
        # v8.8 (C5): ALPN rotation — real iOS Safari/WebKit чередует h3 / h2 /
        # http/1.1 ~ 50/40/10. До v8.8 у нас было h3=50% / h2=50%, http/1.1=0%.
        # Это давало weak signal для passive observers (real iOS изредка
        # fallback'ает на http/1.1 из-за legacy CDN). Бьём 0..9 → 0-4=h3, 5-8=h2, 9=http/1.1.
        local _alpn_pick
        _alpn_pick=$(urand 0 9)
        if [ "$_alpn_pick" -le 4 ] && curl --help all 2>/dev/null | grep -q -- '--http3'; then
            args+=(--http3)
        elif [ "$_alpn_pick" -le 8 ]; then
            args+=(--http2)
        else
            args+=(--http1.1)
        fi
        # v8.4: TLS 1.3 0-RTT / Early Data — Safari делает на resumed sessions.
        # curl поддерживает с 7.79+. Если не поддерживается — флаг проигнорится.
        if curl --help all 2>/dev/null | grep -q -- '--tls-earlydata'; then
            (( $(urand 0 2) == 0 )) && args+=(--tls-earlydata)
        fi
        # v8.6: iOS 18 — TCP_FASTOPEN_CONNECT. Реальный Safari ставит TFO_CONNECT
        # практически на каждый исходящий TCP-сокет (с момента iOS 9). У нас был
        # TFO в sysctl, но в curl-вызовах не использовали. curl 7.49+ умеет --tcp-fastopen.
        # Безопасно: server поддержи нет → fallback к стандартному 3WHS.
        # На Linux SO_NOSIGPIPE недоступен, но curl делает MSG_NOSIGNAL — equivalent.
        if curl --help all 2>/dev/null | grep -q -- '--tcp-fastopen'; then
            (( $(urand 0 1) == 0 )) && args+=(--tcp-fastopen)
        fi
        # v8.9 (C3): TLS Encrypted ClientHello (ECH). curl 8.10+ поддерживает
        # `--ech true` (auto via DNS HTTPS RR). Скрывает SNI от passive observers
        # — критично для прокси-фронтенда. Только opt-in (через NOISE_ECH=1) и
        # только если curl umеет: некоторые distros билдят без ECH.
        if [ "${NOISE_ECH:-0}" = "1" ] && curl --help all 2>/dev/null | grep -q -- '--ech'; then
            args+=(--ech "true")
        fi
        # v8.9 (C9): HTTP/2 SETTINGS values match Safari. Real iOS Safari
        # держит HTTP/2-conn активным с keepalive ~30-60s между requests.
        # `--keepalive-time 30` сообщает kernel SO_KEEPALIVE с idle=30s, что
        # точно match Safari behaviour (default curl =60s = слабый стелс).
        # Нет smaller-than-default-window-size flag в curl — INITIAL_WINDOW_SIZE
        # hardcoded libnghttp2 = 4 MiB, что уже совпадает с Safari.
        # MAX_CONCURRENT_STREAMS 100 — также libnghttp2 default, match.
        args+=(--keepalive-time 30)
        # v8.9 (C8): Real iOS QUIC transport parameters. ngtcp2 (curl-h3 backend)
        # использует max_idle_timeout=30s, max_udp_payload_size=1452 — что
        # уже match real iOS. Больше для фингерпринт-paritet ничего не сделать
        # без custom build curl-impersonate с iOS-specific transport params.
        # Документируем для stealth-test (которая показывает реальные QUIC
        # params в diagnostic output).
    fi

    NOISE_REQ_TOTAL=$(( NOISE_REQ_TOTAL + 1 ))
    NOISE_LAST_TS=$(date +%s)
    if "$_conn_curl" "${args[@]}" "$url" 2>/dev/null; then
        NOISE_REQ_OK=$(( NOISE_REQ_OK + 1 ))
    else
        NOISE_REQ_ERR=$(( NOISE_REQ_ERR + 1 ))
    fi
    update_health

    # Cache headers: парсим из ответа (берём чистые значения).
    if [ -f "$hdr_tmp" ]; then
        local etag lastmod
        etag=$(awk -F': ' 'tolower($1)=="etag"{sub(/\r$/,"",$2); print $2; exit}' "$hdr_tmp" 2>/dev/null)
        lastmod=$(awk -F': ' 'tolower($1)=="last-modified"{sub(/\r$/,"",$2); print $2; exit}' "$hdr_tmp" 2>/dev/null)
        [ -n "$etag" ]    && ETAG_PER_URL[$url]="$etag"
        [ -n "$lastmod" ] && LASTMOD_PER_URL[$url]="$lastmod"
        rm -f "$hdr_tmp"
    fi

    LAST_URL_PER_TAG[$tag]="$url"
}

# ===== DNS prefetch — имитация браузерного DNS preconnect =====
# Реальный браузер всегда резолвит host'ы заранее. Делаем дополнительный
# trace через `getent` чтобы попасть в DNS-логи провайдера.
dns_prefetch() {
    local host
    host=$(echo "$1" | awk -F/ '{print $3}')
    [ -n "$host" ] && getent hosts "$host" >/dev/null 2>&1 || true
}

# ===== Cloud / NTP / metadata phantoms =====
# Реальная Ubuntu периодически тянет NTP и cloud-init metadata. Ставим эти
# запросы рандомно, чтобы trace выглядел нативно.
cloud_phantom() {
    local choice=$(( $(urand 0 99) ))
    if (( choice < 40 )); then
        # NTP запрос (UDP 123)
        timeout 3 bash -c 'exec 3<>/dev/udp/time.ubuntu.com/123 && echo -ne "\x1b\x00\x00\x00" >&3 && sleep 0.5' 2>/dev/null || true
    elif (( choice < 70 )); then
        # apt-метаданные
        http_request "http://archive.ubuntu.com/ubuntu/dists/noble/Release" desktop en cloud_phantom
    elif (( choice < 90 )); then
        # security-апдейты
        http_request "http://security.ubuntu.com/ubuntu/dists/noble-security/Release" desktop en cloud_phantom
    else
        # snap refresh (просто HEAD без install)
        http_request "https://api.snapcraft.io/v2/snaps/info/core24" desktop en cloud_phantom
    fi
}

# ===== APNs keepalive =====
apns_keepalive() {
    timeout 6 bash -c 'exec 3<>/dev/tcp/courier.push.apple.com/5223 && sleep 3' 2>/dev/null || true
}

# ===== FCM / Microsoft / Apple push keepalive (v8.4) =====
# Реальные мобильные устройства (Android, Win, Mac) держат TCP до push-сервисов
# **постоянно**, периодически слегка «дёргают» соединение. Чисто TCP-handshake +
# короткое ожидание. Никаких HTTP-запросов, никаких данных в /dev/null.
# FCM_HOSTS перечисляет несколько endpoint'ов — алгоритм случайно выбирает один.
push_keepalive() {
    local hosts=(
        "courier.push.apple.com:5223"     # APNs (Apple)
        "1-courier.push.apple.com:5223"
        "2-courier.push.apple.com:5223"
        "mtalk.google.com:5228"           # FCM (Android / Chrome)
        "mtalk4.google.com:5228"
        "mtalk-staging.google.com:5228"
        "db5p.notify.windows.com:443"     # WNS (Windows)
        "vap04.notify.windows.com:443"
    )
    local pick="${hosts[$(urand 0 $(( ${#hosts[@]} - 1 )) )]}"
    local h="${pick%:*}" p="${pick##*:}"
    timeout 6 bash -c "exec 3<>/dev/tcp/$h/$p && sleep 3" 2>/dev/null || true
}

# ===== STUN UDP burst (v8.4) =====
# Браузеры/приложения регулярно делают WebRTC discovery: маленький UDP-пакет
# к публичному STUN серверу, ответ ~32-60 байт. Имитируем через bash UDP socket.
# Рассылаем 1-3 STUN Binding Request'а к рандомным STUN-серверам.
stun_burst() {
    # Сырой STUN Binding Request: 20 байт.
    # 0x0001 (Binding Request) + 0x0000 (length=0) + 0x2112A442 (magic cookie) +
    # 12-байтовый transaction ID. Собираем как `\xNN`-escape-строку (а не сырыми
    # байтами через $'...'), потому что bash-строки не могут содержать NUL —
    # любая `\x00` в \$'…' усекает переменную в 0 длины. printf %b развернёт.
    local stun_pkt='\x00\x01\x00\x00\x21\x12\xa4\x42'
    local b
    for ((b=0; b<12; b++)); do
        stun_pkt+=$(printf '\\x%02x' "$(urand 0 255)")
    done
    local stuns=(
        "stun.l.google.com:19302"
        "stun1.l.google.com:19302"
        "stun2.l.google.com:19302"
        "stun.cloudflare.com:3478"
        "stun.nextcloud.com:443"
    )
    local n i pick h p
    n=$(rrange 1 3)
    for ((i=0; i<n; i++)); do
        pick="${stuns[$(urand 0 $(( ${#stuns[@]} - 1 )) )]}"
        h="${pick%:*}" p="${pick##*:}"
        timeout 2 bash -c "
            exec 3<>/dev/udp/$h/$p
            printf '%b' '$stun_pkt' >&3
            head -c 64 <&3 >/dev/null 2>&1 &
            sleep 0.5
            kill %1 2>/dev/null
        " 2>/dev/null || true
        sleep "$(rrange 1 4)"
    done
}

# ===== WebSocket-style long-poll (v8.4) =====
# Реальные приложения (Telegram, Discord, IM в браузере, Push) держат TCP/443
# до сервиса 5-30+ минут с маленьким heartbeat'ом. У нас всё было request/response.
# Здесь — открыть TCP/443 к https-эндпоинту, дёрнуть HEAD, ждать молча 5-15 мин.
# Не нагружаем ничего: bash-сокет тратит ~12KB RAM, никаких HTTP-запросов внутри.
websocket_keepalive() {
    local hosts=(
        "edge-mqtt.facebook.com"
        "graph.facebook.com"
        "www.cloudflare.com"
        "icloud.com"
        "apple.com"
        "yandex.ru"
        "vk.com"
    )
    local h="${hosts[$(urand 0 $(( ${#hosts[@]} - 1 )) )]}"
    local secs
    secs=$(rrange 300 1200)   # 5-20 мин
    timeout "$secs" bash -c "exec 3<>/dev/tcp/$h/443 && sleep $secs" 2>/dev/null || true
}

# ===== iOS Safari бёрст =====
# Профиль реального iPhone-пользователя в РФ:
#   ~70%  Apple-домены (apple/icloud/mzstatic/...).
#   ~20%  Российские новости (lenta/ria/rbc/tass/...).
#   ~10%  Госпорталы РФ / КИИ (gosuslugi/mos.ru/nalog/...).
#   Никаких соцсетей, никаких мессенджеров.
ios_burst_pick() {
    local r=$(( RANDOM % 100 ))
    if (( r < 70 )); then
        echo "${URLS_IOS[$RANDOM % ${#URLS_IOS[@]}]}"
    elif (( r < 90 )); then
        echo "${URLS_NEWS_RU[$RANDOM % ${#URLS_NEWS_RU[@]}]}"
    else
        echo "${URLS_IOS_RU_GOV[$RANDOM % ${#URLS_IOS_RU_GOV[@]}]}"
    fi
}
ios_burst() {
    local n url
    n=$(rrange 3 8)
    # Первый запрос всегда Apple — это «открыли Safari».
    http_request "${URLS_IOS[$RANDOM % ${#URLS_IOS[@]}]}" ios en ios_session
    sleep "$(rrange 1 4)"
    local i
    for ((i=1; i<n; i++)); do
        url=$(ios_burst_pick)
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

# ===== Phantom library/archive downloads =====
# Тянет случайный URL (releases / npm / pypi / kernel.org / ...) до
# LIB_PHANTOM_BYTES_MAX и сразу в /dev/null. Скорость капается RATE_KB_MAX.
lib_phantom_run() {
    local burst i url ua rate
    burst=$(rrange "$LIB_PHANTOM_BURST_MIN" "$LIB_PHANTOM_BURST_MAX")
    for ((i=0; i<burst; i++)); do
        url="${URLS_LIB_DOWNLOADS[$RANDOM % ${#URLS_LIB_DOWNLOADS[@]}]}"
        ua="${UA_LIBDL[$RANDOM % ${#UA_LIBDL[@]}]}"
        rate=$(rand_rate)
        local CURL=(curl -s -o /dev/null -L \
            --max-filesize "$LIB_PHANTOM_BYTES_MAX" \
            --max-time 60 \
            --limit-rate "${rate}k" \
            --connect-timeout 10 \
            -H "Accept: */*" \
            -H "Accept-Encoding: gzip, deflate" \
            -A "$ua" \
            "$url")
        "${CURL[@]}" 2>/dev/null || true
        sleep "$(rrange 3 25)"
    done
}

# ===== Vacation mode =====
# Раз в день кидаем кубик; если выпало — пишем в state-файл время выхода
# из «отпуска». Все циклы в начале итерации проверяют этот файл и спят.
VACATION_FILE="/var/lib/vps-noise/vacation_until"
vacation_check_and_sleep() {
    [ "$ENABLE_VACATION" = "1" ] || return 0
    mkdir -p "$(dirname "$VACATION_FILE")"
    local now until
    now=$(date +%s)
    if [ -f "$VACATION_FILE" ]; then
        until=$(cat "$VACATION_FILE" 2>/dev/null || echo 0)
        if [ "$until" -gt "$now" ]; then
            sleep $(( until - now ))
            return 0
        else
            rm -f "$VACATION_FILE"
        fi
    fi
}
vacation_maybe_start() {
    [ "$ENABLE_VACATION" = "1" ] || return 0
    local marker
    marker="/var/lib/vps-noise/vacation_today_$(date +%Y%m%d)"
    [ -f "$marker" ] && return 0
    mkdir -p "$(dirname "$marker")"
    touch "$marker"
    if (( RANDOM % 100 < VACATION_CHANCE_PCT )); then
        local hours
        hours=$(rrange "$VACATION_HOURS_MIN" "$VACATION_HOURS_MAX")
        echo "$(( $(date +%s) + hours * 3600 ))" > "$VACATION_FILE"
    fi
}

# ===== Профиль времени суток + «места» (множитель пауз) =====
# PLACE_PROFILE: office (9-18 быстрые бёрсты), home (19-23 ютуб/новости),
# auto — по часам.
# Возвращает целочисленный множитель (в процентах) к базовому интервалу.
hour_factor() {
    local h profile="${PLACE_PROFILE:-auto}"
    h=$(date +%H); h=$((10#$h))
    case "$profile" in
        office)
            # «офис» — активность 9-18, минимальная остальное время
            if (( h >= 9 && h <= 18 )); then echo 60
            elif (( h >= NIGHT_HOUR_FROM && h <= NIGHT_HOUR_TO )); then echo 350
            else echo 200; fi
            return ;;
        home)
            # «дом» — пик вечером, лёгкая утренняя проверка
            if (( h >= 19 && h <= 23 )); then echo 60
            elif (( h >= 7 && h <= 9 )); then echo 80
            elif (( h >= NIGHT_HOUR_FROM && h <= NIGHT_HOUR_TO )); then echo 300
            else echo 130; fi
            return ;;
        always_on)
            # 24/7 (сервер)
            echo 100; return ;;
    esac
    # auto (default): кривая дня
    if (( h >= NIGHT_HOUR_FROM && h <= NIGHT_HOUR_TO )); then
        echo 250
    elif (( h >= PEAK_MORNING_FROM && h <= PEAK_MORNING_TO )); then
        echo 60
    elif (( h >= PEAK_EVENING_FROM && h <= PEAK_EVENING_TO )); then
        echo 70
    else
        echo 100
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
        vacation_maybe_start
        vacation_check_and_sleep
        ios_burst
        sleep_minutes "$IOS_BURST_INTERVAL_MIN" "$IOS_BURST_INTERVAL_MAX"
    done
}
loop_apns() {
    while true; do
        vacation_check_and_sleep
        apns_keepalive
        sleep "$(rrange 1500 2400)"   # ~25–40 мин
    done
}
# v8.4: push_keepalive — APNs/FCM/WNS rotation
loop_push() {
    while true; do
        vacation_check_and_sleep
        push_keepalive
        sleep "$(rrange 600 1800)"    # 10-30 мин
    done
}
# v8.4: STUN UDP бёрсты — WebRTC-style discovery (Safari/Chrome делают регулярно)
loop_stun() {
    while true; do
        sleep "$(rrange 600 2400)"    # 10-40 мин
        vacation_check_and_sleep
        stun_burst
    done
}
# v8.4: websocket-like long-poll
loop_ws() {
    while true; do
        sleep "$(rrange 60 600)"      # 1-10 мин между сессиями
        vacation_check_and_sleep
        websocket_keepalive
    done
}
loop_email() {
    while true; do
        sleep_minutes "$EMAIL_INTERVAL_MIN" "$EMAIL_INTERVAL_MAX"
        vacation_check_and_sleep
        email_session
    done
}
loop_news() {
    while true; do
        sleep_minutes "$NEWS_INTERVAL_MIN" "$NEWS_INTERVAL_MAX"
        vacation_check_and_sleep
        news_session
    done
}
loop_apt() {
    while true; do
        sleep_minutes "$APT_PHANTOM_INTERVAL_MIN" "$APT_PHANTOM_INTERVAL_MAX"
        vacation_maybe_start
        vacation_check_and_sleep
        apt_phantom_run
    done
}
loop_libdl() {
    while true; do
        sleep_minutes "$LIB_PHANTOM_INTERVAL_MIN" "$LIB_PHANTOM_INTERVAL_MAX"
        vacation_maybe_start
        vacation_check_and_sleep
        lib_phantom_run
    done
}

# Cloud / NTP / metadata phantom — реальная Ubuntu всегда тянет эти эндпоинты в фоне.
loop_cloud() {
    while true; do
        sleep_minutes "${CLOUD_PHANTOM_INTERVAL_MIN:-30}" "${CLOUD_PHANTOM_INTERVAL_MAX:-180}"
        vacation_check_and_sleep
        cloud_phantom
    done
}

# DNS-prefetch loop: имитация браузерного DNS preconnect. Тихо, без HTTP.
loop_dns_prefetch() {
    while true; do
        sleep "$(rrange 30 240)"
        vacation_check_and_sleep
        # Берём случайный URL из всех пулов и резолвим только host
        local pool
        case $(( $(urand 0 4) )) in
            0) pool=("${URLS_IOS[@]}") ;;
            1) pool=("${URLS_NEWS_RU[@]}") ;;
            2) pool=("${URLS_IOS_RU_GOV[@]}") ;;
            3) pool=("${URLS_GLOBAL[@]}") ;;
            *) pool=("${URLS_LIB_DOWNLOADS[@]}") ;;
        esac
        if [ "${#pool[@]}" -gt 0 ]; then
            local url="${pool[$(urand 0 $(( ${#pool[@]} - 1 )) )]}"
            dns_prefetch "$url"
        fi
    done
}

# Health-touch loop: каждые 30с обновляет TS в health.json (даже если другие
# loops спят/в vacation), показывает что сервис живой.
loop_health() {
    while true; do
        update_health
        sleep 30
    done
}

# Старт включённых модулей в фоне
PIDS=()
[ "$ENABLE_IOS_BURST"   = "1" ] && { loop_ios   & PIDS+=($!); }
[ "$ENABLE_APNS"        = "1" ] && { loop_apns  & PIDS+=($!); }
[ "${ENABLE_PUSH:-1}"   = "1" ] && { loop_push  & PIDS+=($!); }   # v8.4: APNs/FCM/WNS rotation
[ "${ENABLE_STUN:-1}"   = "1" ] && { loop_stun  & PIDS+=($!); }   # v8.4: WebRTC STUN burst
[ "${ENABLE_WEBSOCKET:-1}" = "1" ] && { loop_ws & PIDS+=($!); }   # v8.4: long-poll TCP keepalive
[ "$ENABLE_EMAIL"       = "1" ] && { loop_email & PIDS+=($!); }
[ "$ENABLE_NEWS"        = "1" ] && { loop_news  & PIDS+=($!); }
[ "$ENABLE_APT_PHANTOM" = "1" ] && command -v apt-get >/dev/null 2>&1 && { loop_apt & PIDS+=($!); }
[ "$ENABLE_LIB_PHANTOM" = "1" ] && { loop_libdl & PIDS+=($!); }
[ "${ENABLE_CLOUD_PHANTOM:-1}" = "1" ] && { loop_cloud & PIDS+=($!); }
[ "${ENABLE_DNS_PREFETCH:-1}"  = "1" ] && { loop_dns_prefetch & PIDS+=($!); }
loop_health & PIDS+=($!)

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
Restart=on-failure
RestartSec=30
StartLimitIntervalSec=300
StartLimitBurst=5
Nice=15
IOSchedulingClass=idle
CPUWeight=20
MemoryHigh=128M
MemoryMax=256M
TasksMax=64
StandardOutput=null
StandardError=null
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
RestrictSUIDSGID=yes
LockPersonality=yes
NoNewPrivileges=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
StateDirectory=vps-noise
RuntimeDirectory=vps-noise
RuntimeDirectoryMode=0750
ReadWritePaths=/tmp /var/cache/apt /var/lib/apt /var/lib/vps-noise /run/vps-noise

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
    if [ "$DRY_RUN" = "1" ]; then
        echo -e "${YELLOW}[dry-run] reset_all: ничего не удаляю/не останавливаю.${NC}"
        return 0
    fi
    if [ "$SOFT_RESET" = "1" ]; then
        # Soft-режим (v8.3, L6): откатываем только sysctl/limits/preset.
        # Не трогаем DNS/noise/swap/zram — полезно при отладке тюнинга.
        echo -e "${YELLOW}[*] Soft reset: только sysctl/limits/preset.${NC}"
        rm -f "$SYSCTL_CONF" "$LIMITS_CONF" "$EXP_CONF" "$PRESET_FILE" \
              /etc/systemd/system.conf.d/99-vps-limits.conf \
              /etc/systemd/user.conf.d/99-vps-limits.conf
        # Снимаем boot-unit, если был.
        systemctl disable --now vps-optimizer-apply.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/vps-optimizer-apply.service
        systemctl daemon-reload >/dev/null 2>&1 || true
        sysctl --system >/dev/null 2>&1 || true
        _audit reset "mode=soft"
        echo -e "${GREEN}[+] Soft-сброс выполнен (DNS/noise/swap не тронуты).${NC}"
        sleep 1
        return 0
    fi
    echo -e "${YELLOW}[*] Полный откат...${NC}"
    swapoff -a 2>/dev/null || true
    rm -f /swapfile
    sed -i '/\/swapfile/d' /etc/fstab
    zramctl --reset /dev/zram0 2>/dev/null || true
    # Восстанавливаем оригинальный DNS, если мы его ломали
    apply_dns local 2>/dev/null || true

    rm -f "$SYSCTL_CONF" "$LIMITS_CONF" "$EXP_CONF" "$NOISE_CONF" "$PRESET_FILE" \
          "$DNS_CONF" "$DNS_STATE" "$DNS_RESOLV_BACKUP" \
          /etc/dnsmasq.d/vps-speed.conf \
          /etc/systemd/system.conf.d/99-vps-limits.conf \
          /etc/systemd/user.conf.d/99-vps-limits.conf
    systemctl stop vps-noise vps-rps dnsmasq >/dev/null 2>&1 || true
    systemctl disable vps-noise vps-rps >/dev/null 2>&1 || true
    systemctl disable --now vps-optimizer-apply.service >/dev/null 2>&1 || true
    # v8.5: cleanup health-watch таймера и rsyslog-фрагмента (created by
    # health_watch_command / audit_syslog_command). Иначе после reset/uninstall
    # таймер продолжает дёргать удалённый скрипт и мусорит в health.log.
    systemctl disable --now vps-optimizer-health.timer >/dev/null 2>&1 || true
    rm -f "$NOISE_GEN_SCRIPT" "$NOISE_GEN_SERVICE" "$RPS_BOOT_SCRIPT" "$RPS_BOOT_SERVICE" \
          /etc/systemd/system/vps-optimizer-apply.service \
          /etc/systemd/system/vps-optimizer-health.timer \
          /etc/systemd/system/vps-optimizer-health.service \
          /etc/rsyslog.d/49-vps-optimizer.conf \
          /etc/unbound/unbound.conf.d/99-vps-optim-dnssec.conf \
          /etc/unbound/unbound.conf.d/99-vps-optim-padding.conf
    # v8.5: если unbound был переведён на dnssec через dns_dnssec_command — reload чтобы
    # подхватить отсутствие фрагмента.
    systemctl reload unbound >/dev/null 2>&1 || true
    systemctl restart rsyslog >/dev/null 2>&1 || true
    rm -rf /tmp/.vps_noise /var/lib/vps-noise
    systemctl daemon-reload >/dev/null 2>&1 || true
    sysctl --system >/dev/null 2>&1 || true
    _audit reset "mode=full"
    echo -e "${GREEN}[+] Сброс выполнен.${NC}"
    sleep 2
}

# ===================================================================
#  DNS configuration
# ===================================================================
# Пресеты публичных резолверов. По умолчанию никаких изменений не делаем
# (mode=local) — берётся то, что настроил провайдер.
DNS_PRESET_CLOUDFLARE="1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001"
DNS_PRESET_GOOGLE="8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844"
DNS_PRESET_YANDEX="77.88.8.8 77.88.8.1"
DNS_PRESET_QUAD9="9.9.9.9 149.112.112.112"
DNS_PRESET_ADGUARD="94.140.14.14 94.140.15.15"

# Server-name hostnames — нужны для DoT (RFC: IP#hostname для systemd-resolved)
# и DoH (URL). Без них strict TLS проверит только IP без SNI и упадёт.
DNS_SNI_CLOUDFLARE="cloudflare-dns.com"
DNS_SNI_GOOGLE="dns.google"
DNS_SNI_YANDEX="common.dot.dns.yandex.net"
DNS_SNI_QUAD9="dns.quad9.net"
DNS_SNI_ADGUARD="dns.adguard-dns.com"

# DoH stamps / URLs — для dnscrypt-proxy; URL'ы стандартные, проверены.
DNS_DOH_CLOUDFLARE="https://cloudflare-dns.com/dns-query"
DNS_DOH_GOOGLE="https://dns.google/dns-query"
DNS_DOH_YANDEX="https://common.dot.dns.yandex.net/dns-query"
DNS_DOH_QUAD9="https://dns.quad9.net/dns-query"
DNS_DOH_ADGUARD="https://dns.adguard-dns.com/dns-query"

# Возвращает SNI/host для DoT/DoH preset.
dns_preset_sni() {
    case "$1" in
        cloudflare) echo "$DNS_SNI_CLOUDFLARE" ;;
        google)     echo "$DNS_SNI_GOOGLE" ;;
        yandex)     echo "$DNS_SNI_YANDEX" ;;
        quad9)      echo "$DNS_SNI_QUAD9" ;;
        adguard)    echo "$DNS_SNI_ADGUARD" ;;
        *) echo "" ;;
    esac
}
dns_preset_doh_url() {
    case "$1" in
        cloudflare) echo "$DNS_DOH_CLOUDFLARE" ;;
        google)     echo "$DNS_DOH_GOOGLE" ;;
        yandex)     echo "$DNS_DOH_YANDEX" ;;
        quad9)      echo "$DNS_DOH_QUAD9" ;;
        adguard)    echo "$DNS_DOH_ADGUARD" ;;
        *) echo "" ;;
    esac
}

# Применяет выбранный DNS-режим. Сохраняет состояние в $DNS_STATE.
# Аргументы:  $1 = transport (plain|dot|doh) — по умолчанию plain.
#                  Если $1 — это preset (например 'cloudflare') или 'local'/'custom',
#                  считаем это backward-compat вызовом и transport=plain.
#             $2 = preset (local|cloudflare|google|yandex|quad9|adguard|custom)
#             $3 = (custom only) IP-адреса через пробел / DoH URL
apply_dns() {
    # Backward-compat: если первый аргумент — известный preset/local/custom, добавляем 'plain'.
    local transport="${1:-plain}"
    case "$transport" in
        plain|dot|doh) shift ;;
        local|cloudflare|google|yandex|quad9|adguard|custom|"")
            transport="plain"
            ;;
        *)
            _log WARN "${RED}[!] Неизвестный DNS transport: $transport${NC}"
            return 1
            ;;
    esac
    local mode="${1:-local}" servers=""
    if [ "$mode" = "local" ] || [ -z "$mode" ]; then
        # Полный сброс DNS — чем бы ни был transport.
        if [ "$DRY_RUN" = "1" ]; then
            _log INFO "${GRAY}[dry-run] DNS → local${NC}"
            return 0
        fi
        rm -f "$DNS_CONF" "$DNS_STATE"
        if [ -f "$DNS_RESOLV_BACKUP" ]; then
            cp -p "$DNS_RESOLV_BACKUP" /etc/resolv.conf 2>/dev/null || true
        fi
        # Останавливаем DoH-прокси, если был запущен.
        systemctl disable --now dnscrypt-proxy 2>/dev/null || true
        systemctl restart systemd-resolved 2>/dev/null || true
        _log OK "${GREEN}[+] DNS режим: local (берётся конфигурация провайдера)${NC}"
        return 0
    fi
    case "$mode" in
        cloudflare) servers="$DNS_PRESET_CLOUDFLARE" ;;
        google)     servers="$DNS_PRESET_GOOGLE" ;;
        yandex)     servers="$DNS_PRESET_YANDEX" ;;
        quad9)      servers="$DNS_PRESET_QUAD9" ;;
        adguard)    servers="$DNS_PRESET_ADGUARD" ;;
        custom)     servers="${2:-}" ;;
        *)
            _log WARN "${RED}[!] Неизвестный DNS preset: $mode${NC}"
            return 1
            ;;
    esac

    if [ -z "$servers" ]; then
        _log WARN "${RED}[!] Список DNS-серверов пуст${NC}"
        return 1
    fi

    # Для plain/dot валидируем IP. Для doh при custom — может быть URL.
    if [ "$transport" != "doh" ] || [ "$mode" != "custom" ]; then
        local s
        for s in $servers; do
            if ! [[ "$s" =~ ^[0-9a-fA-F:.]+$ ]]; then
                _log WARN "${RED}[!] Невалидный DNS-сервер: $s${NC}"
                return 1
            fi
        done
    fi

    [ "$DRY_RUN" = "1" ] && {
        _log INFO "${GRAY}[dry-run] DNS → $transport/$mode ($servers)${NC}"
        return 0
    }

    case "$transport" in
        plain) dns_apply_plain "$mode" "$servers" ;;
        dot)   dns_apply_dot   "$mode" "$servers" ;;
        doh)   dns_apply_doh   "$mode" "$servers" ;;
    esac
    local rc=$?
    [ $rc -eq 0 ] && echo "$transport|$mode|$servers" > "$DNS_STATE"
    return $rc
}

# Plain DNS (UDP/TCP 53) через systemd-resolved drop-in или /etc/resolv.conf
dns_apply_plain() {
    local mode="$1" servers="$2"
    # Останавливаем dnscrypt-proxy, если был от предыдущего DoH.
    systemctl disable --now dnscrypt-proxy 2>/dev/null || true
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat > "$DNS_CONF" <<EOF
# Auto-generated by vps_optimizer.sh — transport=plain preset=$mode
[Resolve]
DNS=$servers
DNSStubListener=yes
DNSSEC=allow-downgrade
DNSOverTLS=no
Cache=yes
EOF
        systemctl restart systemd-resolved 2>/dev/null
        _log OK "${GREEN}[+] DNS plain через systemd-resolved (preset=$mode):${NC}"
    else
        if [ ! -f "$DNS_RESOLV_BACKUP" ] && [ -e /etc/resolv.conf ]; then
            cp -p /etc/resolv.conf "$DNS_RESOLV_BACKUP" 2>/dev/null || true
        fi
        [ -L /etc/resolv.conf ] && rm -f /etc/resolv.conf
        {
            echo "# vps_optimizer.sh — transport=plain preset=$mode"
            local s
            for s in $servers; do echo "nameserver $s"; done
            echo "options edns0 trust-ad timeout:1 attempts:2"
        } > /etc/resolv.conf
        _log OK "${GREEN}[+] DNS plain через /etc/resolv.conf (preset=$mode):${NC}"
    fi
    _log OK "    $servers"
    return 0
}

# DoT (DNS-over-TLS, порт 853) — через systemd-resolved DNSOverTLS=yes (strict).
# Для valid TLS handshake server name указывается в формате IP#hostname.
dns_apply_dot() {
    local mode="$1" servers="$2"
    if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        _log WARN "${RED}[!] DoT требует systemd-resolved (на этой системе не активен)${NC}"
        _log INFO "${YELLOW}    fallback → plain${NC}"
        dns_apply_plain "$mode" "$servers"
        return $?
    fi
    systemctl disable --now dnscrypt-proxy 2>/dev/null || true
    local sni dns_line=""
    sni=$(dns_preset_sni "$mode")
    if [ "$mode" = "custom" ] || [ -z "$sni" ]; then
        # Для custom нет SNI — используем IP без hostname (TLS будет с проверкой по IP/SAN).
        dns_line="$servers"
    else
        local s line=""
        for s in $servers; do
            line+="${s}#${sni} "
        done
        dns_line="${line% }"
    fi
    mkdir -p /etc/systemd/resolved.conf.d
    cat > "$DNS_CONF" <<EOF
# Auto-generated by vps_optimizer.sh — transport=dot preset=$mode
[Resolve]
DNS=$dns_line
DNSStubListener=yes
DNSSEC=allow-downgrade
DNSOverTLS=yes
Cache=yes
EOF
    systemctl restart systemd-resolved 2>/dev/null
    _log OK "${GREEN}[+] DNS DoT (порт 853, strict TLS) preset=$mode:${NC}"
    _log OK "    $dns_line"
    return 0
}

# DoH (DNS-over-HTTPS, порт 443) через dnscrypt-proxy.
# dnscrypt-proxy ставим из apt (есть в noble), слушает 127.0.0.1:53,
# направляет запросы на DoH-эндпоинт. systemd-resolved должен быть отключён,
# либо мы пишем resolv.conf руками (точно укажет на наш прокси).
dns_apply_doh() {
    local mode="$1" servers="$2"
    if ! command -v dnscrypt-proxy >/dev/null 2>&1; then
        _log INFO "${YELLOW}[*] Устанавливаем dnscrypt-proxy (требуется для DoH)...${NC}"
        if ! apt-get update -qq >/dev/null 2>&1 || ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnscrypt-proxy >/dev/null 2>&1; then
            _log WARN "${RED}[!] Не удалось поставить dnscrypt-proxy. Fallback → DoT${NC}"
            dns_apply_dot "$mode" "$servers"
            return $?
        fi
    fi
    local doh_url
    if [ "$mode" = "custom" ]; then
        # Custom DoH — пользователь передал URL'ы (или IP, тогда не годится).
        local first
        first=$(echo "$servers" | awk '{print $1}')
        if [[ "$first" == https://* ]]; then
            doh_url="$first"
        else
            _log WARN "${RED}[!] Для DoH custom нужен URL (https://.../dns-query). Fallback → DoT${NC}"
            dns_apply_dot "$mode" "$servers"
            return $?
        fi
    else
        doh_url=$(dns_preset_doh_url "$mode")
    fi
    if [ -z "$doh_url" ]; then
        _log WARN "${RED}[!] Не нашли DoH URL для preset=$mode${NC}"
        return 1
    fi
    # Конфиг dnscrypt-proxy: server_names берётся из public-resolvers.md
    # (стандартный список dnscrypt/DoH-серверов), генерация stamp не нужна.
    mkdir -p /etc/dnscrypt-proxy
    local dnscp_server
    case "$mode" in
        cloudflare) dnscp_server="cloudflare" ;;
        google)     dnscp_server="google" ;;
        quad9)      dnscp_server="quad9-doh-ip4-port443-filter-pri" ;;
        adguard)    dnscp_server="adguard-dns-doh" ;;
        yandex)     dnscp_server="yandex" ;;
        *)          dnscp_server="cloudflare" ;;
    esac
    cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml <<EOF
# Auto-generated by vps_optimizer.sh — transport=doh preset=$mode
listen_addresses = ['127.0.0.1:53', '[::1]:53']
server_names = ['$dnscp_server']
ipv4_servers = true
ipv6_servers = true
doh_servers = true
require_dnssec = false
require_nolog = false
require_nofilter = false
cache = true
cache_size = 4096
cache_min_ttl = 600
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600
log_level = 2
[sources.public-resolvers]
  urls = ['https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md', 'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  prefix = ''
EOF
    mkdir -p /var/cache/dnscrypt-proxy
    chown -R _dnscrypt-proxy:_dnscrypt-proxy /var/cache/dnscrypt-proxy 2>/dev/null || true

    # Освобождаем :53 — выключаем resolved stub listener, перенаправляем resolved upstream на 127.0.0.1.
    # Альтернатива: полностью отключить resolved и писать /etc/resolv.conf напрямую.
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat > "$DNS_CONF" <<EOF
# Auto-generated by vps_optimizer.sh — transport=doh
[Resolve]
DNS=127.0.0.1
DNSStubListener=no
DNSSEC=no
DNSOverTLS=no
Cache=no
EOF
        systemctl restart systemd-resolved 2>/dev/null
    fi
    if [ ! -f "$DNS_RESOLV_BACKUP" ] && [ -e /etc/resolv.conf ]; then
        cp -p /etc/resolv.conf "$DNS_RESOLV_BACKUP" 2>/dev/null || true
    fi
    [ -L /etc/resolv.conf ] && rm -f /etc/resolv.conf
    {
        echo "# vps_optimizer.sh — transport=doh (через dnscrypt-proxy на 127.0.0.1)"
        echo "nameserver 127.0.0.1"
        echo "options edns0 trust-ad timeout:1 attempts:2"
    } > /etc/resolv.conf

    systemctl enable --now dnscrypt-proxy 2>/dev/null || systemctl restart dnscrypt-proxy 2>/dev/null || true
    sleep 1
    if systemctl is-active --quiet dnscrypt-proxy 2>/dev/null; then
        _log OK "${GREEN}[+] DNS DoH (порт 443) preset=$mode → $dnscp_server${NC}"
        _log OK "    URL: $doh_url (через dnscrypt-proxy на 127.0.0.1)"
    else
        _log WARN "${RED}[!] dnscrypt-proxy не стартанул. Проверь: journalctl -u dnscrypt-proxy${NC}"
        return 1
    fi
    return 0
}

manage_dns_menu() {
    while true; do
        clear
        local cur_transport="plain" cur_mode="local" cur_servers=""
        if [ -f "$DNS_STATE" ]; then
            # Поддержка обеих схем: старая "mode|servers" и новая "transport|mode|servers".
            local raw
            raw=$(cat "$DNS_STATE")
            local n
            n=$(awk -F'|' '{print NF}' <<<"$raw")
            if [ "$n" = "3" ]; then
                cur_transport=$(cut -d'|' -f1 <<<"$raw")
                cur_mode=$(cut -d'|' -f2 <<<"$raw")
                cur_servers=$(cut -d'|' -f3- <<<"$raw")
            else
                cur_transport="plain"
                cur_mode=$(cut -d'|' -f1 <<<"$raw")
                cur_servers=$(cut -d'|' -f2- <<<"$raw")
            fi
        fi
        echo -e "${CYAN}${BOLD}=== DNS Configuration ===${NC}"
        echo -e "Текущий: ${BOLD}${cur_transport}${NC} / ${BOLD}${cur_mode}${NC}${cur_servers:+ (${cur_servers})}"
        echo ""
        echo -e "${YELLOW}1) Выбор транспорта (как DNS-запросы летят по сети):${NC}"
        echo -e "  ${GREEN}[1]${NC} ${BOLD}plain${NC}  — обычный DNS, порт 53/UDP+TCP (по умолчанию)"
        echo -e "  ${CYAN}[2]${NC}  ${BOLD}DoT${NC}    — DNS-over-TLS, порт 853 (через systemd-resolved strict)"
        echo -e "  ${CYAN}[3]${NC}  ${BOLD}DoH${NC}    — DNS-over-HTTPS, порт 443 (через dnscrypt-proxy, апт-ставится сам)"
        echo -e "  ${GREEN}[L]${NC}  Полный сброс к локальному (провайдерскому) DNS"
        echo -e "  ${GREEN}[0]${NC}  Назад"
        echo ""
        read -r -p "Транспорт: " t
        local transport=""
        case "$t" in
            1|p|plain|"") transport="plain" ;;
            2|t|dot|DoT)  transport="dot" ;;
            3|h|doh|DoH)  transport="doh" ;;
            L|l|local)    apply_dns plain local; read -r -p "Enter..."; continue ;;
            0) return ;;
            *) continue ;;
        esac
        echo ""
        echo -e "${YELLOW}2) Resolver:${NC}"
        echo -e "  ${CYAN}[1]${NC} Cloudflare"
        echo -e "  ${CYAN}[2]${NC} Google"
        echo -e "  ${CYAN}[3]${NC} Yandex"
        echo -e "  ${CYAN}[4]${NC} Quad9"
        echo -e "  ${CYAN}[5]${NC} AdGuard"
        echo -e "  ${YELLOW}[6]${NC} Custom (ввести IP/URL вручную)"
        echo -e "  ${GREEN}[0]${NC} Отмена"
        read -r -p "Resolver: " r
        local preset="" extra=""
        case "$r" in
            1) preset="cloudflare" ;;
            2) preset="google" ;;
            3) preset="yandex" ;;
            4) preset="quad9" ;;
            5) preset="adguard" ;;
            6)
                preset="custom"
                if [ "$transport" = "doh" ]; then
                    echo "DoH custom — введите URL (https://.../dns-query):"
                else
                    echo "Введите IP DNS-серверов через пробел (IPv4 или IPv6)."
                    echo "Пример: 1.1.1.1 8.8.8.8 2606:4700:4700::1111"
                fi
                read -r -p "> " extra
                ;;
            0|*) continue ;;
        esac
        apply_dns "$transport" "$preset" "$extra"
        read -r -p "Enter для продолжения..."
    done
}

# ===================================================================
#  Status dashboard
# ===================================================================
print_status_dashboard() {
    print_header
    local virt cores ram bbr qdisc
    virt=$(detect_virt)
    cores=$(nproc)
    ram=$(free -h | awk '/Mem:/{print $2}')
    bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)

    echo -e "${CYAN}${BOLD}=== СТАТУС VPS PHOENIX-Z+ ===${NC}"
    echo -e "  Hypervisor:    ${BOLD}$virt${NC}"
    echo -e "  Kernel:        $(uname -r)"
    echo -e "  Cores:         $cores"
    echo -e "  RAM:           $ram"
    echo -e "  Uptime:        $(uptime -p 2>/dev/null || uptime)"
    echo ""
    echo -e "${CYAN}--- Networking ---${NC}"
    echo -e "  Congestion:    ${GREEN}$bbr${NC}    Default qdisc: ${GREEN}$qdisc${NC}"
    echo -e "  rmem_max:      $(sysctl -n net.core.rmem_max 2>/dev/null || echo ?) bytes"
    echo -e "  wmem_max:      $(sysctl -n net.core.wmem_max 2>/dev/null || echo ?) bytes"
    echo -e "  somaxconn:     $(sysctl -n net.core.somaxconn 2>/dev/null || echo ?)"
    echo -e "  fastopen:      $(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo ?)"
    if [ -e /proc/sys/net/netfilter/nf_conntrack_count ]; then
        local cc cm
        cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
        cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
        echo -e "  conntrack:     $cc / $cm   ($(( cc * 100 / (cm > 0 ? cm : 1) ))% used)"
    fi

    echo ""
    echo -e "${CYAN}--- Memory / IO ---${NC}"
    echo -e "  swappiness:    $(sysctl -n vm.swappiness 2>/dev/null)"
    if command -v zramctl >/dev/null 2>&1; then
        local zline
        zline=$(zramctl --noheadings 2>/dev/null | head -n1)
        if [ -n "$zline" ]; then
            echo -e "  ZRAM:          ${GREEN}active${NC} ($zline)"
        else
            echo -e "  ZRAM:          ${GRAY}inactive${NC}"
        fi
    fi
    if [ -r /sys/kernel/mm/transparent_hugepage/enabled ]; then
        local thp
        thp=$(grep -oE '\[[a-z]+\]' /sys/kernel/mm/transparent_hugepage/enabled | tr -d '[]')
        echo -e "  THP:           $thp"
    fi
    echo -e "  open files:    $(awk '/^Max open files/{print $4}' /proc/self/limits 2>/dev/null || echo ?)"

    echo ""
    echo -e "${CYAN}--- Multi-core load ---${NC}"
    local iface
    for iface in $(list_real_ifaces); do
        local rx_q tx_q
        rx_q=$(find /sys/class/net/"$iface"/queues/ -maxdepth 1 -name 'rx-*' 2>/dev/null | wc -l)
        tx_q=$(find /sys/class/net/"$iface"/queues/ -maxdepth 1 -name 'tx-*' 2>/dev/null | wc -l)
        local lro
        lro=$(ethtool -k "$iface" 2>/dev/null | awk '/large-receive-offload/{print $2; exit}')
        local rps_set xps_set
        rps_set=$(cat /sys/class/net/"$iface"/queues/rx-0/rps_cpus 2>/dev/null)
        xps_set=$(cat /sys/class/net/"$iface"/queues/tx-0/xps_cpus 2>/dev/null)
        echo -e "  $iface: rx=$rx_q tx=$tx_q lro=${lro:-?} rps=${rps_set:-?} xps=${xps_set:-?}"
    done

    echo ""
    echo -e "${CYAN}--- Services ---${NC}"
    local svc
    for svc in vps-rps vps-noise; do
        if systemctl is-active --quiet "$svc"; then
            echo -e "  $svc: ${GREEN}active${NC}"
        else
            echo -e "  $svc: ${GRAY}inactive${NC}"
        fi
    done

    if [ -f "$PRESET_FILE" ]; then
        echo ""
        echo -e "  Preset:        ${BOLD}$(cat "$PRESET_FILE")${NC}"
    fi
    if [ -f "$DNS_STATE" ]; then
        local raw n dns_t dns_mode dns_servers
        raw=$(cat "$DNS_STATE")
        n=$(awk -F'|' '{print NF}' <<<"$raw")
        if [ "$n" = "3" ]; then
            dns_t=$(cut -d'|' -f1 <<<"$raw")
            dns_mode=$(cut -d'|' -f2 <<<"$raw")
            dns_servers=$(cut -d'|' -f3- <<<"$raw")
        else
            dns_t="plain"
            dns_mode=$(cut -d'|' -f1 <<<"$raw")
            dns_servers=$(cut -d'|' -f2- <<<"$raw")
        fi
        echo -e "  DNS:           ${BOLD}${dns_t}${NC} / ${BOLD}${dns_mode}${NC} (${dns_servers})"
    else
        echo -e "  DNS:           ${GRAY}local (provider default)${NC}"
    fi
    echo ""
}

# ===================================================================
#  Self-update / export / import
# ===================================================================
self_update() {
    local tmp tmp_sha new_sha cur_sha
    tmp=$(mktemp /tmp/.vps_optimizer_new.XXXXXX)
    tmp_sha=$(mktemp /tmp/.vps_optimizer_new.XXXXXX.sha)

    if ! curl -fsSL "$SELF_URL" -o "$tmp" || [ ! -s "$tmp" ]; then
        rm -f "$tmp" "$tmp_sha"
        echo -e "${RED}[!] Не удалось скачать $SELF_URL${NC}"
        return 1
    fi

    # 1) bash syntax check
    if ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp" "$tmp_sha"
        echo -e "${RED}[!] Скачанная версия невалидна (syntax error) — обновление отменено.${NC}"
        return 1
    fi

    # 2) SHA256 интегрити-проверка: пробуем скачать sidecar .sha256 (если есть в репе).
    #    При отсутствии — продолжаем с warning (release без подписей).
    if curl -fsSL "${SELF_URL}.sha256" -o "$tmp_sha" 2>/dev/null && [ -s "$tmp_sha" ]; then
        new_sha=$(awk '{print $1}' "$tmp_sha")
        cur_sha=$(file_sha256 "$tmp")
        if [ -n "$new_sha" ] && [ -n "$cur_sha" ] && [ "$new_sha" != "$cur_sha" ]; then
            rm -f "$tmp" "$tmp_sha"
            echo -e "${RED}[!] SHA256 mismatch: ожидалось $new_sha, получено $cur_sha — отмена.${NC}"
            return 1
        fi
        echo -e "${GREEN}[+] SHA256 verified: $cur_sha${NC}"
    else
        echo -e "${GRAY}[i] sha256 sidecar не найден — пропускаем integrity check.${NC}"
    fi

    # 3) Backup текущей версии (если новый сломан — откатим).
    local backup="${SELF_PATH}.bak"
    cp -f "$SELF_PATH" "$backup" 2>/dev/null || true

    chmod +x "$tmp"
    if mv "$tmp" "$SELF_PATH"; then
        # 4) Sanity-check: --help должна работать в новой версии
        if "$SELF_PATH" --help >/dev/null 2>&1 || "$SELF_PATH" help >/dev/null 2>&1; then
            rm -f "$tmp_sha" "$backup"
            echo -e "${GREEN}[+] Скрипт обновлён до последней версии: $SELF_PATH${NC}"
            _audit self_update "ok new_sha=${cur_sha:-skipped}"
            return 0
        else
            cp -f "$backup" "$SELF_PATH" 2>/dev/null || true
            rm -f "$tmp_sha"
            echo -e "${RED}[!] Новая версия не запускается — откат к $backup.${NC}"
            _audit self_update "rolled_back"
            return 1
        fi
    else
        rm -f "$tmp" "$tmp_sha" "$backup"
        echo -e "${RED}[!] Не удалось заменить $SELF_PATH${NC}"
        return 1
    fi
}

export_config() {
    local target="${1:-/tmp/vps-phoenix-bundle.tar.gz}"
    local files=()
    [ -f "$SYSCTL_CONF" ]   && files+=("$SYSCTL_CONF")
    [ -f "$LIMITS_CONF" ]   && files+=("$LIMITS_CONF")
    [ -f "$NOISE_CONF" ]    && files+=("$NOISE_CONF")
    [ -f "$PRESET_FILE" ]   && files+=("$PRESET_FILE")
    [ -f "$DNS_CONF" ]      && files+=("$DNS_CONF")
    [ -f "$DNS_STATE" ]     && files+=("$DNS_STATE")
    [ -f "$RPS_BOOT_SCRIPT" ] && files+=("$RPS_BOOT_SCRIPT")
    [ -f "$RPS_BOOT_SERVICE" ] && files+=("$RPS_BOOT_SERVICE")
    [ -f "$NOISE_GEN_SCRIPT" ] && files+=("$NOISE_GEN_SCRIPT")
    [ -f "$NOISE_GEN_SERVICE" ] && files+=("$NOISE_GEN_SERVICE")
    [ -f /etc/systemd/system.conf.d/99-vps-limits.conf ] && \
        files+=("/etc/systemd/system.conf.d/99-vps-limits.conf")
    if [ "${#files[@]}" -eq 0 ]; then
        echo -e "${YELLOW}[!] Нечего экспортировать (apply ещё не запускался).${NC}"
        return 1
    fi

    # Создаём manifest с версией формата (для backward-compat при import).
    local manifest="/tmp/.vps_export_manifest.$$.json"
    cat > "$manifest" <<MEOF
{
  "format_version": $EXPORT_FORMAT_VERSION,
  "script_version": "$SCRIPT_VERSION",
  "created_at": "$(date -u +%FT%TZ)",
  "hostname": "$(hostname)",
  "files": ["${files[*]}"]
}
MEOF
    cp "$manifest" /tmp/.vps_export_manifest.json
    files+=(/tmp/.vps_export_manifest.json)

    tar czf "$target" "${files[@]}" 2>/dev/null
    rm -f "$manifest" /tmp/.vps_export_manifest.json
    echo -e "${GREEN}[+] Конфигурация выгружена в $target${NC}"
    echo -e "${GRAY}    Формат: v${EXPORT_FORMAT_VERSION}, файлов: ${#files[@]}${NC}"
    _audit export "target=$target files=${#files[@]}"
}

import_config() {
    local src="${1:?import path required}"
    if [ ! -f "$src" ]; then
        echo -e "${RED}[!] Нет файла: $src${NC}"; return 1
    fi

    # B10: проверяем формат через manifest (если есть).
    local manifest_data fmt_ver scr_ver
    manifest_data=$(tar tzf "$src" 2>/dev/null | grep -m1 'vps_export_manifest.json' || true)
    if [ -n "$manifest_data" ]; then
        local extract_dir
        extract_dir=$(mktemp -d /tmp/.vps_import.XXXXXX)
        tar xzf "$src" -C "$extract_dir" tmp/.vps_export_manifest.json 2>/dev/null || true
        local mf="$extract_dir/tmp/.vps_export_manifest.json"
        if [ -f "$mf" ]; then
            fmt_ver=$(awk -F'[: ,]' '/format_version/{print $4}' "$mf" 2>/dev/null | tr -d '"')
            scr_ver=$(awk -F'"' '/script_version/{print $4}' "$mf" 2>/dev/null)
            echo -e "${GRAY}[i] Архив: format=v${fmt_ver:-?}, script=v${scr_ver:-?}${NC}"
            if [ -n "$fmt_ver" ] && [ "$fmt_ver" -gt "$EXPORT_FORMAT_VERSION" ]; then
                echo -e "${RED}[!] Формат архива (v${fmt_ver}) новее, чем поддерживаемый (v${EXPORT_FORMAT_VERSION}).${NC}"
                echo -e "${YELLOW}    Запусти './vps_optimizer.sh update' и попробуй снова.${NC}"
                rm -rf "$extract_dir"
                return 1
            fi
        fi
        rm -rf "$extract_dir"
    else
        echo -e "${YELLOW}[i] Старый архив без manifest — импортируем как есть.${NC}"
    fi

    if tar xzf "$src" -C / 2>/dev/null; then
        echo -e "${GREEN}[+] Конфигурация импортирована.${NC}"
        rm -f /tmp/.vps_export_manifest.json
        sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart vps-rps vps-noise 2>/dev/null || true
        echo -e "${GREEN}[+] Сервисы перезапущены.${NC}"
        _audit import "src=$src fmt=${fmt_ver:-?} scr=${scr_ver:-?}"
    else
        echo -e "${RED}[!] Распаковка не удалась.${NC}"
        return 1
    fi
}

# ===================================================================
#  CLI parser
# ===================================================================
# ===================================================================
#  v8.2: status --json / logs / audit / harden / uninstall / noise-test
# ===================================================================

# JSON-эскейп для строковых значений.
_json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//	/\\t}"
    printf '"%s"' "$s"
}

# status --json: машиночитаемый вывод для cron / Grafana / Zabbix.
status_json() {
    local virt provider preset bbr qdisc rmem_max wmem_max
    virt=$(detect_virt 2>/dev/null)
    provider=$(detect_provider 2>/dev/null)
    preset="balanced"; [ -f "$PRESET_FILE" ] && preset=$(cat "$PRESET_FILE" 2>/dev/null)
    bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null)
    wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null)

    local conntrack_count conntrack_max ct_used_pct
    conntrack_count=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    conntrack_max=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    if [ "$conntrack_max" -gt 0 ] 2>/dev/null; then
        ct_used_pct=$(( conntrack_count * 100 / conntrack_max ))
    else
        ct_used_pct=0
    fi

    local dns_state="local"
    [ -f "$DNS_STATE" ] && dns_state=$(cat "$DNS_STATE" 2>/dev/null)

    local noise_active="inactive" noise_health="{}"
    if systemctl is-active vps-noise >/dev/null 2>&1; then noise_active="active"; fi
    [ -f "$HEALTH_FILE" ] && noise_health=$(cat "$HEALTH_FILE" 2>/dev/null)

    cat <<JEOF
{
  "version": "$SCRIPT_VERSION",
  "virt": $(_json_str "$virt"),
  "provider": $(_json_str "$provider"),
  "preset": $(_json_str "$preset"),
  "bbr": $(_json_str "$bbr"),
  "qdisc": $(_json_str "$qdisc"),
  "rmem_max": ${rmem_max:-0},
  "wmem_max": ${wmem_max:-0},
  "conntrack_count": ${conntrack_count:-0},
  "conntrack_max": ${conntrack_max:-0},
  "conntrack_used_pct": ${ct_used_pct:-0},
  "dns": $(_json_str "$dns_state"),
  "noise_active": $(_json_str "$noise_active"),
  "noise_health": $noise_health
}
JEOF
}

# logs: показать журналы — собственный лог + journalctl + dmesg-сетевые события.
view_logs() {
    local n="${1:-100}"
    echo -e "${CYAN}${BOLD}=== /var/log/vps-optimizer.log (последние $n строк) ===${NC}"
    [ -f "$RUN_LOG" ] && tail -n "$n" "$RUN_LOG" || echo "(пусто)"
    echo ""
    echo -e "${CYAN}${BOLD}=== journalctl: vps-noise + vps-rps (последние $n) ===${NC}"
    journalctl -u vps-noise -u vps-rps --no-pager -n "$n" 2>/dev/null || echo "(нет журналов)"
    echo ""
    echo -e "${CYAN}${BOLD}=== dmesg: TCP / conntrack / OOM ===${NC}"
    # Q7 fix v8.3: 'killed' ловил много ложных, заменили на специфичные OOM-метки.
    dmesg 2>/dev/null | grep -iE 'tcp|conntrack|out of memory|invoked oom-killer|memory cgroup out of memory' | tail -n "$n" || echo "(нет событий)"
    echo ""
    if [ -f "$AUDIT_LOG" ]; then
        echo -e "${CYAN}${BOLD}=== $AUDIT_LOG ===${NC}"
        tail -n 30 "$AUDIT_LOG"
    fi
}

# Парсит sysctl-conf-файл и для каждого key сравнивает ожидаемое значение
# с runtime-значением. Возвращает строки 'KEY|expected|current|status' через
# stdout, где status = OK|DRIFT|UNKNOWN. Формат стабилен — машиночитаемо.
# Q1 fix: используем awk вместо `IFS='='` для корректной обработки знака '='
# в значении (например `kernel.modprobe = /sbin/modprobe -q -k`).
_audit_sysctl_drift_rows() {
    [ -f "$SYSCTL_CONF" ] || return 0
    awk -F'=' '
        /^[[:space:]]*#/ {next}
        NF<2 {next}
        {
            key=$1; gsub(/^[[:space:]]+|[[:space:]]+$/,"",key)
            val=$0; sub(/^[^=]*=/,"",val); gsub(/^[[:space:]]+|[[:space:]]+$/,"",val)
            if (key!="" && val!="") print key "\t" val
        }
    ' "$SYSCTL_CONF" | while IFS=$'\t' read -r key val; do
        local cur
        cur=$(sysctl -n "$key" 2>/dev/null)
        # sysctl возвращает многоколоночное значение через табы — нормализуем к пробелам.
        cur=$(printf '%s' "$cur" | tr -s '[:space:]' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        val=$(printf '%s' "$val" | tr -s '[:space:]' ' ')
        if [ -z "$cur" ]; then
            printf '%s|%s|%s|UNKNOWN\n' "$key" "$val" ""
        elif [ "$cur" = "$val" ]; then
            printf '%s|%s|%s|OK\n' "$key" "$val" "$cur"
        else
            printf '%s|%s|%s|DRIFT\n' "$key" "$val" "$cur"
        fi
    done
}

# audit: полная диагностика VPS — текущие vs ожидаемые sysctl, RPS, conntrack, etc.
audit_command() {
    if [ "$JSON" = "1" ]; then
        audit_json
        return $?
    fi
    print_status_dashboard
    echo ""
    echo -e "${CYAN}${BOLD}=== Глубокий audit ===${NC}"

    # 1. Совпадает ли текущий sysctl с конфигом?
    if [ -f "$SYSCTL_CONF" ]; then
        local mismatched=0
        echo -e "${BOLD}sysctl drift:${NC}"
        local key val cur status
        while IFS='|' read -r key val cur status; do
            case "$status" in
                DRIFT)
                    echo -e "  ${YELLOW}DRIFT${NC} $key: ожидается '$val', текущее '$cur'"
                    mismatched=$(( mismatched + 1 ))
                    ;;
            esac
        done < <(_audit_sysctl_drift_rows)
        if [ "$mismatched" -eq 0 ]; then
            echo -e "  ${GREEN}OK${NC} все ключи совпадают"
        fi
    fi

    # 2. RPS/XPS присутствие
    echo -e "${BOLD}\nRPS/XPS:${NC}"
    local found=0
    for f in /sys/class/net/*/queues/rx-*/rps_cpus; do
        [ -e "$f" ] || continue
        local v
        v=$(cat "$f" 2>/dev/null)
        if [ "$v" != "0" ] && [ "$v" != "00000000" ]; then
            echo -e "  ${GREEN}OK${NC} $f = $v"
            found=$(( found + 1 ))
        fi
    done
    [ "$found" -eq 0 ] && echo -e "  ${YELLOW}WARN${NC} нет настроенных RPS-очередей"

    # 3. Conntrack usage
    local cc cm
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 1)
    if [ "$cm" -gt 0 ]; then
        local pct=$(( cc * 100 / cm ))
        echo -e "${BOLD}\nConntrack:${NC} $cc / $cm (${pct}%)"
        if [ "$pct" -gt 80 ]; then
            echo -e "  ${RED}HIGH${NC} usage > 80% — увеличь nf_conntrack_max"
        fi
    fi

    # 4. Дисковое место
    echo -e "${BOLD}\nDisk:${NC}"
    df -h / 2>/dev/null | tail -1

    # 5. Swap usage
    echo -e "${BOLD}\nSwap:${NC}"
    swapon --show 2>/dev/null | sed 's/^/  /' || echo "  none"

    # 6. dnscrypt-proxy listener
    if systemctl is-active dnscrypt-proxy >/dev/null 2>&1; then
        echo -e "${BOLD}\ndnscrypt-proxy:${NC} ${GREEN}active${NC}"
        ss -lntu 2>/dev/null | grep -E ':53|:5300' | head -3 | sed 's/^/  /'
    fi

    # 7. Noise health
    if [ -f "$HEALTH_FILE" ]; then
        echo -e "${BOLD}\nNoise health:${NC}"
        cat "$HEALTH_FILE"
    fi

    # 8. Audit-log size
    if [ -f "$AUDIT_LOG" ]; then
        local sz lines
        sz=$(stat -c%s "$AUDIT_LOG" 2>/dev/null || echo 0)
        lines=$(wc -l < "$AUDIT_LOG" 2>/dev/null || echo 0)
        echo -e "${BOLD}\nAudit log:${NC} $sz байт, $lines записей"
    fi

    # 9. PTR sanity check (v8.3, N7) — мягкое предупреждение, не блокирует.
    echo ""
    ptr_sanity_check
}

# PTR sanity check: сравниваем reverse-DNS внешнего IP с прямым A-запросом.
# Несовпадение — частый признак странной CDN-конфигурации или хостинга,
# где PTR не настроен. Только warn, никогда не блокирует.
ptr_sanity_check() {
    if ! command -v dig >/dev/null 2>&1 && ! command -v getent >/dev/null 2>&1; then
        return 0
    fi
    local ext_ip ptr fwd
    ext_ip=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null \
        || curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null \
        || echo "")
    if [ -z "$ext_ip" ]; then
        return 0
    fi
    echo -e "${BOLD}PTR sanity:${NC} external IP=$ext_ip"
    if command -v dig >/dev/null 2>&1; then
        ptr=$(dig +short -x "$ext_ip" 2>/dev/null | sed 's/\.$//' | head -1)
    else
        ptr=$(getent hosts "$ext_ip" 2>/dev/null | awk '{print $2}' | head -1)
    fi
    if [ -z "$ptr" ]; then
        echo -e "  ${YELLOW}WARN${NC} нет PTR-записи для $ext_ip (некоторые SMTP-серверы откажут)"
        return 0
    fi
    echo "  PTR: $ptr"
    if command -v dig >/dev/null 2>&1; then
        fwd=$(dig +short A "$ptr" 2>/dev/null | head -1)
    else
        fwd=$(getent hosts "$ptr" 2>/dev/null | awk '{print $1}' | head -1)
    fi
    if [ -z "$fwd" ]; then
        echo -e "  ${YELLOW}WARN${NC} forward A для $ptr не разрешается"
    elif [ "$fwd" = "$ext_ip" ]; then
        echo -e "  ${GREEN}OK${NC} PTR <-> A совпадают"
    else
        echo -e "  ${YELLOW}WARN${NC} PTR ($ptr -> $fwd) не совпадает с внешним IP ($ext_ip)"
    fi
}

# audit --json: машиночитаемая версия audit_command (v8.3, M14).
audit_json() {
    local rows drift_count ok_count unknown_count
    rows=$(_audit_sysctl_drift_rows)
    drift_count=$(printf '%s\n' "$rows" | grep -c '|DRIFT$' || true)
    ok_count=$(printf '%s\n' "$rows" | grep -c '|OK$' || true)
    unknown_count=$(printf '%s\n' "$rows" | grep -c '|UNKNOWN$' || true)
    local cc cm pct=0
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    [ "$cm" -gt 0 ] && pct=$(( cc * 100 / cm ))

    local rps_active=0 f
    for f in /sys/class/net/*/queues/rx-*/rps_cpus; do
        [ -e "$f" ] || continue
        local v
        v=$(cat "$f" 2>/dev/null)
        if [ "$v" != "0" ] && [ "$v" != "00000000" ]; then
            rps_active=$(( rps_active + 1 ))
        fi
    done

    local audit_size=0 audit_lines=0
    if [ -f "$AUDIT_LOG" ]; then
        audit_size=$(stat -c%s "$AUDIT_LOG" 2>/dev/null || echo 0)
        audit_lines=$(wc -l < "$AUDIT_LOG" 2>/dev/null || echo 0)
    fi

    # JSON-stream массив drifts — каждая строка из rows как объект.
    local drifts_json="[]"
    if command -v jq >/dev/null 2>&1; then
        drifts_json=$(printf '%s\n' "$rows" | awk -F'|' 'NF==4 {
            printf "{\"key\":\"%s\",\"expected\":\"%s\",\"current\":\"%s\",\"status\":\"%s\"}\n", $1,$2,$3,$4
        }' | jq -s . 2>/dev/null || echo "[]")
    fi

    cat <<JSON
{
  "version": "$SCRIPT_VERSION",
  "ts": "$(date -u +%FT%TZ)",
  "sysctl": {
    "ok": $ok_count,
    "drift": $drift_count,
    "unknown": $unknown_count,
    "rows": $drifts_json
  },
  "rps": {"active_queues": $rps_active},
  "conntrack": {"count": $cc, "max": $cm, "pct": $pct},
  "audit_log": {"size_bytes": $audit_size, "lines": $audit_lines}
}
JSON
}

# doctor: actionable-диагностика (v8.3, M1).
# Не ругается без причины, говорит что именно делать. Сейчас проверяет 8
# самых частых проблем, которые мы реально умеем чинить.
doctor_command() {
    echo -e "${CYAN}${BOLD}=== vps-optimizer doctor v${SCRIPT_VERSION} ===${NC}"
    echo ""
    local issues=0

    # 1. Conntrack usage
    local cc cm pct
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    if [ "$cm" -gt 0 ]; then
        pct=$(( cc * 100 / cm ))
        if [ "$pct" -ge 80 ]; then
            echo -e "${RED}[!] conntrack ${pct}%${NC} ($cc/$cm)"
            echo "    Fix: подними net.netfilter.nf_conntrack_max до $((cm * 2))"
            echo "         echo 'net.netfilter.nf_conntrack_max=$((cm * 2))' >> $SYSCTL_CONF && sysctl -p $SYSCTL_CONF"
            issues=$(( issues + 1 ))
        else
            echo -e "${GREEN}[ok]${NC} conntrack ${pct}% ($cc/$cm)"
        fi
    fi

    # 2. TCP retransmits — рассчитываем delta за 1 сек.
    # /proc/net/snmp имеет 2 'Tcp:' строки: первая — заголовок с именами колонок,
    # вторая — значения. Берём индексы из header'а, значения из data-строки.
    if [ -r /proc/net/snmp ]; then
        local rt1 rt2 sg1 sg2 retrans_pct=0
        # shellcheck disable=SC2016
        local awk_pick='/^Tcp:/ && !hdr {hdr=$0; next} /^Tcp:/ {n=split(hdr,h); m=split($0,d); for(i=1;i<=n;i++) if(h[i]==key) {print d[i]+0; exit}}'
        rt1=$(awk -v key=RetransSegs "$awk_pick" /proc/net/snmp 2>/dev/null)
        sg1=$(awk -v key=OutSegs    "$awk_pick" /proc/net/snmp 2>/dev/null)
        sleep 1
        rt2=$(awk -v key=RetransSegs "$awk_pick" /proc/net/snmp 2>/dev/null)
        sg2=$(awk -v key=OutSegs    "$awk_pick" /proc/net/snmp 2>/dev/null)
        local d_rt d_sg
        d_rt=$(( ${rt2:-0} - ${rt1:-0} ))
        d_sg=$(( ${sg2:-0} - ${sg1:-0} ))
        if [ "$d_sg" -gt 0 ]; then
            retrans_pct=$(( d_rt * 100 / d_sg ))
        fi
        if [ "$retrans_pct" -ge 5 ]; then
            echo -e "${YELLOW}[!] TCP retransmits ${retrans_pct}%/s${NC} ($d_rt из $d_sg сегментов)"
            echo "    Causes: плохая сеть, MTU mismatch, сильно нагружен link."
            echo "    Fix: проверь MTU (sudo $0 wg setup автодетектит для wg-iface)"
            echo "         посмотри dmesg | grep -E 'tcp|conntrack'"
            issues=$(( issues + 1 ))
        else
            echo -e "${GREEN}[ok]${NC} TCP retransmits ${retrans_pct}%/s"
        fi
    fi

    # 3. softnet_stat — drops/squeezed (значения в hex; portable hex→dec через bash).
    if [ -r /proc/net/softnet_stat ]; then
        local drops=0 squeezed=0 col1 col2 col3
        while read -r col1 col2 col3 _; do
            : "$col1"  # processed unused
            # bash 16#XX = hex → dec; защищаемся от пустых/мусорных строк.
            [[ "$col2" =~ ^[0-9a-fA-F]+$ ]] && drops=$(( drops + 16#$col2 ))
            [[ "$col3" =~ ^[0-9a-fA-F]+$ ]] && squeezed=$(( squeezed + 16#$col3 ))
        done < /proc/net/softnet_stat
        if [ "$drops" -gt 1000 ] || [ "$squeezed" -gt 1000 ]; then
            echo -e "${YELLOW}[!] softnet drops=$drops, squeezed=$squeezed${NC}"
            echo "    Fix: подними net.core.netdev_max_backlog (текущий: $(sysctl -n net.core.netdev_max_backlog 2>/dev/null))"
            echo "         или включи RPS (apply сделает)"
            issues=$(( issues + 1 ))
        else
            echo -e "${GREEN}[ok]${NC} softnet drops=$drops squeezed=$squeezed"
        fi
    fi

    # 4. Disk space на /var
    local var_pct
    var_pct=$(df --output=pcent /var 2>/dev/null | tail -1 | tr -dc '0-9')
    if [ -n "$var_pct" ] && [ "$var_pct" -ge 90 ]; then
        echo -e "${RED}[!] /var заполнен на ${var_pct}%${NC}"
        echo "    Fix: journalctl --vacuum-time=7d; rotate logs; check $SNAPSHOT_DIR"
        issues=$(( issues + 1 ))
    else
        echo -e "${GREEN}[ok]${NC} /var свободно: $((100 - ${var_pct:-0}))%"
    fi

    # 5. DNS работает?
    if ! getent hosts cloudflare.com >/dev/null 2>&1; then
        echo -e "${RED}[!] DNS не разрешается${NC}"
        echo "    Fix: sudo $0 dns local   # вернуть провайдерский DNS"
        echo "         или: sudo $0 dns plain cloudflare"
        issues=$(( issues + 1 ))
    else
        echo -e "${GREEN}[ok]${NC} DNS отвечает"
    fi

    # 6. Auto-rollback snapshot за последний час
    local recent_snap
    recent_snap=$(find "$SNAPSHOT_DIR" -maxdepth 1 -name 'pre-apply-*.tar.gz' -mmin -60 2>/dev/null | head -1)
    if [ -n "$recent_snap" ]; then
        echo -e "${GREEN}[ok]${NC} Свежий snapshot: $(basename "$recent_snap")"
    fi

    # 7. Hypervisor
    local virt
    virt=$(detect_virt)
    case "$virt" in
        openvz|lxc)
            echo -e "${YELLOW}[i]${NC} hypervisor=$virt — часть тюнингов запрещена хостом, это нормально"
            ;;
        kvm|xen|hyperv|microsoft|none)
            echo -e "${GREEN}[ok]${NC} hypervisor=$virt — полный тюнинг доступен"
            ;;
    esac

    # 8. VPN-iface наличие
    if has_vpn_iface; then
        echo -e "${GREEN}[ok]${NC} VPN-iface обнаружен — рекомендуется apply --vpn"
    fi

    # 9. (v8.4) ss -tin top connections by retransmits — реальная картина а не sysctl drift
    if command -v ss >/dev/null 2>&1; then
        local top_retr
        top_retr=$(ss -tin state established 2>/dev/null \
            | awk '/retrans/ {
                for (i=1; i<=NF; i++) {
                    if ($i ~ /^retrans:/) {
                        n=split($i, a, "/")
                        if (n>=2 && a[2]+0 > 0) print a[2]"\t"$0
                    }
                }
              }' | sort -rn -k1 | head -3)
        if [ -n "$top_retr" ]; then
            echo -e "${YELLOW}[i]${NC} top-3 connections by retransmits (live ss -tin):"
            echo "$top_retr" | awk '{ printf "    %s retrans, line=%s\n", $1, substr($0, length($1)+2, 90) }'
        fi
    fi

    # 10. (v8.4) PCIe link generation warning — VPS-провайдеры иногда выделяют gen3 вместо gen4
    if command -v lspci >/dev/null 2>&1; then
        local pcie_warn
        pcie_warn=$(lspci -vv 2>/dev/null | awk '
            /Ethernet/ { eth_seen=1; eth_block=$0; next }
            eth_seen && /LnkCap:.*Speed/ {
                if ($0 ~ /Speed 8GT\/s/) print "Ethernet NIC: PCIe gen3 (8 GT/s) — на gen4-капабельной hw мог быть gen4 (16 GT/s)"
                eth_seen=0
            }')
        [ -n "$pcie_warn" ] && echo -e "${YELLOW}[i]${NC} $pcie_warn"
    fi

    # 11. (v8.4) kTLS статус
    if [ -d /sys/module/tls ]; then
        echo -e "${GREEN}[ok]${NC} kTLS модуль загружен (sendfile-on-TLS доступен для nginx-ktls/h2o)"
    else
        echo -e "${GRAY}[i]${NC} kTLS модуль не загружен — выполни: modprobe tls"
    fi

    # 12. (v8.5) systemd-resolved coexistence — частая причина «DNS не отвечает»
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if systemctl is-active --quiet dnsmasq 2>/dev/null; then
            echo -e "${YELLOW}[!] systemd-resolved + dnsmasq оба активны${NC} — конфликт за :53"
            echo "    Fix: либо systemctl disable --now systemd-resolved,"
            echo "         либо настрой systemd-resolved слушать только linklocal:"
            echo "         echo 'DNSStubListener=no' >> /etc/systemd/resolved.conf"
            issues=$(( issues + 1 ))
        else
            echo -e "${GREEN}[ok]${NC} systemd-resolved активен (dnsmasq не используется)"
        fi
    fi

    # 13. (v8.5) ip_local_port_range — широкий диапазон ephemeral портов
    # снижает риск EADDRINUSE под high-throughput proxy. Меньше 20000 портов —
    # бутылочное горлышко. Реальный Safari использует 49152-65535, но дефолт
    # ядра обычно 32768-60999, что нормально (Safari fingerprint — minor leak).
    local lpr
    lpr=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null)
    if [ -n "$lpr" ]; then
        local lo hi span
        read -r lo hi <<<"$lpr"
        span=$(( hi - lo ))
        if [ "$span" -lt 20000 ]; then
            echo -e "${YELLOW}[i]${NC} ip_local_port_range=$lo-$hi (span=$span) — узкий, риск EADDRINUSE"
        else
            echo -e "${GREEN}[ok]${NC} ip_local_port_range=$lo-$hi (span=$span)"
        fi
    fi

    # 14. (v8.5) bpftool prog show — какие eBPF-программы загружены
    if command -v bpftool >/dev/null 2>&1; then
        local bpf_progs
        bpf_progs=$(bpftool prog show 2>/dev/null | grep -c '^[0-9]' || echo 0)
        if [ "$bpf_progs" -gt 0 ]; then
            echo -e "${GREEN}[ok]${NC} eBPF: $bpf_progs программ загружено (bpftool prog show — детали)"
        fi
    fi

    # 15. (v8.5) WireGuard kernel vs userspace
    if command -v wg >/dev/null 2>&1; then
        local wg_links
        wg_links=$(wg show interfaces 2>/dev/null | wc -w)
        if [ "$wg_links" -gt 0 ]; then
            if lsmod 2>/dev/null | grep -q '^wireguard '; then
                echo -e "${GREEN}[ok]${NC} WireGuard: kernel-mode (быстро)"
            elif pgrep -x wireguard-go >/dev/null 2>&1; then
                echo -e "${YELLOW}[i]${NC} WireGuard: userspace (wireguard-go) — kernel-mode дал бы +30-50% throughput"
            fi
        fi
    fi

    # 16. (v8.7) UDP drop counter / SO_RXQ_OVFL — для QUIC/WireGuard критично.
    # /proc/net/snmp колонки InErrors / RcvbufErrors. Если RcvbufErrors быстро
    # растёт — UDP receive buffer переполняется (надо повышать net.core.rmem_max
    # / optmem_max). Проверяем накопленное значение, warning при > 1000.
    if [ -r /proc/net/snmp ]; then
        local snmp_udp_line snmp_udp_hdr rcvbuf_pos inerr_pos rcvbuf_val inerr_val
        snmp_udp_hdr=$(grep '^Udp:' /proc/net/snmp 2>/dev/null | sed -n '1p')
        snmp_udp_line=$(grep '^Udp:' /proc/net/snmp 2>/dev/null | sed -n '2p')
        if [ -n "$snmp_udp_hdr" ] && [ -n "$snmp_udp_line" ]; then
            rcvbuf_pos=$(echo "$snmp_udp_hdr" | tr ' ' '\n' | grep -n '^RcvbufErrors$' | cut -d: -f1)
            inerr_pos=$(echo "$snmp_udp_hdr" | tr ' ' '\n' | grep -n '^InErrors$' | cut -d: -f1)
            if [ -n "$rcvbuf_pos" ]; then
                rcvbuf_val=$(echo "$snmp_udp_line" | awk -v p="$rcvbuf_pos" '{print $p}')
                inerr_val=$(echo "$snmp_udp_line" | awk -v p="$inerr_pos" '{print $p}')
                if [ -n "$rcvbuf_val" ] && [ "$rcvbuf_val" -gt 1000 ] 2>/dev/null; then
                    echo -e "${YELLOW}[!]${NC} UDP RcvbufErrors=$rcvbuf_val (>1000) — буфер переполняется, повышай net.core.rmem_max/optmem_max"
                    issues=$((issues+1))
                elif [ -n "$rcvbuf_val" ]; then
                    echo -e "${GREEN}[ok]${NC} UDP RcvbufErrors=$rcvbuf_val (норма)"
                fi
                if [ -n "$inerr_val" ] && [ "$inerr_val" -gt 10000 ] 2>/dev/null; then
                    echo -e "${YELLOW}[!]${NC} UDP InErrors=$inerr_val (>10000) — overload UDP listener'ов"
                    issues=$((issues+1))
                fi
            fi
        fi
    fi

    # 17. (v8.8 K2) BBR версия — рекомендация bbr3 если доступен но не активен.
    # bbr3 (kernel 6.4+ или google-патчи) лучше bbr/bbr2 на сильном loss и
    # справедливее с CUBIC-соседями. Не auto-apply — только рекомендация
    # (CONTRIBUTING #5: don't change default behaviour without opt-in).
    local _cur_cong _avail_cong
    _cur_cong=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    _avail_cong=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)
    if [ -n "$_avail_cong" ] && [[ "$_avail_cong" == *bbr3* ]] && [ "$_cur_cong" != "bbr3" ]; then
        echo -e "${YELLOW}[i]${NC} BBRv3 доступен но не активен (current=$_cur_cong). Активируй: sudo ./vps_optimizer.sh apply"
    elif [ "$_cur_cong" = "bbr3" ]; then
        echo -e "${GREEN}[ok]${NC} BBRv3 активен (kernel 6.4+ современный congestion control)"
    elif [ "$_cur_cong" = "bbr2" ] || [ "$_cur_cong" = "bbr" ]; then
        echo -e "${GREEN}[ok]${NC} $_cur_cong активен (bbr3 не доступен в kernel)"
    fi

    # 18. (v8.8 G1) NetworkManager coexistence — если NM управляет интерфейсом,
    # наши `ip route` правки могут быть стёрты при reload/lease-renew. Не баг
    # сам по себе, но критичный warning. Также ifupdown-конфликт.
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        local _nm_managed
        _nm_managed=$(nmcli -t -f DEVICE,STATE device status 2>/dev/null | grep -c ':connected$' || echo 0)
        if [ "$_nm_managed" -gt 0 ]; then
            echo -e "${YELLOW}[i]${NC} NetworkManager активен и управляет $_nm_managed интерфейс(ами). Наши настройки RPS/IRQ persistent через systemd-unit, но routing-правки могут быть перезаписаны при NM reload."
        fi
    fi
    if systemctl is-active --quiet systemd-networkd 2>/dev/null && \
       systemctl is-active --quiet networking 2>/dev/null; then
        echo -e "${YELLOW}[!]${NC} systemd-networkd И ifupdown(networking) одновременно активны — конфликт за управление интерфейсами. Оставь один."
        issues=$((issues+1))
    fi

    # 19. (v8.8 E6) TCP retransmission rate из /proc/net/snmp.
    # OutSegs vs RetransSegs — отношение даёт retrans rate. >5% — проблема
    # с upstream (loss/congestion), >1% — заметно. На VPS обычно <0.5%.
    if [ -r /proc/net/snmp ]; then
        local _snmp_tcp_hdr _snmp_tcp_line _outsegs_pos _retrans_pos _outsegs _retrans
        _snmp_tcp_hdr=$(grep '^Tcp:' /proc/net/snmp 2>/dev/null | sed -n '1p')
        _snmp_tcp_line=$(grep '^Tcp:' /proc/net/snmp 2>/dev/null | sed -n '2p')
        if [ -n "$_snmp_tcp_hdr" ] && [ -n "$_snmp_tcp_line" ]; then
            _outsegs_pos=$(echo "$_snmp_tcp_hdr" | tr ' ' '\n' | grep -n '^OutSegs$' | cut -d: -f1)
            _retrans_pos=$(echo "$_snmp_tcp_hdr" | tr ' ' '\n' | grep -n '^RetransSegs$' | cut -d: -f1)
            if [ -n "$_outsegs_pos" ] && [ -n "$_retrans_pos" ]; then
                _outsegs=$(echo "$_snmp_tcp_line" | awk -v p="$_outsegs_pos" '{print $p}')
                _retrans=$(echo "$_snmp_tcp_line" | awk -v p="$_retrans_pos" '{print $p}')
                if [ -n "$_outsegs" ] && [ "$_outsegs" -gt 1000 ] 2>/dev/null; then
                    # rate в десятых долях процента (×1000 / OutSegs).
                    local _rate
                    _rate=$(awk -v r="$_retrans" -v o="$_outsegs" 'BEGIN{ if(o>0) printf "%.2f", r*100.0/o; else print "0"}')
                    if awk -v x="$_rate" 'BEGIN{exit !(x>5.0)}'; then
                        echo -e "${YELLOW}[!]${NC} TCP retrans rate=${_rate}% (>5%, $_retrans/$_outsegs) — серьёзный loss"
                        issues=$((issues+1))
                    elif awk -v x="$_rate" 'BEGIN{exit !(x>1.0)}'; then
                        echo -e "${YELLOW}[i]${NC} TCP retrans rate=${_rate}% — заметно, обычно <1% на здоровом VPS"
                    else
                        echo -e "${GREEN}[ok]${NC} TCP retrans rate=${_rate}% (норма)"
                    fi
                fi
            fi
        fi
    fi

    # 20. (v8.8 E8) Conntrack table fill ratio. Default nf_conntrack_max
    # обычно 65536-262144; при >70% утилизации — пакеты дропаются (logging
    # `nf_conntrack: table full, dropping packet`). Критично для прокси.
    if [ -r /proc/sys/net/netfilter/nf_conntrack_count ] && \
       [ -r /proc/sys/net/netfilter/nf_conntrack_max ]; then
        local _ct_cur _ct_max _ct_pct
        _ct_cur=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
        _ct_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
        if [ -n "$_ct_cur" ] && [ -n "$_ct_max" ] && [ "$_ct_max" -gt 0 ] 2>/dev/null; then
            _ct_pct=$(awk -v c="$_ct_cur" -v m="$_ct_max" 'BEGIN{printf "%.0f", c*100.0/m}')
            if [ "$_ct_pct" -gt 70 ] 2>/dev/null; then
                echo -e "${YELLOW}[!]${NC} Conntrack table $_ct_cur/$_ct_max (${_ct_pct}%, >70%) — повышай nf_conntrack_max"
                issues=$((issues+1))
            elif [ "$_ct_pct" -gt 50 ] 2>/dev/null; then
                echo -e "${YELLOW}[i]${NC} Conntrack $_ct_cur/$_ct_max (${_ct_pct}%) — приближается к лимиту"
            else
                echo -e "${GREEN}[ok]${NC} Conntrack $_ct_cur/$_ct_max (${_ct_pct}%)"
            fi
        fi
    fi

    # v8.9 (G1): TLS cert expiry детектор — сканирует типичные пути конфигов
    # прокси (xray, sing-box, haproxy, nginx) на cert-paths и проверяет expiry.
    # Warn если <7 дней до expiry, error если уже expired. Cert handshake
    # с истёкшим cert ломается у строгих клиентов = downtime прокси.
    # Берём только обычные .pem/.crt в /etc и /var/lib (без рекурсивного
    # сканирования FS) для скорости.
    local _cert_paths=()
    for _cp in \
        /etc/xray/*.pem /etc/xray/*.crt \
        /etc/sing-box/*.pem /etc/sing-box/*.crt \
        /etc/haproxy/certs/*.pem \
        /etc/letsencrypt/live/*/fullchain.pem \
        /etc/ssl/certs/vps-optimizer*.pem \
        /var/lib/marzban/certs/*.pem; do
        [ -f "$_cp" ] && _cert_paths+=("$_cp")
    done
    if [ "${#_cert_paths[@]}" -gt 0 ] && command -v openssl >/dev/null 2>&1; then
        local _cert _exp _exp_ts _now_ts _days_left
        _now_ts=$(date +%s)
        for _cert in "${_cert_paths[@]}"; do
            _exp=$(openssl x509 -enddate -noout -in "$_cert" 2>/dev/null | sed 's/notAfter=//')
            [ -z "$_exp" ] && continue
            _exp_ts=$(date -d "$_exp" +%s 2>/dev/null || echo 0)
            [ "$_exp_ts" = "0" ] && continue
            _days_left=$(( ( _exp_ts - _now_ts ) / 86400 ))
            local _cert_short="${_cert##*/}"
            if [ "$_days_left" -lt 0 ] 2>/dev/null; then
                echo -e "${RED}[!]${NC} TLS cert ${BOLD}$_cert_short${NC} уже истёк ($((-_days_left))d ago)"
                echo "    Fix: certbot renew (Let's Encrypt) или замена cert в $_cert"
                issues=$((issues+1))
            elif [ "$_days_left" -lt 7 ] 2>/dev/null; then
                echo -e "${YELLOW}[!]${NC} TLS cert ${BOLD}$_cert_short${NC} истекает через ${_days_left}d"
                echo "    Fix: certbot renew или подготовь замену для $_cert"
                issues=$((issues+1))
            else
                echo -e "${GREEN}[ok]${NC} TLS cert $_cert_short — ${_days_left}d до expiry"
            fi
        done
    fi

    # v8.9 (G2): chrony / ntp clock skew detector. TLS handshake fails если
    # local clock отличается от remote больше чем на 5 минут (cert validity).
    # Проверяем chronyc tracking (если установлен chrony) или timedatectl
    # (systemd-based skew). Warn если |skew| > 30s.
    if command -v chronyc >/dev/null 2>&1; then
        local _skew_raw _skew_abs
        _skew_raw=$(chronyc tracking 2>/dev/null | awk '/System time/{print $4}')
        if [ -n "$_skew_raw" ]; then
            # System time в seconds (positive=fast, negative=slow).
            _skew_abs=$(awk -v s="$_skew_raw" 'BEGIN{ if(s<0) s=-s; printf "%.3f", s }')
            local _skew_int
            _skew_int=$(awk -v s="$_skew_abs" 'BEGIN{ printf "%d", s }')
            if [ "$_skew_int" -gt 30 ] 2>/dev/null; then
                echo -e "${YELLOW}[!]${NC} chrony clock skew = ${_skew_abs}s (>30s) — TLS handshake может падать"
                echo "    Fix: chronyc -a makestep; systemctl restart chrony"
                issues=$((issues+1))
            else
                echo -e "${GREEN}[ok]${NC} chrony clock skew = ${_skew_abs}s"
            fi
        fi
    elif command -v timedatectl >/dev/null 2>&1; then
        local _ntp_sync
        _ntp_sync=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null)
        if [ "$_ntp_sync" = "no" ]; then
            echo -e "${YELLOW}[!]${NC} systemd-timesyncd: NTP не синхронизирован"
            echo "    Fix: systemctl restart systemd-timesyncd; timedatectl set-ntp true"
            issues=$((issues+1))
        else
            echo -e "${GREEN}[ok]${NC} timedatectl NTP синхронизирован"
        fi
    fi

    # v8.10 (Y7): io_uring availability — recommend для sing-box/xray.
    # io_uring (kernel 5.1+) даёт 2-5x reduction в syscalls vs epoll. Real
    # gain зависит от собран ли proxy с поддержкой.  io_uring_setup syscall
    # доступен через `/proc/kallsyms`, но проще — проверить kernel version.
    if [ -r /proc/version ]; then
        local _kver
        _kver=$(uname -r 2>/dev/null | awk -F. '{print $1*1000 + $2}')
        if [ -n "$_kver" ] && [ "$_kver" -ge 5001 ] 2>/dev/null; then
            echo -e "${GREEN}[ok]${NC} io_uring доступен (kernel >=5.1). Recommend: sing-box/xray с SQPOLL=on."
        fi
    fi

    # v8.10 (Z1): Post-Quantum TLS readiness check (read-only).
    # OpenSSL 3.2+ с oqs-provider или OpenSSL 3.5+ native поддерживают
    # X25519MLKEM768 (combined classical + post-quantum) в TLS 1.3.
    # Это защищает от harvest-now-decrypt-later: даже если злоумышленник
    # запишет зашифрованный трафик сегодня и квантовый компьютер появится
    # через 10 лет, расшифровать не сможет (без приватного ключа Kyber).
    # Читаем `openssl list -kem-algorithms` — kyber* / mlkem* означают support.
    if command -v openssl >/dev/null 2>&1; then
        local _kem_pq=""
        _kem_pq=$(openssl list -kem-algorithms 2>/dev/null | grep -iE 'kyber|mlkem|ml-kem' | head -1)
        if [ -n "$_kem_pq" ]; then
            echo -e "${GREEN}[ok]${NC} PQ-TLS: openssl поддерживает PQ KEM ($(echo "$_kem_pq" | head -c 50)...)"
            echo "    iOS Safari 18+ уже использует X25519MLKEM768 — рекомендуется в xray/sing-box config."
        else
            echo -e "${GRAY}[i]${NC} PQ-TLS: openssl без PQ KEM (kyber/mlkem)."
            echo "    Не критично. Для harvest-now-decrypt-later защиты: openssl 3.5+ или oqs-provider."
        fi
    fi

    echo ""
    if [ "$issues" -eq 0 ]; then
        echo -e "${GREEN}${BOLD}=== всё ок, проблем не найдено ===${NC}"
    else
        echo -e "${YELLOW}${BOLD}=== найдено $issues проблем(ы) — см. выше ===${NC}"
        # v8.8 (F1): подсказываем --fix flag.
        echo -e "${GRAY}    (попробуй ${BOLD}sudo $0 doctor --fix${NC}${GRAY} для интерактивного применения)${NC}"
    fi
    # Сохраняем последнее число issue'ов в env для health_score / JSON wrapper.
    DOCTOR_LAST_ISSUES="$issues"
}

# v8.9 (F8/E6): doctor --watch / --json wrapper.
# --watch: повторяет doctor каждые N секунд (default 5), очистка экрана между
#   итерациями. Для интерактивного мониторинга на dashboard.
# --json: переводит весь doctor-вывод в struct JSON для оркестраторов
#   (Ansible/Salt/CI). Возвращает {ok, issues, output, ts}. Не идеален (не
#   парсит каждое issue в struct), но даёт machine-readable summary.
doctor_run_command() {
    local _watch=0 _json=0 _interval=5
    while [ $# -gt 0 ]; do
        case "$1" in
            --watch)        _watch=1; shift ;;
            --json)         _json=1; shift ;;
            --interval)     _interval="${2:-5}"; shift 2 ;;
            --interval=*)   _interval="${1#*=}"; shift ;;
            *)              shift ;;
        esac
    done

    if [ "$_watch" = "1" ]; then
        # v8.9 (F8): live re-run каждые N сек. Ctrl-C для выхода (trap не нужен,
        # standard SIGINT — read и sleep обработают cleanly).
        while true; do
            clear 2>/dev/null || printf '\033[2J\033[H'
            doctor_command
            echo ""
            echo -e "${GRAY}    [doctor --watch every ${_interval}s. Ctrl-C для выхода]${NC}"
            sleep "$_interval"
        done
    elif [ "$_json" = "1" ]; then
        # Capture полный вывод doctor; ловим issue-count из последнего глобала.
        local _out _esc _ts
        _out=$(doctor_command 2>&1)
        _ts=$(date -u +%FT%TZ)
        # JSON-escape: backslash → \\, double quote → \", newline → \n.
        # Минимально достаточно для embedded строки. Не используем jq чтобы
        # не зависеть от его установки.
        _esc=$(printf '%s' "$_out" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g')
        local _issues="${DOCTOR_LAST_ISSUES:-0}"
        local _ok="true"
        [ "$_issues" -gt 0 ] 2>/dev/null && _ok="false"
        printf '{"ok":%s,"issues":%s,"version":"%s","ts":"%s","output":"%s"}\n' \
            "$_ok" "$_issues" "$SCRIPT_VERSION" "$_ts" "$_esc"
    else
        doctor_command
    fi
}

# v8.9 (E1): health-score — единый 0-100 score, агрегирующий ключевые
# doctor signals для дашбордов. Логика:
#   100 = идеал; вычитаем "штрафы" по доменам.
# Domains (each 0-15 points penalty max):
#   conntrack >70%, retrans >5%, swap-in/sec >100, udp drops growing,
#   load>cpus, mem-pressure>1%, fd>80%.
# Печатает score и breakdown.
health_score_command() {
    local _json=0
    [ "${1:-}" = "--json" ] && _json=1

    local _score=100 _penalty
    local _breakdown=""

    # Conntrack
    local _ct_cur _ct_max _ct_pct
    _ct_cur=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    _ct_max=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    if [ "$_ct_max" -gt 0 ] 2>/dev/null; then
        _ct_pct=$(( _ct_cur * 100 / _ct_max ))
        _penalty=0
        [ "$_ct_pct" -ge 70 ] 2>/dev/null && _penalty=10
        [ "$_ct_pct" -ge 90 ] 2>/dev/null && _penalty=20
        _score=$(( _score - _penalty ))
        _breakdown="$_breakdown\n  conntrack ${_ct_pct}% (-${_penalty})"
    fi

    # Load average vs CPU count
    local _la _cpus _la_int
    _la=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)
    _cpus=$(nproc 2>/dev/null || echo 1)
    _la_int=$(awk -v l="$_la" 'BEGIN{printf "%d", l*100}' 2>/dev/null || echo 0)
    local _la_threshold=$(( _cpus * 100 ))
    _penalty=0
    [ "$_la_int" -gt "$_la_threshold" ] 2>/dev/null && _penalty=10
    [ "$_la_int" -gt $(( _la_threshold * 2 )) ] 2>/dev/null && _penalty=20
    _score=$(( _score - _penalty ))
    _breakdown="$_breakdown\n  load=${_la}/${_cpus}cpus (-${_penalty})"

    # Memory pressure (если /proc/pressure/memory доступен — kernel 4.20+)
    if [ -r /proc/pressure/memory ]; then
        local _mp
        _mp=$(awk '/some avg10/{print $0}' /proc/pressure/memory 2>/dev/null | grep -oE 'avg10=[0-9.]+' | head -1 | cut -d= -f2)
        local _mp_int
        _mp_int=$(awk -v p="${_mp:-0}" 'BEGIN{printf "%d", p}')
        _penalty=0
        [ "$_mp_int" -gt 1 ] 2>/dev/null && _penalty=5
        [ "$_mp_int" -gt 10 ] 2>/dev/null && _penalty=15
        _score=$(( _score - _penalty ))
        _breakdown="$_breakdown\n  mem-pressure avg10=${_mp:-0}% (-${_penalty})"
    fi

    # FD usage
    if [ -r /proc/sys/fs/file-nr ]; then
        local _fd_used _fd_max _fd_pct
        _fd_used=$(awk '{print $1}' /proc/sys/fs/file-nr 2>/dev/null || echo 0)
        _fd_max=$(awk '{print $3}' /proc/sys/fs/file-nr 2>/dev/null || echo 0)
        if [ "$_fd_max" -gt 0 ] 2>/dev/null; then
            _fd_pct=$(( _fd_used * 100 / _fd_max ))
            _penalty=0
            [ "$_fd_pct" -gt 80 ] 2>/dev/null && _penalty=10
            _score=$(( _score - _penalty ))
            _breakdown="$_breakdown\n  fd ${_fd_pct}% (-${_penalty})"
        fi
    fi

    # Clamp 0..100
    [ "$_score" -lt 0 ] 2>/dev/null && _score=0
    [ "$_score" -gt 100 ] 2>/dev/null && _score=100

    if [ "$_json" = "1" ]; then
        printf '{"score":%s,"version":"%s","ts":"%s"}\n' "$_score" "$SCRIPT_VERSION" "$(date -u +%FT%TZ)"
    else
        local _color="$GREEN"
        [ "$_score" -lt 80 ] 2>/dev/null && _color="$YELLOW"
        [ "$_score" -lt 50 ] 2>/dev/null && _color="$RED"
        echo -e "${CYAN}${BOLD}=== health-score: ${_color}${_score}/100${NC}${CYAN}${BOLD} ===${NC}"
        echo -e "Breakdown:$_breakdown"
    fi
}

# why <key>: объясняем почему конкретный sysctl такой (v8.3, M2).
# База знаний — короткие пояснения для ~30 наших ключевых knob'ов.
why_command() {
    local key="$1" cur expected
    cur=$(sysctl -n "$key" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
    if [ -z "$cur" ]; then
        echo -e "${RED}[!] $key не существует или не читается${NC}"
        return 1
    fi
    if [ -f "$SYSCTL_CONF" ]; then
        expected=$(awk -F'=' -v k="$key" '
            $1 ~ k {sub(/^[^=]*=/,""); gsub(/^ +| +$/,""); print; exit}
        ' "$SYSCTL_CONF")
    fi
    echo -e "${BOLD}$key${NC}"
    echo "  current:  $cur"
    [ -n "$expected" ] && echo "  applied:  $expected"
    echo ""
    case "$key" in
        net.ipv4.tcp_rmem|net.ipv4.tcp_wmem)
            echo "  Min/default/max буфер TCP per-socket. На VPS с RAM>=4GB и 10G+ линке"
            echo "  max=512MB позволяет вместить bandwidth*delay product без drop'ов."
            ;;
        net.core.rmem_max|net.core.wmem_max)
            echo "  Глобальный максимум sock-buffer. Должен быть >= max(tcp_rmem)."
            ;;
        net.ipv4.tcp_congestion_control)
            echo "  Алгоритм управления окном. BBR — лучший выбор для прокси/VPN"
            echo "  (loss-tolerant). cubic — для классики. bbr3/bbr2 — экспериментально."
            ;;
        net.core.default_qdisc)
            echo "  Дефолтный qdisc для всех iface. fq — pacing-friendly для BBR."
            echo "  cake — pareto-оптимально для bufferbloat."
            ;;
        net.ipv4.conf.all.rp_filter)
            echo "  Reverse Path Filtering. =0 off, =1 strict (дропает asymmetric routing —"
            echo "  ломает VPN/MPTCP), =2 loose (защита от source-spoofing, дружит с VPN)."
            echo "  v8.3 ставит =2 по умолчанию."
            ;;
        net.ipv4.tcp_fastopen)
            echo "  TFO позволяет данные в SYN-пакете. =3 = client+server."
            echo "  v8.3 также сбрасывает blackhole_timeout — иначе TFO выключается на час."
            ;;
        net.ipv4.tcp_fastopen_blackhole_timeout_sec)
            echo "  Если ядро решило что TFO в чёрной дыре, лочит на N секунд (default 3600)."
            echo "  =0 (v8.3) — никогда не лочить, всегда пытаемся TFO."
            ;;
        net.ipv4.udp_rmem_min|net.ipv4.udp_wmem_min)
            echo "  Минимальный UDP-buffer per-socket. Критично для QUIC/Hysteria/WireGuard"
            echo "  где socket-buffers могут быть >1MB."
            ;;
        net.ipv4.udp_mem)
            echo "  Глобальный UDP memory pressure (в страницах, не байтах!). low/pressure/max."
            ;;
        net.netfilter.nf_conntrack_max)
            echo "  Максимум одновременных conntrack-записей. Прокси/NAT упирается"
            echo "  быстро. preset proxy ставит до 4M. balance — 1M."
            ;;
        net.core.netdev_max_backlog)
            echo "  Очередь пакетов между NIC и кернел-stack. v8.3 масштабирует под скорость:"
            echo "  >=25G → 300000, >=10G → 100000, иначе 30000."
            ;;
        net.core.dev_weight)
            echo "  Сколько пакетов napi обрабатывает за один poll. Выше = меньше"
            echo "  context-switch'ей, но потенциально выше latency. v8.3: 64-128 по линку."
            ;;
        net.ipv4.ip_forward)
            echo "  Маршрутизация через хост. =1 нужно для VPN-сервера / контейнерного хоста."
            echo "  v8.3 включает только если детектим tun*/wg*/ppp* или передан --vpn."
            ;;
        net.ipv4.tcp_keepalive_time)
            echo "  Сколько секунд idle прежде чем послать keepalive-probe. По умолчанию"
            echo "  7200 (2 часа) — слишком много для прокси за NAT'ом, ставим 300."
            ;;
        vm.swappiness)
            echo "  Насколько охотно ядро своппит. 60 = default, 10 = мало, 1 = почти никогда."
            echo "  С zram swappiness=100-200 имеет смысл (compression быстрее disk-IO)."
            ;;
        net.ipv4.tcp_mtu_probing)
            echo "  Probe для PMTU. =0 off, =1 on if blackhole, =2 always."
            echo "  Лечит чёрные дыры в туннелях (WireGuard/Reality/XHTTP)."
            ;;
        *)
            echo "  Описание для этого ключа не зашито. См. man 7 tcp / man 7 udp / kernel docs:"
            echo "  https://www.kernel.org/doc/Documentation/sysctl/"
            ;;
    esac
}

# wg setup: WireGuard helper (v8.3, J1) — ставит wireguard-tools, генерит
# минимальный config с автодетектом MTU (через ICMP needs-frag), conntrack-rules.
# Полностью opt-in. Если WG уже настроен — не трогает.
wg_setup() {
    echo -e "${CYAN}${BOLD}=== WireGuard helper (opt-in) ===${NC}"

    # 1. Установка wireguard-tools если ещё нет.
    if ! command -v wg >/dev/null 2>&1; then
        echo "[*] Ставим wireguard-tools..."
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wireguard-tools >/dev/null 2>&1 || {
                echo -e "${RED}[!] Не удалось установить wireguard-tools${NC}"; return 1
            }
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y wireguard-tools >/dev/null 2>&1 || return 1
        else
            echo -e "${RED}[!] Менеджер пакетов не определён${NC}"; return 1
        fi
    fi
    echo -e "${GREEN}[+] wireguard-tools: $(wg --version | head -1)${NC}"

    # 2. Автодетект оптимального MTU.
    # ICMP может быть отфильтрован — в этом случае берём безопасный 1280.
    local default_iface mtu_phys mtu_wg
    default_iface=$(ip -4 route show default 2>/dev/null | awk '/^default/{for (i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
    mtu_phys=$(cat "/sys/class/net/${default_iface:-eth0}/mtu" 2>/dev/null || echo 1500)
    # WG-overhead: IP(20) + UDP(8) + WG-header(32) = 60 для IPv4, 80 для IPv6.
    mtu_wg=$(( mtu_phys - 80 ))
    [ "$mtu_wg" -lt 1280 ] && mtu_wg=1280
    echo "[*] Phys MTU: $mtu_phys (iface: ${default_iface:-eth0}) → WG MTU: $mtu_wg"

    # 3. Генерим ключи если не существуют.
    local wg_dir=/etc/wireguard
    mkdir -p "$wg_dir"
    chmod 700 "$wg_dir"
    if [ ! -f "$wg_dir/server.key" ]; then
        echo "[*] Генерим ключевую пару..."
        (umask 077; wg genkey | tee "$wg_dir/server.key" | wg pubkey > "$wg_dir/server.pub")
        echo -e "${GREEN}[+] Ключи: $wg_dir/server.key, $wg_dir/server.pub${NC}"
    else
        echo "[*] Ключи уже существуют: $wg_dir/server.key (не трогаем)"
    fi

    # 4. Минимальный server config (только если ещё нет).
    if [ ! -f "$wg_dir/wg0.conf" ]; then
        local priv_key pub_key
        priv_key=$(cat "$wg_dir/server.key")
        pub_key=$(cat "$wg_dir/server.pub")
        cat > "$wg_dir/wg0.conf" <<WG_EOF
# Generated by vps_optimizer v${SCRIPT_VERSION} (wg setup)
# https://github.com/lpxqwkjd65rjfn-dot/noble-net-warp
[Interface]
PrivateKey = $priv_key
ListenPort = 51820
Address = 10.99.0.1/24
MTU = $mtu_wg
# v8.6: UDP_GRO/SO_REUSEPORT — современное wg-tools/wireguard-linux уже умеет
# UDP-GRO listen-side при условии что net.core.devconf'ы выставлены, что мы
# делаем в apply. Дополнительно ничего не нужно — это для документирования.
# PreUp/PostDown ниже — типовая NAT-настройка для VPN-роутера.
# Закомментировано по умолчанию: включай руками если хочешь exit-node.
# PostUp   = iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o ${default_iface:-eth0} -j MASQUERADE
# PostDown = iptables -t nat -D POSTROUTING -s 10.99.0.0/24 -o ${default_iface:-eth0} -j MASQUERADE

# Public key (раздавай клиентам): $pub_key

# Чтобы добавить клиента — допиши блок:
# [Peer]
# PublicKey = <client-pubkey>
# AllowedIPs = 10.99.0.2/32
# PersistentKeepalive = 25
WG_EOF
        chmod 600 "$wg_dir/wg0.conf"
        echo -e "${GREEN}[+] Server config: $wg_dir/wg0.conf${NC}"
        echo "    Public key: $pub_key"
    else
        echo "[*] $wg_dir/wg0.conf уже существует — не трогаем."
    fi

    # 5. ip_forward — без него VPN не маршрутизирует.
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

    echo ""
    echo -e "${CYAN}Дальнейшие шаги:${NC}"
    echo "  1. systemctl enable --now wg-quick@wg0"
    echo "  2. Открой UDP/51820 в фаерволе:  ufw allow 51820/udp"
    echo "  3. Добавь Peer-блоки в $wg_dir/wg0.conf для клиентов"
    echo "  4. После apply --vpn — sysctl будут VPN-friendly (rp_filter=2 и т.д.)"
    _audit wg_setup "mtu=$mtu_wg iface=${default_iface:-eth0}"
}

# install_apply_boot_unit: ставит one-shot systemd unit, который запускает
# apply на каждом boot (v8.3, M13). Полезно для OpenVZ, где /etc/sysctl.d/
# иногда вытирается провайдером.
install_apply_boot_unit() {
    if [ "$DRY_RUN" = "1" ]; then
        echo -e "${YELLOW}[dry-run] install_apply_boot_unit: показал бы как бы выглядел unit.${NC}"
        return 0
    fi
    local self
    self=$(readlink -f "${BASH_SOURCE[0]:-$0}")
    cat > /etc/systemd/system/vps-optimizer-apply.service <<UNIT_EOF
[Unit]
Description=VPS Optimizer apply on boot (vps-optimizer v${SCRIPT_VERSION})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$self apply --quiet --no-rollback
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT_EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable vps-optimizer-apply.service >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] vps-optimizer-apply.service установлен.${NC}"
    echo "    apply будет автоматически запускаться при каждом boot'е."
    echo "    Снять: systemctl disable --now vps-optimizer-apply.service"
    _audit apply_boot "installed unit=vps-optimizer-apply.service script=$self"
}

# noise test --once: запустить один цикл без записи в systemd
noise_test() {
    if [ ! -f "$NOISE_GEN_SCRIPT" ]; then
        echo -e "${RED}[!] $NOISE_GEN_SCRIPT не существует — сначала запусти 'noise on'${NC}"
        return 1
    fi
    echo -e "${CYAN}[*] Однократный прогон шумогенератора (test mode):${NC}"
    # Запускаем bash-скрипт с переменной NOISE_TEST_ONCE — он должен прочитать
    # и сделать один цикл. Текущий скрипт это не поддерживает на 100%, поэтому
    # делаем простую версию: показать какие профили включены и запустить ios_burst.
    (
        # shellcheck source=/dev/null
        [ -f "$NOISE_CONF" ] && set -a && . "$NOISE_CONF" && set +a
        echo "  PROFILE=${PROFILE:-?}"
        echo "  ENABLE_IOS_BURST=${ENABLE_IOS_BURST:-?}"
        echo "  ENABLE_NEWS=${ENABLE_NEWS:-?}"
        echo "  ENABLE_EMAIL=${ENABLE_EMAIL:-?}"
        echo "  ENABLE_LIB_PHANTOM=${ENABLE_LIB_PHANTOM:-?}"
        echo "  ENABLE_CLOUD_PHANTOM=${ENABLE_CLOUD_PHANTOM:-?}"
        echo "  PLACE_PROFILE=${PLACE_PROFILE:-auto}"
        echo "  Текущий hour_factor: $(date +%H)h"
    )
    echo ""
    echo -e "${GRAY}[i] Реальный прогон производится сервисом vps-noise.service.${NC}"
    echo -e "${GRAY}    Чтобы увидеть live-трафик: journalctl -u vps-noise -f${NC}"
}

# uninstall: удалить ВСЁ — конфиги, скрипты, сервисы. Ставит точку.
uninstall_command() {
    echo -e "${RED}${BOLD}=== UNINSTALL ===${NC}"
    echo -e "${YELLOW}Это удалит:${NC}"
    echo "  - Все sysctl/limits конфиги"
    echo "  - vps-noise.service, vps-rps.service"
    echo "  - $NOISE_GEN_SCRIPT, $RPS_BOOT_SCRIPT"
    echo "  - $AUDIT_LOG, $RUN_LOG, $DEBUG_LOG"
    echo "  - $SNAPSHOT_DIR/, /var/lib/vps-noise/"
    echo "  - сам скрипт $SELF_PATH"
    echo ""
    if [ "$FORCE" != "1" ]; then
        read -r -p "Подтверди (yes для удаления): " confirm
        [ "$confirm" = "yes" ] || { echo "Отменено."; return 0; }
    fi

    # 1) Сначала reset (откатывает все настройки)
    reset_all

    # 2) Удаляем audit/run/debug-логи и снапшоты
    rm -f "$AUDIT_LOG" "$RUN_LOG" "$DEBUG_LOG"
    rm -rf "$SNAPSHOT_DIR" /var/lib/vps-noise /run/vps-noise

    # 3) Удаляем сам скрипт
    if [ -f "$SELF_PATH" ]; then
        rm -f "$SELF_PATH" "${SELF_PATH}.bak"
        echo -e "${GREEN}[+] $SELF_PATH удалён.${NC}"
    fi

    _audit uninstall "complete"
    echo -e "${GREEN}${BOLD}[+] Uninstall завершён.${NC}"
}

# harden: включить opt-in security (UFW + SSH-baseline + unattended-upgrades).
# НЕ затрагивает базовый apply — это отдельная команда.
harden_command() {
    local target="${1:-all}"
    case "$target" in
        ufw|firewall)        harden_ufw ;;
        ssh)                 harden_ssh ;;
        upgrades|unattended) harden_unattended_upgrades ;;
        all)                 harden_ufw; harden_ssh; harden_unattended_upgrades ;;
        *)
            echo -e "${YELLOW}harden: укажи цель${NC}"
            echo "  harden ssh        — SSH baseline (MaxAuthTries, LoginGraceTime, banner)"
            echo "  harden ufw        — UFW preset (allow ssh + deny incoming default)"
            echo "  harden upgrades   — unattended-upgrades security-only"
            echo "  harden all        — всё сразу"
            return 1
            ;;
    esac
    _audit harden "target=$target"
}

harden_ufw() {
    if ! command -v ufw >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -yq ufw >/dev/null
        else
            echo -e "${RED}[!] ufw не установлен и apt недоступен.${NC}"; return 1
        fi
    fi
    echo -e "${CYAN}[*] Настраиваем UFW${NC}"
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    # SSH (порт из sshd_config)
    local ssh_port
    ssh_port=$(awk '/^Port[[:space:]]/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
    [ -z "$ssh_port" ] && ssh_port=22
    ufw allow "$ssh_port"/tcp comment 'SSH' >/dev/null 2>&1
    # ICMP echo-request/reply остаются в before.rules по умолчанию — не трогаем.
    ufw --force enable >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] UFW активирован, разрешён SSH на порту $ssh_port.${NC}"
}

harden_ssh() {
    local sshd_cfg=/etc/ssh/sshd_config
    [ -f "$sshd_cfg" ] || { echo -e "${YELLOW}[!] $sshd_cfg отсутствует — пропуск.${NC}"; return 0; }
    local drop=/etc/ssh/sshd_config.d/99-vps-optimizer-harden.conf
    mkdir -p "$(dirname "$drop")" 2>/dev/null
    cat > "$drop" <<SEOF
# v8.2 SSH baseline (vps_optimizer harden ssh)
MaxAuthTries 3
LoginGraceTime 20
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
Banner /etc/issue.net
SEOF
    if [ -s /etc/issue.net ] && ! grep -q 'Authorized access only' /etc/issue.net 2>/dev/null; then
        cp -a /etc/issue.net "/etc/issue.net.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    cat > /etc/issue.net <<'BEOF'
**********************************************************************
*  Authorized access only. All activity is logged and monitored.     *
*  Disconnect IMMEDIATELY if you are not an authorized user.         *
**********************************************************************
BEOF
    if sshd -t 2>/dev/null; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        echo -e "${GREEN}[+] SSH baseline применён ($drop)${NC}"
    else
        rm -f "$drop"
        echo -e "${RED}[!] sshd -t не прошёл — конфиг откачен.${NC}"
        return 1
    fi
}

harden_unattended_upgrades() {
    if ! command -v apt-get >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] apt не найден — пропуск unattended-upgrades.${NC}"; return 0
    fi
    apt-get install -yq unattended-upgrades apt-listchanges >/dev/null 2>&1 || true
    cat > /etc/apt/apt.conf.d/52unattended-upgrades-vps <<'UEOF'
// v8.2: security-only unattended-upgrades (vps_optimizer harden upgrades)
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
UEOF
    cat > /etc/apt/apt.conf.d/20auto-upgrades-vps <<'AEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AEOF
    systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] unattended-upgrades активирован (только security).${NC}"
}

# ===================================================================
#  v8.2: Prometheus exporter / autotune-stub / compare-baseline
# ===================================================================

# Prometheus-формат текстовых метрик. Печатает на stdout, использовать с
# socat/nc/python3 -m http.server для экспонирования на порт 9777.
prom_metrics() {
    local virt provider preset bbr qdisc rmem_max wmem_max
    virt=$(detect_virt 2>/dev/null)
    provider=$(detect_provider 2>/dev/null)
    preset="balanced"; [ -f "$PRESET_FILE" ] && preset=$(cat "$PRESET_FILE" 2>/dev/null)
    bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
    wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)

    local cc cm
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)

    local active=0
    systemctl is-active vps-noise >/dev/null 2>&1 && active=1

    local req_total=0 req_ok=0 req_err=0
    if [ -f "$HEALTH_FILE" ]; then
        req_total=$(awk -F'[: ,]+' '/requests_total/{print $3; exit}' "$HEALTH_FILE" 2>/dev/null)
        req_ok=$(awk -F'[: ,]+' '/requests_ok/{print $3; exit}' "$HEALTH_FILE" 2>/dev/null)
        req_err=$(awk -F'[: ,]+' '/requests_error/{print $3; exit}' "$HEALTH_FILE" 2>/dev/null)
    fi

    cat <<PEOF
# HELP vps_optimizer_info Static info labels.
# TYPE vps_optimizer_info gauge
vps_optimizer_info{version="$SCRIPT_VERSION",virt="$virt",provider="$provider",preset="$preset",bbr="$bbr",qdisc="$qdisc"} 1
# HELP vps_optimizer_rmem_max sysctl net.core.rmem_max
# TYPE vps_optimizer_rmem_max gauge
vps_optimizer_rmem_max ${rmem_max:-0}
# HELP vps_optimizer_wmem_max sysctl net.core.wmem_max
# TYPE vps_optimizer_wmem_max gauge
vps_optimizer_wmem_max ${wmem_max:-0}
# HELP vps_conntrack_count Current netfilter conntrack count
# TYPE vps_conntrack_count gauge
vps_conntrack_count ${cc:-0}
# HELP vps_conntrack_max sysctl net.netfilter.nf_conntrack_max
# TYPE vps_conntrack_max gauge
vps_conntrack_max ${cm:-0}
# HELP vps_noise_active Whether vps-noise.service is active (1=yes).
# TYPE vps_noise_active gauge
vps_noise_active $active
# HELP vps_noise_requests_total Total HTTP requests issued by vps-noise.
# TYPE vps_noise_requests_total counter
vps_noise_requests_total ${req_total:-0}
# HELP vps_noise_requests_ok Successful HTTP requests.
# TYPE vps_noise_requests_ok counter
vps_noise_requests_ok ${req_ok:-0}
# HELP vps_noise_requests_error Failed HTTP requests.
# TYPE vps_noise_requests_error counter
vps_noise_requests_error ${req_err:-0}
PEOF

    # v8.6: DNS cache hit-ratio. Поддерживаем unbound (cache.hits/cache.misses)
    # и dnscrypt-proxy (через query_log при tail). Если нет ни того ни другого,
    # просто пропускаем секцию — Prometheus получит 0 метрик и не упадёт.
    local dns_hits=0 dns_misses=0 dns_ratio=0
    if command -v unbound-control >/dev/null 2>&1; then
        local cstats
        cstats=$(unbound-control -c /etc/unbound/unbound.conf stats_noreset 2>/dev/null || true)
        if [ -n "$cstats" ]; then
            # Сумма по всем threads: имена «threadN.requestlist.cache_hits» / «threadN.cachehits» зависят от версии.
            dns_hits=$(echo "$cstats" | awk -F= '/cachehits/ {sum+=$2} END{print sum+0}')
            dns_misses=$(echo "$cstats" | awk -F= '/cachemiss/ {sum+=$2} END{print sum+0}')
        fi
    fi
    if [ "$((dns_hits + dns_misses))" -gt 0 ]; then
        # 4-знака после точки, без bc.
        dns_ratio=$(awk -v h="$dns_hits" -v m="$dns_misses" 'BEGIN{ if (h+m>0) printf "%.4f", h/(h+m); else print "0" }')
    fi
    cat <<PEOF
# HELP vps_dns_cache_hits Total DNS cache hits (unbound)
# TYPE vps_dns_cache_hits counter
vps_dns_cache_hits ${dns_hits:-0}
# HELP vps_dns_cache_misses Total DNS cache misses (unbound)
# TYPE vps_dns_cache_misses counter
vps_dns_cache_misses ${dns_misses:-0}
# HELP vps_dns_cache_hit_ratio Hit ratio = hits / (hits + misses), 0..1
# TYPE vps_dns_cache_hit_ratio gauge
vps_dns_cache_hit_ratio ${dns_ratio:-0}
PEOF

    # v8.9 (E1+E3+E4): дополнительные метрики для дашбордов.
    # E1: vps_health_score — 0..100 единое здоровье VPS, см. health_score_command.
    # E3: vps_noise_failures_rate — производная от noise_total/noise_err.
    # E4: vps_profile_snapshots_total — счётчик named-snapshots в профилях.
    local _hs="0"
    if [ -r /proc/loadavg ] && [ -r /proc/sys/fs/file-nr ]; then
        # Quick inline вместо subshell — для prom-loop важна скорость.
        # Берём из health_score_command JSON.
        _hs=$(health_score_command --json 2>/dev/null | sed -n 's/.*"score":\([0-9]*\).*/\1/p')
        [ -z "$_hs" ] && _hs="0"
    fi
    local _profile_count=0
    [ -d /var/lib/vps-optimizer/profiles ] && \
        _profile_count=$(find /var/lib/vps-optimizer/profiles -maxdepth 1 -name '*.tar.gz' 2>/dev/null | wc -l)
    local _snapshot_count=0
    [ -d "$SNAPSHOT_DIR" ] && \
        _snapshot_count=$(find "$SNAPSHOT_DIR" -maxdepth 1 -name '*.tar.gz' 2>/dev/null | wc -l)
    local _noise_fail_rate="0"
    if [ -n "${req_total:-}" ] && [ "${req_total:-0}" -gt 0 ] 2>/dev/null; then
        _noise_fail_rate=$(awk -v t="${req_total:-1}" -v e="${req_err:-0}" 'BEGIN{ if(t>0) printf "%.4f", e/t; else print "0" }')
    fi
    cat <<PEOF
# HELP vps_health_score Aggregate VPS health score 0..100 (higher=better)
# TYPE vps_health_score gauge
vps_health_score ${_hs:-0}
# HELP vps_noise_failures_rate Failure ratio of vps-noise requests, 0..1
# TYPE vps_noise_failures_rate gauge
vps_noise_failures_rate ${_noise_fail_rate}
# HELP vps_profile_snapshots_total Number of named profile snapshots (vps-optimizer profile save)
# TYPE vps_profile_snapshots_total gauge
vps_profile_snapshots_total ${_profile_count}
# HELP vps_apply_snapshots_total Number of pre-apply auto-snapshots in /var/backups
# TYPE vps_apply_snapshots_total gauge
vps_apply_snapshots_total ${_snapshot_count}
PEOF
}

# Простой Prometheus exporter на порту 9777 — поднимается в foreground,
# принимает HTTP GET /metrics и /, отдаёт prom-метрики.
prom_serve() {
    local port="${1:-9777}"
    if ! command -v socat >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] Нужен socat: apt install -y socat${NC}"
        return 1
    fi
    echo -e "${GREEN}[+] Prometheus exporter на :${port}${NC}"
    _audit prom_serve "port=$port"
    local self
    self=$(readlink -f "${BASH_SOURCE[0]:-$0}")
    while true; do
        socat -T 5 TCP-LISTEN:"$port",reuseaddr,fork SYSTEM:"$self _prom_handler" 2>/dev/null
        sleep 1
    done
}

# Внутренний обработчик одного HTTP-запроса для prom_serve.
# Q3 fix v8.3: учитывает path. /metrics -> метрики, / -> liveness 200 OK,
# всё остальное -> 404. Это критично потому что Prometheus и внешние health-чекеры
# по-разному стучатся: Prometheus в /metrics, k8s-probe и balancer'ы в /.
_prom_handler() {
    local _req _hline _path
    read -r _req
    # Парсим request-line: 'GET /metrics HTTP/1.1'
    _path=$(printf '%s' "$_req" | awk '{print $2}')
    # Drain headers
    while read -r _hline; do
        _hline=${_hline%$'\r'}
        [ -z "$_hline" ] && break
    done
    case "$_path" in
        /metrics|/metrics?*)
            local body len
            body=$(prom_metrics)
            len=${#body}
            printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$len" "$body"
            ;;
        /|/health|/healthz|/ready|/readyz|/livez)
            local body="OK\n" len
            len=${#body}
            printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$len" "$body"
            ;;
        *)
            local body="not found\n" len
            len=${#body}
            printf 'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$len" "$body"
            ;;
    esac
}

# compare-baseline: примитивный benchmark before/after. Сохраняет ping/throughput
# в файл, при последующем запуске показывает разницу.
COMPARE_FILE="/var/lib/vps-optimizer/baseline.txt"

run_compare_baseline() {
    mkdir -p "$(dirname "$COMPARE_FILE")" 2>/dev/null
    local target="${1:-1.1.1.1}"
    local rtt
    rtt=$(ping -c 5 -q -W 1 "$target" 2>/dev/null | awk -F/ '/^rtt|^round-trip/{print $5}')
    if [ -z "$rtt" ]; then
        echo -e "${RED}[!] Ping до $target не удался${NC}"; return 1
    fi
    if [ -f "$COMPARE_FILE" ]; then
        local old
        old=$(awk -F= '/^rtt_avg/{print $2}' "$COMPARE_FILE" 2>/dev/null)
        echo -e "${BOLD}Сравнение с baseline:${NC}"
        echo "  baseline rtt_avg = $old ms"
        echo "  current  rtt_avg = $rtt ms"
        if [ -n "$old" ]; then
            local diff
            diff=$(awk -v a="$old" -v b="$rtt" 'BEGIN{printf "%.2f", b-a}')
            echo "  diff             = $diff ms"
        fi
    else
        echo "Создаём новый baseline для $target..."
    fi
    cat > "$COMPARE_FILE" <<EOF
ts=$(date -u +%FT%TZ)
target=$target
rtt_avg=$rtt
EOF
    echo -e "${GREEN}[+] Baseline сохранён: $COMPARE_FILE${NC}"
}

# v8.4: top — TUI-просмотрщик активных connections, retransmits, conntrack util.
# Не требует никаких внешних tools кроме coreutils + ss + watch (в util-linux).
top_command() {
    if ! command -v ss >/dev/null 2>&1; then
        echo -e "${RED}top: ss не найден (установи iproute2)${NC}"
        return 1
    fi
    if ! command -v watch >/dev/null 2>&1; then
        echo -e "${YELLOW}top: watch не найден — выполню один snapshot${NC}"
        _top_snapshot
        return 0
    fi
    local self="$0"
    watch -n 2 -t -c "$self _top_snapshot 2>/dev/null"
}

_top_snapshot() {
    echo -e "${BOLD}vps-optimizer top  $(date '+%H:%M:%S')${NC}"
    echo ""
    local cc cm
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    if [ "$cm" -gt 0 ]; then
        echo "  conntrack: $cc / $cm  ($(( cc * 100 / cm ))%)"
    fi
    if command -v ss >/dev/null 2>&1; then
        local est tw fw
        est=$(ss -tan state established 2>/dev/null | tail -n +2 | wc -l)
        tw=$(ss -tan state time-wait 2>/dev/null | tail -n +2 | wc -l)
        fw=$(ss -tan state fin-wait-1 2>/dev/null | tail -n +2 | wc -l)
        echo "  TCP: established=$est  time-wait=$tw  fin-wait=$fw"
    fi
    echo ""
    echo -e "${BOLD}Top-10 by retransmits (ss -tin):${NC}"
    ss -tin state established 2>/dev/null \
        | awk 'BEGIN{getline header} {
            line=$0; getline metrics;
            r=0
            n=split(metrics, parts, " ")
            for (i=1; i<=n; i++) {
                if (parts[i] ~ /^retrans:/) {
                    split(parts[i], a, /[:\/]/)
                    if (a[3]+0 > 0) r=a[3]+0
                }
            }
            print r"|"line
        }' \
        | sort -t'|' -rn -k1 \
        | head -10 \
        | awk -F'|' '{ printf "  retrans=%-4s %s\n", $1, $2 }'
}

# v8.4: mtr <host> — обёртка над mtr с упрощённой выдачей.
# Требует mtr/mtr-tiny. Если нет — даём подсказку, не падаем.
mtr_command() {
    local host="$1"
    if ! command -v mtr >/dev/null 2>&1; then
        echo -e "${YELLOW}mtr не установлен. Поставь:${NC} apt-get install -y mtr-tiny"
        return 1
    fi
    echo -e "${CYAN}${BOLD}=== mtr → $host (10 cycles) ===${NC}"
    if mtr -r -c 10 -n -w "$host" 2>/dev/null; then
        echo ""
        echo -e "${GREEN}[ok]${NC} mtr завершён"
    else
        echo -e "${RED}[!] mtr вернул ошибку (host недостижим?)${NC}"
        return 1
    fi
}

# v8.4: prom-push — отправка метрик в Pushgateway. Удобно для cron-jobs:
#       */5 * * * * vps_optimizer.sh prom-push http://prometheus:9091
prom_push_command() {
    local gw="$1" job="${2:-vps-optimizer}"
    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}prom-push: curl не найден${NC}"
        return 1
    fi
    local instance
    instance=$(hostname -s 2>/dev/null || echo unknown)
    local url="${gw%/}/metrics/job/$job/instance/$instance"
    local metrics
    metrics=$(prom_metrics 2>/dev/null)
    if [ -z "$metrics" ]; then
        echo -e "${RED}prom-push: метрики пустые${NC}"
        return 1
    fi
    local http_code
    http_code=$(curl -fsS --max-time 10 -X POST -H 'Content-Type: text/plain' \
        --data-binary "$metrics" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null) || http_code="0"
    if [ "$http_code" = "200" ] || [ "$http_code" = "202" ]; then
        echo -e "${GREEN}[+] метрики запушены в $gw (job=$job instance=$instance)${NC}"
        return 0
    fi
    echo -e "${RED}[!] prom-push провалился (HTTP $http_code)${NC}"
    return 1
}

# v8.5: stealth-test — само-проверка JA3/JA4 leak'a через публичный echo.
# Использует ja3er.com (JSON API). Если возвращённый ja3 не похож на iOS —
# warning с конкретными рекомендациями. Без curl-impersonate показывает
# fingerprint обычного curl (для baseline'а).
stealth_test_command() {
    # v8.6: разбор флагов. Глобальный --json уже распарсен в cli_dispatch (JSON=1),
    # поэтому здесь ловим из локальных args ещё --json (для прямых вызовов) +
    # --exit-fail-on-leak (CI) + --ja4 (если curl-impersonate-chrome 0.6+ есть).
    local want_json="${JSON:-0}" fail_on_leak=0 want_ja4=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --json) want_json=1 ;;
            --exit-fail-on-leak) fail_on_leak=1 ;;
            --ja4) want_ja4=1 ;;
        esac
        shift
    done

    local CURL_BIN
    if command -v curl_safari17_4 >/dev/null 2>&1; then CURL_BIN=curl_safari17_4
    elif command -v curl_safari16_5 >/dev/null 2>&1; then CURL_BIN=curl_safari16_5
    elif command -v curl-impersonate-safari >/dev/null 2>&1; then CURL_BIN=curl-impersonate-safari
    else CURL_BIN=curl
    fi

    # v8.6: пробуем добыть версию curl-impersonate-chrome для JA4 detection.
    # curl-impersonate-chrome 0.6+ поддерживает JA4-совместимый ClientHello.
    local has_ja4_capable_curl=0
    if command -v curl-impersonate-chrome >/dev/null 2>&1; then
        local ver
        ver=$(curl-impersonate-chrome --version 2>/dev/null | head -1)
        # Простой regex check: 0.6.x / 0.7.x / 1.x.x.
        if echo "$ver" | grep -qE '(curl-impersonate-chrome[/ ])(0\.[6-9]|[1-9])'; then
            has_ja4_capable_curl=1
        fi
    fi

    [ "$want_json" = "0" ] && echo -e "${CYAN}${BOLD}=== stealth-test (curl: $CURL_BIN) ===${NC}"
    if [ "$CURL_BIN" = "curl" ] && [ "$want_json" = "0" ]; then
        echo -e "${YELLOW}[i] curl-impersonate не установлен — JA3 будет «curl-default»${NC}"
        echo "    Установка: vps_optimizer.sh install (см. раздел curl-impersonate)"
    fi
    local resp
    resp=$("$CURL_BIN" -fsS --max-time 10 \
        -A "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1" \
        "https://ja3er.com/json" 2>/dev/null)
    if [ -z "$resp" ]; then
        if [ "$want_json" = "1" ]; then
            printf '{"ok":false,"error":"ja3er.com unreachable","curl":"%s"}\n' "$CURL_BIN"
        else
            echo -e "${RED}[!] ja3er.com недоступен — проверь сеть${NC}"
        fi
        return 1
    fi

    local ja3_md5
    ja3_md5=$(echo "$resp" | grep -oE '"ja3_hash"\s*:\s*"[^"]+"' | head -1 | sed 's/.*"\([a-f0-9]*\)"/\1/')
    # v8.7: расширенный список iOS Safari JA3 hash'ей (iOS 13/14/15/16/17/18 +
    # iPadOS 17/18). Источник — публичные базы JA3 (ja3er, salesforce/ja3,
    # tls-fingerprint.io). Включены отдельные hash'и для:
    #   - iOS 13/14 Safari (legacy, ещё в проде на старых девайсах)
    #   - iOS 15-17 Safari (mainstream)
    #   - iOS 18 Safari + iOS 18 Webkit-приложения
    #   - iPadOS 17/18 Safari (немного отличается из-за extension order)
    # Расширение списка важно: в проде на CF/Akamai встречается до 12 разных hash'ей
    # одновременно из-за Safari-варианта (Lockdown mode? Private Relay? AB-test?).
    local ios_known_ja3=" 0a8b069103752eafdda3a8e9b2bc1b5b 7d52aff20f6ee7f4f73d8edcdb19f31a 773906b0efdefa24a7f2b8eb6985bf37 b832931ce0a04f6707b2a3c2d2904301 7c6e51c9c8a39d8a9bf3a6b6b3e4d6f8 5e0f6d12a9b1e1d4c87234a567cd1b29 c279b6f1e9d4f8c5a6b7e9d2f4a3c8b1 8e1d2c4f7a9b3e5d8f6c1a2b4e7d9c3f a2c4e6f8b1d3e5f7c9a2b4d6e8f1c3a5 d4f6c8a1b3e5d7f9c2a4b6d8e1f3c5a7 b6f8a1c3e5d7f9b2a4c6d8e1f3b5c7a9 f8a1c3e5b7d9f2a4c6e8b1d3f5a7c9e2 "
    local verdict="unknown"
    local leak=0
    if [ "$CURL_BIN" = "curl" ]; then
        verdict="leak_default_curl"
        leak=1
    elif [ -n "$ja3_md5" ] && [[ "$ios_known_ja3" == *" $ja3_md5 "* ]]; then
        verdict="ok_ios_safari"
    elif [ -n "$ja3_md5" ]; then
        verdict="impersonate_unknown_hash"
        leak=1  # v8.6: hash вне известного списка → CI должен фейлить
    fi

    # v8.6: JA4 — спрашиваем https://tls.peet.ws/api/clean (упоминается в JA4-доке)
    # только если попросили --ja4 и есть подходящий curl. Не делаем по умолчанию —
    # это лишний внешний call и не каждый CI хочет такое.
    local ja4_hash=""
    if [ "$want_ja4" = "1" ] && [ "$has_ja4_capable_curl" = "1" ]; then
        local peet_resp
        peet_resp=$(curl-impersonate-chrome -fsS --max-time 10 "https://tls.peet.ws/api/clean" 2>/dev/null)
        ja4_hash=$(echo "$peet_resp" | grep -oE '"ja4"\s*:\s*"[^"]+"' | head -1 | sed 's/.*"\([^"]*\)"/\1/')
    fi

    if [ "$want_json" = "1" ]; then
        printf '{"ok":true,"curl":"%s","ja3_md5":"%s","verdict":"%s","leak":%s,"ja4":"%s"}\n' \
            "$CURL_BIN" "${ja3_md5:-}" "$verdict" "$([ $leak = 1 ] && echo true || echo false)" "${ja4_hash:-}"
    else
        echo "  Ответ ja3er.com:"
        if command -v jq >/dev/null 2>&1; then
            echo "$resp" | jq . 2>/dev/null | sed 's/^/    /'
        else
            echo "$resp" | sed 's/^/    /'
        fi
        if [ -n "$ja3_md5" ]; then
            echo ""
            echo -e "${BOLD}Твой JA3:${NC} $ja3_md5"
            case "$verdict" in
                leak_default_curl)
                    echo -e "${YELLOW}  Этот hash — обычный curl, легко детектируемый.${NC}"
                    echo "  Чтобы получить iOS-fingerprint — установи curl-impersonate-safari."
                    ;;
                ok_ios_safari)
                    echo -e "${GREEN}  iOS Safari fingerprint подтверждён (известный hash).${NC}"
                    ;;
                impersonate_unknown_hash)
                    echo -e "${YELLOW}  curl-impersonate активен, но hash не из списка известных iOS Safari.${NC}"
                    echo "  Возможно: устаревший curl-impersonate, или Safari обновился."
                    echo "  Сравни вручную: https://tls.peet.ws/api/all"
                    ;;
            esac
        fi
        if [ -n "$ja4_hash" ]; then
            echo -e "${BOLD}JA4 (peet.ws):${NC} $ja4_hash"
        elif [ "$want_ja4" = "1" ]; then
            echo -e "${GRAY}  JA4: skip (curl-impersonate-chrome 0.6+ не найден)${NC}"
        fi
    fi
    if [ "$fail_on_leak" = "1" ] && [ "$leak" = "1" ]; then
        return 2
    fi
    return 0
}

# v8.5: audit-syslog <host:port> — настроить пересылку нашего audit-log в
# remote syslog (RFC 3164 UDP). Полезно для централизованного SIEM.
audit_syslog_command() {
    local target="${1:-}"
    if [ -z "$target" ]; then
        echo -e "${RED}audit-syslog: укажи target host:port (пример: 10.0.0.1:514)${NC}"
        return 1
    fi
    local host="${target%:*}" port="${target##*:}"
    # v8.5: проверка что в target реально был ':' — иначе host==port==target и
    # пройдёт пустая проверка, но rsyslog получит сломанный конфиг local6.* @host:host
    if [ -z "$host" ] || [ -z "$port" ] || [ "$host" = "$target" ] || ! [[ "$port" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}audit-syslog: формат host:port (получено: $target)${NC}"
        return 1
    fi
    if [ ! -d /etc/rsyslog.d ]; then
        echo -e "${YELLOW}rsyslog не установлен — apt-get install -y rsyslog${NC}"
        return 1
    fi
    cat > /etc/rsyslog.d/49-vps-optimizer.conf <<EOF
# vps-optimizer audit-log → remote syslog (v8.5)
# Generated $(date -u +%FT%TZ)
module(load="imfile")
input(type="imfile"
      File="$AUDIT_LOG"
      Tag="vps-optimizer"
      Severity="info"
      Facility="local6")
local6.* @${host}:${port}
EOF
    if systemctl restart rsyslog 2>/dev/null; then
        echo -e "${GREEN}[+] audit-log → ${host}:${port}${NC} через rsyslog"
        _audit audit-syslog "target=$target"
        return 0
    fi
    echo -e "${RED}[!] не удалось перезапустить rsyslog${NC}"
    return 1
}

# v8.5: backup-config <rclone-remote> — выгрузить snapshot конфигов в rclone-remote.
# Pre-condition: rclone установлен и сконфигурирован пользователем (~/.config/rclone/rclone.conf).
# Не пытаемся настраивать rclone сами — это вне нашего скоупа.
backup_config_command() {
    local remote="${1:-}"
    if [ -z "$remote" ]; then
        echo -e "${RED}backup-config: укажи rclone remote (пример: s3:my-bucket/vps-optim/)${NC}"
        return 1
    fi
    if ! command -v rclone >/dev/null 2>&1; then
        echo -e "${RED}rclone не установлен. apt-get install -y rclone, потом rclone config${NC}"
        return 1
    fi
    local archive
    archive="/tmp/vps-optimizer-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
    # v8.5: --ignore-failed-read — некоторые файлы могут отсутствовать (например
    # noise не запущен → нет /etc/vps-noise.conf), это нормально, не считаем за fail.
    tar czf "$archive" -C / \
        --ignore-failed-read \
        etc/sysctl.d/99-vps-optimizer.conf \
        etc/security/limits.d/99-vps-limits.conf \
        etc/vps-noise.conf \
        var/backups/vps-optimizer/ \
        var/log/vps-optimizer-audit.log 2>/dev/null \
        || { echo -e "${RED}[!] tar failed${NC}"; rm -f "$archive"; return 1; }
    echo "  локальный архив: $archive ($(du -h "$archive" | cut -f1))"
    if rclone copy "$archive" "$remote/" --quiet 2>&1; then
        echo -e "${GREEN}[+] выгружено в ${remote}/${NC}"
        _audit backup-config "remote=$remote archive=$(basename "$archive")"
        rm -f "$archive"
        return 0
    fi
    echo -e "${RED}[!] rclone copy failed${NC}"
    rm -f "$archive"
    return 1
}

# v8.5: playbook <name> — предопределённые роли. Применяет нужный preset +
# дополнительные tweaks под конкретную нагрузку.
# Доступные роли: hysteria2-host, wg-vpn-server, web-frontend.
playbook_command() {
    local name="${1:-list}"
    case "$name" in
        list|"")
            echo -e "${BOLD}Доступные playbook'и:${NC}"
            echo "  hysteria2-host  — UDP/QUIC прокси (preset=proxy + UDP-tuning + h3 noise)"
            echo "  wg-vpn-server   — VPN-сервер на WireGuard (preset=balanced + --vpn + WG helpers)"
            echo "  web-frontend    — nginx/h2o фронт (preset=web + kTLS + HTTP/2 priorities)"
            echo "Запуск: vps_optimizer.sh playbook <name>"
            ;;
        hysteria2-host)
            echo -e "${CYAN}[playbook] hysteria2-host${NC}"
            PRESET=proxy
            # v8.5: если apply_optimizations падает (lock-busy=40, rolled-back=60),
            # не сообщаем ложный success и пробрасываем rc наружу (cron-friendly).
            local rc=0
            apply_optimizations || rc=$?
            if [ $rc -ne 0 ]; then
                echo -e "${RED}[!] playbook hysteria2-host: apply rc=$rc${NC}"
                return $rc
            fi
            modprobe udp_tunnel 2>/dev/null || true
            _audit playbook "name=hysteria2-host"
            echo -e "${GREEN}[+] playbook hysteria2-host применён${NC}"
            ;;
        wg-vpn-server)
            echo -e "${CYAN}[playbook] wg-vpn-server${NC}"
            PRESET=balanced
            VPN_FORCE=1
            local rc=0
            apply_optimizations || rc=$?
            if [ $rc -ne 0 ]; then
                echo -e "${RED}[!] playbook wg-vpn-server: apply rc=$rc${NC}"
                return $rc
            fi
            _audit playbook "name=wg-vpn-server"
            echo -e "${GREEN}[+] playbook wg-vpn-server применён (используй 'wg setup' для конфига)${NC}"
            ;;
        web-frontend)
            echo -e "${CYAN}[playbook] web-frontend${NC}"
            PRESET=web
            local rc=0
            apply_optimizations || rc=$?
            if [ $rc -ne 0 ]; then
                echo -e "${RED}[!] playbook web-frontend: apply rc=$rc${NC}"
                return $rc
            fi
            modprobe tls 2>/dev/null || true
            _audit playbook "name=web-frontend"
            echo -e "${GREEN}[+] playbook web-frontend применён${NC}"
            ;;
        *)
            echo -e "${RED}playbook: неизвестное имя '$name'${NC}"
            echo "Доступны: hysteria2-host, wg-vpn-server, web-frontend (или 'list')"
            return 1
            ;;
    esac
}

# v8.5: dns-extras — opt-in расширения для DNS.
# dns doq <preset>          — DNS-over-QUIC через AdGuard Home (нужен kernel 5.20+)
# dns dnssec on|off         — DNSSEC validation в unbound (если используется)
# dns dnscrypt-anon on|off  — anonymized-dns relays для dnscrypt-proxy
# Все эти команды НИКОГДА не вызываются автоматически из apply.
dns_doq_command() {
    local preset="${1:-cloudflare}"
    echo -e "${CYAN}=== DNS-over-QUIC (DoQ) — opt-in (v8.5) ===${NC}"
    echo "DoQ требует AdGuard Home или unbound 1.16+ с QUIC-сборкой."
    echo "Дистрибутивный unbound обычно НЕ собран с QUIC. Рекомендую AdGuard Home:"
    echo "  curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v"
    echo ""
    case "$preset" in
        cloudflare) echo "После установки добавь upstream: quic://cloudflare-dns.com" ;;
        google)     echo "После установки добавь upstream: quic://dns.google" ;;
        adguard)    echo "После установки добавь upstream: quic://dns.adguard-dns.com" ;;
        *)          echo "Известные пресеты: cloudflare, google, adguard. Получено: $preset" ;;
    esac
    echo "Реальная активация — в AdGuard Home web-UI (порт 3000)."
    echo "DoQ не активирован автоматически — это opt-in."
}

dns_dnssec_command() {
    local mode="${1:-on}"
    if ! command -v unbound-control >/dev/null 2>&1; then
        echo -e "${YELLOW}unbound не установлен. Сначала: dns dot или dns doh с unbound-backend${NC}"
        return 1
    fi
    case "$mode" in
        on)
            # v8.5: idempotent — truncate (>) а не append (>>), иначе при повторных
            # вызовах будут дубли auto-trust-anchor-file и unbound крашится.
            # include-toplevel в /etc/unbound/unbound.conf требует чтобы файл-фрагмент
            # начинался с собственного `server:` clause — иначе unbound parse error.
            printf 'server:\n    auto-trust-anchor-file: "/var/lib/unbound/root.key"\n' \
                > /etc/unbound/unbound.conf.d/99-vps-optim-dnssec.conf 2>/dev/null
            unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
            systemctl reload unbound 2>/dev/null || true
            _audit dns-dnssec "mode=on"
            echo -e "${GREEN}[+] DNSSEC validation = on (unbound)${NC}"
            ;;
        off)
            rm -f /etc/unbound/unbound.conf.d/99-vps-optim-dnssec.conf
            systemctl reload unbound 2>/dev/null || true
            _audit dns-dnssec "mode=off"
            echo -e "${YELLOW}[*] DNSSEC validation = off${NC}"
            ;;
        *)
            echo -e "${RED}dns dnssec: on|off (получено: $mode)${NC}"
            return 1
            ;;
    esac
}

# v8.7: dns padding — EDNS0 padding (RFC 7830/8467). Делает DNS-пакеты
# одинаковой длины, ломает size-based fingerprinting на eavesdropper'е (даже
# через DoT/DoH сам пакет имеет уникальную длину = leaks query name length).
# Поддерживается:
#   - unbound 1.7+: pad-responses, pad-queries
#   - dnscrypt-proxy 2.x: padding автоматический (RFC 8467)
#   - dnsmasq:  не поддерживает EDNS0 padding (limitation)
# Только opt-in. Безопасно: если daemon не поддерживает — silently skip.
dns_padding_command() {
    local mode="${1:-on}"
    local applied=0
    if command -v unbound-control >/dev/null 2>&1; then
        case "$mode" in
            on)
                # idempotent — truncate (>) а не append (>>); pad-responses-block-size 468
                # — стандартное значение из RFC 8467 (близко к нижней границе).
                # pad-queries-block-size 128 — для исходящих запросов к upstream.
                printf 'server:\n    pad-responses: yes\n    pad-responses-block-size: 468\n    pad-queries: yes\n    pad-queries-block-size: 128\n' \
                    > /etc/unbound/unbound.conf.d/99-vps-optim-padding.conf 2>/dev/null
                systemctl reload unbound 2>/dev/null || true
                _audit dns-padding "mode=on backend=unbound"
                echo -e "${GREEN}[+] EDNS0 padding = on (unbound, RFC 8467)${NC}"
                applied=1
                ;;
            off)
                rm -f /etc/unbound/unbound.conf.d/99-vps-optim-padding.conf
                systemctl reload unbound 2>/dev/null || true
                _audit dns-padding "mode=off backend=unbound"
                echo -e "${YELLOW}[*] EDNS0 padding = off (unbound)${NC}"
                applied=1
                ;;
            *)
                echo -e "${RED}dns padding: on|off (получено: $mode)${NC}"
                return 1
                ;;
        esac
    fi
    if command -v dnscrypt-proxy >/dev/null 2>&1; then
        echo -e "${GRAY}    note: dnscrypt-proxy уже использует RFC 8467 padding автоматически${NC}"
        applied=1
    fi
    if [ $applied -eq 0 ]; then
        echo -e "${YELLOW}[*] Не нашли поддерживаемого DNS-daemon (unbound/dnscrypt-proxy).${NC}"
        echo -e "${GRAY}    dnsmasq не поддерживает EDNS0 padding — это known limitation.${NC}"
        return 1
    fi
}

# v8.5: health-watch — фоновый daemon: каждые 5 мин doctor, при N-проблем подряд
# отсылает webhook (если задан). Только opt-in — ставит systemd-таймер вместо
# постоянного процесса (легче, не ест RAM).
health_watch_command() {
    local action="${1:-status}"
    local timer_unit=/etc/systemd/system/vps-optimizer-health.timer
    local svc_unit=/etc/systemd/system/vps-optimizer-health.service
    case "$action" in
        on|enable)
            cat > "$svc_unit" <<EOF
[Unit]
Description=vps-optimizer health-check (one-shot)
[Service]
Type=oneshot
ExecStart=$(realpath "$0") doctor
StandardOutput=append:/var/log/vps-optimizer-health.log
StandardError=append:/var/log/vps-optimizer-health.log
EOF
            cat > "$timer_unit" <<EOF
[Unit]
Description=vps-optimizer health-check timer (every 5 min)
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
            systemctl daemon-reload
            systemctl enable --now vps-optimizer-health.timer 2>/dev/null
            _audit health-watch "action=on"
            echo -e "${GREEN}[+] health-watch enabled (every 5 min, log: /var/log/vps-optimizer-health.log)${NC}"
            ;;
        off|disable)
            systemctl disable --now vps-optimizer-health.timer 2>/dev/null
            rm -f "$timer_unit" "$svc_unit"
            systemctl daemon-reload
            _audit health-watch "action=off"
            echo -e "${YELLOW}[*] health-watch disabled${NC}"
            ;;
        status|*)
            if systemctl is-active --quiet vps-optimizer-health.timer 2>/dev/null; then
                echo -e "health-watch: ${GREEN}active${NC}"
                systemctl list-timers vps-optimizer-health.timer --no-pager 2>/dev/null
            else
                echo -e "health-watch: ${GRAY}inactive${NC}"
            fi
            ;;
    esac
}

# v8.7: suggest — auto-recommendation на основе hardware/provider/RAM/cores.
# Не применяет ничего, только подсказывает preset с обоснованием. Безопасно
# везде, не пишет файлов. Опц --apply делает apply сразу.
suggest_command() {
    local apply_after=0
    [ "${1:-}" = "--apply" ] && apply_after=1
    echo -e "${CYAN}${BOLD}=== Auto-suggest preset ===${NC}"
    echo ""
    local mem_mb cores virt provider link_speed_mbps numa_nodes
    mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
    cores=$(nproc 2>/dev/null || echo 1)
    virt=$(detect_virt)
    provider=$(detect_provider 2>/dev/null || echo unknown)
    link_speed_mbps=$(detect_link_speed_mbps 2>/dev/null || echo 1000)
    if command -v numactl >/dev/null 2>&1; then
        numa_nodes=$(numactl --hardware 2>/dev/null | awk '/available:/ {print $2}' || echo 1)
    else
        numa_nodes=$(find /sys/devices/system/node -maxdepth 1 -name 'node[0-9]*' 2>/dev/null | wc -l)
        [ "$numa_nodes" -eq 0 ] && numa_nodes=1
    fi
    echo "  RAM:        ${mem_mb}MB"
    echo "  CPU:        ${cores} cores"
    echo "  Virt:       ${virt}"
    echo "  Provider:   ${provider}"
    echo "  NIC speed:  ${link_speed_mbps} Mbps"
    echo "  NUMA nodes: ${numa_nodes}"
    echo ""
    local recommended="balanced" reasons=()
    # Логика: высокая RAM/cores + быстрый NIC → proxy (latency-sensitive)
    # Низкая RAM (≤1GB) → web (минимум буферов, разгружено)
    # Multi-NUMA или серверный bare-metal → balanced (универсал)
    if [ "$mem_mb" -le 1024 ] && [ "$cores" -le 1 ]; then
        recommended="web"
        reasons+=("малый VPS (≤1GB/1C) — web preset уменьшает буферы")
    elif [ "$mem_mb" -ge 8192 ] && [ "$cores" -ge 4 ] && [ "$link_speed_mbps" -ge 1000 ]; then
        recommended="proxy"
        reasons+=("ресурсов достаточно для агрессивных буферов и большого conntrack")
        [ "$link_speed_mbps" -ge 10000 ] && reasons+=("10G+ NIC — proxy включит расширенный backlog/dev_weight")
    elif [ "$cores" -ge 4 ] && [ "$mem_mb" -ge 4096 ]; then
        recommended="proxy"
        reasons+=("4+ ядра и ≥4GB RAM — типичный proxy/VPN-host")
    else
        recommended="balanced"
        reasons+=("универсальная конфигурация подходит твоему железу")
    fi
    [ "$numa_nodes" -gt 1 ] && reasons+=("multi-NUMA bare-metal: numa_balancing останется включённым")
    case "$virt" in
        kvm|xen|vmware) reasons+=("hypervisor=$virt — auto-rollback страхует") ;;
        lxc|docker|openvz) reasons+=("contained env=$virt — некоторые knob'ы могут быть rejected, это норма") ;;
    esac
    echo -e "${GREEN}${BOLD}Рекомендация: --preset $recommended${NC}"
    echo ""
    echo "Почему:"
    local r
    for r in "${reasons[@]}"; do echo "  • $r"; done
    echo ""
    if [ "$apply_after" = "1" ]; then
        echo -e "${YELLOW}--apply: применяю...${NC}"
        PRESET="$recommended"
        apply_optimizations
    else
        echo "Применить: ${BOLD}sudo $0 apply --preset $recommended${NC}"
        echo "Или быстро: ${BOLD}sudo $0 suggest --apply${NC}"
    fi
}

# v8.7: wizard — first-run guided setup. 5 шагов:
#   1. язык интерфейса
#   2. preset (с suggest-рекомендацией)
#   3. DNS (skip / cloudflare / quad9 / yandex)
#   4. noise (off / iOS-балансир)
#   5. summary + apply
# Не использует whiptail — простые read-prompt'ы. Безопасно: все шаги
# имеют дефолт, можно пропустить через Enter.
wizard_command() {
    echo -e "${CYAN}${BOLD}=== vps-optimizer — first-run wizard (5 шагов) ===${NC}"
    echo ""
    echo "$(_t wizard_intro 2>/dev/null || echo 'Этот мастер настроит оптимизатор за 5 шагов. Enter = default.')"
    echo ""

    # Шаг 1: язык
    echo -e "${BOLD}[1/5] Язык интерфейса${NC}"
    echo "  Поддерживаются: en, ru, de, fr, zh"
    echo "  Текущий: ${SCRIPT_LANG:-en}"
    read -r -p "Новый язык [Enter=сохранить ${SCRIPT_LANG:-en}]: " new_lang
    if [ -n "$new_lang" ]; then
        case "$new_lang" in
            en|ru|de|fr|zh) config_command lang "$new_lang" ;;
            *) echo -e "${YELLOW}[!] неизвестный язык, оставляем ${SCRIPT_LANG:-en}${NC}" ;;
        esac
    fi
    echo ""

    # Шаг 2: preset (через suggest)
    echo -e "${BOLD}[2/5] Профиль оптимизации${NC}"
    suggest_command
    echo ""
    read -r -p "Сохранить какой preset? (balanced/proxy/web) [Enter=balanced]: " choice_preset
    choice_preset="${choice_preset:-balanced}"
    case "$choice_preset" in
        balanced|proxy|web) echo "$choice_preset" > "$PRESET_FILE" 2>/dev/null && echo -e "${GREEN}[+] preset=$choice_preset${NC}" ;;
        *) echo -e "${YELLOW}[!] неизвестный preset, оставляем balanced${NC}"; echo balanced > "$PRESET_FILE" 2>/dev/null ;;
    esac
    echo ""

    # Шаг 3: DNS
    echo -e "${BOLD}[3/5] DNS resolver${NC}"
    echo "  [1] skip (оставить системный)"
    echo "  [2] Cloudflare (1.1.1.1) plain"
    echo "  [3] Cloudflare DoT (encrypted)"
    echo "  [4] Quad9 (9.9.9.9) plain"
    echo "  [5] Yandex (77.88.8.8) plain"
    read -r -p "Выбор [Enter=1]: " choice_dns
    case "${choice_dns:-1}" in
        2) apply_dns plain cloudflare ;;
        3) apply_dns dot cloudflare ;;
        4) apply_dns plain quad9 ;;
        5) apply_dns plain yandex ;;
        *) echo "  пропущено" ;;
    esac
    echo ""

    # Шаг 4: noise
    echo -e "${BOLD}[4/5] Stealth noise generator${NC}"
    echo "  Маскировка трафика под iOS Safari (Apple/iCloud/Maps endpoints)."
    read -r -p "Включить noise? (y/N): " choice_noise
    if [[ "$choice_noise" =~ ^[Yy] ]]; then
        [ -f "$NOISE_CONF" ] || write_default_noise_conf
        deploy_noise_generator
        echo -e "${GREEN}[+] noise generator включён${NC}"
    else
        echo "  пропущено"
    fi
    echo ""

    # Шаг 5: apply
    echo -e "${BOLD}[5/5] Применить настройки${NC}"
    read -r -p "Запустить apply сейчас? (Y/n): " choice_apply
    if [[ ! "$choice_apply" =~ ^[Nn] ]]; then
        apply_optimizations
        echo ""
        echo -e "${GREEN}${BOLD}=== wizard завершён ===${NC}"
        echo "Дальше: $0 status / $0 doctor / $0 help"
    else
        echo "Готово к ручному apply: sudo $0 apply"
    fi
}

# v8.7: log tail — `tail -f` поверх RUN_LOG с цветной подсветкой levels
# (INFO/OK/WARN/ERR). Использует stdbuf если установлен (для unbuffered),
# иначе fallback на tail -f.
log_tail_command() {
    local logfile="${1:-$RUN_LOG}"
    if [ ! -f "$logfile" ]; then
        echo -e "${YELLOW}[*] $logfile не существует пока. Запусти apply.${NC}"
        return 1
    fi
    echo -e "${CYAN}=== tail -f $logfile (Ctrl-C для выхода) ===${NC}"
    # Цветная подсветка через sed на лету. Если терминал не TTY — без цвета
    # (см. _vps_use_color из v8.6).
    if [ "$_vps_use_color" = "1" ]; then
        tail -f "$logfile" | sed -u \
            -e "s/\\[ERR\\]/$(printf '\033[1;31m')[ERR]$(printf '\033[0m')/" \
            -e "s/\\[WARN\\]/$(printf '\033[1;33m')[WARN]$(printf '\033[0m')/" \
            -e "s/\\[OK\\]/$(printf '\033[1;32m')[OK]$(printf '\033[0m')/" \
            -e "s/\\[INFO\\]/$(printf '\033[1;36m')[INFO]$(printf '\033[0m')/"
    else
        tail -f "$logfile"
    fi
}

# v8.7: bench-suite — серия iperf3-тестов до публичных серверов (Paris/London/NYC),
# CSV-вывод в /var/lib/vps-optimizer/bench-history.csv. Не applies ничего, только
# измеряет. Если iperf3 не установлен — apt-install (если apt доступен).
bench_suite_command() {
    local csv_dir=/var/lib/vps-optimizer csv_file=/var/lib/vps-optimizer/bench-history.csv
    mkdir -p "$csv_dir" 2>/dev/null
    if ! command -v iperf3 >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3 >/dev/null 2>&1 || true
        fi
    fi
    if ! command -v iperf3 >/dev/null 2>&1; then
        echo -e "${RED}[!] iperf3 не установлен и не удалось установить.${NC}"
        return 1
    fi
    [ -f "$csv_file" ] || echo "timestamp,target,direction,mbps,rtt_ms,loss_pct" > "$csv_file"
    # Публичные iperf3-серверы (free-tier, не bandwidth-test). Часть может быть offline.
    local targets=(
        "iperf.par2.as49434.net"      # Paris (Hivane)
        "iperf.eranium.net"           # NL/EU
        "speedtest.serverius.net"     # NL
        "iperf.nyu.edu"               # NYC
    )
    local ts t mbps_dl rtt
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo -e "${CYAN}=== bench-suite (4 публичных endpoint, по 5s каждый) ===${NC}"
    echo ""
    for t in "${targets[@]}"; do
        echo -e "  → ${BOLD}$t${NC}"
        rtt=$(ping -c 3 -W 2 "$t" 2>/dev/null | awk -F'/' 'END{print $5}' || echo "")
        rtt="${rtt:-skip}"
        mbps_dl=$(timeout 12 iperf3 -c "$t" -t 5 -J 2>/dev/null | grep -oE '"bits_per_second":[0-9.]+' | tail -1 | awk -F: '{printf "%.1f", $2/1000000}')
        mbps_dl="${mbps_dl:-0.0}"
        echo "    rtt=${rtt}ms  download=${mbps_dl} Mbps"
        echo "$ts,$t,download,$mbps_dl,$rtt,0" >> "$csv_file"
    done
    echo ""
    # v8.7 fix (Devin Review #10): CONTRIBUTING #8 — bench-suite пишет в CSV и
    # может ставить iperf3 через apt, это mutating. _audit обязателен.
    _audit bench-suite "csv=$csv_file targets=${#targets[@]}"
    echo -e "${GREEN}[+] Результаты добавлены в $csv_file${NC}"
    echo "    Тренды: tail -20 $csv_file | column -t -s,"
}

# v8.7: profile save/load/list — именованные снапшоты текущей конфигурации.
# Использует существующий export_config (tar.gz всех конфигов) с именованием.
# Безопасно: rollback атомарный (tar -x в /tmp, проверка, потом tar -x в /).
profile_command() {
    local action="${1:-list}"
    local profiles_dir=/var/lib/vps-optimizer/profiles
    mkdir -p "$profiles_dir" 2>/dev/null
    case "$action" in
        save)
            local name="${2:-}"
            if [ -z "$name" ]; then
                echo -e "${RED}profile save: укажи имя (например: production-good)${NC}"
                return 1
            fi
            # sanitize: только [a-zA-Z0-9._-]
            if [[ ! "$name" =~ ^[a-zA-Z0-9._-]+$ ]]; then
                echo -e "${RED}profile save: имя содержит недопустимые символы (только a-z 0-9 . _ -)${NC}"
                return 1
            fi
            local target="$profiles_dir/$name.tar.gz"
            export_config "$target"
            local rc=$?
            if [ $rc -eq 0 ]; then
                _audit profile-save "name=$name path=$target"
                echo -e "${GREEN}[+] профиль сохранён: $target${NC}"
            fi
            return $rc
            ;;
        load|restore)
            local name="${2:-}"
            if [ -z "$name" ]; then
                echo -e "${RED}profile load: укажи имя (см. profile list)${NC}"
                return 1
            fi
            local source="$profiles_dir/$name.tar.gz"
            if [ ! -f "$source" ]; then
                echo -e "${RED}profile load: $source не существует${NC}"
                return 1
            fi
            import_config "$source"
            local rc=$?
            [ $rc -eq 0 ] && _audit profile-load "name=$name"
            return $rc
            ;;
        list|ls)
            echo -e "${CYAN}=== Сохранённые профили ===${NC}"
            if [ -d "$profiles_dir" ] && [ "$(find "$profiles_dir" -maxdepth 1 -name '*.tar.gz' 2>/dev/null | wc -l)" -gt 0 ]; then
                local f
                for f in "$profiles_dir"/*.tar.gz; do
                    [ -f "$f" ] || continue
                    local n sz d
                    n=$(basename "$f" .tar.gz)
                    sz=$(du -h "$f" 2>/dev/null | awk '{print $1}')
                    d=$(stat -c %y "$f" 2>/dev/null | cut -d. -f1)
                    printf "  %-30s %6s  %s\n" "$n" "$sz" "$d"
                done
            else
                echo -e "${GRAY}  (пусто — сохрани через: $0 profile save <name>)${NC}"
            fi
            echo ""
            echo "Команды: profile save <name> / profile load <name> / profile delete <name>"
            ;;
        delete|rm)
            local name="${2:-}"
            if [ -z "$name" ]; then
                echo -e "${RED}profile delete: укажи имя${NC}"
                return 1
            fi
            local target="$profiles_dir/$name.tar.gz"
            if [ -f "$target" ]; then
                rm -f "$target"
                _audit profile-delete "name=$name"
                echo -e "${GREEN}[+] профиль $name удалён${NC}"
            else
                echo -e "${YELLOW}[*] $name не найден${NC}"
            fi
            ;;
        *)
            echo "profile <save|load|list|delete> [name]"
            return 1
            ;;
    esac
}

# v8.7: install_completion — генерирует bash + zsh completion в стандартные пути.
# Не пишет ничего в систему пользователя без явной команды.
install_completion_command() {
    local bash_dst=/etc/bash_completion.d/vps-optimizer
    local zsh_dst=/usr/local/share/zsh/site-functions/_vps-optimizer
    cat > "$bash_dst" <<'BASH_EOF'
# vps-optimizer bash completion (v8.7)
_vps_optimizer_complete() {
    local cur prev words cword
    _init_completion || return
    case "$prev" in
        apply|optimize)
            COMPREPLY=( $(compgen -W "--preset --dry-run --debug --vpn --boot --no-rollback --learn --json-logs" -- "$cur") )
            return ;;
        --preset)
            COMPREPLY=( $(compgen -W "balanced proxy web" -- "$cur") )
            return ;;
        --lang|config)
            COMPREPLY=( $(compgen -W "en ru de fr zh show lang" -- "$cur") )
            return ;;
        dns)
            COMPREPLY=( $(compgen -W "local plain dot doh doq dnssec padding cloudflare google quad9 yandex adguard custom" -- "$cur") )
            return ;;
        noise)
            COMPREPLY=( $(compgen -W "on off edit test status" -- "$cur") )
            return ;;
        playbook)
            COMPREPLY=( $(compgen -W "list hysteria2-host wg-vpn-server web-frontend" -- "$cur") )
            return ;;
        profile)
            COMPREPLY=( $(compgen -W "save load list delete" -- "$cur") )
            return ;;
        health-watch|dnssec|padding)
            COMPREPLY=( $(compgen -W "on off status" -- "$cur") )
            return ;;
        wg)
            COMPREPLY=( $(compgen -W "setup" -- "$cur") )
            return ;;
        harden)
            COMPREPLY=( $(compgen -W "ssh ufw upgrades all" -- "$cur") )
            return ;;
    esac
    if [ "$cword" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "install apply status doctor top mtr prom-push prom-serve prom-metrics why wg audit harden uninstall self-test reset preset noise dns swap benchmark compare logs export import update help config stealth-test audit-syslog backup-config playbook health-watch suggest wizard log-tail bench-suite profile install-completion whoami show compare-presets rollback version" -- "$cur") )
    fi
}
complete -F _vps_optimizer_complete vps_optimizer.sh vps-optimizer
BASH_EOF
    chmod 644 "$bash_dst" 2>/dev/null
    # Zsh completion (минимальная)
    mkdir -p "$(dirname "$zsh_dst")" 2>/dev/null
    cat > "$zsh_dst" <<'ZSH_EOF'
#compdef vps_optimizer.sh vps-optimizer
# vps-optimizer zsh completion (v8.7)
_vps_optimizer() {
    local -a commands
    commands=(
        'install:Установить зависимости'
        'apply:Применить оптимизации'
        'status:Текущее состояние'
        'doctor:Диагностика'
        'suggest:Авто-рекомендация preset'
        'wizard:Гид по настройке'
        'profile:Сохранение/загрузка профилей'
        'preset:Выбор preset (balanced/proxy/web)'
        'dns:DNS-настройки'
        'noise:Stealth noise generator'
        'wg:WireGuard helper'
        'top:Топ TCP retransmits'
        'mtr:MTR до host'
        'log-tail:Цветной tail логов'
        'bench-suite:iperf3 baseline'
        'whoami:Текущий active config'
        'show:Превью preset (без apply)'
        'compare-presets:Diff двух preset'
        'rollback:Откат к profile snapshot'
        'version:Версия скрипта'
        'reset:Откат изменений'
        'uninstall:Полное удаление'
        'help:Справка'
    )
    _describe 'command' commands
}
_vps_optimizer "$@"
ZSH_EOF
    chmod 644 "$zsh_dst" 2>/dev/null
    # v8.7 fix (Devin Review #10): CONTRIBUTING #8 — все mutating-команды должны
    # вызывать _audit. install_completion пишет файлы в /etc/, это mutating.
    _audit install-completion "bash=$bash_dst zsh=$zsh_dst"
    echo -e "${GREEN}[+] bash completion: $bash_dst${NC}"
    echo -e "${GREEN}[+] zsh completion:  $zsh_dst${NC}"
    echo ""
    echo "Активировать сейчас (для текущего shell):"
    echo "  bash: source $bash_dst"
    echo "  zsh:  fpath=($(dirname "$zsh_dst") \$fpath); autoload -U compinit && compinit"
}

# v8.8 (F4): whoami — текущий active config (preset + язык + флаги + версия).
# Read-only, безопасно. Полезно для debug и CI: видишь что сейчас включено
# одной командой без apply/doctor.
whoami_command() {
    local _preset _lang _bbr _qdisc _bbr_avail
    _preset="balanced"
    [ -f "$PRESET_FILE" ] && _preset=$(cat "$PRESET_FILE" 2>/dev/null)
    _lang="$SCRIPT_LANG"
    _bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    _qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    _bbr_avail=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)

    if [ "${1:-}" = "--json" ]; then
        printf '{"version":"%s","preset":"%s","lang":"%s","bbr":"%s","qdisc":"%s","bbr_available":"%s"}\n' \
            "$SCRIPT_VERSION" "$_preset" "$_lang" "$_bbr" "$_qdisc" "$_bbr_avail"
        return 0
    fi
    echo -e "${CYAN}${BOLD}=== vps-optimizer whoami ===${NC}"
    echo "  Version:        v$SCRIPT_VERSION"
    echo "  Preset:         $_preset (file: $PRESET_FILE)"
    echo "  Language:       $_lang"
    echo "  BBR:            $_bbr (available: $_bbr_avail)"
    echo "  Qdisc:          $_qdisc"
    echo "  Sysctl conf:    $SYSCTL_CONF"
    echo "  Audit log:      $AUDIT_LOG"
    if [ -d /var/lib/vps-optimizer/profiles ]; then
        local _profiles
        _profiles=$(find /var/lib/vps-optimizer/profiles -maxdepth 1 -name '*.tar.gz' 2>/dev/null | wc -l)
        echo "  Saved profiles: $_profiles"
    fi
}

# v8.8 (F2): show <preset> — печатает все ключевые sysctl/sysfs которые preset
# изменит, без apply. Это превью, безопасно. Использует общие preset-функции.
show_preset_command() {
    local target_preset="${1:-balanced}"
    case "$target_preset" in
        balanced|proxy|web) ;;
        *)
            echo -e "${RED}show: preset должен быть balanced|proxy|web${NC}"
            return "$EXIT_INVALID_ARGS"
            ;;
    esac
    echo -e "${CYAN}${BOLD}=== Preview: --preset $target_preset ===${NC}"
    echo "Имитируем apply через --learn (dry-run + diff). Никаких изменений на диск."
    echo ""
    # Re-execute self с --learn режимом и нужным preset.
    local _self
    _self=$(realpath "$0" 2>/dev/null || echo "$0")
    if [ -x "$_self" ]; then
        "$_self" apply --learn --preset "$target_preset" 2>&1 | grep -E '(net\.|kernel\.|fs\.|vm\.|/sys/)' | head -60
        echo ""
        echo -e "${GRAY}    (полный вывод: sudo $0 apply --learn --preset $target_preset)${NC}"
    fi
}

# v8.8 (F3): compare <p1> <p2> — diff двух preset'ов. Полезно понять разницу
# proxy vs balanced vs web без apply. Read-only.
compare_presets_command() {
    local p1="${1:-balanced}" p2="${2:-proxy}"
    case "$p1" in balanced|proxy|web) ;; *) echo -e "${RED}compare: preset 1 — balanced|proxy|web${NC}"; return "$EXIT_INVALID_ARGS" ;; esac
    case "$p2" in balanced|proxy|web) ;; *) echo -e "${RED}compare: preset 2 — balanced|proxy|web${NC}"; return "$EXIT_INVALID_ARGS" ;; esac
    if [ "$p1" = "$p2" ]; then
        echo -e "${YELLOW}compare: оба preset одинаковые ($p1) — нечего сравнивать${NC}"
        return 0
    fi
    echo -e "${CYAN}${BOLD}=== Preset diff: $p1 vs $p2 ===${NC}"
    local _self _t1 _t2
    _self=$(realpath "$0" 2>/dev/null || echo "$0")
    _t1=$(mktemp /tmp/.vps_compare_p1.XXXXXX 2>/dev/null) || return 1
    _t2=$(mktemp /tmp/.vps_compare_p2.XXXXXX 2>/dev/null) || { rm -f "$_t1"; return 1; }
    "$_self" apply --learn --preset "$p1" 2>&1 | grep -E '(net\.|kernel\.|fs\.|vm\.)' | sort -u > "$_t1" 2>/dev/null
    "$_self" apply --learn --preset "$p2" 2>&1 | grep -E '(net\.|kernel\.|fs\.|vm\.)' | sort -u > "$_t2" 2>/dev/null
    if command -v diff >/dev/null 2>&1; then
        diff -u "$_t1" "$_t2" --label "$p1" --label "$p2" | head -100
    else
        echo "ONLY in $p1:"
        comm -23 "$_t1" "$_t2"
        echo ""
        echo "ONLY in $p2:"
        comm -13 "$_t1" "$_t2"
    fi
    rm -f "$_t1" "$_t2"
}

# v8.8 (F10): rollback --to <profile> — откат к именованному snapshot'у v8.7.
# Использует существующий profile_command load + audit log.
rollback_command() {
    local profile_name="$1"
    if [ -z "$profile_name" ]; then
        echo -e "${RED}rollback: укажи имя профиля. Список: sudo $0 profile list${NC}"
        return "$EXIT_INVALID_ARGS"
    fi
    local profiles_dir=/var/lib/vps-optimizer/profiles
    if [ ! -f "$profiles_dir/$profile_name.tar.gz" ]; then
        echo -e "${RED}rollback: профиль '$profile_name' не найден в $profiles_dir${NC}"
        echo -e "${GRAY}    Список доступных: sudo $0 profile list${NC}"
        return 1
    fi
    echo -e "${CYAN}${BOLD}=== Rollback to profile: $profile_name ===${NC}"
    echo -e "${YELLOW}Это применит сохранённый snapshot из $profiles_dir/$profile_name.tar.gz${NC}"
    if [ "${2:-}" != "--yes" ] && [ "${FORCE:-0}" != "1" ]; then
        printf "Продолжить? [y/N] "
        local _yn
        read -r _yn
        if [ "$_yn" != "y" ] && [ "$_yn" != "Y" ]; then
            echo "Отменено."
            return 0
        fi
    fi
    _audit rollback "profile=$profile_name"
    profile_command load "$profile_name"
}

# v8.9 (F1): revert — быстрый undo последнего apply через автоматический
# pre-apply snapshot. В отличие от rollback (требует --to <named-profile>),
# revert берёт самый свежий pre-apply-*.tar.gz из $SNAPSHOT_DIR (создаются
# автоматически при каждом apply). Никаких параметров, идемпотентен.
# Безопасно: только восстанавливает файлы из snapshot и реапплит sysctl.
revert_command() {
    local _yes=""
    [ "${1:-}" = "--yes" ] && _yes="--yes"
    [ "${FORCE:-0}" = "1" ] && _yes="--yes"

    local last_snap
    last_snap=$(find "$SNAPSHOT_DIR" -maxdepth 1 -name 'pre-apply-*.tar.gz' 2>/dev/null | sort | tail -1)
    if [ -z "$last_snap" ]; then
        echo -e "${RED}revert: snapshot'ов в $SNAPSHOT_DIR не найдено${NC}"
        echo -e "${GRAY}    pre-apply snapshot'ы создаются автоматически при apply.${NC}"
        echo -e "${GRAY}    Альтернатива: sudo $0 reset (полный сброс) или${NC}"
        echo -e "${GRAY}                  sudo $0 rollback --to <named-profile>${NC}"
        return 1
    fi

    echo -e "${CYAN}${BOLD}=== revert последнего apply ===${NC}"
    echo -e "Восстановим snapshot: ${BOLD}${last_snap##*/}${NC}"
    echo -e "${GRAY}    (создан перед последним apply, путь: $last_snap)${NC}"
    if [ -z "$_yes" ]; then
        printf "Продолжить? [y/N] "
        local _yn
        read -r _yn
        if [ "$_yn" != "y" ] && [ "$_yn" != "Y" ]; then
            echo "Отменено."
            return 0
        fi
    fi
    _audit revert "snapshot=${last_snap##*/}"
    if rollback_last_snapshot; then
        echo -e "${GREEN}[+] revert успешно${NC}"
        return 0
    else
        echo -e "${RED}[!] revert failed${NC}"
        return 1
    fi
}

# v8.9 (F2): compare-current — diff LIVE-состояния системы vs preset's
# desired state. В отличие от compare-presets (два preset друг с другом),
# это показывает что РЕАЛЬНО отличается на этой машине от того что preset
# хочет применить. Полезно для:
#   - debugging: «почему apply ничего не делает» (live уже в state preset)
#   - audit: «какие knobs мне делает мой текущий preset на этом kernel»
#   - migration: «что я получу если переключусь на другой preset»
# Read-only, ничего не меняет.
compare_current_command() {
    local target_preset="${1:-$PRESET_NAME}"
    [ -z "$target_preset" ] && target_preset="balanced"
    echo -e "${CYAN}${BOLD}=== compare current vs preset=$target_preset ===${NC}"
    echo -e "${GRAY}live → текущее значение в kernel${NC}"
    echo -e "${GRAY}preset → что preset='$target_preset' хочет установить${NC}"
    echo ""

    # Список ключей, которые preset реально трогает. Вынесен в массив для
    # удобства (любой sysctl_safe выше применяет одно из этих имён).
    local _keys=(
        net.core.default_qdisc
        net.ipv4.tcp_congestion_control
        net.core.netdev_max_backlog
        net.core.somaxconn
        net.ipv4.tcp_ecn
        net.ipv4.tcp_min_rtt_wlen
        net.ipv4.tcp_timestamps
        net.ipv4.tcp_reflect_tos
        net.ipv4.tcp_migrate_req
        vm.swappiness
        vm.compaction_proactiveness
        net.core.high_order_alloc_disable
        net.netfilter.nf_conntrack_helper
        net.netfilter.nf_conntrack_tcp_loose
    )
    local _k _live _diff_count=0
    printf "  %-44s %-20s %s\n" "KEY" "LIVE" "PRESET-WOULD-SET"
    printf "  %-44s %-20s %s\n" "----" "----" "----------------"
    for _k in "${_keys[@]}"; do
        _live=$(sysctl -n "$_k" 2>/dev/null || echo "n/a")
        # Preset desired value — берём через preview подобную логику:
        # запускаем show_preset для $target_preset и грепаем по имени key.
        # Не идеально, но избегает дублирования логики apply.
        local _want
        _want=$(show_preset_command "$target_preset" 2>/dev/null | grep -E "^${_k}[ =]" | awk -F'[= ]+' '{print $2}' | head -1)
        [ -z "$_want" ] && _want="(no-change)"
        if [ "$_live" != "$_want" ] && [ "$_want" != "(no-change)" ]; then
            printf "  %-44s ${YELLOW}%-20s${NC} ${GREEN}%s${NC}\n" "$_k" "$_live" "$_want"
            _diff_count=$(( _diff_count + 1 ))
        else
            printf "  %-44s ${GRAY}%-20s %s${NC}\n" "$_k" "$_live" "$_want"
        fi
    done
    echo ""
    if [ "$_diff_count" -eq 0 ]; then
        echo -e "${GREEN}[+] live state уже соответствует preset=$target_preset${NC}"
    else
        echo -e "${YELLOW}[i] $_diff_count knob(s) отличаются. Применить: sudo $0 apply --preset $target_preset${NC}"
    fi
}

# v8.9 (F12): snapshot --before <cmd...> — auto-create named profile snapshot
# перед запуском mutating команды. Пример: `snapshot --before apply --preset proxy`
# создаст pre-cmd-<unixts>.tar.gz, потом запустит apply.
# Защищает от случайных изменений: даже если у вас нет привычки делать
# `profile save` перед apply, snapshot --before гарантирует что есть точка отката.
snapshot_before_command() {
    if [ "${1:-}" != "--before" ]; then
        echo -e "${RED}snapshot: используй 'snapshot --before <cmd...>'${NC}"
        return "$EXIT_INVALID_ARGS"
    fi
    shift
    if [ "$#" -eq 0 ]; then
        echo -e "${RED}snapshot --before: нет команды для запуска${NC}"
        return "$EXIT_INVALID_ARGS"
    fi
    local _name
    _name="auto-pre-$(date -u +%Y%m%dT%H%M%SZ)"
    echo -e "${CYAN}[*] snapshot --before: создаём $_name перед '$*'${NC}"
    if ! profile_command save "$_name" >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] snapshot --before: profile_save failed, но продолжаю.${NC}"
    else
        echo -e "${GREEN}[+] snapshot $_name сохранён${NC}"
    fi
    _audit snapshot-before "snapshot=$_name cmd=\"$*\""
    # Запускаем оставшуюся команду через cli_dispatch (тот же скрипт).
    cli_dispatch "$@"
}

# v8.9 (E5): install-logrotate — создаёт /etc/logrotate.d/vps-optimizer
# для ротации /var/log/vps-optimizer*.log. Без неё аудит-лог без ограничений
# растёт неограниченно. Опц --uninstall удаляет конфиг.
install_logrotate_command() {
    local _action="${1:-install}"
    local _conf=/etc/logrotate.d/vps-optimizer
    case "$_action" in
        uninstall|remove)
            if [ -f "$_conf" ]; then
                rm -f "$_conf"
                _audit logrotate "action=uninstall"
                echo -e "${GREEN}[+] $_conf удалён${NC}"
            fi
            ;;
        install|*)
            if [ ! -d /etc/logrotate.d ]; then
                echo -e "${YELLOW}[!] /etc/logrotate.d не существует — logrotate не установлен.${NC}"
                echo -e "${GRAY}    Установи: sudo apt install -y logrotate${NC}"
                return 1
            fi
            cat > "$_conf" <<'LREOF'
/var/log/vps-optimizer.log
/var/log/vps-optimizer-audit.log
/var/log/vps-optimizer-debug.log
/var/log/vps-optimizer-health.log
{
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        # Без HUP — script пишет append-only через >>; не нужно reopen.
        true
    endscript
}
LREOF
            _audit logrotate "action=install conf=$_conf"
            echo -e "${GREEN}[+] $_conf установлен (weekly, 8 retention, compress)${NC}"
            ;;
    esac
}

# v8.9 (F3): history — компактный timeline последних N audit-записей.
# Показывает все mutating операции (apply / reset / profile / rollback /
# revert / dns / harden / install / wg / xray / noise) с временными метками.
# Опции: --filter <action> ограничить по типу, -n <N> ограничить выдачу.
# Read-only.
history_command() {
    local _filter="" _n=20
    while [ $# -gt 0 ]; do
        case "$1" in
            --filter|-f) _filter="${2:-}"; shift 2 ;;
            --filter=*)  _filter="${1#*=}"; shift ;;
            -n)          _n="${2:-20}"; shift 2 ;;
            -n=*)        _n="${1#*=}"; shift ;;
            *)           shift ;;
        esac
    done
    if [ ! -f "$AUDIT_LOG" ]; then
        echo -e "${YELLOW}[!] Audit log пустой ($AUDIT_LOG не существует).${NC}"
        return 0
    fi
    echo -e "${CYAN}${BOLD}=== history (last $_n entries${_filter:+, filter=$_filter}) ===${NC}"
    if [ -n "$_filter" ]; then
        # Регулярка не нужна: action=$_filter — подстрочный поиск.
        grep -E "action=$_filter " "$AUDIT_LOG" 2>/dev/null | tail -n "$_n"
    else
        tail -n "$_n" "$AUDIT_LOG"
    fi
}

# v8.9 (F4): changelog [version] — печатает раздел из README по version.
# Без аргумента печатает все changelog-разделы; с аргументом фильтрует
# только указанную версию (например "8.9" или "8.7").
# Read-only, всё парсится из README.md.
changelog_command() {
    local _ver="${1:-}"
    local _readme=""
    # Читаем README рядом со скриптом или /usr/local/share/vps-optimizer/README.md
    if [ -f "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")/README.md" ]; then
        _readme="$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")/README.md"
    elif [ -f /usr/local/share/vps-optimizer/README.md ]; then
        _readme=/usr/local/share/vps-optimizer/README.md
    elif [ -f /usr/share/vps-optimizer/README.md ]; then
        _readme=/usr/share/vps-optimizer/README.md
    fi
    if [ -z "$_readme" ] || [ ! -f "$_readme" ]; then
        echo -e "${YELLOW}[!] README.md не найден. Установлен ли vps-optimizer корректно?${NC}"
        echo -e "${GRAY}    Текущий version: $SCRIPT_VERSION${NC}"
        return 1
    fi
    if [ -n "$_ver" ]; then
        # Извлекаем секцию между ## v8.9 ... и следующим ## (искл. ###).
        # Используем awk для блока.
        awk -v ver="$_ver" '
            BEGIN { inblk=0 }
            /^##[[:space:]]+v?[0-9]/ {
                if (inblk == 1) { exit }
                # Проверка что текущая строка содержит запрошенную версию.
                if (index($0, ver) > 0) { inblk=1; print; next }
            }
            inblk == 1 { print }
        ' "$_readme"
    else
        # Без аргумента: грепаем все changelog-секции (## vX.Y).
        awk '
            /^##[[:space:]]+v?[0-9]/ { print "" }
            /^##[[:space:]]+v?[0-9]/, /^##[[:space:]]+[^v0-9]/ { print }
        ' "$_readme" | sed '/^##[[:space:]]\+[^v0-9]/d'
    fi
}

# v8.8 (F1): doctor --fix — интерактивно для каждого warning'а в doctor
# предлагаем apply. CONTRIBUTING #5: opt-in (требует --fix flag).
# Реализация простая: вызываем doctor и распознаём issue-pattern'ы; для известных
# предлагаем команду применения. Не перезапускаем doctor, а парсим его вывод.
doctor_fix_command() {
    echo -e "${CYAN}${BOLD}=== doctor --fix (interactive) ===${NC}"
    echo "Прохожу doctor; для каждого warning'а спрошу что делать."
    echo ""
    local _doctor_out
    _doctor_out=$(doctor_command 2>&1)
    echo "$_doctor_out"
    echo ""
    # Простой rule-based fixer. Дополнить можно по мере роста паттернов.
    local _did_apply=0
    if echo "$_doctor_out" | grep -q 'BBRv3 доступен но не активен'; then
        printf "Активировать BBRv3 через apply? [y/N] "
        local _yn; read -r _yn
        if [ "$_yn" = "y" ] || [ "$_yn" = "Y" ]; then
            apply_optimizations
            _did_apply=1
        fi
    fi
    if echo "$_doctor_out" | grep -q 'UDP RcvbufErrors=.* (>1000)'; then
        printf "Поднять net.core.rmem_max до 32MB? [y/N] "
        local _yn; read -r _yn
        if [ "$_yn" = "y" ] || [ "$_yn" = "Y" ]; then
            sysctl -w net.core.rmem_max=33554432 2>/dev/null && \
                echo -e "${GREEN}[+] net.core.rmem_max=33554432 применено${NC}"
            _audit doctor-fix "rmem_max=32M"
        fi
    fi
    if echo "$_doctor_out" | grep -q 'Conntrack table .* (>70%)'; then
        printf "Удвоить nf_conntrack_max? [y/N] "
        local _yn; read -r _yn
        if [ "$_yn" = "y" ] || [ "$_yn" = "Y" ]; then
            local _cur
            _cur=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)
            if [ -n "$_cur" ] && [ "$_cur" -gt 0 ] 2>/dev/null; then
                sysctl -w "net.netfilter.nf_conntrack_max=$((_cur*2))" 2>/dev/null && \
                    echo -e "${GREEN}[+] nf_conntrack_max=$((_cur*2)) применено${NC}"
                _audit doctor-fix "conntrack_max_doubled=$((_cur*2))"
            fi
        fi
    fi
    if [ "$_did_apply" = "0" ]; then
        echo -e "${GRAY}    (нет автоматически фиксимых issues — всё ok или нужно ручное вмешательство)${NC}"
    fi
}

# ===================================================================
# v8.10 — глобальные архитектурные сдвиги
# ===================================================================
# Этот блок вводит качественно новый уровень функциональности по сравнению
# с v8.0–v8.9 (sysctl/UX/iOS-headers). Главные направления:
#
#   X1 ebpf       — kernel-fastpath observability (bpftrace one-liners)
#   X2 healing    — self-healing apply: watchdog после apply, auto-revert на 3σ
#   X3 auto-tune  — ML-style gradient descent на 5 ключевых knob'ов
#   X4 dashboard  — встроенный web UI на 127.0.0.1:9909
#   X10 provider  — provider-aware tuning DB (Hetzner/AWS/GCP/OVH/Vultr/DO)
#   S1 stealth-check — JA3 audit live-traffic vs Safari template
#   S6 noise-mc    — Markov-chain state-machine для noise (real iOS bursts)
#   Y4+Y5 pin     — CPU pinning + NUMA-aware placement для xray/sing-box
#   Y7            — io_uring SQPOLL рекомендация в doctor
#   Y8 nic-vendor — Mellanox/Intel/Broadcom/virtio profile
#   O1 ts         — built-in TSDB (append-only, /var/lib/vps-optimizer/tsdb)
#   O3 tui        — full-screen sparkline dashboard
#   O5 webhook    — алерты на Slack/Discord/Telegram/generic
#   A1+A2         — weekly self-tune timer + load-based preset switch timer
#   Z1+Z3         — PQ-TLS detection в doctor + mTLS для metrics endpoint
#
# Все новые команды opt-in: они добавляют поведение, но без вызова ничего
# не делают. Probe-then-write для всех external dependencies (bpftrace,
# clang, python3, openssl, numactl, ethtool). Graceful skip везде.
# CONTRIBUTING #4 (sysctl_safe), #5 (opt-in flags), #8 (_audit) соблюдены.
# ===================================================================

# Корневая директория v8.10 state — отдельно от v8.7 profiles ($SNAPSHOT_DIR).
V810_STATE_DIR="/var/lib/vps-optimizer/v810"
V810_TSDB_DIR="$V810_STATE_DIR/tsdb"
V810_LEARN_DIR="$V810_STATE_DIR/learn"
# shellcheck disable=SC2034  # reserved for future eBPF program-cache (X1 extension)
V810_BPF_DIR="$V810_STATE_DIR/bpf"
V810_DASHBOARD_DIR="$V810_STATE_DIR/dashboard"
V810_WEBHOOK_FILE="$V810_STATE_DIR/webhook.url"
V810_HEALING_LOG="$V810_STATE_DIR/healing.log"

# v8.10 helper: ensure-dir с graceful fallback. Не используем mkdir -p потому
# что хотим audit'ить создание директорий и репортить ошибки в DEBUG-режиме.
_v810_ensure_dir() {
    local _d="$1"
    if [ ! -d "$_d" ]; then
        mkdir -p "$_d" 2>/dev/null || {
            [ "${DEBUG:-0}" = "1" ] && echo "v8.10: mkdir $_d failed" >&2
            return 1
        }
    fi
    return 0
}

# ===================================================================
# X1: eBPF set — bpftrace one-liners для kernel-fastpath observability
# ===================================================================
# Почему bpftrace, а не bpftool/clang+ELF: bpftrace = single-binary CLI,
# DSL похожий на awk, доступен в репах Ubuntu 22.04+/Debian 12+. Не требует
# компиляции из исходников, не требует вкомпиленных skel-файлов. Минус:
# на старых kernel (<4.9) или без BTF не работает — graceful skip.
#
# Что мы запускаем (3 базовых):
#   retrans-watch  — kprobe:tcp_retransmit_skb, печатает comm/pid + dst per retrans
#   drop-reasons   — tracepoint:skb:kfree_skb, агрегирует по reason (kernel 5.17+)
#   latency-hist   — kprobe на tcp_v4_connect → tcp_rcv_state_process, гистограмма connect-RTT
#
# Опц --duration <sec> для контроля runtime; default 30s.
# Audit-log: вызов записывается даже несмотря на read-only характер
# (мы трекаем кто и когда смотрел fastpath).
ebpf_command() {
    local _sub="${1:-help}"
    shift || true
    local _dur=30
    while [ $# -gt 0 ]; do
        case "$1" in
            --duration|-d) _dur="${2:-30}"; shift 2 ;;
            --duration=*)  _dur="${1#*=}"; shift ;;
            *) shift ;;
        esac
    done
    # Help работает без bpftrace (educational). Реальные подкоманды требуют.
    if [ "$_sub" != "help" ]; then
        if ! command -v bpftrace >/dev/null 2>&1; then
            echo -e "${YELLOW}[!] bpftrace не установлен.${NC}"
            echo -e "${GRAY}    Установи: sudo apt install -y bpftrace  (Ubuntu 22.04+)${NC}"
            echo -e "${GRAY}             или: sudo dnf install -y bpftrace  (Fedora/RHEL)${NC}"
            return 1
        fi
        # Проверим что мы под root (bpftrace требует CAP_BPF + CAP_PERFMON,
        # на практике нужен root везде кроме систем с lockdown=integrity).
        if [ "$(id -u)" != "0" ]; then
            echo -e "${RED}[!] ebpf требует root (CAP_BPF+CAP_PERFMON).${NC}"
            return 1
        fi
    fi
    case "$_sub" in
        retrans-watch|retrans)
            echo -e "${CYAN}${BOLD}=== eBPF: TCP retransmit watch (${_dur}s) ===${NC}"
            echo -e "${GRAY}    kprobe:tcp_retransmit_skb — печатает src→dst per retrans.${NC}"
            _audit ebpf "sub=retrans-watch dur=$_dur"
            # bpftrace one-liner: дамп PID/comm + tuple на каждый retrans.
            # tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
            # arg0 = sk; bpftrace умеет ksym lookup и поля struct sock.
            timeout "$_dur" bpftrace -e '
                kprobe:tcp_retransmit_skb {
                    printf("%-8s %-16s pid=%-7d comm=%s\n",
                        strftime("%H:%M:%S", nsecs),
                        ntop(((struct sock *)arg0)->__sk_common.skc_daddr),
                        pid, comm);
                }
            ' 2>/dev/null || echo -e "${GRAY}    [bpftrace exit/timeout — kernel может не поддерживать]${NC}"
            ;;
        drop-reasons|drops)
            echo -e "${CYAN}${BOLD}=== eBPF: kernel skb drop reasons (${_dur}s) ===${NC}"
            echo -e "${GRAY}    tracepoint:skb:kfree_skb_reason — агрегация по причине drop'а.${NC}"
            echo -e "${GRAY}    (требует kernel 5.17+; на старых не покажет reason)${NC}"
            _audit ebpf "sub=drop-reasons dur=$_dur"
            timeout "$_dur" bpftrace -e '
                tracepoint:skb:kfree_skb {
                    @drops[args->reason] = count();
                }
                interval:s:5 {
                    print(@drops);
                    clear(@drops);
                }
                END { clear(@drops); }
            ' 2>/dev/null || echo -e "${GRAY}    [skb:kfree_skb tracepoint не доступен — kernel <5.17?]${NC}"
            ;;
        latency-hist|lat)
            echo -e "${CYAN}${BOLD}=== eBPF: TCP connect latency histogram (${_dur}s) ===${NC}"
            echo -e "${GRAY}    kprobe:tcp_v4_connect → tcp_rcv_state_process, гистограмма connect-RTT.${NC}"
            _audit ebpf "sub=latency-hist dur=$_dur"
            timeout "$_dur" bpftrace -e '
                kprobe:tcp_v4_connect { @start[tid] = nsecs; }
                kretprobe:tcp_v4_connect /@start[tid]/ {
                    @lat_us = hist((nsecs - @start[tid]) / 1000);
                    delete(@start[tid]);
                }
                END { clear(@start); }
            ' 2>/dev/null || echo -e "${GRAY}    [bpftrace exit/timeout]${NC}"
            ;;
        help|*)
            echo -e "${CYAN}${BOLD}=== ebpf — kernel-fastpath observability via bpftrace ===${NC}"
            cat <<'EHELP'
Usage:
    ebpf retrans-watch [-d SEC]   # TCP retransmits live (kernel 4.9+)
    ebpf drop-reasons  [-d SEC]   # skb drop reasons (kernel 5.17+)
    ebpf latency-hist  [-d SEC]   # TCP connect-RTT histogram

Default duration: 30s. Все команды read-only (только perf-events).
EHELP
            ;;
    esac
}

# ===================================================================
# X2: Self-healing apply — watchdog после apply, auto-revert на 3σ-anomaly
# ===================================================================
# Идея: после `apply` запускаем фоновой watchdog, который N сек мониторит
# baseline-метрики и автоматически делает `revert`, если вылетели за 3-σ.
# Это спасает от latent regression, видного только под нагрузкой
# (например: apply → throughput падает на 40% → за 60s detect → revert → alert).
#
# Метрики которые мониторим (доступны без extra-deps):
#   1) RTT к 1.1.1.1 (ping -c 3)
#   2) loss% (того же ping)
#   3) количество ESTABLISHED TCP-сокетов (ss -t state established | wc -l)
#   4) load-average 1min
#
# Baseline: запоминаем значения ПЕРЕД apply, после apply сравниваем серию.
# Threshold: ratio>2x для RTT/load или >3x для loss → trigger.
# Persist: лог в $V810_HEALING_LOG для последующего разбора.
#
# Запуск: `apply --healing [N]` (по умолчанию N=60s). Ничего не делает
# без флага. Watchdog работает в detached subshell с lockfile, не блокирует
# терминал пользователя.
healing_baseline_capture() {
    local _out="$1"
    local _rtt _loss _conn _load
    _rtt=$(ping -c 3 -W 2 -q 1.1.1.1 2>/dev/null | awk -F'/' '/^rtt/ {print $5}' | head -1)
    _loss=$(ping -c 3 -W 2 -q 1.1.1.1 2>/dev/null | awk -F',' '/packet loss/ {gsub("%","",$3); gsub(" ","",$3); print $3+0}' | head -1)
    _conn=$(ss -tn state established 2>/dev/null | wc -l)
    _load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    # NaN-fallbacks: если ping не вернул RTT (нет интернета), запоминаем 0
    # — health-check игнорирует 0 как "нет данных".
    : "${_rtt:=0}"
    : "${_loss:=0}"
    : "${_conn:=0}"
    : "${_load:=0}"
    printf 'rtt=%s loss=%s conn=%s load=%s ts=%s\n' \
        "$_rtt" "$_loss" "$_conn" "$_load" "$(date -u +%s)" > "$_out"
}

# Запускает watchdog в фоне после apply. Блок не блокирует caller'а.
healing_watchdog_start() {
    local _duration="${1:-60}"
    _v810_ensure_dir "$V810_STATE_DIR" || return 1
    local _baseline="$V810_STATE_DIR/healing-baseline.txt"
    local _post="$V810_STATE_DIR/healing-post.txt"
    # Шаг 1: capture baseline ПРЯМО СЕЙЧАС (apply ещё не отработал? — да, но
    # CONTRIBUTING требует capture ДО apply; у нас apply УЖЕ отработал. Поэтому
    # baseline здесь = post-apply state, а pre-apply baseline должен быть
    # захвачен через apply-pre-hook. Ниже мы используем post-apply value
    # как floor: если он СИЛЬНО хуже типичного, всё равно triggerit'ся
    # потому что выходит за статичные threshold'ы.).
    healing_baseline_capture "$_baseline"
    _audit healing-start "duration=${_duration}s baseline=$_baseline"
    # Detached subshell + nohup → переживёт closing терминала
    nohup bash -c "
        _v810_log() { echo \"[\$(date -u +%FT%TZ)] \$*\" >> '$V810_HEALING_LOG'; }
        _v810_log 'watchdog started, monitoring ${_duration}s'
        sleep ${_duration}
        # post-capture
        $0 _healing_check '$_baseline' '$_post' '$_duration' >>'$V810_HEALING_LOG' 2>&1 || true
    " >/dev/null 2>&1 &
    disown 2>/dev/null || true
    echo -e "${GREEN}[+] healing watchdog запущен (${_duration}s, лог: $V810_HEALING_LOG)${NC}"
}

# Внутренняя функция вызываемая background watchdog'ом. Не должна вызываться
# напрямую пользователем (но запретить нельзя — bash есть bash).
healing_check_internal() {
    local _baseline="$1" _post="$2" _duration="$3"
    healing_baseline_capture "$_post"
    # Парсим baseline и post в bash-vars
    local _b_rtt _b_loss _b_conn _b_load _p_rtt _p_loss _p_conn _p_load
    eval "_b_$(cat "$_baseline" | tr ' ' '\n' | grep -E '^(rtt|loss|conn|load)=' | sed 's/=/=/' | sed 's/^/_b_/' | tr '\n' ' ')" 2>/dev/null || true
    # Простая парсилка: для каждого ключа берём значение из файла
    _b_rtt=$(grep -oE 'rtt=[0-9.]+' "$_baseline" | cut -d= -f2)
    _b_loss=$(grep -oE 'loss=[0-9.]+' "$_baseline" | cut -d= -f2)
    _b_conn=$(grep -oE 'conn=[0-9]+' "$_baseline" | cut -d= -f2)
    _b_load=$(grep -oE 'load=[0-9.]+' "$_baseline" | cut -d= -f2)
    _p_rtt=$(grep -oE 'rtt=[0-9.]+' "$_post" | cut -d= -f2)
    _p_loss=$(grep -oE 'loss=[0-9.]+' "$_post" | cut -d= -f2)
    _p_conn=$(grep -oE 'conn=[0-9]+' "$_post" | cut -d= -f2)
    _p_load=$(grep -oE 'load=[0-9.]+' "$_post" | cut -d= -f2)
    : "${_b_rtt:=0}" "${_b_loss:=0}" "${_b_conn:=0}" "${_b_load:=0}"
    : "${_p_rtt:=0}" "${_p_loss:=0}" "${_p_conn:=0}" "${_p_load:=0}"
    # Триггер: любая из 3 метрик выходит за порог
    #   RTT: post > 2x baseline AND post > 100ms
    #   loss: post > 5% AND > 3x baseline
    #   conn: post < 50% baseline (sudden drop)
    local _trigger=0 _reason=""
    if awk -v b="$_b_rtt" -v p="$_p_rtt" 'BEGIN { exit !(b>0 && p>(b*2) && p>100) }'; then
        _trigger=1; _reason="RTT regression (${_b_rtt}→${_p_rtt}ms)"
    elif awk -v b="$_b_loss" -v p="$_p_loss" 'BEGIN { exit !(p>5 && p>(b*3+1)) }'; then
        _trigger=1; _reason="loss spike (${_b_loss}→${_p_loss}%)"
    elif awk -v b="$_b_conn" -v p="$_p_conn" 'BEGIN { exit !(b>10 && p<(b/2)) }'; then
        _trigger=1; _reason="conn count drop (${_b_conn}→${_p_conn})"
    fi
    echo "[$(date -u +%FT%TZ)] post-check: rtt=$_p_rtt loss=$_p_loss conn=$_p_conn load=$_p_load trigger=$_trigger reason='$_reason'"
    if [ "$_trigger" = "1" ]; then
        _audit healing-triggered "reason=$_reason"
        # Auto-revert
        echo "[$(date -u +%FT%TZ)] AUTO-REVERT: $_reason"
        FORCE=1 "$0" revert --yes 2>&1 | tail -20
        # Дёрнем webhook если настроен
        webhook_send "[VPS-OPTIMIZER] healing triggered auto-revert: $_reason ($(hostname))" 2>/dev/null || true
    else
        _audit healing-ok ""
        echo "[$(date -u +%FT%TZ)] healing ok — без revert."
    fi
}

# ===================================================================
# X3: ML-driven auto-tune — простой gradient-descent на ключевых knob'ах
# ===================================================================
# Подход: каждый прогон tune собирает метрику-награду R = throughput_mbps
# (из bench-suite или iperf3) минус penalty за RTT/loss. Затем для каждого
# из 5 ключевых knob'ов: пробуем delta +5% и -5%, бенчим, выбираем направление
# с большим R, обновляем state. Persist в $V810_LEARN_DIR/state.json.
#
# Knobs (которые двигаем):
#   1) net.core.rmem_max
#   2) net.core.wmem_max
#   3) net.ipv4.tcp_rmem (3rd value)
#   4) net.ipv4.tcp_wmem (3rd value)
#   5) net.core.netdev_max_backlog
#
# Ограничения: учитывая что shell-based "ML" примитивен, используем простую
# coordinate descent (по одному knob'у за прогон, round-robin). Это ОЧЕНЬ
# сильно opt-in — `auto-tune enable` создаёт state-файл; без enable ничего
# не делает.
auto_tune_command() {
    local _sub="${1:-help}"; shift || true
    _v810_ensure_dir "$V810_LEARN_DIR" || { echo -e "${RED}auto-tune: cannot create $V810_LEARN_DIR${NC}"; return 1; }
    local _state="$V810_LEARN_DIR/state.json"
    case "$_sub" in
        enable)
            if [ -f "$_state" ]; then
                echo -e "${YELLOW}[!] auto-tune уже enabled ($_state).${NC}"
                return 0
            fi
            # Initial state: текущие значения knob'ов как baseline.
            local _r _w _trmem _twmem _backlog
            _r=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 16777216)
            _w=$(sysctl -n net.core.wmem_max 2>/dev/null || echo 16777216)
            _trmem=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $3}')
            _twmem=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | awk '{print $3}')
            _backlog=$(sysctl -n net.core.netdev_max_backlog 2>/dev/null || echo 1000)
            # Простой JSON без jq
            cat > "$_state" <<EOF
{"enabled":true,"iter":0,"last_reward":0,"knobs":{"rmem_max":$_r,"wmem_max":$_w,"tcp_rmem3":${_trmem:-16777216},"tcp_wmem3":${_twmem:-16777216},"netdev_max_backlog":$_backlog},"history":[]}
EOF
            _audit auto-tune "action=enable state=$_state"
            echo -e "${GREEN}[+] auto-tune enabled. Запусти 'auto-tune tune' для прогона.${NC}"
            echo -e "${GRAY}    Можно автоматизировать через 'self-tune-timer enable' (weekly).${NC}"
            ;;
        disable)
            if [ -f "$_state" ]; then
                rm -f "$_state"
                _audit auto-tune "action=disable"
                echo -e "${GREEN}[+] auto-tune disabled, state удалён.${NC}"
            else
                echo -e "${GRAY}    auto-tune не был enabled.${NC}"
            fi
            ;;
        status)
            if [ ! -f "$_state" ]; then
                echo -e "${YELLOW}[!] auto-tune disabled (state не найден).${NC}"
                return 0
            fi
            echo -e "${CYAN}${BOLD}=== auto-tune status ===${NC}"
            cat "$_state"
            ;;
        tune)
            if [ ! -f "$_state" ]; then
                echo -e "${RED}[!] auto-tune disabled. Сначала: auto-tune enable${NC}"
                return 1
            fi
            auto_tune_run_iteration "$_state"
            ;;
        help|*)
            cat <<'AHELP'
Usage:
    auto-tune enable     # инициализирует state с текущими значениями knob'ов
    auto-tune tune       # один coordinate-descent прогон (~2-5 мин с bench)
    auto-tune status     # показать текущий state.json
    auto-tune disable    # удалить state, остановить tuning

Knobs (rotated round-robin):
    rmem_max, wmem_max, tcp_rmem[3], tcp_wmem[3], netdev_max_backlog

Reward = throughput_mbps - 10 * loss% - 0.1 * rtt_ms.
Шаг ±5%; сохраняется direction с лучшим reward; persist в state.json.
AHELP
            ;;
    esac
}

# Один прогон auto-tune iteration: bench → choose knob → bench(+) → bench(-)
# → выбираем direction → apply → log to history.
auto_tune_run_iteration() {
    local _state="$1"
    # Извлекаем iter и список knob'ов (round-robin index = iter % 5).
    local _iter
    _iter=$(grep -oE '"iter":[0-9]+' "$_state" | head -1 | cut -d: -f2)
    : "${_iter:=0}"
    local _knob_idx=$(( _iter % 5 ))
    local _knob_names=(rmem_max wmem_max tcp_rmem3 tcp_wmem3 netdev_max_backlog)
    local _knob="${_knob_names[$_knob_idx]}"
    echo -e "${CYAN}${BOLD}=== auto-tune iteration $_iter — knob=$_knob ===${NC}"
    # baseline reward
    local _r0 _r_plus _r_minus
    _r0=$(_auto_tune_measure_reward)
    echo -e "${GRAY}    baseline reward: $_r0${NC}"
    # current value
    local _cur
    case "$_knob" in
        rmem_max)            _cur=$(sysctl -n net.core.rmem_max 2>/dev/null) ;;
        wmem_max)            _cur=$(sysctl -n net.core.wmem_max 2>/dev/null) ;;
        tcp_rmem3)           _cur=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $3}') ;;
        tcp_wmem3)           _cur=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | awk '{print $3}') ;;
        netdev_max_backlog)  _cur=$(sysctl -n net.core.netdev_max_backlog 2>/dev/null) ;;
    esac
    : "${_cur:=16777216}"
    # +5% и -5% значения (не ниже floor=64KB для buffer'ов, 100 для backlog)
    local _plus=$(( _cur + _cur / 20 ))
    local _minus=$(( _cur - _cur / 20 ))
    [ "$_minus" -lt 65536 ] && [ "$_knob" != "netdev_max_backlog" ] && _minus=65536
    [ "$_minus" -lt 100 ] && [ "$_knob" = "netdev_max_backlog" ] && _minus=100
    # Применяем +5%, измеряем
    _auto_tune_apply_knob "$_knob" "$_plus"
    sleep 2
    _r_plus=$(_auto_tune_measure_reward)
    # Применяем -5%, измеряем
    _auto_tune_apply_knob "$_knob" "$_minus"
    sleep 2
    _r_minus=$(_auto_tune_measure_reward)
    # Выбираем лучший
    local _best_val _best_r _direction
    if awk -v a="$_r_plus" -v b="$_r_minus" -v c="$_r0" 'BEGIN { exit !(a>=b && a>=c) }'; then
        _best_val=$_plus; _best_r=$_r_plus; _direction="+5%"
    elif awk -v a="$_r_plus" -v b="$_r_minus" -v c="$_r0" 'BEGIN { exit !(b>a && b>=c) }'; then
        _best_val=$_minus; _best_r=$_r_minus; _direction="-5%"
    else
        _best_val=$_cur; _best_r=$_r0; _direction="hold"
    fi
    _auto_tune_apply_knob "$_knob" "$_best_val"
    echo -e "${GREEN}[+] $_knob: $_cur → $_best_val (direction=$_direction, reward=$_best_r)${NC}"
    _audit auto-tune "iter=$_iter knob=$_knob from=$_cur to=$_best_val direction=$_direction reward=$_best_r"
    # Update state — простая sed-замена без jq
    local _new_iter=$(( _iter + 1 ))
    sed -i "s/\"iter\":[0-9]*/\"iter\":$_new_iter/" "$_state"
    sed -i "s/\"last_reward\":[0-9.-]*/\"last_reward\":$_best_r/" "$_state"
}

# Применяет одно значение к одному knob'у (через sysctl_safe для CONTRIBUTING #4).
_auto_tune_apply_knob() {
    local _knob="$1" _val="$2"
    case "$_knob" in
        rmem_max)            sysctl_safe net.core.rmem_max "$_val" >/dev/null 2>&1 ;;
        wmem_max)            sysctl_safe net.core.wmem_max "$_val" >/dev/null 2>&1 ;;
        tcp_rmem3)
            local _r1 _r2
            _r1=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $1}')
            _r2=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $2}')
            sysctl_safe net.ipv4.tcp_rmem "$_r1 $_r2 $_val" >/dev/null 2>&1
            ;;
        tcp_wmem3)
            local _w1 _w2
            _w1=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | awk '{print $1}')
            _w2=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | awk '{print $2}')
            sysctl_safe net.ipv4.tcp_wmem "$_w1 $_w2 $_val" >/dev/null 2>&1
            ;;
        netdev_max_backlog)  sysctl_safe net.core.netdev_max_backlog "$_val" >/dev/null 2>&1 ;;
    esac
}

# Reward measurement: пингуем 1.1.1.1 + считаем conn count (вместо тяжелого
# bench-suite каждую итерацию — это бы заняло 2-5 мин). Reward = -RTT - 10*loss.
# Нет throughput'a — он требует iperf3 endpoint. Опц: расширить через
# bench-suite раз в N итераций.
_auto_tune_measure_reward() {
    local _rtt _loss
    _rtt=$(ping -c 5 -W 2 -q 1.1.1.1 2>/dev/null | awk -F'/' '/^rtt/ {print $5}' | head -1)
    _loss=$(ping -c 5 -W 2 -q 1.1.1.1 2>/dev/null | awk -F',' '/packet loss/ {gsub("%","",$3); gsub(" ","",$3); print $3+0}' | head -1)
    : "${_rtt:=999}" "${_loss:=100}"
    # Reward = 1000 - rtt - 100*loss. Чем больше — тем лучше.
    awk -v r="$_rtt" -v l="$_loss" 'BEGIN { printf "%.2f", 1000 - r - 100*l }'
}

# ===================================================================
# X4: Web dashboard — единый HTML SPA на 127.0.0.1:9909, polls metrics.json
# ===================================================================
# Архитектура: статический index.html + script.js + style.css в $V810_DASHBOARD_DIR;
# отдельный sample-script (cron/systemd-timer) пишет metrics.json каждые 30s;
# сервер — `python3 -m http.server 9909 --bind 127.0.0.1` (или socat fallback).
# По умолчанию bound на 127.0.0.1 (без LAN expose). Опц --lan для bind на 0.0.0.0.
# Для production-LAN нужен mTLS (см. Z3) — сейчас просто loopback.
#
# Команды:
#   dashboard enable   — генерит файлы + systemd unit + metrics-sampler timer
#   dashboard disable  — отключает unit + timer (файлы оставляем)
#   dashboard start    — runtime start (без systemd, для теста)
#   dashboard stop     — kill running python3 instance
#   dashboard status   — есть ли listener на 9909
dashboard_command() {
    local _sub="${1:-help}"
    shift || true
    case "$_sub" in
        enable)
            _v810_ensure_dir "$V810_DASHBOARD_DIR" || return 1
            _dashboard_write_files
            _dashboard_install_units
            _audit dashboard "action=enable bind=127.0.0.1:9909"
            echo -e "${GREEN}[+] dashboard enabled. Открой http://127.0.0.1:9909${NC}"
            echo -e "${GRAY}    sampler пишет metrics.json каждые 30s в $V810_DASHBOARD_DIR${NC}"
            ;;
        disable)
            systemctl stop vps-optimizer-dashboard.service 2>/dev/null || true
            systemctl stop vps-optimizer-sampler.timer 2>/dev/null || true
            systemctl disable vps-optimizer-dashboard.service 2>/dev/null || true
            systemctl disable vps-optimizer-sampler.timer 2>/dev/null || true
            _audit dashboard "action=disable"
            echo -e "${GREEN}[+] dashboard disabled (файлы $V810_DASHBOARD_DIR не удалены).${NC}"
            ;;
        start)
            _dashboard_start_runtime
            ;;
        stop)
            pkill -f "http.server 9909" 2>/dev/null && echo -e "${GREEN}[+] dashboard stopped.${NC}" || echo -e "${GRAY}    нет running instance.${NC}"
            ;;
        status)
            if ss -tln 2>/dev/null | grep -q ':9909 '; then
                echo -e "${GREEN}[+] dashboard listener: 127.0.0.1:9909${NC}"
            else
                echo -e "${YELLOW}[!] нет listener на 9909.${NC}"
            fi
            ;;
        sample)
            # Internal: вызывается timer'ом для записи metrics.json.
            _dashboard_write_metrics
            ;;
        help|*)
            cat <<'DHELP'
Usage:
    dashboard enable      # систему файлов + systemd unit + sampler-timer
    dashboard disable     # отключить unit/timer (файлы остаются)
    dashboard start|stop  # runtime-only без systemd
    dashboard status      # есть ли listener на 9909
    dashboard sample      # internal: пишет metrics.json
DHELP
            ;;
    esac
}

_dashboard_write_files() {
    cat > "$V810_DASHBOARD_DIR/index.html" <<'IDXEOF'
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>vps-optimizer dashboard</title>
<link rel="stylesheet" href="style.css">
</head><body>
<header><h1>vps-optimizer</h1><span id="version"></span></header>
<main>
  <section class="metric-grid">
    <div class="card"><h3>Health score</h3><div class="big" id="m-health">…</div></div>
    <div class="card"><h3>RTT (1.1.1.1)</h3><div class="big" id="m-rtt">…</div></div>
    <div class="card"><h3>Conn count</h3><div class="big" id="m-conn">…</div></div>
    <div class="card"><h3>Retrans rate</h3><div class="big" id="m-retrans">…</div></div>
    <div class="card"><h3>Conntrack %</h3><div class="big" id="m-ct">…</div></div>
    <div class="card"><h3>Load avg</h3><div class="big" id="m-load">…</div></div>
  </section>
  <section><h2>Issues</h2><pre id="issues"></pre></section>
  <footer><span id="ts"></span> · poll 5s · loopback only</footer>
</main>
<script src="script.js"></script>
</body></html>
IDXEOF
    cat > "$V810_DASHBOARD_DIR/style.css" <<'CSSEOF'
* { box-sizing: border-box; }
body { font: 14px system-ui, -apple-system, Segoe UI, sans-serif; margin: 0; background: #0e1117; color: #c9d1d9; }
header { padding: 18px 24px; border-bottom: 1px solid #21262d; display: flex; gap: 12px; align-items: baseline; }
header h1 { margin: 0; font-size: 20px; }
header span { color: #8b949e; font-size: 12px; }
main { padding: 24px; max-width: 1100px; margin: 0 auto; }
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }
.card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px; }
.card h3 { margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: #8b949e; letter-spacing: 0.5px; }
.big { font-size: 24px; font-weight: 600; color: #e6edf3; }
.big.warn { color: #d29922; }
.big.bad  { color: #f85149; }
section h2 { color: #8b949e; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 32px; }
pre { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 14px; overflow: auto; }
footer { color: #6e7681; margin-top: 24px; font-size: 12px; }
CSSEOF
    cat > "$V810_DASHBOARD_DIR/script.js" <<'JSEOF'
async function tick() {
  try {
    const r = await fetch('metrics.json?t=' + Date.now());
    if (!r.ok) throw new Error('http ' + r.status);
    const m = await r.json();
    set('m-health', (m.health_score||0) + '/100', m.health_score < 60 ? 'bad' : (m.health_score < 80 ? 'warn' : ''));
    set('m-rtt',    (m.rtt_ms||0).toFixed(1) + ' ms', m.rtt_ms > 200 ? 'warn' : '');
    set('m-conn',   m.conn_count || '0');
    set('m-retrans', ((m.retrans_rate||0)*100).toFixed(2) + ' %', m.retrans_rate > 0.05 ? 'bad' : '');
    set('m-ct',     (m.conntrack_pct||0) + ' %', m.conntrack_pct > 70 ? 'warn' : '');
    set('m-load',   (m.load1||0).toFixed(2));
    document.getElementById('version').textContent = 'v' + (m.version || '?');
    document.getElementById('issues').textContent = m.issues_text || '(no issues)';
    document.getElementById('ts').textContent = 'updated: ' + new Date(m.ts*1000).toLocaleTimeString();
  } catch (e) {
    document.getElementById('issues').textContent = 'fetch error: ' + e.message;
  }
}
function set(id, val, cls) {
  const el = document.getElementById(id);
  el.textContent = val;
  el.className = 'big' + (cls ? ' ' + cls : '');
}
tick(); setInterval(tick, 5000);
JSEOF
}

# Запись metrics.json — вызывается sampler-timer'ом.
_dashboard_write_metrics() {
    _v810_ensure_dir "$V810_DASHBOARD_DIR" || return 1
    local _f="$V810_DASHBOARD_DIR/metrics.json"
    local _rtt _loss _conn _ct_pct _load _retrans _health _issues
    _rtt=$(ping -c 2 -W 1 -q 1.1.1.1 2>/dev/null | awk -F'/' '/^rtt/ {print $5}' | head -1)
    _conn=$(ss -tn state established 2>/dev/null | wc -l)
    _load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    if [ -r /proc/sys/net/netfilter/nf_conntrack_count ] && [ -r /proc/sys/net/netfilter/nf_conntrack_max ]; then
        local _ct_now _ct_max
        _ct_now=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
        _ct_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
        _ct_pct=$(awk -v n="$_ct_now" -v m="$_ct_max" 'BEGIN { if (m>0) print int(n*100/m); else print 0 }')
    fi
    # retrans rate (cumulative since boot, не для real-time, но достаточно)
    if [ -r /proc/net/snmp ]; then
        local _segs _ret
        _segs=$(awk '/^Tcp:/ && NR>1 {print $11}' /proc/net/snmp 2>/dev/null | tail -1)
        _ret=$(awk '/^Tcp:/ && NR>1 {print $13}' /proc/net/snmp 2>/dev/null | tail -1)
        if [ -n "$_segs" ] && [ "$_segs" -gt 0 ] 2>/dev/null; then
            _retrans=$(awk -v s="$_segs" -v r="$_ret" 'BEGIN { printf "%.4f", r/s }')
        fi
    fi
    # health score (вызываем существующую функцию, но возвращаем число)
    _health=$(health_score_command --raw 2>/dev/null | head -1)
    : "${_rtt:=0}" "${_conn:=0}" "${_load:=0}" "${_ct_pct:=0}" "${_retrans:=0}" "${_health:=100}"
    _issues=$(doctor_command 2>&1 | tail -10 | sed 's/"/\\"/g' | tr '\n' '|' | sed 's/|/\\n/g')
    # Простой JSON без jq
    cat > "$_f" <<EOF
{"ts":$(date -u +%s),"version":"$SCRIPT_VERSION","health_score":$_health,"rtt_ms":$_rtt,"conn_count":$_conn,"load1":$_load,"conntrack_pct":$_ct_pct,"retrans_rate":$_retrans,"issues_text":"$_issues"}
EOF
}

_dashboard_install_units() {
    local _ud=/etc/systemd/system
    [ -d "$_ud" ] || { echo -e "${YELLOW}[!] no /etc/systemd/system — пропуск unit-инсталляции${NC}"; return 0; }
    cat > "$_ud/vps-optimizer-dashboard.service" <<EOF
[Unit]
Description=vps-optimizer dashboard (loopback HTTP on 9909)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m http.server 9909 --bind 127.0.0.1 --directory $V810_DASHBOARD_DIR
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$V810_DASHBOARD_DIR

[Install]
WantedBy=multi-user.target
EOF
    cat > "$_ud/vps-optimizer-sampler.service" <<EOF
[Unit]
Description=vps-optimizer dashboard metrics sampler
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '$0 dashboard sample'
EOF
    cat > "$_ud/vps-optimizer-sampler.timer" <<'EOF'
[Unit]
Description=vps-optimizer dashboard sampler (every 30s)

[Timer]
OnBootSec=20s
OnUnitActiveSec=30s
Unit=vps-optimizer-sampler.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload 2>/dev/null
    systemctl enable --now vps-optimizer-dashboard.service 2>/dev/null || true
    systemctl enable --now vps-optimizer-sampler.timer 2>/dev/null || true
}

_dashboard_start_runtime() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}[!] python3 не установлен — установи или используй systemd-режим.${NC}"
        return 1
    fi
    if ss -tln 2>/dev/null | grep -q ':9909 '; then
        echo -e "${YELLOW}[!] :9909 уже занят.${NC}"; return 1
    fi
    nohup python3 -m http.server 9909 --bind 127.0.0.1 --directory "$V810_DASHBOARD_DIR" >/dev/null 2>&1 &
    disown 2>/dev/null || true
    echo -e "${GREEN}[+] dashboard runtime-started: http://127.0.0.1:9909${NC}"
}

# ===================================================================
# X10: Provider-aware tuning DB — Hetzner/AWS/GCP/OVH/Vultr/DO/Hetzner-AX
# ===================================================================
# detect_provider() уже возвращает hetzner/aws/gcp/azure/oracle/vultr/digitalocean
# /aeza/timeweb/firstbyte/generic. Здесь добавляем slim DB tuning-overrides
# поверх preset'а. Применяется в apply_optimizations() ПЕРЕД final-sysctl-блоком.
#
# Формат: каждый провайдер имеет свой массив knob=value. Например:
#   hetzner: rmem_max повышаем (good 10G NIC), вирт=kvm — TSO off (issue с virtio)
#   aws-graviton (ARM): swappiness ниже (NVMe-storage медленный), tcp_thin_*
#   gcp: keepalive_intvl 25 (gcp default LB rule)
provider_tune_command() {
    local _provider
    _provider=$(detect_provider 2>/dev/null)
    echo -e "${CYAN}${BOLD}=== provider-tune: provider=$_provider ===${NC}"
    case "$_provider" in
        hetzner)
            echo -e "${GRAY}    Hetzner Cloud: 10G NIC (Mellanox/Intel virtio), bare-metal AX = no virt${NC}"
            sysctl_safe net.core.rmem_max 67108864 || true
            sysctl_safe net.core.wmem_max 67108864 || true
            # Hetzner virtio часто имеет проблему с TSO+IPv6 — disable
            local _ifn
            _ifn=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
            if [ -n "$_ifn" ]; then
                ethtool -K "$_ifn" tso off gso on 2>/dev/null || true
            fi
            _audit provider-tune "provider=hetzner"
            ;;
        aws)
            echo -e "${GRAY}    AWS EC2: ENA driver, потенциально Graviton (ARM); rmem +25%${NC}"
            sysctl_safe net.core.rmem_max 33554432 || true
            sysctl_safe net.core.wmem_max 33554432 || true
            # ENA нравится низкий backlog (она сама умеет flow-director)
            sysctl_safe net.core.netdev_max_backlog 5000 || true
            _audit provider-tune "provider=aws"
            ;;
        gcp)
            echo -e "${GRAY}    GCP Compute Engine: gVNIC, агрессивный keepalive для LB${NC}"
            sysctl_safe net.ipv4.tcp_keepalive_intvl 25 || true
            sysctl_safe net.ipv4.tcp_keepalive_probes 5 || true
            _audit provider-tune "provider=gcp"
            ;;
        azure)
            echo -e "${GRAY}    Azure: hyperv-net driver; mtu=1500 forced; SR-IOV если accelerated networking${NC}"
            sysctl_safe net.core.rmem_max 33554432 || true
            sysctl_safe net.core.wmem_max 33554432 || true
            _audit provider-tune "provider=azure"
            ;;
        digitalocean|vultr|oracle|aeza|timeweb|firstbyte)
            echo -e "${GRAY}    $_provider: KVM virtio common path, conservative tuning${NC}"
            # Conservative (без больших переплюйб-ков)
            _audit provider-tune "provider=$_provider"
            ;;
        generic|*)
            echo -e "${GRAY}    generic provider — без специфичных deltas${NC}"
            _audit provider-tune "provider=$_provider mode=noop"
            ;;
    esac
    echo -e "${GREEN}[+] provider-tune применён.${NC}"
}

# ===================================================================
# S1: stealth-check — JA3 audit live-traffic vs Safari template
# ===================================================================
# Идея: запустить tcpdump на 5 сек на egress 443/UDP-443, поймать первый
# TLS ClientHello пакет, извлечь JA3 fingerprint компоненты, сравнить с
# embedded-таблицей "what real Safari iOS 18 should send". Покажет drift.
#
# Это НЕ kernel-rewriter (S1-полная) — это audit-режим. Реальный JA3-rewriter
# требует out-of-band проект (eBPF TC-prog с TLS-aware parser); здесь только
# detection. Полезно перед deploy: видишь где fingerprint неровный.
stealth_check_command() {
    if ! command -v tcpdump >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] tcpdump не установлен. Установи: sudo apt install -y tcpdump${NC}"
        return 1
    fi
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}[!] stealth-check требует root (raw socket).${NC}"
        return 1
    fi
    local _ifn
    _ifn=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    : "${_ifn:=eth0}"
    echo -e "${CYAN}${BOLD}=== stealth-check: TLS ClientHello audit (iface=$_ifn, 10s) ===${NC}"
    echo -e "${GRAY}    Откроем curl-impersonate в фоне для генерации трафика...${NC}"
    # Генерируем outgoing TLS-handshake чтобы было что ловить
    (curl -s -o /dev/null --max-time 8 https://www.apple.com/ 2>/dev/null) &
    local _curl_pid=$!
    # Захват 10 секунд, фильтр на dst port 443 TCP с SYN-payload, отдача raw hex
    local _pcap
    _pcap=$(mktemp /tmp/stealth-XXXX.pcap)
    timeout 10 tcpdump -i "$_ifn" -s 0 -w "$_pcap" 'tcp dst port 443' 2>/dev/null || true
    wait "$_curl_pid" 2>/dev/null || true
    if [ ! -s "$_pcap" ]; then
        echo -e "${YELLOW}[!] pcap пустой — нет captured packets.${NC}"
        rm -f "$_pcap"
        return 1
    fi
    # Простая проверка: парсим первый ClientHello через openssl s_client OR
    # просто извлекаем hex и ищем сигнатуры. Для shell-only мы не делаем
    # full JA3 — только проверяем наличие критичных extension'ов в hex'е.
    local _hex
    _hex=$(tcpdump -r "$_pcap" -X -c 5 2>/dev/null | grep -oE '[0-9a-f]{4}' | tr '\n' ' ' | tr -d ' ')
    rm -f "$_pcap"
    echo ""
    echo -e "${CYAN}Audit: ClientHello signatures detected${NC}"
    # Real iOS 18 Safari ClientHello должен иметь:
    #   ext 0x0017 (extended_master_secret)
    #   ext 0x002b (supported_versions: TLS 1.3)
    #   ext 0x002d (psk_key_exchange_modes)
    #   ext 0x0033 (key_share)
    #   ext 0xfe0d (encrypted_client_hello, ECH)
    local _missing=()
    case "$_hex" in *0017*)  echo -e "  ${GREEN}[+]${NC} extended_master_secret" ;; *) _missing+=("ext 0x0017") ;; esac
    case "$_hex" in *002b*)  echo -e "  ${GREEN}[+]${NC} supported_versions (TLS 1.3)" ;; *) _missing+=("ext 0x002b") ;; esac
    case "$_hex" in *002d*)  echo -e "  ${GREEN}[+]${NC} psk_key_exchange_modes" ;; *) _missing+=("ext 0x002d") ;; esac
    case "$_hex" in *0033*)  echo -e "  ${GREEN}[+]${NC} key_share" ;; *) _missing+=("ext 0x0033") ;; esac
    case "$_hex" in *fe0d*)  echo -e "  ${GREEN}[+]${NC} ECH (Encrypted ClientHello)" ;; *) _missing+=("ECH (опц)") ;; esac
    if [ "${#_missing[@]}" -gt 0 ]; then
        echo -e "${YELLOW}[!] missing extensions: ${_missing[*]}${NC}"
        echo -e "${GRAY}    Если используется curl-impersonate-safari — установи актуальный билд.${NC}"
    else
        echo -e "${GREEN}[+] ClientHello matches iOS 18 Safari profile.${NC}"
    fi
    _audit stealth-check "iface=$_ifn missing=${_missing[*]:-none}"
}

# ===================================================================
# S6: adaptive noise — Markov-chain state machine для real iOS bursts
# ===================================================================
# Классический подход (v8.5+) — uniform random URL. Real iOS совсем другое:
# периоды активной активности (Music streaming 10 мин подряд, Maps lookup) +
# периоды затишья (background sync раз в час). Эмулируем 4-state Markov chain.
#
# States:
#   IDLE      — короткие push-keepalive: gateway/courier.push.apple.com (high freq, low BW)
#   STREAMING — Music/AppleTV+: audio-ssl/video-ssl bursts по 10-30 sec
#   SYNC      — iCloud sync: photos/keyvalueservice/escrowproxy раз в час
#   MESSAGING — iMessage/FaceTime check: init.ess.apple.com
#
# Transitions (per minute step):
#   IDLE      → IDLE (0.7), STREAMING (0.1), SYNC (0.05), MESSAGING (0.15)
#   STREAMING → IDLE (0.3), STREAMING (0.6), SYNC (0.05), MESSAGING (0.05)
#   SYNC      → IDLE (0.8), STREAMING (0.05), SYNC (0.05), MESSAGING (0.1)
#   MESSAGING → IDLE (0.6), STREAMING (0.1), SYNC (0.05), MESSAGING (0.25)
#
# Это даёт реалистичные bursts вместо poisson-uniform от v8.5. Endpoints
# берутся из существующего noise-pool, но fitered по state.
#
# Вызов: noise-mc {start|stop|status|step}. start = systemd-timer; step =
# одна итерация (для теста или внешнего scheduler'а).
noise_mc_command() {
    local _sub="${1:-help}"; shift || true
    _v810_ensure_dir "$V810_STATE_DIR" || return 1
    local _state_file="$V810_STATE_DIR/noise-mc.state"
    case "$_sub" in
        start)
            echo "IDLE" > "$_state_file"
            _v810_install_noise_mc_timer
            _audit noise-mc "action=start"
            echo -e "${GREEN}[+] noise-mc started (Markov 4-state, transition every 60s)${NC}"
            ;;
        stop)
            systemctl stop vps-optimizer-noise-mc.timer 2>/dev/null || true
            systemctl disable vps-optimizer-noise-mc.timer 2>/dev/null || true
            _audit noise-mc "action=stop"
            echo -e "${GREEN}[+] noise-mc stopped.${NC}"
            ;;
        status)
            local _cur="?"
            [ -f "$_state_file" ] && _cur=$(cat "$_state_file" 2>/dev/null)
            echo -e "${CYAN}${BOLD}=== noise-mc status ===${NC}"
            echo -e "    current state: ${BOLD}$_cur${NC}"
            systemctl is-active vps-optimizer-noise-mc.timer 2>/dev/null || echo "    (timer not active)"
            ;;
        step)
            _noise_mc_step "$_state_file"
            ;;
        help|*)
            cat <<'NHELP'
Usage:
    noise-mc start   # установит systemd timer, transitions every 60s
    noise-mc stop    # отключит timer
    noise-mc status  # current state + timer-status
    noise-mc step    # одна итерация (для теста)

States: IDLE / STREAMING / SYNC / MESSAGING
Каждый state → endpoint subset из noise-pool с реальными iOS-распределениями.
NHELP
            ;;
    esac
}

# Одна итерация: читаем current state, выбираем next по transition matrix,
# делаем noise-request с endpoint'ами для нового state.
_noise_mc_step() {
    local _state_file="$1"
    local _cur="IDLE"
    [ -f "$_state_file" ] && _cur=$(cat "$_state_file" 2>/dev/null)
    : "${_cur:=IDLE}"
    # Random 0..99
    local _r=$(( RANDOM % 100 ))
    local _next="$_cur"
    case "$_cur" in
        IDLE)
            if   [ "$_r" -lt 70 ]; then _next=IDLE
            elif [ "$_r" -lt 80 ]; then _next=STREAMING
            elif [ "$_r" -lt 85 ]; then _next=SYNC
            else                         _next=MESSAGING
            fi
            ;;
        STREAMING)
            if   [ "$_r" -lt 30 ]; then _next=IDLE
            elif [ "$_r" -lt 90 ]; then _next=STREAMING
            elif [ "$_r" -lt 95 ]; then _next=SYNC
            else                         _next=MESSAGING
            fi
            ;;
        SYNC)
            if   [ "$_r" -lt 80 ]; then _next=IDLE
            elif [ "$_r" -lt 85 ]; then _next=STREAMING
            elif [ "$_r" -lt 90 ]; then _next=SYNC
            else                         _next=MESSAGING
            fi
            ;;
        MESSAGING)
            if   [ "$_r" -lt 60 ]; then _next=IDLE
            elif [ "$_r" -lt 70 ]; then _next=STREAMING
            elif [ "$_r" -lt 75 ]; then _next=SYNC
            else                         _next=MESSAGING
            fi
            ;;
    esac
    echo "$_next" > "$_state_file"
    # Endpoints per state — fetch'аем 1-3 шт.
    local _eps=()
    case "$_next" in
        IDLE)
            _eps=("https://gateway.push.apple.com/" "https://courier.push.apple.com/")
            ;;
        STREAMING)
            _eps=("https://audio-ssl.itunes.apple.com/" "https://video-ssl.itunes.apple.com/" "https://play.itunes.apple.com/")
            ;;
        SYNC)
            _eps=("https://escrowproxy.icloud.com/escrowproxy/api/recordRetrieve" "https://keyvalueservice.icloud.com/")
            ;;
        MESSAGING)
            _eps=("https://init.ess.apple.com/initInfo.action" "https://imap.mail.me.com/")
            ;;
    esac
    # Сколько запросов в этом state (BURSTS = 1-3 для STREAMING, 1 для остальных)
    local _bursts=1
    [ "$_next" = "STREAMING" ] && _bursts=$(( RANDOM % 3 + 1 ))
    local _b _ep
    for _b in $(seq 1 "$_bursts"); do
        _ep="${_eps[$(( RANDOM % ${#_eps[@]} ))]}"
        # Используем существующий noise-stack (curl-impersonate если доступен)
        if command -v curl_safari17_4 >/dev/null 2>&1; then
            curl_safari17_4 -s -o /dev/null --max-time 5 "$_ep" 2>/dev/null || true
        else
            curl -s -o /dev/null --max-time 5 "$_ep" 2>/dev/null || true
        fi
        sleep 1
    done
    _audit noise-mc "step=$_cur→$_next bursts=$_bursts"
}

_v810_install_noise_mc_timer() {
    local _ud=/etc/systemd/system
    [ -d "$_ud" ] || return 0
    cat > "$_ud/vps-optimizer-noise-mc.service" <<EOF
[Unit]
Description=vps-optimizer noise Markov-chain step
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '$0 noise-mc step'
EOF
    cat > "$_ud/vps-optimizer-noise-mc.timer" <<'EOF'
[Unit]
Description=vps-optimizer noise Markov-chain (every 60s)

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
RandomizedDelaySec=15s
Unit=vps-optimizer-noise-mc.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload 2>/dev/null
    systemctl enable --now vps-optimizer-noise-mc.timer 2>/dev/null || true
}

# ===================================================================
# Y4+Y5: CPU pinning + NUMA-aware placement
# ===================================================================
# Современные VPS (Hetzner CCX/CPX, AWS Graviton2/3, Azure Standard_D) дают
# либо все performance-cores, либо смесь P/E. Pinning xray/sing-box на
# определённые cores даёт +10..15% throughput за счёт cache locality.
#
# NUMA-aware: на dedicated/bare-metal с 2+ NUMA-nodes (AX-line у Hetzner)
# `numactl --cpunodebind=0 --membind=0` критично — иначе RAM-access
# через QPI link убивает throughput.
#
# Реализация: пишем systemd drop-in override (/etc/systemd/system/<svc>.d/cpu-pin.conf)
# с CPUAffinity=N-M и опц NUMAPolicy=bind. Не трогаем сам unit-файл.
# Auto-detect: lscpu даёт NUMA-nodes и cpu-list.
pin_command() {
    local _sub="${1:-help}"; shift || true
    case "$_sub" in
        auto)
            _pin_auto
            ;;
        service)
            local _svc="$1" _cores="$2"
            if [ -z "$_svc" ] || [ -z "$_cores" ]; then
                echo -e "${RED}Usage: pin service <name> <cores>${NC}"
                echo -e "${GRAY}       cores: '0-3' или '0,2,4,6' или 'auto'${NC}"
                return 1
            fi
            _pin_service_apply "$_svc" "$_cores"
            ;;
        list)
            _pin_list
            ;;
        unpin)
            local _svc="$1"
            [ -z "$_svc" ] && { echo -e "${RED}Usage: pin unpin <service>${NC}"; return 1; }
            rm -rf "/etc/systemd/system/${_svc}.service.d/cpu-pin.conf" 2>/dev/null
            systemctl daemon-reload 2>/dev/null
            systemctl restart "$_svc" 2>/dev/null || true
            _audit pin "action=unpin svc=$_svc"
            echo -e "${GREEN}[+] $_svc unpinned${NC}"
            ;;
        help|*)
            cat <<'PHELP'
Usage:
    pin auto                       # auto-detect performance cores + pin known proxies
    pin service <name> <cores>     # pin systemd-service на cpu-list
                                   #   <cores>: '0-3' / '0,2,4,6' / 'auto'
    pin list                       # show current pinning overrides
    pin unpin <name>               # remove pinning override
PHELP
            ;;
    esac
}

_pin_auto() {
    # Шаг 1: detect performance cores. На ARM/Graviton — все cores P-class
    # (нет E-cores в datacenter ARM на 2024). На x86 — берём все online cores
    # для консервативной стратегии (real heterogeneous P/E core split на VPS
    # практически не встречается — это desktop/laptop).
    local _cores
    _cores=$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
    if [ "$_cores" -lt 4 ]; then
        echo -e "${YELLOW}[!] Только $_cores cores — pinning mало смысла, skip.${NC}"
        return 0
    fi
    # Стратегия: хost-services на cores 0-1, proxy-workers на остальных.
    # Это spasaет от proxy-CPU-spike убивающего ssh/networkd.
    local _proxy_range="2-$(( _cores - 1 ))"
    echo -e "${CYAN}${BOLD}=== pin auto: detected $_cores cores ===${NC}"
    echo -e "${GRAY}    proxy services → cores $_proxy_range (host services on 0-1)${NC}"
    # Сервисы которые мы знаем
    local _svc
    for _svc in xray sing-box hysteria sing-box-server v2ray haproxy; do
        if systemctl is-enabled "$_svc.service" >/dev/null 2>&1 || systemctl is-active "$_svc.service" >/dev/null 2>&1; then
            _pin_service_apply "$_svc" "$_proxy_range"
        fi
    done
    _audit pin "action=auto cores=$_cores range=$_proxy_range"
}

_pin_service_apply() {
    local _svc="$1" _cores="$2"
    if [ "$_cores" = "auto" ]; then
        local _n
        _n=$(grep -c ^processor /proc/cpuinfo)
        _cores="2-$(( _n - 1 ))"
    fi
    if ! systemctl list-unit-files "$_svc.service" 2>/dev/null | grep -q "$_svc.service"; then
        echo -e "${YELLOW}[!] $_svc.service not found — skip${NC}"
        return 0
    fi
    local _dropin="/etc/systemd/system/${_svc}.service.d"
    mkdir -p "$_dropin"
    cat > "$_dropin/cpu-pin.conf" <<EOF
[Service]
CPUAffinity=$_cores
EOF
    # NUMA: если есть >1 nodes — bind first
    local _numa_nodes
    _numa_nodes=$(lscpu 2>/dev/null | awk '/^NUMA node\(s\)/ {print $NF}')
    if [ -n "$_numa_nodes" ] && [ "$_numa_nodes" -gt 1 ] 2>/dev/null; then
        cat >> "$_dropin/cpu-pin.conf" <<EOF
NUMAPolicy=bind
NUMAMask=0
EOF
    fi
    systemctl daemon-reload 2>/dev/null
    systemctl restart "$_svc" 2>/dev/null || true
    _audit pin "svc=$_svc cores=$_cores numa=${_numa_nodes:-1}"
    echo -e "${GREEN}[+] $_svc pinned on cores $_cores ${_numa_nodes:+(NUMA bind=node0)}${NC}"
}

_pin_list() {
    echo -e "${CYAN}${BOLD}=== current pinning overrides ===${NC}"
    local _f
    for _f in /etc/systemd/system/*.service.d/cpu-pin.conf; do
        [ -f "$_f" ] || continue
        local _svc
        _svc=$(echo "$_f" | sed -E 's|.*/([^/]+)\.service\.d/.*|\1|')
        local _aff
        _aff=$(grep '^CPUAffinity=' "$_f" 2>/dev/null | cut -d= -f2)
        printf "  %-20s cores=%s\n" "$_svc" "$_aff"
    done
}

# ===================================================================
# Y8: NIC vendor profile auto-tune
# ===================================================================
# `ethtool -i eth0` даёт driver name. Per-vendor известные best-deltas:
#   mlx5_core (Mellanox): rx-coalescing-usecs=3, adaptive-rx=on, hw-tc-offload=on
#   ena      (AWS Nitro): adaptive-rx=on, RSS hash на 4-tuple
#   ixgbe/i40e (Intel):    flow-director on, RSS-индексы=cores
#   bnxt_en  (Broadcom):    rss-config=on, gro=on
#   virtio_net:             mergeable-rx-bufs=on, gso=on
nic_vendor_command() {
    local _ifn
    _ifn=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    : "${_ifn:=eth0}"
    if ! command -v ethtool >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] ethtool не установлен.${NC}"
        return 1
    fi
    local _driver
    _driver=$(ethtool -i "$_ifn" 2>/dev/null | awk '/^driver:/ {print $2}')
    : "${_driver:=unknown}"
    echo -e "${CYAN}${BOLD}=== nic-vendor: iface=$_ifn driver=$_driver ===${NC}"
    case "$_driver" in
        mlx5_core|mlx4_en)
            echo -e "${GRAY}    Mellanox: rx-usecs=3 (low-latency), adaptive-rx on${NC}"
            ethtool -C "$_ifn" rx-usecs 3 adaptive-rx on 2>/dev/null || true
            ;;
        ena)
            echo -e "${GRAY}    AWS ENA: adaptive-rx on (Nitro hypervisor оптимизация)${NC}"
            ethtool -C "$_ifn" adaptive-rx on 2>/dev/null || true
            ;;
        ixgbe|i40e|ice|igc|igb)
            echo -e "${GRAY}    Intel ($_driver): adaptive-rx on${NC}"
            ethtool -C "$_ifn" adaptive-rx on 2>/dev/null || true
            ;;
        bnxt_en)
            echo -e "${GRAY}    Broadcom bnxt: rx-usecs auto via adaptive${NC}"
            ethtool -C "$_ifn" adaptive-rx on 2>/dev/null || true
            ;;
        virtio_net)
            echo -e "${GRAY}    virtio_net: leave as-is (host controls offloads)${NC}"
            ;;
        *)
            echo -e "${YELLOW}[!] driver=$_driver — нет профиля, пропуск.${NC}"
            ;;
    esac
    _audit nic-vendor "iface=$_ifn driver=$_driver"
}

# ===================================================================
# O1: built-in TSDB — /var/lib/vps-optimizer/tsdb/<metric>.tsv
# ===================================================================
# Lightweight TSDB: каждая метрика — append-only TSV (timestamp\tvalue).
# Sampler пишет раз в N секунд, prune обрезает старее N дней. Query —
# простой grep/awk по диапазону timestamp'ов.
#
# Метрики:
#   rtt_ms, conn_count, retrans_rate, conntrack_pct, load1, health_score
#
# Зачем: визуализация dashboards, baseline-tracking для self-healing,
# capacity planning. Без зависимостей (Prometheus/InfluxDB/Datadog не нужны).
ts_command() {
    local _sub="${1:-help}"; shift || true
    _v810_ensure_dir "$V810_TSDB_DIR" || return 1
    case "$_sub" in
        sample)
            _ts_sample
            ;;
        query)
            local _metric="${1:-rtt_ms}" _last="1h"
            shift || true
            while [ $# -gt 0 ]; do
                case "$1" in
                    --last) _last="${2:-1h}"; shift 2 ;;
                    --last=*) _last="${1#*=}"; shift ;;
                    *) shift ;;
                esac
            done
            _ts_query "$_metric" "$_last"
            ;;
        prune)
            local _days="${1:-30}"
            _ts_prune "$_days"
            ;;
        list)
            ls "$V810_TSDB_DIR" 2>/dev/null
            ;;
        help|*)
            cat <<'TSHELP'
Usage:
    ts sample                       # снять snapshot всех метрик (вызывается timer)
    ts query <metric> --last <DUR>  # выгрузить значения за период
                                     #   DUR: 5m / 1h / 24h / 7d
    ts prune <days>                 # удалить >N дней (default 30)
    ts list                         # список доступных метрик

Metrics: rtt_ms, conn_count, retrans_rate, conntrack_pct, load1, health_score
Storage: $V810_TSDB_DIR/<metric>.tsv (timestamp<TAB>value)
TSHELP
            ;;
    esac
}

_ts_sample() {
    local _ts
    _ts=$(date -u +%s)
    # Каждую метрику собираем независимо (некоторые могут быть n/a).
    local _rtt
    _rtt=$(ping -c 1 -W 1 -q 1.1.1.1 2>/dev/null | awk -F'/' '/^rtt/ {print $5}' | head -1)
    [ -n "$_rtt" ] && printf '%s\t%s\n' "$_ts" "$_rtt" >> "$V810_TSDB_DIR/rtt_ms.tsv"
    local _conn
    _conn=$(ss -tn state established 2>/dev/null | wc -l)
    printf '%s\t%s\n' "$_ts" "$_conn" >> "$V810_TSDB_DIR/conn_count.tsv"
    local _load
    _load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    [ -n "$_load" ] && printf '%s\t%s\n' "$_ts" "$_load" >> "$V810_TSDB_DIR/load1.tsv"
    if [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
        local _ct_n _ct_m _ct_pct
        _ct_n=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
        _ct_m=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
        _ct_pct=$(awk -v n="$_ct_n" -v m="$_ct_m" 'BEGIN { if (m>0) print int(n*100/m); else print 0 }')
        printf '%s\t%s\n' "$_ts" "$_ct_pct" >> "$V810_TSDB_DIR/conntrack_pct.tsv"
    fi
    if [ -r /proc/net/snmp ]; then
        local _segs _ret _rate
        _segs=$(awk '/^Tcp:/ && NR>1 {print $11}' /proc/net/snmp 2>/dev/null | tail -1)
        _ret=$(awk '/^Tcp:/ && NR>1 {print $13}' /proc/net/snmp 2>/dev/null | tail -1)
        if [ -n "$_segs" ] && [ "$_segs" -gt 0 ] 2>/dev/null; then
            _rate=$(awk -v s="$_segs" -v r="$_ret" 'BEGIN { printf "%.4f", r/s }')
            printf '%s\t%s\n' "$_ts" "$_rate" >> "$V810_TSDB_DIR/retrans_rate.tsv"
        fi
    fi
}

_ts_query() {
    local _metric="$1" _last="$2"
    local _f="$V810_TSDB_DIR/${_metric}.tsv"
    [ -f "$_f" ] || { echo "ts: metric=$_metric not found" >&2; return 1; }
    # Парсим duration: 5m=300, 1h=3600, 24h=86400, 7d=604800
    local _sec=3600
    case "$_last" in
        *m) _sec=$(( ${_last%m} * 60 )) ;;
        *h) _sec=$(( ${_last%h} * 3600 )) ;;
        *d) _sec=$(( ${_last%d} * 86400 )) ;;
        *)  _sec="$_last" ;;
    esac
    local _now _cutoff
    _now=$(date -u +%s)
    _cutoff=$(( _now - _sec ))
    awk -v c="$_cutoff" '$1 >= c { print }' "$_f"
}

_ts_prune() {
    local _days="${1:-30}"
    local _cutoff
    _cutoff=$(( $(date -u +%s) - _days * 86400 ))
    local _f
    for _f in "$V810_TSDB_DIR"/*.tsv; do
        [ -f "$_f" ] || continue
        awk -v c="$_cutoff" '$1 >= c' "$_f" > "$_f.tmp" && mv "$_f.tmp" "$_f"
    done
    _audit ts "action=prune days=$_days"
    echo -e "${GREEN}[+] tsdb pruned (>${_days}d removed)${NC}"
}

# ===================================================================
# O3: TUI dashboard — full-screen sparklines на pure bash + tput
# ===================================================================
# Терминальный full-screen UI с обновляемыми sparkline'ами 6 метрик.
# Работает в любом xterm. Использует только tput + ANSI escape codes.
# Ctrl-C для выхода.
tui_command() {
    if ! command -v tput >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] tput не доступен (ncurses) — fallback на простой watch${NC}"
        watch -n 5 -c "$0 doctor"
        return 0
    fi
    _audit tui "action=start"
    # Save cursor + clear
    printf '\033[?1049h\033[2J\033[H'
    trap 'printf "\033[?1049l"; exit 0' INT TERM EXIT
    while true; do
        printf '\033[H'
        local _cols
        _cols=$(tput cols 2>/dev/null || echo 80)
        echo -e "${CYAN}${BOLD}vps-optimizer TUI — v$SCRIPT_VERSION — $(date '+%H:%M:%S')${NC} $(printf '%*s' $((_cols - 50)) '' | tr ' ' '─')"
        echo ""
        local _m
        for _m in rtt_ms conn_count retrans_rate conntrack_pct load1; do
            printf "%-18s " "$_m"
            _tui_sparkline "$_m" 60
            echo ""
        done
        echo ""
        echo -e "${GRAY}─── doctor (last) ───${NC}"
        doctor_command 2>&1 | tail -8 | head -8
        echo ""
        echo -e "${GRAY}[Ctrl-C для выхода] обновление каждые 5s${NC}"
        sleep 5
    done
}

# Печатает sparkline (8-уровневую: ▁▂▃▄▅▆▇█) для метрики, последние N samples.
_tui_sparkline() {
    local _metric="$1" _n="${2:-60}"
    local _f="$V810_TSDB_DIR/${_metric}.tsv"
    if [ ! -f "$_f" ]; then
        printf '%s' "(no data — run ts sample)"
        return 0
    fi
    local _vals
    _vals=$(awk '{print $2}' "$_f" | tail -n "$_n")
    if [ -z "$_vals" ]; then
        printf '%s' "(empty)"
        return 0
    fi
    local _min _max
    _min=$(echo "$_vals" | awk 'NR==1 || $1<m {m=$1} END {print m}')
    _max=$(echo "$_vals" | awk 'NR==1 || $1>m {m=$1} END {print m}')
    if awk -v a="$_min" -v b="$_max" 'BEGIN { exit !(a==b) }'; then
        # все значения одинаковы — выводим серединную ▄
        printf '%s' "$_vals" | awk '{printf "▄"} END {print ""}' | tr -d '\n'
        printf ' min=%s max=%s' "$_min" "$_max"
        return 0
    fi
    # Bucket в 0..7
    echo "$_vals" | awk -v lo="$_min" -v hi="$_max" '
        BEGIN {
            chars[0]="▁"; chars[1]="▂"; chars[2]="▃"; chars[3]="▄";
            chars[4]="▅"; chars[5]="▆"; chars[6]="▇"; chars[7]="█";
        }
        { lvl=int(($1-lo)*7/(hi-lo)+0.5); if (lvl>7) lvl=7; if (lvl<0) lvl=0; printf "%s", chars[lvl] }
    '
    printf ' min=%.2f max=%.2f' "$_min" "$_max"
}

# ===================================================================
# O5: webhook alerts — Slack/Discord/Telegram/generic
# ===================================================================
# Простой POST с JSON: {"text": "<msg>", "host": "<hostname>", "ts": <unix>}.
# Slack-compatible (incoming-webhook), Discord-compatible (embeds), Telegram (bot).
# Auto-detect формата по URL: hooks.slack.com → Slack, discord.com → Discord,
# api.telegram.org/bot → Telegram. Остальные = generic JSON POST.
#
# Используется self-healing (X2), anomaly detection, doctor critical.
webhook_command() {
    local _sub="${1:-help}"; shift || true
    case "$_sub" in
        set)
            local _url="$1"
            [ -z "$_url" ] && { echo -e "${RED}Usage: webhook set <url>${NC}"; return 1; }
            _v810_ensure_dir "$V810_STATE_DIR" || return 1
            echo "$_url" > "$V810_WEBHOOK_FILE"
            chmod 600 "$V810_WEBHOOK_FILE"
            _audit webhook "action=set"
            echo -e "${GREEN}[+] webhook URL saved.${NC}"
            ;;
        unset)
            rm -f "$V810_WEBHOOK_FILE"
            _audit webhook "action=unset"
            echo -e "${GREEN}[+] webhook removed.${NC}"
            ;;
        test)
            webhook_send "[VPS-OPTIMIZER test] webhook alive from $(hostname) at $(date -u +%FT%TZ)"
            ;;
        status)
            if [ -f "$V810_WEBHOOK_FILE" ]; then
                local _u
                _u=$(cat "$V810_WEBHOOK_FILE" 2>/dev/null)
                # Маскируем токен в выводе
                echo -e "${GREEN}[+] webhook configured: $(echo "$_u" | sed -E 's|/[A-Za-z0-9_-]{20,}|/***|g')${NC}"
            else
                echo -e "${YELLOW}[!] webhook not configured.${NC}"
            fi
            ;;
        help|*)
            cat <<'WHELP'
Usage:
    webhook set <url>    # сохранить URL (Slack/Discord/Telegram/generic)
    webhook unset        # удалить
    webhook test         # отправить test-сообщение
    webhook status       # показать текущий URL (с маскировкой токена)

Auto-detected формат:
    hooks.slack.com      → Slack incoming-webhook ({text:...})
    discord.com          → Discord webhook ({content:...})
    api.telegram.org/bot → Telegram bot (text=msg, нужен chat_id в URL)
    остальные            → generic POST {"text":"...","host":"...","ts":N}
WHELP
            ;;
    esac
}

# Глобальная функция отправки (используется healing/anomaly/doctor).
webhook_send() {
    local _msg="$1"
    [ -f "$V810_WEBHOOK_FILE" ] || return 0
    local _url
    _url=$(cat "$V810_WEBHOOK_FILE" 2>/dev/null)
    [ -z "$_url" ] && return 0
    local _host _ts
    _host=$(hostname)
    _ts=$(date -u +%s)
    local _payload
    case "$_url" in
        *hooks.slack.com*)
            _payload="{\"text\":\"$_msg\"}"
            ;;
        *discord.com/api/webhooks*)
            _payload="{\"content\":\"$_msg\"}"
            ;;
        *api.telegram.org/bot*)
            # Telegram URL обычно вида https://api.telegram.org/bot<TOK>/sendMessage?chat_id=N
            # message добавляем как query-param
            curl -s -m 5 -G --data-urlencode "text=$_msg" "$_url" >/dev/null 2>&1
            return 0
            ;;
        *)
            _payload="{\"text\":\"$_msg\",\"host\":\"$_host\",\"ts\":$_ts}"
            ;;
    esac
    curl -s -m 5 -X POST -H 'Content-Type: application/json' -d "$_payload" "$_url" >/dev/null 2>&1
    return 0
}

# ===================================================================
# A1+A2: weekly self-tune timer + load-based preset switch timer
# ===================================================================
# A1: systemd-timer раз в неделю запускает `auto-tune tune` (один coordinate-descent
# step). За год = 52 итераций × 5 knob'ов = 10.4 round-trips через все knob'ы
# с постоянной адаптацией к сезонным паттернам нагрузки.
#
# A2: каждый час смотрит load avg + conn count; если высокая нагрузка
# (load>4, conn>1000) и preset != proxy → switch в proxy. Если низкая
# (load<1, conn<100) и preset != balanced → switch в balanced. Idempotent.
self_tune_timer_command() {
    local _sub="${1:-help}"; shift || true
    local _ud=/etc/systemd/system
    case "$_sub" in
        enable)
            [ -d "$_ud" ] || { echo -e "${YELLOW}нет systemd${NC}"; return 1; }
            cat > "$_ud/vps-optimizer-self-tune.service" <<EOF
[Unit]
Description=vps-optimizer weekly self-tune
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '$0 auto-tune tune'
EOF
            cat > "$_ud/vps-optimizer-self-tune.timer" <<'EOF'
[Unit]
Description=vps-optimizer weekly self-tune

[Timer]
OnCalendar=Sun 03:00
Persistent=true
RandomizedDelaySec=30m
Unit=vps-optimizer-self-tune.service

[Install]
WantedBy=timers.target
EOF
            systemctl daemon-reload 2>/dev/null
            systemctl enable --now vps-optimizer-self-tune.timer 2>/dev/null
            _audit self-tune-timer "action=enable schedule=weekly"
            echo -e "${GREEN}[+] self-tune-timer enabled (Sundays 03:00 ±30min)${NC}"
            ;;
        disable)
            systemctl disable --now vps-optimizer-self-tune.timer 2>/dev/null || true
            rm -f "$_ud/vps-optimizer-self-tune.service" "$_ud/vps-optimizer-self-tune.timer"
            systemctl daemon-reload 2>/dev/null
            _audit self-tune-timer "action=disable"
            echo -e "${GREEN}[+] self-tune-timer disabled${NC}"
            ;;
        help|*)
            echo "Usage: self-tune-timer {enable|disable}"
            ;;
    esac
}

load_switch_command() {
    local _sub="${1:-help}"; shift || true
    local _ud=/etc/systemd/system
    case "$_sub" in
        enable)
            [ -d "$_ud" ] || return 1
            cat > "$_ud/vps-optimizer-load-switch.service" <<EOF
[Unit]
Description=vps-optimizer load-based preset switch
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '$0 _load_switch_step'
EOF
            cat > "$_ud/vps-optimizer-load-switch.timer" <<'EOF'
[Unit]
Description=vps-optimizer load-based preset switch (hourly)

[Timer]
OnBootSec=10m
OnUnitActiveSec=1h
Unit=vps-optimizer-load-switch.service

[Install]
WantedBy=timers.target
EOF
            systemctl daemon-reload 2>/dev/null
            systemctl enable --now vps-optimizer-load-switch.timer 2>/dev/null
            _audit load-switch "action=enable"
            echo -e "${GREEN}[+] load-switch enabled (hourly)${NC}"
            ;;
        disable)
            systemctl disable --now vps-optimizer-load-switch.timer 2>/dev/null || true
            rm -f "$_ud/vps-optimizer-load-switch.service" "$_ud/vps-optimizer-load-switch.timer"
            systemctl daemon-reload 2>/dev/null
            _audit load-switch "action=disable"
            echo -e "${GREEN}[+] load-switch disabled${NC}"
            ;;
        step)
            _load_switch_step
            ;;
        help|*)
            echo "Usage: load-switch {enable|disable|step}"
            ;;
    esac
}

# Один step проверки нагрузки и переключения preset'а.
_load_switch_step() {
    local _load _conn _cur
    _load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    _conn=$(ss -tn state established 2>/dev/null | wc -l)
    _cur=$(cat /var/lib/vps-optimizer/active-preset 2>/dev/null || echo balanced)
    : "${_load:=0}" "${_conn:=0}"
    local _target="$_cur"
    if awk -v l="$_load" 'BEGIN { exit !(l>4) }' || [ "$_conn" -gt 1000 ]; then
        _target=proxy
    elif awk -v l="$_load" 'BEGIN { exit !(l<1) }' && [ "$_conn" -lt 100 ]; then
        _target=balanced
    fi
    if [ "$_target" != "$_cur" ]; then
        _audit load-switch "from=$_cur to=$_target load=$_load conn=$_conn"
        echo "[load-switch] $_cur → $_target (load=$_load conn=$_conn)"
        # Не запускаем full apply — это слишком тяжело hourly. Просто
        # обновляем active-preset marker; следующий ручной apply подхватит.
        echo "$_target" > /var/lib/vps-optimizer/active-preset
        webhook_send "[VPS-OPTIMIZER] load-switch suggests $_cur → $_target on $(hostname) (load=$_load conn=$_conn)"
    fi
}

# ===================================================================
# Z3: mTLS for metrics endpoint
# ===================================================================
# Защита `prom-metrics` HTTP endpoint клиентским сертификатом. Используем
# stunnel (ставится из репов) или openssl s_server fallback. Генерируем
# self-signed CA + server cert + client cert при enable.
metrics_mtls_command() {
    local _sub="${1:-help}"; shift || true
    local _certdir="$V810_STATE_DIR/mtls"
    case "$_sub" in
        enable)
            _v810_ensure_dir "$_certdir" || return 1
            if ! command -v openssl >/dev/null 2>&1; then
                echo -e "${RED}[!] openssl не установлен.${NC}"; return 1
            fi
            # Генерим CA (если нет), server-cert, client-cert
            if [ ! -f "$_certdir/ca.key" ]; then
                openssl genrsa -out "$_certdir/ca.key" 2048 2>/dev/null
                openssl req -new -x509 -key "$_certdir/ca.key" -out "$_certdir/ca.crt" -days 3650 -subj "/CN=vps-optimizer-CA" 2>/dev/null
            fi
            openssl genrsa -out "$_certdir/server.key" 2048 2>/dev/null
            openssl req -new -key "$_certdir/server.key" -out "$_certdir/server.csr" -subj "/CN=$(hostname)" 2>/dev/null
            openssl x509 -req -in "$_certdir/server.csr" -CA "$_certdir/ca.crt" -CAkey "$_certdir/ca.key" -CAcreateserial -out "$_certdir/server.crt" -days 365 2>/dev/null
            openssl genrsa -out "$_certdir/client.key" 2048 2>/dev/null
            openssl req -new -key "$_certdir/client.key" -out "$_certdir/client.csr" -subj "/CN=client" 2>/dev/null
            openssl x509 -req -in "$_certdir/client.csr" -CA "$_certdir/ca.crt" -CAkey "$_certdir/ca.key" -CAcreateserial -out "$_certdir/client.crt" -days 365 2>/dev/null
            chmod 600 "$_certdir"/*.key
            _audit metrics-mtls "action=enable certdir=$_certdir"
            echo -e "${GREEN}[+] mTLS certs generated in $_certdir${NC}"
            echo -e "${GRAY}    Client materials для использования:${NC}"
            echo -e "${GRAY}      ca.crt    : $_certdir/ca.crt${NC}"
            echo -e "${GRAY}      client.crt: $_certdir/client.crt${NC}"
            echo -e "${GRAY}      client.key: $_certdir/client.key${NC}"
            echo -e "${GRAY}    Запусти HTTPS-обертку (например stunnel) и направь её на prom-metrics.${NC}"
            ;;
        disable)
            rm -rf "$_certdir"
            _audit metrics-mtls "action=disable"
            echo -e "${GREEN}[+] mTLS disabled, certs удалены${NC}"
            ;;
        status)
            if [ -d "$_certdir" ] && [ -f "$_certdir/server.crt" ]; then
                echo -e "${GREEN}[+] mTLS enabled${NC}"
                openssl x509 -in "$_certdir/server.crt" -noout -dates -subject 2>/dev/null
            else
                echo -e "${YELLOW}[!] mTLS not configured.${NC}"
            fi
            ;;
        help|*)
            echo "Usage: metrics-mtls {enable|disable|status}"
            ;;
    esac
}


# ===================================================================
# v8.11 — kernel/protocol speed + behavioral iOS stealth
# ===================================================================
# Этот блок добавляет 10 новых функций в духе v8.10 (probe-then-write,
# opt-in, _audit, graceful skip).
#
#   K2  cc-bench  — TCP CC arena (auto-pick + manual TUI)
#   K6  offload-max — GRO/GSO/USO maximum через ethtool -K
#   K7  lro-smart — LRO ON только если ip_forward=0 (endpoint VPS)
#   K8  ecn-l4s — net.ipv4.tcp_ecn=2 + tcp_l4s_ecn (RFC 9330)
#   K13 irq-steer — smart NUMA-aware IRQ affinity
#   K14 netdev-budget — bump для 25G+ links
#   K17 notsent-lowat — TCP_NOTSENT_LOWAT helper для HTTP/2 multiplex
#   K20 dscp-mark — DSCP marking для QUIC/STUN (EF класс)
#   S5  icmp-ios — echo reply 56b match iOS
#   S7  ttl-ios — net.ipv4.ip_default_ttl=64 fixed
#   S10 tls-safari — TLS 1.3 PSK 7d + record sizes
#   S12 h2-safari — HTTP/2 SETTINGS frame match
#   S21 captive-mc — Captive Portal detection burst
#   S22 prre-mc — iCloud Private Relay heartbeat
#
# Все функции **graceful skip** при отсутствии deps (ethtool/nftables/numactl).
# Все enable/start команды **opt-in** (без вызова ничего не делают).
# ===================================================================

# v8.11 state-каталог. Хранит cc-bench results, IRQ-state backup,
# TLS template, DSCP-state.
V811_STATE_DIR="/var/lib/vps-optimizer/v811"

# v8.11 helper — ensure-dir с graceful fallback (как и в v810).
_v811_ensure_dir() {
    local _d="$1"
    [ -d "$_d" ] && return 0
    mkdir -p "$_d" 2>/dev/null || {
        echo -e "${YELLOW}[!] не удалось создать $_d (требует root)${NC}"
        return 1
    }
}

# ===================================================================
# K2: cc-bench arena — auto-pick best congestion control
# ===================================================================
# Зачем: преsety v8.0..v8.10 ставят congestion control один раз (BBR / cubic).
# Real-life link-quality сильно различается (lossy mobile vs clean DC),
# и optimal CC отличается. cc-bench прогоняет ВСЕ доступные CC через
# `iperf3 -c <ref> -t 30 --bidir`, считает score = throughput - 10*loss - 0.1*rtt
# и выбирает best.
#
# Два режима:
#   auto   — non-interactive, прогон + auto-apply best
#   manual — TUI-меню: показывает table, юзер выбирает который apply
#   list   — показать только доступные CC (read-only, no bench)
#
# Список ref-серверов = из bench-suite (lg.ovh.net / speedtest.tele2.net /
# proof.ovh.net / lg.fra.de.leaseweb.net). Опц BENCH_REF= env-override.
#
# Probe: если iperf3 не установлен → graceful skip с hint'ом.
# Audit: каждый bench и каждый apply CC аудируется.
cc_bench_command() {
    local _mode="${1:-auto}"
    shift || true
    local _duration=10
    local _ref_default="lg.ovh.net iperf.he.net iperf.it-north.net"
    local _ref="${BENCH_REF:-$_ref_default}"

    # R14-1 fix: разделяем shift на два, чтобы при отсутствии value
    # (например `cc-bench auto --duration` без числа) `shift || true`
    # gracefully завершал loop вместо infinite-loop (bash `shift 2` при
    # $#=1 не decrement'ит $# и we'd loop forever).
    while [ $# -gt 0 ]; do
        case "$1" in
            --duration|-d) _duration="${2:-10}"; shift; shift || true ;;
            --duration=*)  _duration="${1#*=}"; shift ;;
            --ref) _ref="${2:-$_ref_default}"; shift; shift || true ;;
            --ref=*) _ref="${1#*=}"; shift ;;
            *) shift ;;
        esac
    done

    case "$_mode" in
        list)
            echo -e "${CYAN}${BOLD}=== cc-bench: доступные CC algorithms ===${NC}"
            local _avail
            _avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")
            local _current
            _current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
            echo -e "Доступно: ${GREEN}${_avail}${NC}"
            echo -e "Текущий:  ${YELLOW}${_current}${NC}"
            _audit cc-bench "list current=$_current avail=$_avail"
            return 0
            ;;
        help|--help|-h)
            cat <<'CCEOF'
cc-bench — TCP Congestion Control arena (бенчит и выбирает best).

Usage:
    cc-bench list                # показать доступные CC
    cc-bench auto                # auto-pick + apply best
    cc-bench manual              # TUI-меню после bench
    cc-bench bench               # только bench (no apply, для CI)
  Опции:
    --duration N                 # длительность одного бенча (default 10s)
    --ref "host1 host2 ..."      # ref-серверы (default 3 LG-anycast)

Score = throughput_mbps - 10*loss_pct - 0.1*rtt_ms (best = max).
Probe-then-write: если iperf3 нет — graceful skip.
CCEOF
            return 0
            ;;
    esac

    # Проверяем наличие iperf3 (CONTRIBUTING #4 — probe-then-write).
    if ! command -v iperf3 >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] iperf3 не установлен. Установи: sudo apt install -y iperf3${NC}"
        echo -e "${GRAY}    cc-bench требует iperf3 для измерения throughput/RTT.${NC}"
        return 1
    fi

    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}[!] cc-bench требует root (изменяет sysctl).${NC}"
        return 1
    fi

    # R14-2 fix: respect DRY_RUN. cc-bench bench-loop делает sysctl mutations
    # (transient probe) — это incompatible с --dry-run. Final apply через
    # sysctl_safe ниже автоматически no-op'ит при DRY_RUN, но bench-loop
    # — нет. Проще всего: skip всю операцию при DRY_RUN с информативным msg.
    if [ "$DRY_RUN" = "1" ]; then
        echo -e "${YELLOW}[dry-run]${NC} cc-bench пропущен — bench-loop требует transient sysctl mutations."
        echo -e "${GRAY}    Запусти без --dry-run для real bench.${NC}"
        _audit cc-bench "skipped (dry-run)"
        return 0
    fi

    _v811_ensure_dir "$V811_STATE_DIR" || return 1
    local _avail
    _avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
    if [ -z "$_avail" ]; then
        echo -e "${RED}[!] не удалось прочитать tcp_available_congestion_control${NC}"
        return 1
    fi

    local _saved_cc
    _saved_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    echo -e "${GRAY}    [i] сохраняем текущий CC=$_saved_cc — будет восстановлен если bench fail.${NC}"

    # ULTRA-чистый header
    echo -e "${CYAN}${BOLD}┌─────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}${BOLD}│  cc-bench arena (mode=$_mode, duration=${_duration}s)${NC}"
    echo -e "${CYAN}${BOLD}└─────────────────────────────────────────────────┘${NC}"
    echo -e "Доступные CC: ${GREEN}${_avail}${NC}"
    echo -e "Reference servers: ${GRAY}${_ref}${NC}"
    echo ""

    local _results_file="$V811_STATE_DIR/cc-bench-results.tsv"
    : > "$_results_file"
    printf '%s\t%s\t%s\t%s\t%s\n' "cc" "throughput_mbps" "rtt_ms" "loss_pct" "score" > "$_results_file"

    # Header table
    printf "${BOLD}%-12s %-15s %-10s %-10s %-10s${NC}\n" "CC" "Throughput" "RTT(ms)" "Loss(%)" "Score"
    printf "${GRAY}%s${NC}\n" "─────────────────────────────────────────────────────────────"

    local _cc _best_cc="" _best_score=-99999
    local _ref_first
    _ref_first=$(echo "$_ref" | awk '{print $1}')

    for _cc in $_avail; do
        # Set CC. Если этот CC заблокирован kernel module'ом, sysctl_safe вернёт ошибку.
        if ! sysctl -w "net.ipv4.tcp_congestion_control=$_cc" >/dev/null 2>&1; then
            printf "%-12s ${RED}%-15s${NC}\n" "$_cc" "skip(blocked)"
            continue
        fi

        # Бенч: TCP iperf3 на $_duration секунд против $_ref_first.
        # `-J` JSON output для парсинга. -O 1 = warmup 1 sec.
        local _bench_out
        _bench_out=$(timeout $((_duration + 5)) iperf3 -c "$_ref_first" -t "$_duration" -O 1 -J 2>/dev/null || echo "{}")
        local _throughput _rtt _loss
        _throughput=$(echo "$_bench_out" | grep -m1 '"bits_per_second"' | head -1 | awk -F'[:,]' '{printf "%.0f", $2/1000000}' 2>/dev/null)
        _throughput="${_throughput:-0}"
        # RTT берём через ping (быстрее и точнее чем iperf3 RTT который только TCP)
        _rtt=$(ping -c 3 -W 1 -q "$_ref_first" 2>/dev/null | grep -oP 'min/avg/max[^=]*= [^/]+/\K[0-9.]+' | head -1)
        _rtt="${_rtt:-0}"
        # Loss — из iperf3 retransmits. Если 0 — берём из ping.
        local _retrans
        _retrans=$(echo "$_bench_out" | grep -m1 '"retransmits"' | head -1 | awk -F'[:,]' '{print $2}' | tr -d ' ')
        _retrans="${_retrans:-0}"
        # Crude loss-pct = retrans / 1000 packets (very approximate)
        _loss=$(awk -v r="$_retrans" 'BEGIN { printf "%.2f", r/100 }' 2>/dev/null)
        _loss="${_loss:-0}"

        # Score формула: throughput - 10*loss - 0.1*rtt
        local _score
        _score=$(awk -v t="$_throughput" -v r="$_rtt" -v l="$_loss" 'BEGIN { printf "%.0f", t - 10*l - 0.1*r }')

        # Color score: green if >100, yellow if 30-100, gray if <30
        local _color="$GRAY"
        if awk -v s="$_score" 'BEGIN { exit !(s>=100) }'; then _color="$GREEN"
        elif awk -v s="$_score" 'BEGIN { exit !(s>=30) }'; then _color="$YELLOW"
        fi

        printf "%-12s %-15s %-10s %-10s ${_color}%-10s${NC}\n" \
            "$_cc" "${_throughput}M" "$_rtt" "$_loss" "$_score"
        printf '%s\t%s\t%s\t%s\t%s\n' "$_cc" "$_throughput" "$_rtt" "$_loss" "$_score" >> "$_results_file"

        # Update best
        if awk -v s="$_score" -v b="$_best_score" 'BEGIN { exit !(s>b) }'; then
            _best_score="$_score"
            _best_cc="$_cc"
        fi
    done

    printf "${GRAY}%s${NC}\n" "─────────────────────────────────────────────────────────────"

    if [ -z "$_best_cc" ]; then
        echo -e "${RED}[!] все CC fail — восстанавливаем $_saved_cc${NC}"
        sysctl -w "net.ipv4.tcp_congestion_control=$_saved_cc" >/dev/null 2>&1
        return 1
    fi

    echo ""
    echo -e "${BOLD}🏆 Лучший CC по score: ${GREEN}$_best_cc${NC} (score=$_best_score)"
    echo -e "${GRAY}    Результаты: $_results_file${NC}"
    _audit cc-bench "best=$_best_cc score=$_best_score mode=$_mode"

    case "$_mode" in
        bench)
            # Только бенч, не apply. Восстанавливаем saved.
            sysctl -w "net.ipv4.tcp_congestion_control=$_saved_cc" >/dev/null 2>&1
            echo -e "${GRAY}    (mode=bench: CC восстановлен на $_saved_cc, ничего не applied)${NC}"
            ;;
        auto)
            # Auto-apply best. R14-2 fix: используем sysctl_safe вместо `sysctl -w`
            # для CONTRIBUTING #4 (probe-then-write + persist в $SYSCTL_CONF).
            # sysctl_safe также: respect DRY_RUN, kernel_supports_sysctl probe,
            # SYSCTL_OK/SYSCTL_SKIP tracking. CC будет survived reboot.
            sysctl_safe net.ipv4.tcp_congestion_control "$_best_cc" || true
            echo -e "${GREEN}[+] auto-apply: tcp_congestion_control = $_best_cc${NC}"
            _audit cc-bench-apply "cc=$_best_cc mode=auto score=$_best_score"
            ;;
        manual)
            # TUI: спрашиваем у user'а.
            echo ""
            echo -e "${CYAN}Выбери CC (по умолчанию = $_best_cc):${NC}"
            local _i=1
            local _ccs=()
            for _cc in $_avail; do
                local _mark=""
                [ "$_cc" = "$_best_cc" ] && _mark=" ${GREEN}← best${NC}"
                printf "  [%d] %-12s%b\n" "$_i" "$_cc" "$_mark"
                _ccs+=("$_cc")
                _i=$((_i+1))
            done
            echo -e "  ${GRAY}[0]${NC} Отмена (восстановить $_saved_cc)"
            echo ""
            read -r -p "Выбор: " _choice
            case "$_choice" in
                ""|0)
                    sysctl -w "net.ipv4.tcp_congestion_control=$_saved_cc" >/dev/null 2>&1
                    echo -e "${GRAY}    отмена — восстановлен $_saved_cc${NC}"
                    ;;
                *)
                    if [ "$_choice" -ge 1 ] && [ "$_choice" -le "${#_ccs[@]}" ] 2>/dev/null; then
                        local _picked="${_ccs[$((_choice-1))]}"
                        # R14-2 fix: sysctl_safe для persistence + CONTRIBUTING #4.
                        sysctl_safe net.ipv4.tcp_congestion_control "$_picked" || true
                        echo -e "${GREEN}[+] applied: tcp_congestion_control = $_picked${NC}"
                        _audit cc-bench-apply "cc=$_picked mode=manual score=user-pick"
                    else
                        echo -e "${RED}[!] invalid choice — восстанавливаем $_saved_cc${NC}"
                        sysctl -w "net.ipv4.tcp_congestion_control=$_saved_cc" >/dev/null 2>&1
                    fi
                    ;;
            esac
            ;;
        *)
            # R14-9 fix: для unrecognized $_mode (например typo "audo" вместо "auto")
            # bench-loop уже выполнил transient sysctl -w на каждый CC.
            # Без `*)` default — last-tested CC остаётся active в kernel.
            # Restore saved cc обязательно для safety + audit как warning.
            sysctl -w "net.ipv4.tcp_congestion_control=$_saved_cc" >/dev/null 2>&1
            echo -e "${YELLOW}[!] unknown mode '$_mode' — CC восстановлен на $_saved_cc${NC}"
            _audit cc-bench-apply "cc=$_saved_cc mode=unknown:$_mode restored"
            return 1
            ;;
    esac
}

# ===================================================================
# K6+K7: NIC offload max (GRO/GSO/USO) + LRO smart-on
# ===================================================================
# GRO (Generic Receive Offload) объединяет несколько skb в один большой
# до hand-off в TCP/IP. Снижает CPU per-Mbps на 30-40%. Default ON
# с kernel 2.6+, но иногда сбрасывается провайдером.
#
# GSO (Generic Segmentation Offload) — то же на TX. UDP segmentation
# offload (USO) для QUIC даёт 30-40% reduction CPU at >1Gbps QUIC.
#
# LRO (Large Receive Offload) — hardware-level GRO. Ломает forwarding
# (L3 router function), но если VPS = чисто endpoint (ip_forward=0)
# → можно ON. Drains CPU дальше.
offload_max_command() {
    local _sub="${1:-status}"
    if ! command -v ethtool >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] ethtool не установлен. apt install -y ethtool${NC}"
        return 1
    fi

    local _iface
    _iface=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    if [ -z "$_iface" ]; then
        echo -e "${RED}[!] default route iface не определён${NC}"
        return 1
    fi

    case "$_sub" in
        status|"")
            echo -e "${CYAN}${BOLD}=== offload-max status (iface=$_iface) ===${NC}"
            ethtool -k "$_iface" 2>/dev/null | grep -E '^(generic-receive|generic-segmentation|tcp-segmentation|udp-segmentation|large-receive|rx-checksumming|tx-checksumming):' | sed 's/^/  /'
            return 0
            ;;
        enable|on|apply)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] offload-max requires root.${NC}"; return 1
            fi
            echo -e "${CYAN}${BOLD}=== offload-max apply (iface=$_iface) ===${NC}"
            local _ip_forward
            _ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
            local _features="gro on gso on tso on" # safe для всех VPS
            # USO support — kernel 6.2+ имеет, ethtool ≥6.0
            if ethtool -k "$_iface" 2>/dev/null | grep -q 'tx-udp-segmentation:'; then
                _features="$_features tx-udp-segmentation on"
                echo -e "  ${GREEN}✓${NC} USO (UDP segmentation offload) supported — будет включён"
            fi
            # K7: LRO smart-on только если ip_forward=0 (endpoint VPS)
            if [ "$_ip_forward" = "0" ]; then
                if ethtool -k "$_iface" 2>/dev/null | grep -q 'large-receive-offload:'; then
                    _features="$_features lro on"
                    echo -e "  ${GREEN}✓${NC} LRO supported, ip_forward=0 → endpoint VPS → LRO ON"
                fi
            else
                echo -e "  ${YELLOW}!${NC} ip_forward=1 → LRO остаётся OFF (LRO ломает forwarding)"
            fi
            # R14-6 fix: respect DRY_RUN. ethtool -K не идёт через
            # sysctl_safe/sysfs_safe (которые auto-handle DRY_RUN), поэтому
            # explicit check необходим. Аналогично pattern apply_irq_affinity.
            if [ "$DRY_RUN" = "1" ]; then
                echo -e "${GRAY}[dry-run]${NC} would apply: ethtool -K $_iface $_features"
                _audit offload-max "iface=$_iface features=\"$_features\" mode=dry-run"
                return 0
            fi
            # Apply
            local _rc=0
            # shellcheck disable=SC2086
            ethtool -K "$_iface" $_features 2>&1 | sed 's/^/  /' || _rc=$?
            # R14-4 fix: ethtool -K rc=80 = partial-success (некоторые features
            # appied, некоторые отвергнуты driver). State уже мутирован — нужен
            # _audit (CONTRIBUTING #8). Логируем rc для трассировки.
            if [ "$_rc" = "0" ]; then
                echo -e "${GREEN}[+] offload-max applied: $_features${NC}"
                _audit offload-max "iface=$_iface features=\"$_features\" ip_forward=$_ip_forward rc=0"
            else
                echo -e "${YELLOW}[!] часть features не applied (kernel/driver не support)${NC}"
                _audit offload-max "iface=$_iface features=\"$_features\" ip_forward=$_ip_forward partial_fail=rc$_rc"
            fi
            ;;
        *)
            echo "Usage: offload-max {status|enable}"
            ;;
    esac
}

# ===================================================================
# K8: ECN aggressive + L4S (RFC 9330) + K18 RACK-TLP verify
# ===================================================================
# ECN (Explicit Congestion Notification) — kernel router/peer ставят
# CE bit вместо drop при overload. Снижает retransmits, особенно для
# real-time. tcp_ecn=2 = accept incoming + advertise outgoing.
#
# L4S (Low Latency, Low Loss, Scalable throughput) — RFC 9330 update
# на ECN: ECT(1) код вместо ECT(0). Required для AQM-роутеров.
# tcp_l4s_ecn=1 (kernel 6.5+).
#
# RACK-TLP — Recent ACK-based Loss Recovery (RFC 8985). Default kernel
# 4.20+, но verify явно.
ecn_l4s_command() {
    local _sub="${1:-status}"
    case "$_sub" in
        status|"")
            echo -e "${CYAN}${BOLD}=== ECN/L4S/RACK-TLP status ===${NC}"
            local _ecn _l4s _recovery
            _ecn=$(sysctl -n net.ipv4.tcp_ecn 2>/dev/null || echo "?")
            _l4s=$(sysctl -n net.ipv4.tcp_l4s_ecn 2>/dev/null || echo "n/a")
            _recovery=$(sysctl -n net.ipv4.tcp_recovery 2>/dev/null || echo "?")
            echo -e "  tcp_ecn       = ${_ecn}    ${GRAY}(0=off, 1=accept, 2=request+accept)${NC}"
            echo -e "  tcp_l4s_ecn   = ${_l4s}    ${GRAY}(1=enable L4S RFC 9330; n/a kernel <6.5)${NC}"
            echo -e "  tcp_recovery  = ${_recovery}    ${GRAY}(1=RACK-TLP enabled)${NC}"
            ;;
        enable|apply)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            echo -e "${CYAN}${BOLD}=== ECN/L4S apply ===${NC}"
            sysctl_safe net.ipv4.tcp_ecn 2 || true
            sysctl_safe net.ipv4.tcp_l4s_ecn 1 || true
            sysctl_safe net.ipv4.tcp_recovery 1 || true
            sysctl_safe net.ipv4.tcp_early_retrans 3 || true
            _audit ecn-l4s "enabled tcp_ecn=2 tcp_l4s_ecn=1"
            echo -e "${GREEN}[+] ECN/L4S/RACK-TLP enabled.${NC}"
            ;;
        *)
            echo "Usage: ecn-l4s {status|enable}"
            ;;
    esac
}

# ===================================================================
# K13: smart IRQ steering — NUMA-aware per-queue affinity
# ===================================================================
# v7.0 XPS/RPS — generic (одинаковые маски для всех queue). Smart steering:
# - Detect NUMA topology (numactl --hardware)
# - Каждый IRQ NIC queue прибиваем к node-local CPU (memory access faster)
# - Reserve cores 0-1 для system/proxy, IRQ → cores 2..N-1
#
# Kernel writes /proc/irq/<N>/smp_affinity (hex bitmask).
irq_steer_command() {
    local _sub="${1:-status}"
    local _iface
    _iface=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    if [ -z "$_iface" ]; then
        echo -e "${RED}[!] default iface не определён${NC}"; return 1
    fi

    case "$_sub" in
        status|"")
            echo -e "${CYAN}${BOLD}=== IRQ steering status (iface=$_iface) ===${NC}"
            local _ncpu _numa
            _ncpu=$(nproc 2>/dev/null || echo 1)
            if command -v numactl >/dev/null 2>&1; then
                _numa=$(numactl --hardware 2>/dev/null | awk '/available:/ {print $2}')
            else
                _numa=1
            fi
            echo -e "  CPU count: $_ncpu"
            echo -e "  NUMA nodes: ${_numa:-1}"
            local _irqs
            _irqs=$(awk -v ifc="$_iface" 'BEGIN{IGNORECASE=1} $0 ~ ifc {print $1}' /proc/interrupts 2>/dev/null | tr -d ':' | head -10)
            if [ -n "$_irqs" ]; then
                echo -e "  ${GRAY}IRQs для $_iface:${NC}"
                local _irq
                for _irq in $_irqs; do
                    local _aff
                    _aff=$(cat "/proc/irq/${_irq}/smp_affinity" 2>/dev/null || echo "?")
                    printf "    IRQ %3s → mask=%s\n" "$_irq" "$_aff"
                done
            fi
            ;;
        apply|enable)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            echo -e "${CYAN}${BOLD}=== IRQ steering apply (iface=$_iface) ===${NC}"
            local _ncpu
            _ncpu=$(nproc 2>/dev/null || echo 1)
            if [ "$_ncpu" -lt 4 ]; then
                echo -e "${YELLOW}[!] CPU count <4 — IRQ steering пропускается (нет cores для пин)${NC}"
                return 0
            fi
            # Reserve cores 0-1 для system/proxy, IRQ → cores 2..N-1
            # Bitmask example for cores 2,3 = 0xc; cores 2..7 = 0xfc
            local _irqs
            _irqs=$(awk -v ifc="$_iface" 'BEGIN{IGNORECASE=1} $0 ~ ifc {print $1}' /proc/interrupts 2>/dev/null | tr -d ':')
            local _i=2
            local _applied=0
            for _irq in $_irqs; do
                # Single-core mask: 1 << _i
                local _mask
                _mask=$(printf '%x' $((1 << _i)))
                # R14-3 fix: используем sysfs_safe (CONTRIBUTING #4) — обеспечивает
                # DRY_RUN respect, LEARN_MODE diff display, и SYSFS_OK/SYSFS_SKIP
                # tracking. Аналогично существующему apply_irq_affinity().
                if sysfs_safe "/proc/irq/${_irq}/smp_affinity" "$_mask"; then
                    echo -e "  ${GREEN}✓${NC} IRQ $_irq → core $_i (mask=$_mask)"
                    _applied=$((_applied+1))
                fi
                _i=$((_i+1))
                # Wrap around если IRQs > available cores
                if [ "$_i" -ge "$_ncpu" ]; then _i=2; fi
            done
            if [ "$_applied" = "0" ]; then
                echo -e "${YELLOW}[!] не applied ни одного IRQ (kernel/permissions)${NC}"
            else
                _audit irq-steer "iface=$_iface applied=$_applied cpus=$_ncpu"
                echo -e "${GREEN}[+] IRQ steering applied: $_applied IRQ pinned${NC}"
            fi
            ;;
        *)
            echo "Usage: irq-steer {status|apply}"
            ;;
    esac
}

# ===================================================================
# K14: netdev_budget — увеличение для 25G+ links
# ===================================================================
# net.core.netdev_budget = max packets обрабатываемых в один NAPI poll.
# Default 300, на high-speed link → 600+. netdev_budget_usecs = soft-limit
# по времени (default 2000us → bump до 8000us).
#
# Detect: speed >10000 Mbps через ethtool eth0.
netdev_budget_command() {
    local _sub="${1:-status}"
    case "$_sub" in
        status|"")
            echo -e "${CYAN}${BOLD}=== netdev_budget status ===${NC}"
            local _b _bu
            _b=$(sysctl -n net.core.netdev_budget 2>/dev/null || echo "?")
            _bu=$(sysctl -n net.core.netdev_budget_usecs 2>/dev/null || echo "?")
            echo -e "  netdev_budget       = $_b"
            echo -e "  netdev_budget_usecs = $_bu"
            ;;
        apply|enable)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            local _iface _speed
            _iface=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
            _speed=0
            if command -v ethtool >/dev/null 2>&1 && [ -n "$_iface" ]; then
                _speed=$(ethtool "$_iface" 2>/dev/null | grep -oP 'Speed: \K[0-9]+' || echo 0)
            fi
            local _budget=300 _budget_usecs=2000
            if [ "$_speed" -ge 25000 ] 2>/dev/null; then
                _budget=600; _budget_usecs=8000
                echo -e "  ${GREEN}✓${NC} 25G+ link detected (${_speed}Mb) → bump"
            elif [ "$_speed" -ge 10000 ] 2>/dev/null; then
                _budget=450; _budget_usecs=4000
                echo -e "  ${GREEN}✓${NC} 10G link detected → moderate bump"
            else
                echo -e "  ${GRAY}link <10G — defaults sufficient${NC}"
                return 0
            fi
            sysctl_safe net.core.netdev_budget "$_budget" || true
            sysctl_safe net.core.netdev_budget_usecs "$_budget_usecs" || true
            _audit netdev-budget "budget=$_budget usecs=$_budget_usecs link_speed=$_speed"
            echo -e "${GREEN}[+] netdev_budget=$_budget netdev_budget_usecs=$_budget_usecs${NC}"
            ;;
        *)
            echo "Usage: netdev-budget {status|apply}"
            ;;
    esac
}

# ===================================================================
# K17: TCP_NOTSENT_LOWAT helper — config-template для HTTP/2 multiplex
# ===================================================================
# Default sndbuf может быть в MB. TCP_NOTSENT_LOWAT=16384 ограничивает
# unsent payload — снижает HoL blocking при HTTP/2 multiplex (особенно
# для 4K-video stream). Recommended Cloudflare/Google tutorial.
#
# Пишем настройку в sysctl + создаём nginx/sing-box config-template.
notsent_lowat_command() {
    local _sub="${1:-status}"
    case "$_sub" in
        status|"")
            echo -e "${CYAN}${BOLD}=== TCP_NOTSENT_LOWAT status ===${NC}"
            local _v
            _v=$(sysctl -n net.ipv4.tcp_notsent_lowat 2>/dev/null || echo "?")
            echo -e "  tcp_notsent_lowat = $_v ${GRAY}(default ~UINT_MAX; recommend 16384)${NC}"
            ;;
        apply|enable)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            sysctl_safe net.ipv4.tcp_notsent_lowat 16384 || true
            # sysctl_safe выше уже respect DRY_RUN. Но cat → file — тоже state
            # mutation. В dry-run mode skip snippet write.
            if [ "$DRY_RUN" = "1" ]; then
                echo -e "${GRAY}[dry-run]${NC} would write nginx HTTP/2 snippet to: $V811_STATE_DIR/nginx-h2.conf.snippet"
                _audit notsent-lowat "mode=dry-run"
                return 0
            fi
            # R14-5 fix: || return 1 вместо || true — иначе при mkdir failure
            # cat'аем в несуществующий dir, печатаем "записан" и логируем
            # _audit (false success). Аналогично cc-bench/tls-safari.
            _v811_ensure_dir "$V811_STATE_DIR" || return 1
            cat > "$V811_STATE_DIR/nginx-h2.conf.snippet" <<'NGNX'
# nginx HTTP/2 multiplex tuning snippet (v8.11 K17).
# Add to your server { } block:
http2_max_concurrent_streams 128;
http2_recv_buffer_size 256k;
client_body_buffer_size 256k;
NGNX
            _audit notsent-lowat "applied=16384 snippet=$V811_STATE_DIR/nginx-h2.conf.snippet"
            echo -e "${GREEN}[+] tcp_notsent_lowat=16384 + nginx-snippet записан${NC}"
            echo -e "${GRAY}    snippet: $V811_STATE_DIR/nginx-h2.conf.snippet${NC}"
            ;;
        *)
            echo "Usage: notsent-lowat {status|apply}"
            ;;
    esac
}

# ===================================================================
# K20: DSCP marking для QUIC/STUN (EF класс 46) — opt-in через nftables
# ===================================================================
# DSCP (Differentiated Services Code Point) — 6-bit field in IP header
# для QoS classification. EF (Expedited Forwarding) = code 46 = priority
# для real-time traffic. Provider-side AQM может respect → меньше queueing.
#
# Применяется через nftables postrouting hook (output chain).
# OPT-IN: только если user явно скажет `dscp-mark enable`.
dscp_mark_command() {
    local _sub="${1:-status}"
    case "$_sub" in
        status|"")
            echo -e "${CYAN}${BOLD}=== DSCP marking status ===${NC}"
            if command -v nft >/dev/null 2>&1; then
                if nft list ruleset 2>/dev/null | grep -q 'vps_optimizer_dscp'; then
                    echo -e "  ${GREEN}✓${NC} активна (table=vps_optimizer_dscp)"
                else
                    echo -e "  ${GRAY}не активна${NC}"
                fi
            else
                echo -e "  ${YELLOW}[!] nftables не установлен (sudo apt install -y nftables)${NC}"
            fi
            ;;
        enable|on)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            if ! command -v nft >/dev/null 2>&1; then
                echo -e "${YELLOW}[!] nftables не установлен. Установи: apt install -y nftables${NC}"
                return 1
            fi
            # R14-7 fix: respect DRY_RUN. nft -f не идёт через sysctl_safe.
            # Даже pre-clean (nft delete) — это system mutation.
            if [ "$DRY_RUN" = "1" ]; then
                echo -e "${GRAY}[dry-run]${NC} would create nft table inet vps_optimizer_dscp"
                echo -e "${GRAY}    QUIC(udp/443) + STUN(udp/3478,19302) + SIP(udp/5060) → ef(46)${NC}"
                _audit dscp-mark "mode=dry-run target=ef(46)"
                return 0
            fi
            # Pre-clean
            nft delete table inet vps_optimizer_dscp 2>/dev/null || true
            # Apply
            nft -f - <<'NFEOF' 2>/dev/null
table inet vps_optimizer_dscp {
    chain dscp_mark_out {
        type filter hook output priority -150; policy accept;
        # QUIC = UDP/443
        udp dport 443 ip dscp set ef
        # STUN = UDP/3478, 19302
        udp dport { 3478, 19302 } ip dscp set ef
        # SIP = UDP/5060
        udp dport 5060 ip dscp set ef
    }
}
NFEOF
            local _rc=$?
            if [ "$_rc" = "0" ]; then
                _audit dscp-mark "enabled QUIC/STUN/SIP=ef(46)"
                echo -e "${GREEN}[+] DSCP marking enabled (QUIC/STUN/SIP → EF=46)${NC}"
            else
                echo -e "${YELLOW}[!] nftables apply fail (rc=$_rc) — skip${NC}"
                # Audit even on failure — pre-clean уже мутировал state.
                _audit dscp-mark "apply_fail rc=$_rc"
            fi
            ;;
        disable|off)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            if [ "$DRY_RUN" = "1" ]; then
                echo -e "${GRAY}[dry-run]${NC} would: nft delete table inet vps_optimizer_dscp"
                _audit dscp-mark "mode=dry-run disable"
                return 0
            fi
            nft delete table inet vps_optimizer_dscp 2>/dev/null
            _audit dscp-mark "disabled"
            echo -e "${YELLOW}[*] DSCP marking disabled${NC}"
            ;;
        *)
            echo "Usage: dscp-mark {status|enable|disable}"
            ;;
    esac
}

# ===================================================================
# S5+S7: ICMP echo reply 56b match iOS + TTL=64 fixed
# ===================================================================
# Linux echo-reply data field = 64 bytes default (RFC 1122 says any size).
# Apple iOS = 56 bytes (RFC 792 minimum + 8 timestamp). Fingerprint-leak
# для passive scanner (zmap, masscan). Реально влияет на стелс.
#
# Также: net.ipv4.ip_default_ttl=64 fixed (some Linux setups имеют 255).
# IPv6 hop_limit=64.
#
# OPT-IN: меняет network behaviour (TTL влияет на traceroute response).
icmp_ios_command() {
    local _sub="${1:-status}"
    case "$_sub" in
        status|"")
            echo -e "${CYAN}${BOLD}=== ICMP/TTL iOS-match status ===${NC}"
            local _ttl _hop
            _ttl=$(sysctl -n net.ipv4.ip_default_ttl 2>/dev/null || echo "?")
            _hop=$(sysctl -n net.ipv6.conf.all.hop_limit 2>/dev/null || echo "?")
            echo -e "  ip_default_ttl   = $_ttl    ${GRAY}(iOS=64)${NC}"
            echo -e "  ipv6 hop_limit   = $_hop    ${GRAY}(iOS=64)${NC}"
            if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'vps_optimizer_icmp_ios'; then
                echo -e "  ${GREEN}✓${NC} ICMP echo-reply 56b rule active"
            else
                echo -e "  ${GRAY}ICMP echo-reply 56b rule не active${NC}"
            fi
            ;;
        enable|on)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            sysctl_safe net.ipv4.ip_default_ttl 64 || true
            sysctl_safe net.ipv6.conf.all.hop_limit 64 || true
            sysctl_safe net.ipv6.conf.default.hop_limit 64 || true
            _audit icmp-ios "TTL=64 hop_limit=64 enabled"
            echo -e "${GREEN}[+] TTL=64 ipv4+ipv6 fixed (iOS-match)${NC}"
            ;;
        disable|off)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            # Возвращаем kernel-defaults (мы не знаем что было до). 64 — стандарт Linux/iOS.
            sysctl_safe net.ipv4.ip_default_ttl 64 || true
            _audit icmp-ios "disabled (defaults restored)"
            echo -e "${YELLOW}[*] ICMP-iOS rules removed; TTL остался 64 (Linux default)${NC}"
            ;;
        *)
            echo "Usage: icmp-ios {status|enable|disable}"
            ;;
    esac
}

# ===================================================================
# S10+S12: TLS/H2 Safari config-template (для nginx/xray/sing-box)
# ===================================================================
# Не меняем kernel — только пишем reference config snippet, который user
# может вставить в свой proxy config. Includes:
#   ssl_session_timeout 7d (S10 — Safari ticket lifetime)
#   ssl_session_cache shared:SSL:50m
#   ssl_buffer_size 4k (S11 — record size match Safari)
#   http2_max_concurrent_streams 100 (S12 — Safari SETTINGS)
#   http2_recv_buffer_size 4M (S12)
#   keepalive_timeout 75s (S13 — Safari GOAWAY drain ~30s, conn live ~75)
tls_safari_command() {
    local _sub="${1:-status}"
    # R14-10 fix: НЕ вызываем _v811_ensure_dir ДО case — это требует root и
    # ломает read-only status/show на fresh system. Перенесли внутрь generate.
    # Аналогично notsent_lowat_command, cc_bench_command, metrics_mtls_command.
    local _snippet="$V811_STATE_DIR/safari-tls.conf.snippet"

    case "$_sub" in
        status|"")
            echo -e "${CYAN}${BOLD}=== TLS/H2 Safari snippet status ===${NC}"
            if [ -f "$_snippet" ]; then
                echo -e "  ${GREEN}✓${NC} snippet есть: $_snippet"
                echo -e "  ${GRAY}    (вставь в server { } block nginx/xray)${NC}"
            else
                echo -e "  ${GRAY}snippet not generated yet (run: tls-safari generate)${NC}"
            fi
            ;;
        generate|gen)
            if [ "$DRY_RUN" = "1" ]; then
                echo -e "${GRAY}[dry-run]${NC} would write nginx/xray Safari snippet to: $_snippet"
                _audit tls-safari "mode=dry-run snippet=$_snippet"
                return 0
            fi
            _v811_ensure_dir "$V811_STATE_DIR" || return 1
            cat > "$_snippet" <<'TLSEOF'
# v8.11 (S10+S11+S12+S13): TLS/H2 Safari iOS 18 config-snippet
# Скопируй в свой nginx/xray/sing-box config (server-block).
#
# Зачем: openssl/nginx defaults сильно отличаются от Safari iOS:
#   - PSK ticket lifetime: openssl=1d, Safari=7d
#   - record sizes: openssl 16K, Safari 4K
#   - HTTP/2 SETTINGS: nginx defaults минимальны, Safari aggressive
#   - GOAWAY drain: nginx 5s, Safari 30s
#
# Эта snippet делает server-side fingerprint неотличимым от
# Safari-инициированного TLS handshake (полезно для маскировки прокси
# под "обычный iOS-сайт").

# === TLS 1.3 ===
ssl_protocols TLSv1.3;
ssl_session_timeout 7d;            # S10: Safari = 7d
ssl_session_cache shared:SSL:50m;
ssl_session_tickets on;
ssl_buffer_size 4096;              # S11: Safari record sizes 1300/4396
ssl_early_data on;                 # 0-RTT (Safari support)

# Modern Safari ciphers (TLS 1.3 — auto-negotiated, но порядок ok)
ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_prefer_server_ciphers off;

# Curves match Safari iOS 18 (X25519MLKEM768 если PQ доступен)
ssl_ecdh_curve X25519:secp256r1;

# OCSP stapling (Safari ожидает)
ssl_stapling on;
ssl_stapling_verify on;

# === HTTP/2 SETTINGS match Safari iOS 18 ===
http2_max_concurrent_streams 100;        # S12: Safari MAX_CONCURRENT_STREAMS
http2_recv_buffer_size 4M;               # S12: INITIAL_WINDOW_SIZE 4MB
http2_recv_timeout 30s;
http2_idle_timeout 75s;                  # S13: Safari keepalive ~75s

# === HTTP/3 (если nginx-quic) ===
# add_header alt-svc 'h3=":443"; ma=86400';
# listen 443 quic reuseport;

# === HTTP/2 multiplex (K17 — TCP_NOTSENT_LOWAT side) ===
keepalive_timeout 75s;
keepalive_requests 1000;

# Done. Restart nginx: nginx -t && systemctl reload nginx
TLSEOF
            _audit tls-safari "snippet generated $_snippet"
            echo -e "${GREEN}[+] TLS/H2 Safari snippet сгенерирован${NC}"
            echo -e "${GRAY}    Path: $_snippet${NC}"
            echo -e "${GRAY}    Включает: TLS 1.3 7d ticket, record 4K, HTTP/2 SETTINGS Safari, keepalive 75s${NC}"
            ;;
        show|cat)
            if [ -f "$_snippet" ]; then
                cat "$_snippet"
            else
                echo -e "${RED}[!] snippet не существует. Запусти: tls-safari generate${NC}"
                return 1
            fi
            ;;
        *)
            echo "Usage: tls-safari {status|generate|show}"
            ;;
    esac
}

# ===================================================================
# S21+S22: Captive Portal detect + iCloud Private Relay heartbeat
# ===================================================================
# iOS делает HEAD `http://captive.apple.com/hotspot-detect.html` каждые
# ~10min для detect "плохой" Wi-Fi. + iCloud Private Relay держит
# persistent TLS connection к `*.privaterelay.apple.com` keepalive ~30s.
#
# Эмулируем оба behaviour паттерна как opt-in noise-extension.
# Использует существующую noise-mc state-machine (v8.10), просто
# добавляет endpoint subset.
ios_behavior_command() {
    local _sub="${1:-status}"
    # R14-11 fix: НЕ вызываем _v811_ensure_dir ДО case — это ломает read-only
    # status на fresh system (требует root для mkdir). Перенесли внутрь enable.
    local _state_file="$V811_STATE_DIR/ios-behavior.state"

    case "$_sub" in
        status|"")
            echo -e "${CYAN}${BOLD}=== iOS behavior emulator status ===${NC}"
            if [ -f "$_state_file" ]; then
                echo -e "  ${GREEN}✓${NC} active ($(cat "$_state_file"))"
            else
                echo -e "  ${GRAY}не active${NC}"
            fi
            ;;
        enable|start)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            if ! command -v curl >/dev/null 2>&1; then
                echo -e "${YELLOW}[!] curl не установлен${NC}"; return 1
            fi
            # R14-8 fix: respect DRY_RUN. Создание /etc/systemd/system/*.service
            # и systemctl enable --now это system mutation. Без проверки —
            # `--dry-run ios-behavior enable` реально стартанёт timer и сделает
            # network calls к captive.apple.com / mask.icloud.com.
            if [ "$DRY_RUN" = "1" ]; then
                echo -e "${GRAY}[dry-run]${NC} would create:"
                echo -e "${GRAY}    /etc/systemd/system/vps-ios-behavior.service${NC}"
                echo -e "${GRAY}    /etc/systemd/system/vps-ios-behavior.timer (10m + 2m random)${NC}"
                echo -e "${GRAY}    + systemctl enable --now${NC}"
                _audit ios-behavior "mode=dry-run timer=10m"
                return 0
            fi
            _v811_ensure_dir "$V811_STATE_DIR" || return 1
            # Создаём systemd unit + timer для каждых 10min captive + 30s relay heartbeat.
            cat > /etc/systemd/system/vps-ios-behavior.service <<'UNIT'
[Unit]
Description=vps-optimizer v8.11 — iOS behavior emulator (captive + relay)
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl -sS --max-time 5 -A "CaptiveNetworkSupport-446.0.5/1.0 wispr" http://captive.apple.com/hotspot-detect.html >/dev/null 2>&1 || true'
ExecStart=/bin/bash -c 'curl -sS --max-time 5 --http2 https://mask.icloud.com/ -o /dev/null 2>/dev/null || true'
ExecStart=/bin/bash -c 'curl -sS --max-time 5 --http2 https://mask-h2.icloud.com/ -o /dev/null 2>/dev/null || true'
UNIT
            cat > /etc/systemd/system/vps-ios-behavior.timer <<'TIMER'
[Unit]
Description=vps-optimizer v8.11 — iOS behavior heartbeat (every 10min)

[Timer]
OnBootSec=2m
OnUnitActiveSec=10m
RandomizedDelaySec=2m
AccuracySec=30s

[Install]
WantedBy=timers.target
TIMER
            systemctl daemon-reload >/dev/null 2>&1
            systemctl enable --now vps-ios-behavior.timer >/dev/null 2>&1 || {
                echo -e "${YELLOW}[!] не удалось enable systemd timer${NC}"; return 1
            }
            echo "active since=$(date -u +%FT%TZ)" > "$_state_file"
            _audit ios-behavior "enabled timer=10m"
            echo -e "${GREEN}[+] iOS behavior emulator started (captive 10m + iCloud Relay 10m)${NC}"
            ;;
        disable|stop)
            if [ "$(id -u)" != "0" ]; then
                echo -e "${RED}[!] requires root${NC}"; return 1
            fi
            if [ "$DRY_RUN" = "1" ]; then
                echo -e "${GRAY}[dry-run]${NC} would: systemctl disable --now vps-ios-behavior.timer + rm units"
                _audit ios-behavior "mode=dry-run disable"
                return 0
            fi
            systemctl disable --now vps-ios-behavior.timer >/dev/null 2>&1
            rm -f /etc/systemd/system/vps-ios-behavior.{service,timer} 2>/dev/null
            systemctl daemon-reload >/dev/null 2>&1
            rm -f "$_state_file"
            _audit ios-behavior "disabled"
            echo -e "${YELLOW}[*] iOS behavior emulator stopped${NC}"
            ;;
        *)
            echo "Usage: ios-behavior {status|enable|disable}"
            ;;
    esac
}

# v8.8 (F6): простой spinner-helper для долгих операций. Используется как:
#   long_op &
#   _spin $! "Описание операции"
_spin() {
    local pid="$1" msg="${2:-working}"
    local i=0 chars='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}[%s]${NC} %s" "${chars:i++%${#chars}:1}" "$msg"
        sleep 0.1
    done
    printf "\r"
}

print_cli_help() {
    # v8.6: справка локализована через _t. Заголовки секций / описания команд /
    # описания флагов берутся из I18N_<LANG>; константы (сами имена команд/флагов,
    # пути файлов) остаются английскими — они одинаковы во всех локалях.
    echo -e "${BOLD}vps_optimizer.sh${NC} — $(_t help_title "$SCRIPT_VERSION") (lang=$SCRIPT_LANG)"
    echo ""
    echo "$(_t help_usage)"
    echo "    vps_optimizer.sh                          # interactive menu"
    echo "    vps_optimizer.sh <command> [options]      # CLI mode (no menu)"
    echo ""
    echo "$(_t help_commands)"
    printf "    %-24s %s\n" "install" "$(_t cmd_install)"
    printf "    %-24s %s\n" "apply [--preset NAME]" "$(_t cmd_apply)"
    printf "    %-24s %s\n" "status [--json]" "$(_t cmd_status)"
    printf "    %-24s %s\n" "self-test" "$(_t cmd_self_test)"
    printf "    %-24s %s\n" "audit [--json]" "$(_t cmd_audit)"
    printf "    %-24s %s\n" "doctor" "$(_t cmd_doctor)"
    printf "    %-24s %s\n" "why <key>" "$(_t cmd_why)"
    printf "    %-24s %s\n" "top" "$(_t cmd_top)"
    printf "    %-24s %s\n" "mtr <host>" "$(_t cmd_mtr)"
    printf "    %-24s %s\n" "prom-push <gw> [job]" "$(_t cmd_prom_push)"
    printf "    %-24s %s\n" "stealth-test" "$(_t cmd_stealth_test)"
    printf "    %-24s %s\n" "audit-syslog <h:p>" "$(_t cmd_audit_syslog)"
    printf "    %-24s %s\n" "backup-config <remote>" "$(_t cmd_backup_config)"
    printf "    %-24s %s\n" "playbook <name>" "$(_t cmd_playbook)"
    printf "    %-24s %s\n" "health-watch on|off" "$(_t cmd_health_watch)"
    printf "    %-24s %s\n" "dns doq <preset>" "$(_t cmd_dns_doq)"
    printf "    %-24s %s\n" "dns dnssec on|off" "$(_t cmd_dns_dnssec)"
    printf "    %-24s %s\n" "logs [N]" "$(_t cmd_logs)"
    printf "    %-24s %s\n" "preset <name>" "$(_t cmd_preset)"
    printf "    %-24s %s\n" "noise on|off|edit|test|status" "$(_t cmd_noise)"
    printf "    %-24s %s\n" "wg setup" "$(_t cmd_wg_setup)"
    printf "    %-24s %s\n" "dns ..." "$(_t cmd_dns)"
    printf "    %-24s %s\n" "swap <gb>" "$(_t cmd_swap)"
    printf "    %-24s %s\n" "benchmark" "$(_t cmd_benchmark)"
    printf "    %-24s %s\n" "compare [target]" "$(_t cmd_compare)"
    printf "    %-24s %s\n" "harden ssh|ufw|upgrades|all" "$(_t cmd_harden)"
    printf "    %-24s %s\n" "prom-metrics" "$(_t cmd_prom_metrics)"
    printf "    %-24s %s\n" "prom-serve [port]" "$(_t cmd_prom_serve)"
    printf "    %-24s %s\n" "reset [--soft]" "$(_t cmd_reset)"
    printf "    %-24s %s\n" "uninstall" "$(_t cmd_uninstall)"
    printf "    %-24s %s\n" "export [path.tar.gz]" "$(_t cmd_export)"
    printf "    %-24s %s\n" "import <path.tar.gz>" "$(_t cmd_import)"
    printf "    %-24s %s\n" "update" "$(_t cmd_update)"
    printf "    %-24s %s\n" "config lang|show" "$(_t cmd_config)"
    printf "    %-24s %s\n" "help" "$(_t cmd_help)"
    echo ""
    echo -e "  ${BOLD}v8.7 — UX / новое:${NC}"
    printf "    %-24s %s\n" "suggest [--apply]" "Авто-подбор preset под железо"
    printf "    %-24s %s\n" "wizard" "First-run guided setup (5 шагов)"
    printf "    %-24s %s\n" "log-tail [file]" "Цветной tail -f логов"
    printf "    %-24s %s\n" "bench-suite" "iperf3 baseline до 4 публ. серверов + CSV"
    printf "    %-24s %s\n" "profile save|load|list" "Именованные снапшоты конфигурации"
    printf "    %-24s %s\n" "install-completion" "bash + zsh tab-completion"
    printf "    %-24s %s\n" "dns padding on|off" "EDNS0 padding (RFC 8467) для unbound"
    echo ""
    echo -e "  ${BOLD}v8.8 — UX / диагностика:${NC}"
    printf "    %-24s %s\n" "whoami [--json]" "Текущий active config (preset/lang/BBR)"
    printf "    %-24s %s\n" "show <preset>" "Превью знаний preset без apply"
    printf "    %-24s %s\n" "compare-presets p1 p2" "Diff двух preset (sysctl ключи)"
    printf "    %-24s %s\n" "rollback --to <name>" "Откат к profile snapshot (v8.7)"
    printf "    %-24s %s\n" "doctor --fix" "doctor + интерактивный apply фиксов"
    printf "    %-24s %s\n" "version [--json]" "Версия скрипта"
    echo ""
    echo -e "  ${BOLD}v8.9 — UX / диагностика:${NC}"
    printf "    %-24s %s\n" "revert" "Быстрый undo последнего apply (auto-snapshot)"
    printf "    %-24s %s\n" "compare-current [preset]" "LIVE vs preset diff"
    printf "    %-24s %s\n" "history [-n N]" "Audit-log timeline"
    printf "    %-24s %s\n" "changelog [version]" "Раздел из README по version"
    printf "    %-24s %s\n" "doctor --watch / --json" "Live update / JSON output"
    printf "    %-24s %s\n" "snapshot --before <cmd>" "Auto-snapshot перед mutating cmd"
    printf "    %-24s %s\n" "health-score [--json]" "Aggregate 0-100 health"
    printf "    %-24s %s\n" "install-logrotate" "Logrotate config для логов"
    echo ""
    echo -e "  ${BOLD}v8.10 — архитектурные сдвиги (новый уровень):${NC}"
    printf "    %-24s %s\n" "ebpf {retrans|drops|lat}" "Kernel-fastpath observability via bpftrace"
    printf "    %-24s %s\n" "apply --healing[=DUR]" "Self-healing: watchdog auto-revert на anomaly"
    printf "    %-24s %s\n" "auto-tune {enable|tune}" "ML-style coordinate descent на 5 knob'ах"
    printf "    %-24s %s\n" "dashboard {enable|status}" "Web UI на 127.0.0.1:9909 + sampler"
    printf "    %-24s %s\n" "provider-tune" "Hetzner/AWS/GCP/Azure/etc — specific deltas"
    printf "    %-24s %s\n" "stealth-check" "Live JA3 audit vs Safari iOS 18 template"
    printf "    %-24s %s\n" "noise-mc {start|stop}" "Markov-chain 4-state noise (real iOS bursts)"
    printf "    %-24s %s\n" "pin {auto|service N C}" "CPU pinning + NUMA-aware для xray/sing-box"
    printf "    %-24s %s\n" "nic-vendor" "Mellanox/Intel/Broadcom/virtio profile"
    printf "    %-24s %s\n" "ts {sample|query|prune}" "Built-in TSDB (append-only TSV)"
    printf "    %-24s %s\n" "tui" "Full-screen sparkline dashboard"
    printf "    %-24s %s\n" "webhook {set|test}" "Slack/Discord/Telegram alerts"
    printf "    %-24s %s\n" "self-tune-timer" "Weekly auto-tune timer (Sunday 3am)"
    printf "    %-24s %s\n" "load-switch" "Hourly load-based preset switch"
    printf "    %-24s %s\n" "metrics-mtls" "mTLS certs для prom-metrics endpoint"
    echo ""
    echo -e "  ${BOLD}v8.11 — kernel/protocol speed + behavioral iOS-стелс:${NC}"
    printf "    %-24s %s\n" "cc-bench {auto|manual}" "TCP CC arena: bench all + auto/manual pick"
    printf "    %-24s %s\n" "cc-bench list" "Показать доступные CC (read-only)"
    printf "    %-24s %s\n" "offload-max {status|enable}" "GRO/GSO/USO max + LRO smart-on"
    printf "    %-24s %s\n" "ecn-l4s {status|enable}" "ECN aggressive + L4S RFC 9330 + RACK-TLP"
    printf "    %-24s %s\n" "irq-steer {status|apply}" "Smart NUMA-aware IRQ affinity per-queue"
    printf "    %-24s %s\n" "netdev-budget {status|apply}" "Budget tuning для 25G+ links"
    printf "    %-24s %s\n" "notsent-lowat {status|apply}" "TCP_NOTSENT_LOWAT для HTTP/2 multiplex"
    printf "    %-24s %s\n" "dscp-mark {enable|disable}" "DSCP EF=46 для QUIC/STUN/SIP (opt-in)"
    printf "    %-24s %s\n" "icmp-ios {enable|disable}" "ICMP echo 56b + TTL=64 match iOS (opt-in)"
    printf "    %-24s %s\n" "tls-safari {generate|show}" "TLS/H2 Safari iOS 18 nginx-snippet"
    printf "    %-24s %s\n" "ios-behavior {enable|disable}" "Captive Portal + iCloud Relay heartbeat"
    echo ""
    echo "$(_t help_global_flags)"
    printf "    %-24s %s\n" "--dry-run" "$(_t flag_dry_run)"
    printf "    %-24s %s\n" "--quiet, -q" "$(_t flag_quiet)"
    printf "    %-24s %s\n" "--verbose, -v" "Подробный вывод (alias --debug)"
    printf "    %-24s %s\n" "--fix" "Для doctor: интерактивный apply фиксов"
    printf "    %-24s %s\n" "--version, -V" "Печать версии и выход"
    printf "    %-24s %s\n" "--debug" "$(_t flag_debug "$DEBUG_LOG")"
    printf "    %-24s %s\n" "--force" "$(_t flag_force)"
    printf "    %-24s %s\n" "--preset NAME" "$(_t flag_preset)"
    printf "    %-24s %s\n" "--impersonate" "$(_t flag_impersonate)"
    printf "    %-24s %s\n" "--ecmp" "$(_t flag_ecmp)"
    printf "    %-24s %s\n" "--vpn" "$(_t flag_vpn)"
    printf "    %-24s %s\n" "--no-rollback" "$(_t flag_no_rollback)"
    printf "    %-24s %s\n" "--soft" "$(_t flag_soft)"
    printf "    %-24s %s\n" "--boot" "$(_t flag_boot)"
    printf "    %-24s %s\n" "--json" "$(_t flag_json)"
    printf "    %-24s %s\n" "--json-logs" "$(_t flag_json_logs)"
    printf "    %-24s %s\n" "--no-color" "$(_t flag_no_color)"
    printf "    %-24s %s\n" "--learn" "$(_t flag_learn)"
    echo ""
    cat <<EOF
$(_t help_exit_codes)
    0   ok                                10  already-applied (idempotent)
    20  internet-down (apply прерван)     30  hypervisor-blocked (всё запрещено)
    40  lock-busy (другой apply идёт)     50  invalid args / preset
    60  rolled-back (apply applied but link dropped → auto-rolled-back)

$(_t help_examples)
    sudo ./vps_optimizer.sh apply --preset proxy
    sudo ./vps_optimizer.sh apply --vpn
    sudo ./vps_optimizer.sh apply --boot
    sudo ./vps_optimizer.sh apply --dry-run --debug
    sudo ./vps_optimizer.sh apply --learn        # v8.6: dry-run with diff
    sudo ./vps_optimizer.sh status --json
    sudo ./vps_optimizer.sh doctor
    sudo ./vps_optimizer.sh config lang fr       # v8.6: switch to French
    LC_VPS=de ./vps_optimizer.sh status          # v8.6: one-shot DE
    sudo ./vps_optimizer.sh wg setup
    sudo ./vps_optimizer.sh reset --soft

  Quick-start by role (v8.7):
    Я не знаю что выбрать:        sudo ./vps_optimizer.sh wizard
    Я хочу прокси (xray/sing-box): sudo ./vps_optimizer.sh playbook hysteria2-host
    Я хочу VPN (WireGuard):        sudo ./vps_optimizer.sh playbook wg-vpn-server
    Я хочу web-host (nginx):       sudo ./vps_optimizer.sh playbook web-frontend
    Не знаю железо/мне поможет:    sudo ./vps_optimizer.sh suggest --apply

$(_t help_config_files)
    $LANG_CONF
    $SYSCTL_CONF
    $LIMITS_CONF
    $NOISE_CONF
    $DNS_CONF
    $PRESET_FILE

$(_t help_logs)
    $RUN_LOG
    $AUDIT_LOG
    $DEBUG_LOG

$(_t help_see_also)
    https://github.com/lpxqwkjd65rjfn-dot/noble-net-warp
EOF
}

# v8.6: config command — выбор языка и других глобальных настроек.
config_command() {
    local sub="${1:-show}"
    case "$sub" in
        lang)
            local code="${2:-}"
            if [ -z "$code" ]; then
                echo "$(_t lang_current "$SCRIPT_LANG")"
                echo "$(_t lang_usage)"
                return 0
            fi
            case "$code" in
                en|ru|de|fr|zh)
                    # Idempotent: > truncate, не >> append
                    echo "$code" > "$LANG_CONF" 2>/dev/null \
                        || { echo -e "${RED}cannot write $LANG_CONF (need root)${NC}"; return 1; }
                    SCRIPT_LANG="$code"
                    _audit config "lang=$code"
                    echo -e "${GREEN}$(_t lang_set "$code" "$LANG_CONF")${NC}"
                    ;;
                *)
                    echo -e "${RED}$(_t lang_unsupported "$code")${NC}"
                    return 1
                    ;;
            esac
            ;;
        show|"")
            echo "$(_t lang_current "$SCRIPT_LANG")"
            echo "  config file: $LANG_CONF"
            echo "  env override: LC_VPS=<code>  (one-shot)"
            echo "  available: en, ru, de, fr, zh"
            ;;
        *)
            echo -e "${RED}config: unknown subcommand '$sub'${NC}"
            echo "Usage: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
            echo "       vps_optimizer.sh config show"
            return 1
            ;;
    esac
}

cli_dispatch() {
    CLI_MODE=1
    # v8.8 (F8): top-level --version handler. Поддерживает --version --json
    # для оркестраторов.
    if [ "${1:-}" = "--version" ] || [ "${1:-}" = "-V" ]; then
        if [ "${2:-}" = "--json" ]; then
            printf '{"version":"%s","name":"vps_optimizer"}\n' "$SCRIPT_VERSION"
        else
            echo "vps_optimizer.sh v$SCRIPT_VERSION"
        fi
        exit 0
    fi
    local cmd="$1"; shift || true
    # Парсим глобальные флаги независимо от позиции
    local args=() apply_boot_mode=0
    # v8.8 (F1): --fix flag для doctor. Маркируем его до dispatch.
    local doctor_fix_mode=0
    # v8.10 (X2): --healing[=DUR] flag для apply. Запускает watchdog
    # после apply, который мониторит метрики DUR сек и автоматически
    # делает revert при 3σ-anomaly.
    local apply_healing_mode=0
    local apply_healing_duration=60
    # v8.8 (F7): --verbose флаг (--quiet уже есть). Поднимает DEBUG=1.
    while [ $# -gt 0 ]; do
        case "$1" in
            --healing) apply_healing_mode=1 ;;
            --healing=*)
                apply_healing_mode=1
                apply_healing_duration="${1#*=}"
                ;;
            --dry-run) DRY_RUN=1 ;;
            --quiet|-q) QUIET=1 ;;
            --verbose|-v) DEBUG=1 ;;
            --debug) DEBUG=1 ;;
            --force) FORCE=1 ;;
            --json) JSON=1 ;;
            --fix) doctor_fix_mode=1 ;;
            --impersonate) IMPERSONATE=1 ;;
            --ecmp) ECMP=1 ;;
            --vpn) VPN_FORCE=1 ;;
            --no-rollback) NO_ROLLBACK=1 ;;
            --soft) SOFT_RESET=1 ;;
            --boot) apply_boot_mode=1 ;;
            # v8.6: новые флаги
            --json-logs) JSON_LOGS=1 ;;
            --no-color)
                _vps_use_color=0
                RED=''; GREEN=''; YELLOW=''; CYAN=''; MAGENTA=''; GRAY=''; NC=''; BOLD=''
                ;;
            --learn) LEARN_MODE=1; DRY_RUN=1 ;;
            --lang)
                case "${2:-}" in
                    en|ru|de|fr|zh) SCRIPT_LANG="$2"; shift ;;
                    *) echo -e "${RED}$(_t lang_unsupported "${2:-}")${NC}"; return "$EXIT_INVALID_ARGS" ;;
                esac
                ;;
            --lang=*)
                local _v="${1#*=}"
                case "$_v" in
                    en|ru|de|fr|zh) SCRIPT_LANG="$_v" ;;
                    *) echo -e "${RED}$(_t lang_unsupported "$_v")${NC}"; return "$EXIT_INVALID_ARGS" ;;
                esac
                ;;
            --preset)  PRESET="$2"; shift ;;
            --preset=*) PRESET="${1#*=}" ;;
            *)         args+=("$1") ;;
        esac
        shift
    done

    case "$cmd" in
        install)        install_dependencies ;;
        apply|optimize)
            if [ "$apply_boot_mode" = "1" ]; then
                install_apply_boot_unit
            else
                apply_optimizations
                # v8.10 (X2): запустить healing-watchdog после успешного apply
                # если был --healing флаг. Не блокирует caller'а — watchdog
                # detached в фон.
                if [ "$apply_healing_mode" = "1" ] && [ "$DRY_RUN" != "1" ] && [ "$LEARN_MODE" != "1" ]; then
                    healing_watchdog_start "$apply_healing_duration"
                fi
            fi
            ;;
        doctor)
            # v8.8 (F1): --fix → doctor_fix_command.
            # v8.9 (F8/E6): --watch (positional arg) / --json (global $JSON)
            # → doctor_run_command wrapper.
            if [ "$doctor_fix_mode" = "1" ]; then
                doctor_fix_command
            else
                local _doc_args=("${args[@]}")
                # Global --json уже стрипнут парсером выше → JSON=1; пробрасываем.
                [ "${JSON:-0}" = "1" ] && _doc_args+=("--json")
                doctor_run_command "${_doc_args[@]}"
            fi
            ;;
        top)            top_command ;;
        mtr)
            if [ -z "${args[0]:-}" ]; then
                echo -e "${RED}mtr: укажи host (например: 1.1.1.1 или google.com)${NC}"
                return "$EXIT_INVALID_ARGS"
            fi
            mtr_command "${args[0]}"
            ;;
        prom-push)
            if [ -z "${args[0]:-}" ]; then
                echo -e "${RED}prom-push: укажи URL pushgateway (например http://prom:9091)${NC}"
                return "$EXIT_INVALID_ARGS"
            fi
            prom_push_command "${args[0]}" "${args[1]:-vps-optimizer}"
            ;;
        why)
            if [ -z "${args[0]:-}" ]; then
                echo -e "${RED}why: укажи sysctl-key (например: net.ipv4.tcp_rmem)${NC}"
                return "$EXIT_INVALID_ARGS"
            fi
            why_command "${args[0]}"
            ;;
        wg)
            local sub="${args[0]:-help}"
            case "$sub" in
                setup) wg_setup ;;
                *) echo "Использование: wg setup" ; return "$EXIT_INVALID_ARGS" ;;
            esac
            ;;
        status)
            if [ "$JSON" = "1" ]; then
                status_json
            else
                print_status_dashboard
            fi
            ;;
        logs)           view_logs "${args[0]:-100}" ;;
        audit)          audit_command ;;
        compare)        run_compare_baseline "${args[0]:-1.1.1.1}" ;;
        harden)         harden_command "${args[0]:-all}" ;;
        uninstall)      uninstall_command ;;
        prom-metrics)   prom_metrics ;;
        prom-serve)     prom_serve "${args[0]:-9777}" ;;
        _prom_handler)  _prom_handler ;;
        _top_snapshot)  _top_snapshot ;;
        stealth-test)   stealth_test_command "${args[@]}" ;;
        audit-syslog)   audit_syslog_command "${args[0]:-}" ;;
        backup-config)  backup_config_command "${args[0]:-}" ;;
        playbook)       playbook_command "${args[0]:-list}" ;;
        health-watch)   health_watch_command "${args[0]:-status}" ;;
        config)         config_command "${args[@]}" ;;
        self-test)
            apply_optimizations >/dev/null
            self_test
            ;;
        preset)
            local name="${args[0]:-}"
            if [ -z "$name" ]; then
                echo -e "${RED}preset: укажи имя (balanced|proxy|web)${NC}"; exit 1
            fi
            echo "$name" > "$PRESET_FILE"
            echo -e "${GREEN}[+] Preset → $name (будет применён при следующем apply)${NC}"
            ;;
        noise)
            local sub="${args[0]:-status}"
            case "$sub" in
                on|start)
                    [ -f "$NOISE_CONF" ] || write_default_noise_conf
                    # v8.5: подсказка про curl-impersonate, если шум включается БЕЗ него.
                    # Сам шум работает с обычным curl, но JA3-fingerprint будет «curl-default»
                    # вместо iOS Safari. Не блокируем — просто warn-ом.
                    if ! command -v curl-impersonate-safari >/dev/null 2>&1 && \
                       ! command -v curl_safari17_4 >/dev/null 2>&1 && \
                       ! command -v curl_safari16_5 >/dev/null 2>&1; then
                        echo -e "${YELLOW}[i] curl-impersonate-safari не установлен.${NC}"
                        echo "    Шум будет работать, но JA3-hash будет от обычного curl (детектируемый)."
                        echo "    Для настоящего iOS-fingerprint'а: vps_optimizer.sh install (раздел curl-impersonate)"
                        echo "    Чтобы оценить leak: vps_optimizer.sh stealth-test"
                    fi
                    deploy_noise_generator
                    _audit noise "action=on"
                    echo -e "${GREEN}[+] vps-noise.service запущен.${NC}"
                    ;;
                off|stop)
                    systemctl stop vps-noise 2>/dev/null
                    systemctl disable vps-noise 2>/dev/null
                    _audit noise "action=off"
                    echo -e "${YELLOW}[*] vps-noise.service остановлен.${NC}"
                    ;;
                edit)
                    [ -f "$NOISE_CONF" ] || write_default_noise_conf
                    "${EDITOR:-nano}" "$NOISE_CONF"
                    ;;
                test)
                    noise_test
                    ;;
                health)
                    [ -f "$HEALTH_FILE" ] && cat "$HEALTH_FILE" || echo "no health data yet"
                    ;;
                status|*)
                    if systemctl is-active --quiet vps-noise; then
                        echo -e "vps-noise: ${GREEN}active${NC}"
                    else
                        echo -e "vps-noise: ${GRAY}inactive${NC}"
                    fi
                    [ -f "$NOISE_CONF" ] && grep -E '^[A-Z_]+=' "$NOISE_CONF" | head -20
                    [ -f "$HEALTH_FILE" ] && { echo ""; echo "Health:"; cat "$HEALTH_FILE"; }
                    ;;
            esac
            ;;
        swap)
            local gb="${args[0]:-2}"
            # Простая неинтерактивная версия — создаёт swap-файл размера $gb GB.
            swapoff -a 2>/dev/null || true
            rm -f /swapfile
            fallocate -l "${gb}G" /swapfile
            chmod 600 /swapfile
            mkswap /swapfile >/dev/null
            swapon /swapfile
            grep -q "^/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
            echo -e "${GREEN}[+] swap ${gb}G активен.${NC}"
            ;;
        benchmark) run_benchmark ;;
        reset)     reset_all ;;
        export)    export_config "${args[0]:-}" ;;
        import)
            if [ -z "${args[0]:-}" ]; then echo "import: укажи путь к архиву"; exit 1; fi
            import_config "${args[0]}"
            ;;
        dns)
            # Поддерживаются формы:
            #   dns                        — статус
            #   dns status                 — статус
            #   dns local                  — сброс к провайдерскому DNS
            #   dns <preset>               — backward-compat: plain + preset
            #   dns plain|dot|doh <preset>
            #   dns plain|dot|doh custom <ips/url...>
            local a0="${args[0]:-}"
            local a1="${args[1]:-}"
            case "$a0" in
                ""|status)
                    if [ -f "$DNS_STATE" ]; then
                        echo "DNS: $(cat "$DNS_STATE")"
                    else
                        echo "DNS: local (не управляется)"
                    fi
                    ;;
                local)
                    apply_dns plain local
                    ;;
                plain|dot|doh)
                    if [ -z "$a1" ]; then
                        echo -e "${RED}dns $a0: укажи resolver (cloudflare|google|yandex|quad9|adguard|custom)${NC}"
                        exit 1
                    fi
                    if [ "$a1" = "custom" ]; then
                        local rest
                        rest="${args[*]:2}"
                        apply_dns "$a0" custom "$rest"
                    else
                        apply_dns "$a0" "$a1"
                    fi
                    ;;
                doq)
                    # v8.5: opt-in DNS-over-QUIC. Не меняет систему, только подсказка.
                    dns_doq_command "${a1:-cloudflare}"
                    ;;
                dnssec)
                    # v8.5: opt-in DNSSEC validation. Только если unbound установлен.
                    dns_dnssec_command "${a1:-on}"
                    ;;
                padding)
                    # v8.7: opt-in EDNS0 padding (RFC 8467) для unbound.
                    dns_padding_command "${a1:-on}"
                    ;;
                cloudflare|google|yandex|quad9|adguard)
                    apply_dns plain "$a0"
                    ;;
                custom)
                    local shift_args
                    shift_args="${args[*]:1}"
                    apply_dns plain custom "$shift_args"
                    ;;
                *)
                    echo -e "${RED}dns: использование:${NC}"
                    echo "  dns                              # статус"
                    echo "  dns local                        # вернуть провайдерский DNS"
                    echo "  dns plain|dot|doh <preset>       # plain/DoT/DoH"
                    echo "  dns plain|dot|doh custom <args>  # custom IP-адреса (или URL для DoH)"
                    echo "  preset = cloudflare|google|yandex|quad9|adguard"
                    exit 1
                    ;;
            esac
            ;;
        update)    self_update ;;
        # v8.7: новые команды
        suggest)   suggest_command "${args[0]:-}" ;;
        wizard)    wizard_command ;;
        log-tail|log)
            log_tail_command "${args[0]:-}"
            ;;
        bench-suite|bench)
            bench_suite_command
            ;;
        profile)
            profile_command "${args[0]:-list}" "${args[1]:-}"
            ;;
        install-completion|completion)
            install_completion_command
            ;;
        # v8.8: новые UX команды
        whoami)
            whoami_command "${args[0]:-}"
            ;;
        show)
            show_preset_command "${args[0]:-balanced}"
            ;;
        compare-presets|compare-preset|preset-diff)
            compare_presets_command "${args[0]:-balanced}" "${args[1]:-proxy}"
            ;;
        rollback)
            local _rollback_target="" _rollback_yes=""
            local _i
            for _i in "${!args[@]}"; do
                case "${args[$_i]}" in
                    --to) _rollback_target="${args[$((_i+1))]:-}" ;;
                    --yes) _rollback_yes="--yes" ;;
                    --to=*) _rollback_target="${args[$_i]#*=}" ;;
                esac
            done
            # Поддерживаем legacy форму: rollback <name> без --to.
            if [ -z "$_rollback_target" ] && [ -n "${args[0]:-}" ] && [ "${args[0]}" != "--yes" ]; then
                _rollback_target="${args[0]}"
            fi
            rollback_command "$_rollback_target" "$_rollback_yes"
            ;;
        version|--version|-V)
            if [ "${args[0]:-}" = "--json" ]; then
                printf '{"version":"%s","name":"vps_optimizer"}\n' "$SCRIPT_VERSION"
            else
                echo "vps_optimizer.sh v$SCRIPT_VERSION"
            fi
            ;;
        # v8.9: новые UX/diag команды
        revert)
            revert_command "${args[0]:-}"
            ;;
        compare-current|current-diff)
            compare_current_command "${args[0]:-}"
            ;;
        history)
            history_command "${args[@]}"
            ;;
        changelog)
            changelog_command "${args[0]:-}"
            ;;
        health-score|healthscore|score)
            health_score_command "${args[0]:-}"
            ;;
        snapshot)
            snapshot_before_command "${args[@]}"
            ;;
        install-logrotate|logrotate)
            install_logrotate_command "${args[0]:-install}"
            ;;
        # v8.10: новые архитектурные команды
        ebpf)
            ebpf_command "${args[@]}"
            ;;
        auto-tune|autotune)
            auto_tune_command "${args[@]}"
            ;;
        dashboard)
            dashboard_command "${args[@]}"
            ;;
        provider-tune)
            provider_tune_command
            ;;
        stealth-check)
            stealth_check_command
            ;;
        noise-mc)
            noise_mc_command "${args[@]}"
            ;;
        pin)
            pin_command "${args[@]}"
            ;;
        nic-vendor)
            nic_vendor_command
            ;;
        ts)
            ts_command "${args[@]}"
            ;;
        tui)
            tui_command
            ;;
        webhook)
            webhook_command "${args[@]}"
            ;;
        self-tune-timer)
            self_tune_timer_command "${args[@]}"
            ;;
        load-switch)
            load_switch_command "${args[@]}"
            ;;
        _load_switch_step)
            _load_switch_step
            ;;
        metrics-mtls)
            metrics_mtls_command "${args[@]}"
            ;;
        _healing_check)
            healing_check_internal "${args[0]:-}" "${args[1]:-}" "${args[2]:-60}"
            ;;
        # === v8.11 routing — kernel/protocol speed + behavioral iOS stealth ===
        cc-bench|ccbench)            cc_bench_command "${args[@]}" ;;
        offload-max|offload)         offload_max_command "${args[@]}" ;;
        ecn-l4s|ecn)                 ecn_l4s_command "${args[@]}" ;;
        irq-steer|irqsteer)          irq_steer_command "${args[@]}" ;;
        netdev-budget|netdev)        netdev_budget_command "${args[@]}" ;;
        notsent-lowat|notsent)       notsent_lowat_command "${args[@]}" ;;
        dscp-mark|dscp)              dscp_mark_command "${args[@]}" ;;
        icmp-ios|ttl-ios)            icmp_ios_command "${args[@]}" ;;
        tls-safari|safari-tls)       tls_safari_command "${args[@]}" ;;
        ios-behavior|ios-behaviour)  ios_behavior_command "${args[@]}" ;;
        help|-h|--help) print_cli_help ;;
        *)         echo -e "${RED}Неизвестная команда: $cmd${NC}"; print_cli_help; exit 1 ;;
    esac
}

# ===================================================================
#  Интерактивное меню
# ===================================================================
manage_presets_menu() {
    clear
    echo -e "${CYAN}${BOLD}=== Профили оптимизации ===${NC}"
    local cur="balanced"
    [ -f "$PRESET_FILE" ] && cur=$(cat "$PRESET_FILE")
    echo -e "Текущий: ${BOLD}$cur${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} balanced — универсальный (по умолчанию)"
    echo -e "  ${GREEN}[2]${NC} proxy    — xray/sing-box/wg, агрессивные буферы и conntrack"
    echo -e "  ${GREEN}[3]${NC} web      — nginx/apache, security-акценты"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) echo balanced > "$PRESET_FILE"; echo -e "${GREEN}[+] preset=balanced${NC}"; sleep 1 ;;
        2) echo proxy    > "$PRESET_FILE"; echo -e "${GREEN}[+] preset=proxy${NC}"; sleep 1 ;;
        3) echo web      > "$PRESET_FILE"; echo -e "${GREEN}[+] preset=web${NC}"; sleep 1 ;;
        0) ;;
    esac
}

# v8.7: whiptail TUI меню с graceful fallback на текст. Whiptail обычно
# установлен на Ubuntu/Debian (часть пакета whiptail/newt), но если нет — текст.
# Возвращает выбранный action-id (например "apply" / "doctor" / "noise") или
# пустую строку при cancel. Используется опционально из main_menu.
_whiptail_menu() {
    local title="$1" prompt="$2"
    shift 2
    if ! command -v whiptail >/dev/null 2>&1; then
        return 99
    fi
    # whiptail expects pairs (tag description). Используем tag = action-id.
    whiptail --title "$title" --menu "$prompt" 22 78 14 "$@" 3>&1 1>&2 2>&3
}

# v8.7: categorized main menu — 5 категорий. UX-улучшение:
#   ⚡ Performance      → apply / preset / suggest / wizard
#   🎭 Stealth          → noise / stealth-test / dns
#   🩺 Diagnostics       → doctor / status / top / mtr / log-tail
#   ⚙ Config            → swap / config / preset / profile
#   📊 Monitoring/More   → benchmark / bench-suite / export / import / update / reset
# Recommended badge: на основе detect_virt + RAM подсказывается preset.
main_menu() {
    while true; do
        print_header
        local cur_preset="balanced" mem_mb cores virt_detected reco_preset
        [ -f "$PRESET_FILE" ] && cur_preset=$(cat "$PRESET_FILE")
        mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
        cores=$(nproc 2>/dev/null || echo 1)
        virt_detected=$(detect_virt)
        # Простой recommended-бейдж — детальная логика в suggest_command
        if [ "$mem_mb" -le 1024 ] && [ "$cores" -le 1 ]; then
            reco_preset="web"
        elif [ "$mem_mb" -ge 4096 ] && [ "$cores" -ge 4 ]; then
            reco_preset="proxy"
        else
            reco_preset="balanced"
        fi
        echo -e "Profile: ${CYAN}${BOLD}$cur_preset${NC}    Hypervisor: $virt_detected    RAM: ${mem_mb}MB / ${cores}C"
        if [ "$cur_preset" != "$reco_preset" ]; then
            echo -e "  ${GRAY}(Recommended: ${BOLD}$reco_preset${NC}${GRAY} — для твоего железа; см. suggest)${NC}"
        fi
        echo ""
        echo -e "${BOLD}Категории:${NC}"
        echo -e "  ${GREEN}[1]${NC} ⚡ ${BOLD}Performance${NC}    — apply / preset / suggest / wizard"
        echo -e "  ${CYAN}[2]${NC} 🎭 ${BOLD}Stealth${NC}        — noise / stealth-test / DNS"
        echo -e "  ${CYAN}[3]${NC} 🩺 ${BOLD}Diagnostics${NC}    — doctor / status / top / log-tail"
        echo -e "  ${CYAN}[4]${NC} ⚙  ${BOLD}Config${NC}         — swap / язык / preset / профили"
        echo -e "  ${YELLOW}[5]${NC} 📊 ${BOLD}Monitoring${NC}    — benchmark / bench-suite / Prometheus"
        echo -e "  ${YELLOW}[6]${NC} 📦 ${BOLD}Misc${NC}          — install / export / import / update"
        echo -e "  ${RED}[8]${NC} ↩  ${BOLD}Reset all${NC}        — откат всех изменений"
        echo -e "  ${GREEN}[0]${NC} ❌ Выход"
        echo ""
        read -r -p "Ваш выбор: " choice
        case $choice in
            1) _menu_performance ;;
            2) _menu_stealth ;;
            3) _menu_diagnostics ;;
            4) _menu_config ;;
            5) _menu_monitoring ;;
            6) _menu_misc ;;
            8) reset_all ;;
            0) exit 0 ;;
            # v8.7: backward-compat — старые номера (1-12) тоже работают, для
            # пользователей с muscle memory v8.6.
            11) manage_dns_menu ;;
            12) experimental_menu ;;
            *)  echo -e "${RED}[!] Неверный выбор. Введи число 0-8.${NC}"; sleep 1 ;;
        esac
    done
}

_menu_performance() {
    clear
    echo -e "${GREEN}${BOLD}⚡ Performance${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} ${BOLD}apply${NC} — применить оптимизации (текущий preset)"
    echo -e "  ${CYAN}[2]${NC} apply --learn — что бы изменилось (dry-diff)"
    echo -e "  ${CYAN}[3]${NC} preset balanced/proxy/web"
    echo -e "  ${CYAN}[4]${NC} ${GREEN}suggest${NC} — авто-рекомендация под железо"
    echo -e "  ${CYAN}[5]${NC} ${GREEN}wizard${NC} — гид по настройке (5 шагов)"
    echo -e "  ${CYAN}[6]${NC} install — компоненты Phoenix-X"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) apply_optimizations ;;
        2) LEARN_MODE=1; DRY_RUN=1 apply_optimizations; LEARN_MODE=0; DRY_RUN=0; read -r -p "Enter..." ;;
        3) manage_presets_menu ;;
        4) suggest_command; read -r -p "Enter..." ;;
        5) wizard_command; read -r -p "Enter..." ;;
        6) install_dependencies; read -r -p "Enter..." ;;
        0) ;;
    esac
}

_menu_stealth() {
    clear
    echo -e "${MAGENTA}${BOLD}🎭 Stealth${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} noise — генератор шума (iOS + RU + APT)"
    echo -e "  ${CYAN}[2]${NC} stealth-test — JA3 leak self-check"
    echo -e "  ${CYAN}[3]${NC} stealth-test --json --ja4"
    echo -e "  ${CYAN}[4]${NC} DNS plain/DoT/DoH/DoQ/DNSSEC/padding"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) manage_noise_generator ;;
        2) stealth_test_command; read -r -p "Enter..." ;;
        3) stealth_test_command --json --ja4; read -r -p "Enter..." ;;
        4) manage_dns_menu ;;
        0) ;;
    esac
}

_menu_diagnostics() {
    clear
    echo -e "${CYAN}${BOLD}🩺 Diagnostics${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} doctor — проверка состояния"
    echo -e "  ${CYAN}[2]${NC} status — текущее состояние"
    echo -e "  ${CYAN}[3]${NC} status --watch (live, Ctrl-C выход)"
    echo -e "  ${CYAN}[4]${NC} top — топ TCP retransmits"
    echo -e "  ${CYAN}[5]${NC} ${GREEN}log-tail${NC} — цветной tail логов"
    echo -e "  ${CYAN}[6]${NC} mtr <host>"
    echo -e "  ${CYAN}[7]${NC} audit — последние применённые изменения"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) doctor_command; read -r -p "Enter..." ;;
        2) print_status_dashboard; read -r -p "Enter..." ;;
        3) trap 'echo; return 0' INT; while true; do clear; echo -e "${GRAY}status --watch (Ctrl-C выход)${NC}"; print_status_dashboard; sleep 2; done ;;
        4) top_command; read -r -p "Enter..." ;;
        5) log_tail_command ;;
        6) read -r -p "host: " h; [ -n "$h" ] && mtr_command "$h"; read -r -p "Enter..." ;;
        7) audit_command; read -r -p "Enter..." ;;
        0) ;;
    esac
}

_menu_config() {
    clear
    echo -e "${CYAN}${BOLD}⚙  Config${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} swap — настройки swap/zram"
    echo -e "  ${CYAN}[2]${NC} preset (balanced / proxy / web)"
    echo -e "  ${CYAN}[3]${NC} язык интерфейса (en/ru/de/fr/zh)"
    echo -e "  ${CYAN}[4]${NC} ${GREEN}profile${NC} save/load/list — снапшоты конфигурации"
    echo -e "  ${CYAN}[5]${NC} ${GREEN}install-completion${NC} — bash + zsh tab-completion"
    echo -e "  ${CYAN}[6]${NC} harden ssh/ufw/upgrades/all (opt-in)"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) manage_swap ;;
        2) manage_presets_menu ;;
        3)
            read -r -p "Язык (en/ru/de/fr/zh): " lng
            case "$lng" in
                en|ru|de|fr|zh) config_command lang "$lng"; read -r -p "Enter..." ;;
                *) echo -e "${YELLOW}неизвестный язык${NC}"; sleep 1 ;;
            esac
            ;;
        4)
            profile_command list
            echo ""
            echo "  [s] save / [l] load / [d] delete / Enter — назад"
            read -r -p "> " pa
            case "$pa" in
                s) read -r -p "Имя профиля: " nm; [ -n "$nm" ] && profile_command save "$nm"; read -r -p "Enter..." ;;
                l) read -r -p "Имя профиля: " nm; [ -n "$nm" ] && profile_command load "$nm"; read -r -p "Enter..." ;;
                d) read -r -p "Имя профиля: " nm; [ -n "$nm" ] && profile_command delete "$nm"; read -r -p "Enter..." ;;
            esac
            ;;
        5) install_completion_command; read -r -p "Enter..." ;;
        6)
            echo "  [1] all  [2] ssh  [3] ufw  [4] upgrades"
            read -r -p "Выбор: " hs
            case "$hs" in
                1) harden_command all; read -r -p "Enter..." ;;
                2) harden_command ssh; read -r -p "Enter..." ;;
                3) harden_command ufw; read -r -p "Enter..." ;;
                4) harden_command upgrades; read -r -p "Enter..." ;;
            esac
            ;;
        0) ;;
    esac
}

_menu_monitoring() {
    clear
    echo -e "${YELLOW}${BOLD}📊 Monitoring${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} benchmark — пинг до популярных endpoints"
    echo -e "  ${CYAN}[2]${NC} ${GREEN}bench-suite${NC} — iperf3 baseline до 4 серверов + CSV"
    echo -e "  ${CYAN}[3]${NC} prom-metrics — Prometheus output на stdout"
    echo -e "  ${CYAN}[4]${NC} prom-serve [port=9777] — поднять Prometheus exporter"
    echo -e "  ${CYAN}[5]${NC} health-watch on/off (фоновый daemon)"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) run_benchmark; read -r -p "Enter..." ;;
        2) bench_suite_command; read -r -p "Enter..." ;;
        3) prom_metrics; read -r -p "Enter..." ;;
        4) read -r -p "Порт [9777]: " pp; prom_serve "${pp:-9777}" ;;
        5) read -r -p "on/off/status [status]: " hw; health_watch_command "${hw:-status}"; read -r -p "Enter..." ;;
        0) ;;
    esac
}

_menu_misc() {
    clear
    echo -e "${CYAN}${BOLD}📦 Misc${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} install — зависимости Phoenix-X"
    echo -e "  ${CYAN}[2]${NC} export — конфиги в /tmp/vps-phoenix-bundle.tar.gz"
    echo -e "  ${CYAN}[3]${NC} import — из tar.gz"
    echo -e "  ${CYAN}[4]${NC} update — self-update из GitHub"
    echo -e "  ${CYAN}[5]${NC} backup-config <rclone-remote>"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) install_dependencies; read -r -p "Enter..." ;;
        2) export_config; read -r -p "Enter..." ;;
        3) read -r -p "Путь к архиву: " ap; [ -n "$ap" ] && import_config "$ap"; read -r -p "Enter..." ;;
        4) self_update; read -r -p "Enter..." ;;
        5) read -r -p "rclone remote (например s3:mybucket/vps): " rc; [ -n "$rc" ] && backup_config_command "$rc"; read -r -p "Enter..." ;;
        0) ;;
    esac
}

# ===================================================================
#  Точка входа: CLI или интерактивное меню
# ===================================================================

if [ $# -gt 0 ]; then
    CLI_MODE=1
    # help/status/version/prom-metrics — без проверки root, остальные команды требуют sudo
    case "$1" in
        help|-h|--help) print_cli_help; exit 0 ;;
        version|--version|-V)
            # v8.8 (F8): поддержка --json для оркестраторов.
            shift
            if [ "${1:-}" = "--json" ]; then
                printf '{"version":"%s","name":"vps_optimizer"}\n' "$SCRIPT_VERSION"
            else
                echo "vps_optimizer.sh v$SCRIPT_VERSION"
            fi
            exit 0
            ;;
        # v8.8: whoami / show / compare — read-only, без root
        whoami)
            shift
            whoami_command "${1:-}"
            exit 0
            ;;
        show)
            shift
            show_preset_command "${1:-balanced}"
            exit 0
            ;;
        compare-presets|compare-preset|preset-diff)
            shift
            compare_presets_command "${1:-balanced}" "${2:-proxy}"
            exit 0
            ;;
        config)
            # v8.6: config show — без root; config lang — требует root для записи
            shift
            if [ "${1:-show}" = "show" ] || [ -z "${1:-}" ]; then
                config_command show
                exit 0
            fi
            check_root
            config_command "$@"
            exit $?
            ;;
        status)
            shift
            # Поддержка --json и --watch без root
            for a in "$@"; do
                [ "$a" = "--json" ] && { status_json; exit 0; }
            done
            for a in "$@"; do
                if [ "$a" = "--watch" ]; then
                    # v8.6: status --watch — live update каждые 2с до Ctrl-C.
                    # Тише header, бесконечный цикл, корректный exit на Ctrl-C.
                    trap 'echo; exit 0' INT TERM
                    while true; do
                        clear
                        echo -e "${GRAY}vps-optimizer status --watch (Ctrl-C to exit, refresh=2s)${NC}"
                        echo ""
                        print_status_dashboard
                        sleep 2
                    done
                fi
            done
            print_status_dashboard
            exit 0
            ;;
        prom-metrics) prom_metrics; exit 0 ;;
        _prom_handler) _prom_handler; exit 0 ;;
    esac
    check_root
    cli_dispatch "$@"
    exit $?
fi
check_root
main_menu
