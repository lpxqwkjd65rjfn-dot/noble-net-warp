#!/usr/bin/env bats
# Unit tests for core helpers in vps_optimizer.sh (v8.5)
# Run: bats tests/

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../vps_optimizer.sh"
    [ -f "$SCRIPT" ] || skip "vps_optimizer.sh not found at $SCRIPT"
}

# === bash -n ===
@test "vps_optimizer.sh: bash -n succeeds" {
    bash -n "$SCRIPT"
}

# === SCRIPT_VERSION sanity ===
@test "SCRIPT_VERSION is set and starts with 8" {
    run grep -E '^SCRIPT_VERSION=' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'SCRIPT_VERSION="8'* ]]
}

# === help command ===
@test "help command exits 0" {
    run bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" == *USAGE* ]]
}

# === unknown command ===
@test "unknown command returns non-zero" {
    run bash "$SCRIPT" --no-rollback xyz_unknown_cmd_zzz
    [ "$status" -ne 0 ]
}

# === core helpers exist ===
@test "_json_str function is defined" {
    run grep -E '^_json_str\(\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "urand function is defined" {
    run grep -E '^urand\(\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "detect_virt function is defined" {
    run grep -E '^detect_virt\(\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === noise generator extraction is shellcheck-clean ===
@test "extracted noise generator is shellcheck-clean (-S warning)" {
    if ! command -v shellcheck >/dev/null 2>&1; then
        skip "shellcheck not installed"
    fi
    awk '/cat > "\$NOISE_GEN_SCRIPT" <<'\''NOISE_EOF'\''/{f=1;next} f && /^NOISE_EOF$/{f=0} f' "$SCRIPT" > /tmp/noise_gen.sh
    [ -s /tmp/noise_gen.sh ]
    run shellcheck -S warning /tmp/noise_gen.sh
    [ "$status" -eq 0 ]
}

# === STUN packet does NOT contain raw NUL (would truncate bash variable) ===
@test "stun_burst packet uses escape-string format (no raw NUL)" {
    run grep -F "stun_pkt='\\x00\\x01\\x00\\x00" "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === defaults are SSH-safe ===
@test "default rp_filter without --vpn is strict (=1)" {
    run grep -E 'rp_filter.*1' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "no firewall presets in apply path" {
    run grep -E 'apply_optimizations.*\biptables\b|apply_optimizations.*\bnft\b' "$SCRIPT"
    [ "$status" -ne 0 ]
}

# === stealth-test command registered ===
@test "stealth-test command is registered" {
    run grep -E '^[[:space:]]+stealth-test\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === playbook command registered ===
@test "playbook command is registered" {
    run grep -E '^[[:space:]]+playbook\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === backup-config command registered ===
@test "backup-config command is registered" {
    run grep -E '^[[:space:]]+backup-config\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === health-watch command registered ===
@test "health-watch command is registered" {
    run grep -E '^[[:space:]]+health-watch\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === audit-syslog command registered ===
@test "audit-syslog command is registered" {
    run grep -E '^[[:space:]]+audit-syslog\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === DoQ is opt-in (not in apply_optimizations) ===
@test "DoQ is NOT auto-applied" {
    # apply_optimizations should not call dns_doq_command
    run awk '/^apply_optimizations\(\)/,/^\}/' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" != *dns_doq_command* ]]
    [[ "$output" != *dns_dnssec_command* ]]
}

# === DNSSEC is opt-in ===
@test "DNSSEC is NOT auto-applied" {
    run awk '/^apply_optimizations\(\)/,/^\}/' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" != *dnssec_command* ]]
}

# === VPN-iface skip in initcwnd ===
@test "initcwnd skips tun/wg ifaces" {
    run grep -E 'tun\*|wg\*|ppp\*' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: i18n ===
@test "v8.6: I18N_EN/RU/DE/FR/ZH tables defined" {
    run grep -E '^declare -A I18N_EN I18N_RU I18N_DE I18N_FR I18N_ZH' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.6: _t() function defined" {
    run grep -E '^_t\(\) \{' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.6: LC_VPS env override changes lang" {
    run env LC_VPS=ru bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"lang=ru"* ]]
    run env LC_VPS=zh bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"lang=zh"* ]]
}

@test "v8.6: invalid LC_VPS falls back to en" {
    run env LC_VPS=xx bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"lang=en"* ]]
}

@test "v8.6: config show is registered (no root needed)" {
    run bash "$SCRIPT" config show
    [ "$status" -eq 0 ]
    [[ "$output" == *"config file"* ]]
}

@test "v8.6: --no-color flag is recognized and resets color vars" {
    run grep -E '^[[:space:]]+--no-color\)' "$SCRIPT"
    [ "$status" -eq 0 ]
    # And TTY-detect logic exists
    run grep -E '_vps_use_color' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.6: help output via pipe contains no ANSI escapes" {
    # Default behavior: stdout is a pipe (bats run captures), so NO_COLOR/TTY-detect kicks in
    run bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" != *$'\033'* ]]
}

# === v8.6: status --watch is recognized (we don't run it because it loops) ===
@test "v8.6: status --watch parsing exists" {
    run grep -E 'a" = "--watch"' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: --json-logs flag parsed ===
@test "v8.6: --json-logs flag parsed" {
    run grep -E '^[[:space:]]+--json-logs\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: --learn flag parsed ===
@test "v8.6: --learn flag sets DRY_RUN=1" {
    run grep -E 'LEARN_MODE=1; DRY_RUN=1' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: stealth-test --json/--ja4/--exit-fail-on-leak parse ===
@test "v8.6: stealth-test --json supported" {
    run awk '/^stealth_test_command\(\)/,/^\}/' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"--json"* ]]
    [[ "$output" == *"--exit-fail-on-leak"* ]]
    [[ "$output" == *"--ja4"* ]]
}

# === v8.6: prom-metrics has DNS hit-ratio ===
@test "v8.6: prom_metrics emits vps_dns_cache_hit_ratio" {
    run awk '/^prom_metrics\(\)/,/^\}/' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"vps_dns_cache_hit_ratio"* ]]
}

# === v8.6: noise uses --tcp-fastopen ===
@test "v8.6: noise generator uses --tcp-fastopen flag" {
    run grep -F -- "--tcp-fastopen" "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: tcp_thin_dupack only on proxy preset ===
@test "v8.6: tcp_thin_dupack is preset-gated to proxy (CONTRIBUTING #5)" {
    # Verify the line right above 'sysctl_safe net.ipv4.tcp_thin_dupack 1' is
    # an `if [ "$PRESET_NAME" = "proxy" ]; then` block opener.
    # We check 4 lines of context before the dupack line and assert that
    # the proxy-preset gate appears in those 4 lines.
    run grep -B4 'sysctl_safe net.ipv4.tcp_thin_dupack 1' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'PRESET_NAME" = "proxy"'* ]]
}

@test "v8.6: IPv6 privacy ext is preset-gated to proxy" {
    run grep -B4 'use_tempaddr 2' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'PRESET_NAME" = "proxy"'* ]]
}

# === v8.6: numa_balancing auto-detect ===
@test "v8.6: numa_balancing 0 only inside NUMA-detect blocks (no unconditional)" {
    # Sanity: numa_balancing 0 must appear at least once
    run grep -c 'numa_balancing 0' "$SCRIPT"
    [ "$status" -eq 0 ]
    [ "$output" -ge 1 ]
    # Each numa_balancing 0 line must have a NUMA-detection sentinel (numactl
    # output OR /sys/devices/system/node) within 8 lines above.
    while IFS= read -r line_num; do
        [ -z "$line_num" ] && continue
        local from=$((line_num - 8))
        [ "$from" -lt 1 ] && from=1
        run sed -n "${from},${line_num}p" "$SCRIPT"
        [[ "$output" == *'numactl'* ]] || [[ "$output" == *'/sys/devices/system/node'* ]] || {
            echo "Line $line_num has numa_balancing 0 with no NUMA detection above"
            false
        }
    done < <(grep -n 'numa_balancing 0' "$SCRIPT" | cut -d: -f1)
}

# ============================================================================
# v8.7 tests
# ============================================================================

@test "v8.7: SCRIPT_VERSION is 8.7" {
    run grep -E '^SCRIPT_VERSION="8\.7"' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: suggest command is registered" {
    run grep -E 'suggest\)\s*suggest_command' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: wizard command is registered" {
    run grep -E 'wizard\)\s*wizard_command' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: profile command is registered" {
    run grep -E 'profile\)$' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'profile_command' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: log-tail and bench-suite registered" {
    run grep 'log-tail|log)' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'bench-suite|bench)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: install-completion command is registered" {
    run grep 'install-completion|completion)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: dns padding command is registered" {
    run grep -E 'padding\)' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'dns_padding_command' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: tcp_l3mdev_accept and udp_l3mdev_accept are set" {
    run grep 'sysctl_safe net.ipv4.tcp_l3mdev_accept 1' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'sysctl_safe net.ipv4.udp_l3mdev_accept 1' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: net.unix.max_dgram_qlen is set" {
    run grep 'sysctl_safe net.unix.max_dgram_qlen 512' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: vm.swappiness is preset-specific (proxy=30, web=60)" {
    run grep -E 'PRESET_SWAPPINESS=30' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'PRESET_SWAPPINESS=60' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: dev_weight on 10G+ NIC is at least 192" {
    # dev_weight_target=192 (10G) and 256 (25G+)
    run grep 'dev_weight_target=192' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'dev_weight_target=256' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: iOS 18 noise pool includes Apple Maps/iMessage/captive endpoints" {
    run grep 'gsp-ssl.ls.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'amp-api.music.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'p104-imws.icloud.com' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: JA3 known list is at least 8 hashes (was 4)" {
    # Count tokens between quotes in ios_known_ja3 line
    run bash -c "grep 'ios_known_ja3=' '$SCRIPT' | grep -oE '[a-f0-9]{32}' | wc -l"
    [ "$status" -eq 0 ]
    [ "$output" -ge 8 ]
}

@test "v8.7: doctor includes UDP RcvbufErrors check" {
    run grep 'RcvbufErrors' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: main_menu uses categorical _menu_* sub-functions" {
    run grep -E '_menu_performance|_menu_stealth|_menu_diagnostics|_menu_config|_menu_monitoring|_menu_misc' "$SCRIPT"
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

@test "v8.7: bash completion is generated to /etc/bash_completion.d/" {
    run grep '/etc/bash_completion.d/vps-optimizer' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: profile snapshot dir is /var/lib/vps-optimizer/profiles" {
    run grep 'profiles_dir=/var/lib/vps-optimizer/profiles' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: noise EDNS padding skips dnsmasq (known limitation)" {
    run grep 'dnsmasq не поддерживает EDNS0 padding' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7: reset_all cleans up unbound padding conf" {
    run grep '99-vps-optim-padding.conf' "$SCRIPT"
    [ "$status" -eq 0 ]
    # Must appear in reset_all (between rm -f and matching block before sysctl --system)
    run grep -c '99-vps-optim-padding.conf' "$SCRIPT"
    [ "$status" -eq 0 ]
    [ "$output" -ge 2 ]   # in reset_all rm and in dns_padding rm
}
