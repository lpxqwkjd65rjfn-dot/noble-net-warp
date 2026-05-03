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

@test "v8.7: SCRIPT_VERSION is at least 8.7" {
    # SCRIPT_VERSION может быть 8.7+ (8.8, 8.9, ...) — bump в новых релизах ок.
    run grep -E '^SCRIPT_VERSION="8\.[7-9]"' "$SCRIPT"
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

@test "v8.7 fix R10-1: no buggy udp_l3mdev_accept 0 line (was overriding our v8.7=1)" {
    # Devin Review #10 caught a v8.6 bug: udp_l3mdev_accept=0 was set with a comment
    # about udp_hash_entries (wrong sysctl name + wrong value). Removed in v8.7.
    run grep -E 'sysctl_safe net\.ipv4\.udp_l3mdev_accept 0' "$SCRIPT"
    [ "$status" -ne 0 ]   # must NOT match
}

@test "v8.7 fix R10-2: install_completion_command calls _audit (CONTRIBUTING #8)" {
    run grep '_audit install-completion' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.7 fix R10-3: bench_suite_command calls _audit (CONTRIBUTING #8)" {
    run grep '_audit bench-suite' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.x: SCRIPT_VERSION present and current" {
    # Catches 8.8+ going forward including multi-digit minors (8.10, 8.11, ...).
    run grep -E '^SCRIPT_VERSION="8\.([89]|[1-9][0-9]+)"$' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 K1: BIG TCP IPv6 — gso/gro_max=196608 on kernel 6.3+" {
    run grep '_gso_target=196608' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'gso_max_size "?\$_gso_target' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'gro_max_size "?\$_gso_target' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 K3: Accurate ECN tcp_ecn=3 gated to kernel 6.0+" {
    run grep -E 'sysctl_safe net\.ipv4\.tcp_ecn 3' "$SCRIPT"
    [ "$status" -eq 0 ]
    # AccECN must be inside a kernel-version check — line above must have _krn_maj >= 6
    run grep -B5 'sysctl_safe net\.ipv4\.tcp_ecn 3' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'_krn_maj'* ]] || [[ "$output" == *'kernel'* ]]
}

@test "v8.8 N1: txqueuelen auto-tune for 10G+ links" {
    run grep -E 'txqueuelen 5000' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'txqueuelen 10000' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 A2: tcp_min_rtt_wlen=300 on non-proxy preset" {
    # Non-proxy presets get 300; proxy keeps 600 from v8.4.
    run grep -B3 'sysctl_safe net.ipv4.tcp_min_rtt_wlen 300' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'PRESET_NAME'*'!='*'proxy'* ]]
}

@test "v8.8 A5: tcp_syn_linear_timeouts=4" {
    run grep -E 'sysctl_safe net\.ipv4\.tcp_syn_linear_timeouts 4' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 C8: ip_local_reserved_ports for VPN listeners" {
    run grep -E 'sysctl_safe net\.ipv4\.ip_local_reserved_ports' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep '51820' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep '1194' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 C9: tcp_timestamps=2 only on proxy preset" {
    # CONTRIBUTING #5: stealth knob gated to proxy.
    run grep -B3 'sysctl_safe net.ipv4.tcp_timestamps 2' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'PRESET_NAME'*'='*'proxy'* ]]
}

@test "v8.8 C1: APNs gateway endpoints in noise pool" {
    run grep 'gateway.push.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'courier.push.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 C2: iCloud Private Relay endpoints" {
    run grep 'mask.icloud.com' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'mask-h2.icloud.com' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 C3+C10+C11: App Store + Apple ID + Configurator endpoints" {
    run grep 'appstoreconnect.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'idmsa.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'albert.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 C5: ALPN rotation distributes h3/h2/http/1.1 (50/40/10)" {
    run grep '_alpn_pick' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E '\-\-http1\.1' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 G3: VPN-iface skip-list extended (cloudflared/tailscale/zerotier)" {
    run grep -E 'cloudflared\*|tailscale\*|zt\*|utun\*' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 G1: doctor checks NetworkManager coexistence" {
    run grep -E 'NetworkManager.*активен.*управляет|NetworkManager.*coexistence' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 E6: doctor calculates TCP retrans rate" {
    run grep -E 'TCP retrans rate' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'RetransSegs' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 E8: doctor checks conntrack table fill ratio" {
    run grep -E 'Conntrack.*table|nf_conntrack_max' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep '_ct_pct' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 K2: doctor recommends BBRv3 if available but not active" {
    run grep -E 'BBRv3 доступен но не активен' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 F4: whoami_command exists and supports --json" {
    run grep '^whoami_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -A20 '^whoami_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'"--json"'* ]]
}

@test "v8.8 F2: show_preset_command exists" {
    run grep '^show_preset_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 F3: compare_presets_command exists" {
    run grep '^compare_presets_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 F10: rollback_command uses profile snapshots" {
    run grep '^rollback_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -A30 '^rollback_command()' "$SCRIPT"
    [[ "$output" == *'profile_command load'* ]]
    run grep -A30 '^rollback_command()' "$SCRIPT"
    [[ "$output" == *'_audit rollback'* ]]
}

@test "v8.8 F1: doctor_fix_command provides interactive fixes" {
    run grep '^doctor_fix_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep '_audit doctor-fix' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 F8: --version --json supported" {
    run grep -E '"name":"vps_optimizer"' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8 F7: --verbose flag aliased to --debug" {
    run grep -E '\-\-verbose\|-v' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.8: bash completion includes new commands" {
    run grep -E 'whoami show compare-presets rollback version' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# ---- v8.9 regression tests ----

@test "v8.9: SCRIPT_VERSION bumped to 8.9" {
    run grep '^SCRIPT_VERSION="8.9"' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 K2: tcp_reflect_tos via sysctl_safe" {
    run grep 'sysctl_safe net.ipv4.tcp_reflect_tos 1' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 K3: tcp_migrate_req via sysctl_safe" {
    run grep 'sysctl_safe net.ipv4.tcp_migrate_req 1' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 K4: vm.compaction_proactiveness via sysctl_safe" {
    run grep 'sysctl_safe vm.compaction_proactiveness 20' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 K8: high_order_alloc_disable via sysctl_safe" {
    run grep 'sysctl_safe net.core.high_order_alloc_disable 0' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 G3+G4: nf_conntrack security flags via sysctl_safe" {
    run grep 'sysctl_safe net.netfilter.nf_conntrack_helper 0' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'sysctl_safe net.netfilter.nf_conntrack_tcp_loose 0' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 N5: ring buffer auto-tune via ethtool -G" {
    run grep -E 'ethtool -G.*rx' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'Pre-set maximums' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 N3: qdisc cake on bare-metal vs fq on virt" {
    run grep -E 'modprobe sch_cake' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E '_virt_now.*=.*detect_virt' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 N7: disk I/O scheduler nvme=none, hdd=bfq" {
    run grep -E 'nvme.*target=.*none' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'rotational.*=.*1.*bfq' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 C1: pick_curl_per_conn function exists" {
    run grep '^pick_curl_per_conn()' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 C1: noise function uses pick_curl_per_conn" {
    run grep '_conn_curl=$(pick_curl_per_conn)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 C2: iOS 18 UA pinning with weighted distribution" {
    run grep 'iPhone OS 18_3' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'iPhone OS 18_2' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 C3: TLS ECH opt-in via NOISE_ECH" {
    run grep 'NOISE_ECH' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -- '--ech' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 C4: Apple AV CDN endpoints in noise pool" {
    run grep 'audio-ssl.itunes.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'video-ssl.itunes.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 C5: Spotlight Suggestions endpoints" {
    run grep 'api-tip.cdn-apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'api.smoot.apple.com' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 C6: iCloud Keychain endpoints" {
    run grep 'escrowproxy.icloud.com' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'keyvalueservice.icloud.com' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 C9: --keepalive-time set in curl args" {
    run grep -- '--keepalive-time 30' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 F1: revert_command exists" {
    run grep '^revert_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep '_audit revert' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 F2: compare_current_command exists" {
    run grep '^compare_current_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 F3: history_command exists" {
    run grep '^history_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 F4: changelog_command exists" {
    run grep '^changelog_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 F8/E6: doctor_run_command supports --watch and --json" {
    run grep '^doctor_run_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -A30 '^doctor_run_command()' "$SCRIPT"
    [[ "$output" == *'--watch'* ]]
    [[ "$output" == *'--json'* ]]
}

@test "v8.9 E1: health_score_command exists" {
    run grep '^health_score_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 F12: snapshot_before_command exists" {
    run grep '^snapshot_before_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep '_audit snapshot-before' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 E5: install_logrotate_command exists" {
    run grep '^install_logrotate_command()' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep '/etc/logrotate.d/vps-optimizer' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 G1: doctor checks TLS cert expiry" {
    run grep -E 'TLS cert.*истёк|TLS cert.*expiry' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 G2: doctor checks chrony/timedatectl skew" {
    run grep -E 'chronyc tracking' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'NTPSynchronized' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9 E1+E3+E4: prom_metrics includes health_score, noise_failures_rate, profile_snapshots" {
    run grep 'vps_health_score' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'vps_noise_failures_rate' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep 'vps_profile_snapshots_total' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.9: cli_dispatch routes new commands (revert, history, snapshot, etc.)" {
    run grep -E '^[[:space:]]+revert\)' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E '^[[:space:]]+history\)' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E '^[[:space:]]+snapshot\)' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'compare-current' "$SCRIPT"
    [ "$status" -eq 0 ]
}
