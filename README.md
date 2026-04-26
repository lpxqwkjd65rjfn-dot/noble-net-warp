# 🦅 Noble Net Warp / VPS Optimizer

Single-file Bash 5+ tool that turns a stock cloud Ubuntu 22.04/24.04 VPS into a
tuned, low-latency proxy / edge / web host **without touching the hypervisor**
and **without breaking on locked-down OpenVZ/LXC**.

Every kernel knob is applied via **probe-then-write** — if the kernel/host
rejects it, it is silently skipped instead of being persisted into a broken
`/etc/sysctl.d/` file. After `apply` you get a coloured self-test showing
`OK / SKIPPED / DENIED` per setting.

---

## Quick start

```bash
curl -O https://raw.githubusercontent.com/lpxqwkjd65rjfn-dot/noble-net-warp/main/vps_optimizer.sh
chmod +x vps_optimizer.sh
sudo ./vps_optimizer.sh apply --preset proxy
sudo ./vps_optimizer.sh status
```

For machine-readable status (Grafana / cron alerts / Zabbix):

```bash
sudo ./vps_optimizer.sh status --json
sudo ./vps_optimizer.sh prom-metrics            # Prometheus text format
sudo ./vps_optimizer.sh prom-serve 9777 &       # exporter on :9777
```

Self-update (with SHA256 verification when sidecar is published):

```bash
sudo ./vps_optimizer.sh update
```

Full uninstall (resets all settings + removes the script itself):

```bash
sudo ./vps_optimizer.sh uninstall
```

---

## ✨ What it does

### Network stack — deep TCP / UDP tuning

- **BBR + fq_codel** by default, full pacing tuning (`tcp_pacing_ss_ratio`,
  `tcp_pacing_ca_ratio`, `tcp_min_rtt_wlen`).
- **Modern TCP recovery**: RACK, passive ECN, thin-stream linear timeouts,
  `tcp_reordering`, `tcp_max_reordering`, `tcp_early_retrans=3`, `tcp_frto=2`,
  `tcp_autocorking=0`, `tcp_limit_output_bytes`.
- **v8.2 additions**: `tcp_rto_min_us`, `tcp_comp_sack_delay_ns`,
  `tcp_comp_sack_nr`, `tcp_comp_sack_slack_ns`, `tcp_pingpong_thresh`,
  `tcp_min_tso_segs`, `tcp_tso_win_divisor`, `tcp_no_ssthresh_metrics_save`.
- **Low-latency / fast-failover**: `tcp_mtu_probing=1` + `tcp_base_mss=1024`
  (cures PMTU black holes on tunnels / proxies — WireGuard / Reality / XHTTP),
  `tcp_low_latency=1`, `tcp_workaround_signed_windows=1`, `tcp_retries2=8`,
  `netdev_budget=600` + `netdev_budget_usecs=8000`.
- **Adaptive buffers**: `ethtool` reads real link speed; `tcp_rmem` / `tcp_wmem`
  ceilings auto-grow up to 256 MB on 10G+ and 512 MB on 25G+.
- **conntrack tuning**: `nf_conntrack_max` 1M..2M, `nf_conntrack_buckets=256k`,
  `tcp_timeout_established=600` — fixes the silent dropped-packet ceiling at
  ~65k connections that cripples busy proxies by default.
- **MPTCP** auto-enabled on Linux 5.6+.
- **ECMP / multipath**: detected automatically when the host has multiple
  default routes (or use `--ecmp`).

### CPU / IRQ load distribution

- **Multi-queue auto-expand**: `ethtool -L combined N` raises virtio-net (and
  similar) from the default 1 queue to `min(N_cpus, max_combined)` — usually
  the #1 bottleneck on cloud VPS.
- **RPS / RFS / XPS** with kernel-correct cpumask format that works on hosts
  with **>32 CPUs** (comma-separated 32-bit hex chunks).
- **`isolcpus=`-aware** affinity: dedicated/isolated cores excluded from
  RPS/XPS/IRQ rotation.
- **NIC offload safety**: TSO/GSO/GRO are only changed on bare-metal/KVM/Xen.
  In OpenVZ/LXC/Docker we only force `lro off` (which is what proxies need)
  and leave the rest under host control.

### Memory / I/O

- **THP → `madvise`** (no latency spikes that `always` causes on proxy
  workloads).
- **I/O scheduler auto-pick**: `none` for NVMe, `mq-deadline` for SSD.
- **VM tuning**: `vm.max_map_count=1M`, `vm.overcommit_memory=1`,
  `watermark_scale_factor=125` + `watermark_boost_factor=15000`,
  `compaction_proactiveness=0`, dirty ratios, `admin_reserve_kbytes=16384`.
- **ZRAM** (lz4) auto-setup when supported.
- `core_pattern → /bin/false` so a crash dump can't fill the disk.

### DNS — three transports, manual choice

```bash
sudo ./vps_optimizer.sh dns plain yandex
sudo ./vps_optimizer.sh dns dot cloudflare
sudo ./vps_optimizer.sh dns doh quad9
sudo ./vps_optimizer.sh dns doh custom https://my-doh.example/dns-query
sudo ./vps_optimizer.sh dns local
```

Built-in resolvers: **Cloudflare / Google / Yandex / Quad9 / AdGuard**, plus
`custom <ips/url>`. Local **dnsmasq** caching (10k entries, neg-ttl 60s) sits
in front of any upstream so repeat-query RTT collapses to near-zero.

### Stealth — white-noise traffic generator

A separate, sandboxed `vps-noise.service` (systemd-hardened: `PrivateTmp`,
`ProtectSystem`, `ProtectKernelTunables`, `LockPersonality`,
`RestrictSUIDSGID`, `RestrictNamespaces`, `NoNewPrivileges`,
`MemoryMax=256M`, `TasksMax=64`, `Restart=on-failure`,
`StartLimitBurst=5`) emits a realistic background traffic profile **without
ever writing payload to disk** (`curl -o /dev/null` everywhere).

Loops:

| Loop | Cadence | Behaviour |
|---|---|---|
| iOS Safari / CFNetwork bursts | 1–6 min | Apple, iCloud, mzstatic, AppStore, Weather, News, Stocks, Maps, GSA. iOS 18.x / iPadOS 18.x / 17.x / 16.x UAs. |
| APNs keepalive | 25–40 min | `courier.push.apple.com:5223` keepalive. |
| RU email | 45–180 min | Yandex.Mail / Mail.ru / Max.ru, multiple inner pages per session. |
| RU news | 20–90 min | lenta / ria / rbc / tass / kommersant / vedomosti / gazeta / rg / iz / interfax / kp / dzen / mk / fontanka / meduza. |
| Library / archive phantom | 90 min – 6 h | GitHub releases, npm registry, PyPI, Maven, RubyGems, crates.io, kernel.org, GNU FTP, openssl.org, Apache archive, Debian/Ubuntu APT mirrors. UAs: `curl`, `Wget`, `pip`, `npm`, `Maven`, `Go-http-client`, `Debian APT-HTTP/1.3 Ubuntu/24.04`. |
| **Cloud / NTP / cloud-init phantom** *(v8.2)* | 30–180 min | `archive.ubuntu.com`, `security.ubuntu.com`, `time.ubuntu.com:123`, `api.snapcraft.io` — what every real Ubuntu node hits in the background. |
| **DNS prefetch** *(v8.2)* | 30–240 s | Browser-style DNS preconnect — silent `getent` lookups against random hosts from all pools. |
| **Health touch** *(v8.2)* | 30 s | Updates `/run/vps-noise/health.json` so `noise health` / `prom-serve` always show liveness. |

Plus:

- **iOS RU-strict mode**: 70% Apple / 20% RU news / 10% RU government &
  critical-infrastructure portals. **No social networks, no messengers** by
  design.
- **Diurnal curve**: nights ×2.5 longer pauses, morning/evening peaks ×0.6–0.7,
  day ×1.0.
- **Place profile** *(v8.2)*: `auto` / `office` / `home` / `always_on` —
  shapes the curve to look like a 9–18 office machine, an evening-peak home
  machine, or a true 24/7 server.
- **Vacation mode**: ~7% chance per day to enter 6–72 h of complete silence.
  State persists in `/var/lib/vps-noise/`.
- **Referer chains** *(v8.2)*: every burst now sends real `Referer:` headers
  walking through your "session" pages, with correct `Sec-Fetch-Site:
  same-origin/cross-site/none` decisions per hop.
- **HTTP cache headers** *(v8.2)*: `If-None-Match` / `If-Modified-Since`
  emitted on repeat URLs, exactly how a real browser cache behaves.
- **`/dev/urandom` randomness** *(v8.2)*: replaces `$RANDOM` so parallel
  loops can't accidentally pick correlated URLs.
- Optional **curl-impersonate-safari** (auto-installed with
  `install --impersonate`) for real Safari TLS / JA3 / JA4 fingerprint —
  defeats handshake-level fingerprinting.

### Security & robustness

- **Probe-then-write** for every sysctl/sysfs.
- **Hypervisor detection** (KVM / Xen / OpenVZ / LXC / Docker / WSL) — features
  the host forbids are silently skipped.
- **Kernel-version gating** for MPTCP, BBR3, etc.
- **Lock-file** (`/var/lock/vps-optimizer.lock`) prevents two `apply`s racing.
- **Rollback snapshot** taken before every `apply`
  (`/var/backups/vps-optimizer/pre-apply-*.tar.gz`).
- **Idempotency**: identical sysctl content → no rewrite, no `sysctl -p`.
- **Audit log** (`/var/log/vps-optimizer-audit.log`) records every mutating
  command with timestamp + user.
- **Debug log** (`--debug`, `/var/log/vps-optimizer-debug.log`) records every
  sysctl/sysfs write attempt with OK / SKIP / DENIED.
- **Self-update with SHA256 verification** (when sidecar `.sha256` is
  published with the release) and automatic rollback if the new script doesn't
  pass `--help`.
- **Connectivity pre-check** before `apply` — warns if the host has no
  internet (won't accidentally lock you out via DNS).
- **Full `reset`** restores DNS, dnsmasq, dnscrypt-proxy, ZRAM, swap, RPS
  service, sysctl, limits, the noise service.

### Opt-in security baseline (`harden`)

Separate from the default `apply` to avoid surprising production:

```bash
sudo ./vps_optimizer.sh harden ssh        # MaxAuthTries 3, no password auth, banner
sudo ./vps_optimizer.sh harden ufw        # default deny, allow detected SSH port
sudo ./vps_optimizer.sh harden upgrades   # unattended-upgrades security-only
sudo ./vps_optimizer.sh harden all
```

---

## CLI reference

```text
install                         Setup base components (dnsmasq, ethtool, jq, socat...)
                                use `--impersonate` to also install curl-impersonate
apply [--preset NAME]           Apply sysctl/sysfs/ZRAM. NAME: balanced (default) / proxy / web
    [--vpn]                     Force VPN-friendly knobs (rp_filter=2, ip_forward=1, accept_local=1)
    [--no-rollback]             Disable the post-apply auto-rollback safety net
    [--boot]                    Install one-shot systemd unit so `apply` runs on every boot
status [--json]                 Status dashboard, or JSON for cron / Grafana
self-test                       Re-verify applied settings
audit [--json]                  Deep diagnostics (drift / conntrack / RPS / DNS / PTR), `--json` for monitoring
doctor                          Actionable diagnostics with concrete fixes (conntrack, retransmits, softnet, /var, DNS)
why <key>                       Knowledge base: explain a specific sysctl key (e.g. `why net.ipv4.tcp_rmem`)
wg setup                        Opt-in WireGuard helper: ICMP-based MTU autodetect + base config
logs [N]                        Last N log lines: own log + journalctl + dmesg + audit
preset <name>                   Save a preset for the next apply
noise on|off|edit|test|status|health   Manage the stealth noise generator
dns ...                         Manage DNS (plain | dot | doh — see `--help`)
swap <gb>                       Create a swapfile of N GB
benchmark                       Latency check against popular endpoints
compare [target]                Save / diff a ping baseline (default 1.1.1.1)
harden ssh|ufw|upgrades|all     Opt-in security baseline (does NOT touch default apply)
prom-metrics                    Dump Prometheus metrics to stdout
prom-serve [port]               Start a Prometheus exporter (default :9777)
reset [--soft]                  Full rollback. `--soft` keeps DNS / noise / swap untouched
uninstall                       Reset + remove the script itself
export [path.tar.gz]            Bundle all configs (with manifest)
import <path.tar.gz>            Apply a bundle (with version check)
update                          Self-update from GitHub (with SHA256 verification)
help                            Print full help
```

### Global flags

```text
--dry-run        preview only, no writes
--quiet, -q      minimum output (cron/scripts)
--debug          verbose log to /var/log/vps-optimizer-debug.log
--force          ignore lock / interactive confirmations
--preset NAME    use a specific preset (balanced|proxy|web)
--impersonate    use curl-impersonate in noise (if installed)
--ecmp           force ECMP/multipath knobs (multi-NIC)
--vpn            force VPN-friendly knobs (auto-detected by default)
--no-rollback    disable the auto-rollback safety net after `apply`
--soft           soft mode for `reset` — keep DNS / noise / swap intact
--boot           install one-shot systemd unit for `apply` (re-applies on every boot)
--json           JSON output (for `status` / `audit`)
```

### Cron-friendly exit codes

```text
 0   ok
10   already-applied (idempotent no-op)
20   no internet (probe failed)
30   blocked by hypervisor/container restrictions
40   another instance is running (lock busy)
50   invalid arguments / unknown preset
60   auto-rolled-back due to connectivity loss
```

---

## Tested & validated

- `bash -n` — clean.
- `shellcheck` — 0 warnings on the host script and on the embedded noise
  generator.
- Probe-then-write verified to skip cleanly on locked-down OpenVZ.

---

## Compatibility

- **Required**: root, Bash 5+, Ubuntu 22.04 / 24.04 (or Debian 11/12 with
  minor adjustments).
- **Hypervisor**: KVM, Xen, VMware — full feature set.
  OpenVZ / LXC — features the host forbids are auto-skipped.
- **Kernels**: ≥ 5.4 minimum; ≥ 5.10 recommended for the full feature surface
  (RACK, MPTCP, modern NAPI knobs); some `tcp_*` v8.2 keys land on 6.x.
- **Disk**: ≤ 30 MB of additional packages installed by the optional
  `install` step (`dnsmasq`, `zram-tools`, `jq`, `nano`, `socat`, ...).

---

## Files this script touches

```text
/etc/sysctl.d/99-vps-optimizer.conf
/etc/sysctl.d/99-vps-experimental.conf
/etc/security/limits.d/99-vps-limits.conf
/etc/systemd/system/vps-noise.service
/etc/systemd/system/vps-rps.service
/etc/systemd/resolved.conf.d/99-vps-optimizer.conf
/etc/dnsmasq.d/vps-speed.conf
/etc/dnscrypt-proxy/dnscrypt-proxy.toml      (only when DoH selected)
/etc/vps-noise.conf
/etc/vps-optimizer.preset
/etc/vps-optimizer.dns
/usr/local/bin/vps_noise_gen.sh
/usr/local/sbin/vps_rps_boot.sh
/var/lib/vps-noise/                          (vacation state, cookie jars)
/var/log/vps-optimizer.log
/var/log/vps-optimizer-audit.log
/var/log/vps-optimizer-debug.log
/var/backups/vps-optimizer/                  (pre-apply snapshots)
/var/lock/vps-optimizer.lock
/run/vps-noise/health.json
```

`uninstall` removes all of them.

---

## Changelog

### v8.3 PHOENIX-Z++ — VPN-safe (current)

**Главное:** apply теперь VPN/SSH-friendly по дефолту, сам себя откатывает если потерял связь.

**SSH/VPN safety net:**
- **Auto-rollback** после `apply`: пробуем DNS + TCP/443; если связь упала — откатываем на pre-apply snapshot. Защита от своего же sysctl. Отключаемо: `--no-rollback`.
- **VPN-friendly auto-detect** (opt-in): если виден `tun*`/`wg*`/`ppp*` iface, или передан `--vpn` — автоматически переключаем `rp_filter` со strict (=1) на loose (=2), включаем `accept_local=1`, `ip_forward=1`, `nf_conntrack_helper=0`. Без VPN остаётся прежний strict-режим (backward-compat).

**UDP / QUIC / VPN скорость:**
- **UDP-GRO/GSO** ethtool offloads: `rx-udp-gro-forwarding`, `tx-udp-segmentation` — даёт **2-3x throughput** для QUIC/Hysteria2/TUIC/WireGuard на 5.18+ ядрах.
- **TCP Fast Open black-hole defuse**: `tcp_fastopen_blackhole_timeout_sec=0` — без этого после первой неудачи TFO лочился на 1 час.
- **UDP stack hardening**: `udp_rmem_min`/`udp_wmem_min`/`udp_mem` подняты — нужно для тяжёлого QUIC. `net.core.optmem_max` остался 4MB (как было в v8.2) — этого достаточно для SO_ZEROCOPY у sing-box/xray.
- **gRPC keepalive sysctl**: для long-lived потоков sing-box/xray.
- **netdev_max_backlog/dev_weight** автомасштаб: 25G+ → 300000/128, 10G+ → 100000/96, иначе 30000/64.

**Новые команды:**
- `doctor` — actionable-диагностика: проверяет conntrack, retransmits, softnet drops, /var, DNS — с подсказками как починить.
- `why <key>` — объясняет почему конкретный sysctl такой (knowledge base ~30 ключей).
- `audit --json` — машиночитаемый аудит для мониторинга.
- `wg setup` — WireGuard helper (opt-in): автодетект MTU через ICMP needs-frag, генерация конфига, ip_forward.
- `reset --soft` — откат только sysctl, оставляет DNS/noise/swap.
- `apply --boot` — one-shot systemd unit для apply на каждом boot (для OpenVZ, где `/etc/sysctl.d/` иногда вытирается).
- `apply --vpn` — явный VPN-режим без auto-detect.
- PTR sanity check в `audit` (только warn).

**Cron-friendly exit codes:**
`0`=ok, `10`=already-applied, `20`=internet-down, `30`=hypervisor-blocked, `40`=lock-busy, `50`=invalid-args, `60`=rolled-back.

**Daily snapshots:**
`/var/backups/vps-optimizer/daily-YYYYMMDD.tar.gz` — 1 в сутки, держим 7 дней. Pre-apply снапшоты держим до 30 штук с авто-rotation.

**Микро-фиксы (Q1-Q5,Q7,Q8):**
- audit drift parser: `awk` вместо `IFS='='` для значений с `=`.
- `_prom_handler` различает `/metrics`, `/`, `/healthz` (Prometheus + k8s liveness).
- `install_curl_impersonate` тянет latest tag через GitHub API (fallback 0.6.1).
- dmesg log filter: `out of memory|invoked oom-killer` вместо `killed` (меньше ложных).
- `detect_provider` hostname-эвристика теперь требует доменный суффикс, не любую подстроку.

**Не сделано (отложено по соображениям SSH/VPN-безопасности):**
- Egress-firewall preset (мог закрыть SSH).
- Disable kernel watchdog (мог скрыть реальные проблемы ядра).
- GRUB-tweaks (требует ребут).
- AppArmor profile noise (мог сломать на нестандартных ядрах).
- HugePages (мог OOM на маленьких VPS).

### v8.2 PHOENIX-Z++

- New TCP knobs: `tcp_rto_min_us`, `tcp_comp_sack_*`, `tcp_pingpong_thresh`,
  `tcp_min_tso_segs`, `tcp_tso_win_divisor`, `tcp_no_ssthresh_metrics_save`,
  `high_order_alloc_disable`.
- ECMP / multipath auto-detect (`fib_multipath_hash_policy=1` when 2+ default
  routes or `--ecmp`).
- NIC offload safety: only touch TSO/GSO/GRO on hosts where it's safe; in
  containers we limit ourselves to `lro off`.
- Idempotent `apply`: identical sysctl conf → no rewrite, no `sysctl -p`.
- Pre-apply rollback snapshot in `/var/backups/vps-optimizer/`.
- Lock file prevents concurrent `apply`s.
- Internet-connectivity pre-check.
- New CLI: `status --json`, `logs`, `audit`, `harden`, `uninstall`,
  `compare`, `prom-metrics`, `prom-serve`, `version`, `noise test`,
  `noise health`.
- Audit log for every mutating command. Debug log under `--debug`.
- `self-update` now verifies SHA256 (sidecar `.sha256`) and rolls back if the
  new script fails sanity check.
- `import` / `export` use a manifest with `format_version` for forward
  compatibility.
- `vps-noise.service`: hardened (Protect{System,Home,Kernel*}, LockPersonality,
  RestrictSUIDSGID, RestrictNamespaces, TasksMax=64, Restart=on-failure +
  StartLimit). Health written to `/run/vps-noise/health.json`.
- Noise generator: real `Referer:` chains, `Sec-Fetch-Site` per hop,
  `If-None-Match` / `If-Modified-Since` cache simulation,
  cloud / NTP / cloud-init phantom loop, browser-style DNS prefetch loop,
  `/dev/urandom` randomness, place profile (`office` / `home` / `always_on` /
  `auto`).
- `--impersonate` flag: optional auto-install of `curl-impersonate-safari`.
- Provider auto-detect via `dmidecode` / hostname (Hetzner / DigitalOcean /
  Vultr / AWS / GCP / Azure / Aeza / Timeweb / Firstbyte / Oracle).
- Full `--help` rewrite + man-style flags reference.
- README rewritten.

### v8.1.1 PHOENIX-Z+

First stable tagged release. v6.0 → v8.1.1 development cycle merged.

- Adaptive TCP/UDP buffers, BBR + fq_codel, RACK / ECN / MPTCP.
- conntrack tuning, MPTCP on 5.6+.
- Multi-queue auto-expand, RPS / XPS / RFS, isolcpus-aware affinity.
- THP → `madvise`, NVMe / SSD I/O scheduler auto-pick, ZRAM.
- DoT / DoH via systemd-resolved / dnscrypt-proxy with provider presets.
- iOS Safari + RU email / news + APT phantom + lib phantom + vacation mode.
- Probe-then-write for every knob, hypervisor + kernel-version gates.
- Three presets (balanced / proxy / web), full CLI, dry-run, self-test.
- Bug fixes: `tcp_fin_timeout` preset override, >32-CPU XPS cpumask,
  persistent-boot-script multi-queue + isolcpus parity.

---

## License

MIT — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md). For vulnerabilities — please open a private
GitHub Security Advisory rather than a public issue.
