<div align="center">

# ⚡ noble-net-warp

### Universal Ubuntu 24.04 network optimizer — now with a self-learning AI core

Unlocks maximum performance for **any** virtual machine and accelerates **all** protocols.

![version](https://img.shields.io/badge/version-8.20_PHOENIX--Z++_ULTRACODE-blueviolet?style=for-the-badge)
![shell](https://img.shields.io/badge/bash-single--file-121011?style=for-the-badge&logo=gnu-bash&logoColor=white)
![target](https://img.shields.io/badge/Ubuntu-22.04_·_24.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![license](https://img.shields.io/badge/license-see_LICENSE-green?style=for-the-badge)

</div>

---

## 🚀 What is this?

`noble-net-warp` is a **single-file** (`vps_optimizer.sh`) Bash tool that tunes the
entire Linux network stack for VPS / VM workloads — BBR, qdisc shaping, conntrack,
RPS/XPS/IRQ affinity, ZRAM, MPTCP, THP — and adds a **self-learning AI autotuner**,
**multi-endpoint resilience**, a **user hook system**, and an advanced
**iOS traffic-masking (white-noise)** engine.

> 💡 Everything lives in **one script**. No modules, no dependencies to vendor —
> copy it to your server and run.

---

## ✨ Highlights (v8.17 → v8.20 ULTRACODE)

| Area | Feature | Why it matters |
|------|---------|----------------|
| 🤖 **AI v8.20** | Smarter self-learning core | **UCB1** arm selection + **load-aware gating** + **EWMA Network-IQ** + **best-arm/regret memory**. Converges faster, refuses to learn under load, still pure-bash & disk-safe on the weakest VPS. |
| 🎬 **White-noise v8.20** | Native iOS-app traffic | **RUTUBE · VK Видео · Одноклассники (OK) · ЛитРес** emulated 1:1 with real **CFNetwork/Darwin** app User-Agents — indistinguishable from an iPhone in RU. |
| 🧬 **sysctl v8.20** | Rare/custom knobs | Compressed-SACK timing, ECN+fallback, pingpong-thresh, shrink-window, migrate-req, netdev budget — all probe-safe (skipped silently if the kernel lacks them). |
| 🚦 **Queue v8.20** | Selectable qdisc + **noble-aqm** | Pick `fq` · `fq_codel` · `cake` · or the **custom `noble-aqm`** — an RTT-adaptive CAKE profile (auto memlimit, ACK-filter, diffserv4, split-gso, ingress shaping) that ships in *no other tool*. |
| 🌐 **Resilience** | Multi-endpoint failover | Quorum-based connectivity check across a pool — survives single-endpoint / regional blocks. |
| 🪝 **Extensibility** | User hook system | Drop scripts into `/etc/vps-optimizer.d/` — customise without forking. |
| 🎭 **Stealth** | iOS service-mesh + Low Power Mode | Mimics the *daemon* traffic of an idle iPhone, not just Safari browsing. |
| 📊 **Insight** | Bufferbloat Grade + Network DNA | One human-readable grade (A+…F) and an environment fingerprint. |
| 🎨 **UX** | Refreshed interactive menu | Framed TUI, new 🤖 AI section, 100% feature-accurate. |

---

## 🤖 Smart Network Autotuner (AI)

A closed-loop **measure → tune → re-evaluate** controller, designed to run on
even the smallest VPS.

- **Lightweight** — pure `bash` + `awk`, **no daemon** (one `systemd` oneshot per tick).
- **Passive metrics only** — `/proc/net/snmp` + `ss`. Generates **zero** extra traffic.
- **Disk-safe** — a single, atomically-rewritten, **size-capped** state file (never appends → disk can't fill).
- **Self-learning** — ε-greedy **multi-armed bandit** over qdisc arms (`fq` / `fq_codel` / `cake`), with **decaying exploration** as confidence grows.
- **BDP buffer right-sizing** — socket buffers scaled to bandwidth-delay product, RAM-aware ceiling (safe on tiny VPS, generous on fast ones).
- **Weak-VPS guard** — below a RAM floor it switches to **exploit-only** (applies the best-known policy, no experiments).
- **Network IQ + EWMA** — a 0–100 score with an exponentially-smoothed trend that's stable enough to chart.
- **UCB1 explorer (v8.20)** — confidence-bound arm selection tries every qdisc once, then narrows fast → far fewer bad pulls than plain ε-greedy.
- **Load-aware gating (v8.20)** — skips the learning step when 1-min loadavg/core exceeds `NETTUNE_LOADAVG_GATE` (keeps applying the best-known policy), so a busy box never poisons the reward signal.
- **Best-arm & regret memory (v8.20)** — remembers the historically strongest policy and tracks how far the current pick is from it.

```bash
sudo ./vps_optimizer.sh nettune on       # enable idle-priority learning timer
sudo ./vps_optimizer.sh nettune status   # arm · Network IQ · per-arm Q-values
sudo ./vps_optimizer.sh nettune once     # run one learning step now
sudo ./vps_optimizer.sh nettune off      # disable
sudo ./vps_optimizer.sh nettune reset    # wipe learned policy
```

---

## 🌐 Multi-endpoint failover

Connectivity is now verified against a **pool** of endpoints with a **quorum**, so a
single blocked resolver (common in some regions) no longer triggers a false
"no internet" rollback.

```bash
# Override the pool / quorum via env:
LC_VPS_PROBE_HOSTS="1.1.1.1 8.8.8.8 77.88.8.8" LC_VPS_PROBE_QUORUM=2 \
  sudo ./vps_optimizer.sh apply
```

---

## 🪝 User hook system

Extend `apply` without touching the script. Drop **executable** files into:

```
/etc/vps-optimizer.d/pre-apply.d/      # run before optimizations
/etc/vps-optimizer.d/post-apply.d/     # run after optimizations
```

```bash
sudo mkdir -p /etc/vps-optimizer.d/post-apply.d
sudo tee /etc/vps-optimizer.d/post-apply.d/10-my-tweak.sh >/dev/null <<'EOF'
#!/bin/bash
sysctl -w net.core.somaxconn=65535
EOF
sudo chmod +x /etc/vps-optimizer.d/post-apply.d/10-my-tweak.sh
```

> Hooks run in lexical order and are **non-fatal** — a failing hook is logged
> (and audited) but never aborts `apply`. They honour `DRY_RUN` and receive
> `VPS_HOOK_PHASE` / `VPS_SCRIPT_VERSION`.

---

## 🎭 Stealth / white-noise engine (iOS)

On top of the existing engine (per-connection JA3 rotation, curl-impersonate-safari,
circadian timing, Markov-6, IMAP IDLE, RU human profile, APT phantom):

- **iOS background service-mesh** — emulates the silent daemon traffic of an idle
  iPhone: CloudKit, Maps tiles, Weather, Siri/auth, OTA checks, App Store bag,
  Push gateways — all through the same **JA3/UA-coherent** request path.
- **Low Power Mode simulation** — a deterministic per-day window throttles
  background fetch, so the pattern *breathes* like a real device.

- **RU iOS-app mesh (v8.20)** — adds first-class, schedule-aware traffic for the
  apps a real Russian iPhone user opens daily: **RUTUBE** & **VK Видео** (evening
  prime-time bursts), **Одноклассники / OK** (day+evening feed) and **ЛитРес**
  (late-evening reading). Each uses its own native **CFNetwork/Darwin** User-Agent
  and real API endpoints — a 1:1 match for NSURLSession traffic.

> The traffic now resembles a phone in someone's pocket — not just a browser session.

---

## 📊 Insight commands

```bash
sudo ./vps_optimizer.sh grade   # Bufferbloat Grade A+..F (idle vs loaded RTT)
sudo ./vps_optimizer.sh dna     # Network DNA fingerprint + recommended preset
```

---

## 🎛️ Custom knobs (env-overridable)

| Variable | Default | Purpose |
|----------|---------|---------|
| `NETTUNE_ENABLE` | `1` | Master switch for the AI autotuner |
| `NETTUNE_EPS` | `15` | Exploration rate (%) for the ε-greedy fallback |
| `NETTUNE_UCB` | `1` | Use UCB1 selection (set `0` for legacy ε-greedy) |
| `NETTUNE_UCB_C` | `1.4` | UCB1 confidence-bonus weight |
| `NETTUNE_LOADAVG_GATE` | `4.0` | Skip learning when loadavg/core exceeds this |
| `NETTUNE_EWMA_ALPHA` | `0.30` | Smoothing factor for the EWMA Network-IQ |
| `NETTUNE_RAM_FLOOR_MB` | `256` | Below this → exploit-only mode |
| `NETTUNE_STATE_MAX_BYTES` | `8192` | Hard cap for the state file |
| `NETTUNE_BDP_FACTOR` | `120` | BDP scaling (% of bandwidth-delay product) |
| `NETTUNE_W_RETRANS` / `NETTUNE_W_RTT` | `60` / `40` | Reward weights |
| `NETTUNE_INTERVAL_SEC` / `NETTUNE_BOOT_SEC` | `900` / `300` | Timer cadence |
| `LC_VPS_PROBE_HOSTS` / `LC_VPS_PROBE_QUORUM` | pool / `2` | Failover endpoints / quorum |
| `LC_VPS_HOOK_DIR` | `/etc/vps-optimizer.d` | Hook directory |
| `QDISC_MODE` | `auto` | Queue discipline: `auto`/`fq`/`fq_codel`/`cake`/`noble` (custom noble-aqm) |
| `ENABLE_IOS_MESH` / `ENABLE_IOS_LOW_POWER` | `1` / `1` | iOS noise features |
| `ENABLE_RUTUBE_BURST` / `ENABLE_VKVIDEO_BURST` | `1` / `1` | RUTUBE / VK Видео iOS traffic |
| `ENABLE_OKRU_BURST` / `ENABLE_LITRES_BURST` | `1` / `1` | Одноклассники / ЛитРес iOS traffic |

---

## 🚦 Queue discipline selector (NEW)

Choose how the kernel schedules packets — straight from the interactive menu
(*Кастомизация* → *Алгоритм очереди*) or via the `QDISC_MODE` env var:

| Mode | What it does |
|------|--------------|
| `auto` | Intelligent pick based on virtualization + BBR (recommended default) |
| `fq` | **fq+** — hand-tuned pacing: EDT, `horizon` (5.14+), `ce_threshold` (L4S), `timer_slack` (5.17+), bigger buckets/quantum |
| `fq_codel` | **fq_codel+** — L4S `ce_threshold 1ms`, RAM-scaled `memory_limit`, RTT-adaptive target/interval |
| `cake` | Full noble CAKE profile **+ bidirectional ingress AQM** (IFB) |
| `noble` | **🔥 Custom `noble-aqm`** — exclusive to this project |

**`noble-aqm`** is a hand-built AQM profile that exists nowhere else. It:

- measures live **RTT to the gateway** and feeds it into CAKE (`rtt <measured>ms`),
- auto-scales **`memlimit`** to the box's RAM (4–64 MB envelope) so it never
  bloats a 256 MB VPS,
- enables **`ack-filter`**, **`diffserv4`**, **`dual-srchost`/`dual-dsthost`**,
  **`split-gso`** and tuned **`overhead/mpu`** for VPN-style flows,
- adds **bidirectional shaping** — download-side AQM via an `ifb-noble` IFB device,
- uses a **multi-tier fallback** (full → medium → basic `tc` profile) so it loads on 6.x *and* old LTS kernels,
- applies a hand-tuned **`fq_codel` fallback** (target/interval derived from RTT)
  if `sch_cake` is missing — so it degrades gracefully on minimal kernels,
- is fully **probe-safe & bounded** — failures are logged, never fatal.

```bash
# one-off
sudo QDISC_MODE=noble ./vps_optimizer.sh
# or persist in /etc/vps-noise.conf:  QDISC_MODE="noble"
```

---

## 📦 Quick start

```bash
git clone https://github.com/lpxqwkjd65rjfn-dot/noble-net-warp.git
cd noble-net-warp
chmod +x vps_optimizer.sh

sudo ./vps_optimizer.sh            # interactive menu
sudo ./vps_optimizer.sh apply      # apply optimizations
sudo ./vps_optimizer.sh nettune on # enable the AI autotuner
sudo ./vps_optimizer.sh grade      # check your Bufferbloat Grade
```

---

## 🖥️ Interactive menu

```
┌─ Категории ───────────────────────────────────────────┐
  [1] ⚡ Performance   apply · preset · suggest · wizard
  [2] 🎭 Stealth       noise iOS+RU(RUTUBE·VK Видео·OK·ЛитРес) · stealth-test · DNS
  [3] 🩺 Diagnostics   doctor · status · top · log-tail
  [4] ⚙  Config        swap · язык · preset · профили · hooks
  [5] 📊 Monitoring    benchmark · bench-suite · Prometheus
  [6] 📦 Misc          install · export · import · update
  [7] 🤖 AI Network    nettune(UCB1·load-gate·EWMA) · grade · dna · BDP
  [8] ↩  Reset all     откат всех изменений
  [0] ❌ Выход
└───────────────────────────────────────────────────────┘
```

---

## 🔒 Safety & design principles

- ✅ **Single file** — easy to audit, copy, and version.
- ✅ **Idempotent apply** with snapshot + rollback (Time-Machine).
- ✅ **Multi-endpoint health checks** before committing changes.
- ✅ **AI runs at idle priority** (`Nice=15`, `IOSchedulingClass=idle`) and never floods the disk.
- ✅ **i18n** (en / ru / de / fr) · Prometheus metrics + alerts · man page.

---

<div align="center">

Made for people who want their VPS to be **fast, resilient, and quietly smart.** ⚡

</div>
