<div align="center">

# ⚡ noble-net-warp

### Universal Ubuntu 24.04 network optimizer — now with a self-learning AI core

Unlocks maximum performance for **any** virtual machine and accelerates **all** protocols.

![version](https://img.shields.io/badge/version-8.19_PHOENIX--Z++-blueviolet?style=for-the-badge)
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

## ✨ Highlights (v8.17 → v8.19)

| Area | Feature | Why it matters |
|------|---------|----------------|
| 🤖 **AI** | Smart Network Autotuner | Self-learning ε-greedy bandit + BDP buffer right-sizing. Runs on the weakest VPS. |
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
- **Network IQ** — a 0–100 score that rises as the policy converges.

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
| `NETTUNE_EPS` | `15` | Exploration rate (%) for the bandit |
| `NETTUNE_RAM_FLOOR_MB` | `256` | Below this → exploit-only mode |
| `NETTUNE_STATE_MAX_BYTES` | `8192` | Hard cap for the state file |
| `NETTUNE_BDP_FACTOR` | `120` | BDP scaling (% of bandwidth-delay product) |
| `NETTUNE_W_RETRANS` / `NETTUNE_W_RTT` | `60` / `40` | Reward weights |
| `NETTUNE_INTERVAL_SEC` / `NETTUNE_BOOT_SEC` | `900` / `300` | Timer cadence |
| `LC_VPS_PROBE_HOSTS` / `LC_VPS_PROBE_QUORUM` | pool / `2` | Failover endpoints / quorum |
| `LC_VPS_HOOK_DIR` | `/etc/vps-optimizer.d` | Hook directory |
| `ENABLE_IOS_MESH` / `ENABLE_IOS_LOW_POWER` | `1` / `1` | iOS noise features |

---

## 📦 Quick start

```bash
git clone https://github.com/<owner>/noble-net-warp.git
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
  [2] 🎭 Stealth       noise iOS+RU+APT · stealth-test · DNS
  [3] 🩺 Diagnostics   doctor · status · top · log-tail
  [4] ⚙  Config        swap · язык · preset · профили · hooks
  [5] 📊 Monitoring    benchmark · bench-suite · Prometheus
  [6] 📦 Misc          install · export · import · update
  [7] 🤖 AI Network    nettune · grade · dna · BDP-autosize
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
