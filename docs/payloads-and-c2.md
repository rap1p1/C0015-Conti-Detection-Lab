# Payloads and C2 Decisions

> Answers three questions: (1) how the three requested phases map to the source campaign, (2) the C2 decision
> (foothold + operator) based on researched, install-verified options, and (3) whether the 3-VM AD model is
> sufficient. The chain blueprint remains `docs/implementation-plan.md`; this document locks in the payload and C2
> infrastructure.

## 1. Alignment of the three phases with the source campaign

| Requested phase | C0015 source (DFIR/MITRE) | Alignment verdict |
|---|---|---|
| 1. Initial payload + macro in docm -> macro -> HTA -> benign bootstrap -> stop at beacon callback | Word macro (T1204.002) -> encoded HTA JS/VBS (T1059.005/.007, T1027) -> fetch `compareForfor.jpg` (T1036, T1105) -> REGSVR32 (T1218.010) -> Bazar callback + myexternalip (T1016) | **MATCH — 1:1**. Lab: the same chain, a benign DLL with a `.jpg` extension, callback into C2-SIM v3 (no real Bazar/Cobalt Strike). Fidelity HIGH for the chain mechanics; the phishing delivery `[INFERRED-C0015]` is replaced by a lab step that creates a password-protected ZIP + docm placed on WS01 (executable — see the policy list below) |
| 2. Operator sessions: discovery -> target selection -> lab auth -> WMI + benign process/DLL -> collection -> transfer of dummy data to an internal sink; RDP next; AnyDesk + LSASS access must be studied | Operator from the runbook (copy-paste errors — S2) -> ShareFinder / found_shares -> WMIC -> rundll32 -> 143.dll (T1047/T1570) -> Rclone/MEGA twice (T1567.002/T1030) -> RDP day 2 (T1021.001) -> AnyDesk in `Videos\` (T1219.002) -> Process Hacker -> LSASS "likely" (T1003.001-adjacent, day 5) | **MATCH, source order preserved** (two transfer rounds with RDP in between). Safe deltas: MEGA -> internal sink; WMI uses pre-provisioned `it.admin` with explicit credentials (runas/CIM `-Credential` — fixed in `docs/implementation-plan.md` Section 2.2); **LSASS = safe telemetry study** (E10 access-mask, no dump — Section 4) |
| 3. A different bounded payload on a separate dummy corpus + scope check + restore (still enough Conti telemetry) | Conti batch deploy domain-wide (T1486) + post-impact file listing (T1083); does not touch the DC | **MATCH on telemetry, different scope (safety-mandated)**: `c0015_impact.ps1` keeps the Conti observables (high-speed fan-out, rename/extension, note creation, breadth) on an allowlisted corpus + restore verification; no real encryption, no propagation, no DC touch (the campaign also did not touch the DC — fidelity +1) |

**Policy: no technique stays unknown in the chain.** Every chain step has executable behavior in the lab. Historic
gaps are replaced by executed techniques carrying labels (no blanks, no "unknown" markers in the chain):

- Phishing delivery (`[INFERRED-C0015]`) -> **executed**: a real password-protected ZIP + docm is created, staged on
  WS01 and opened with its password (only the email-transport part is a surrogate — artifact creation/open are real).
- Credential provenance (historically `[UNKNOWN-C0015]`) -> **executed**: S7 auth controls (denied/allowed/revoked)
  demonstrate authorization; the operator owning a pre-provisioned credential is a real run input (`[LAB-SURROGATE]`).
- LSASS access (`[INFERRED-C0015]`) -> **executed safely**: a Process-Hacker-like lab tool opens a handle to
  `lsass.exe` with minimal rights (`PROCESS_QUERY_LIMITED_INFORMATION`) -> real E10 ProcessAccess targeting
  `lsass.exe` + access-mask analysis; NO memory read, NO dump, NO credentials (Section 4).
- 143.dll transfer mechanism to the target (historically `[UNKNOWN-C0015]`) -> **executed**: S8a copy via admin share
  C$ (T1570 surrogate) with its own evidence.
- Injection D8B3/143 (`[OBSERVED-C0015]`) -> **executed as replay/toy**: fixture E10/E8 + toy `lab-target.exe` if
  approved — never inject system processes (hard boundary, unchanged).

## 2. C2 decisions — foothold vs operator channel (researched, install-verified)

### 2.1 Foothold automation (S1 -> S3): C2-SIM v3 (implemented + tested 17/17)

Keep `scripts/c2sim_v2.py` (v3): register/task/result with server-side receipts. **Dynamic tasking** (`POST /cmd`)
lets the operator enqueue benign commands for the beacon (like a real C2 operator) while the fixed DFIR discovery
batch remains the default stream when nothing is queued. Why keep the beacon path: the macro -> HTA -> DLL -> beacon
chain needs **deterministic telemetry** (parent chain, E7 hash, callback) to map 1:1 with the campaign; a real C2
framework would change the entire process signature (no more Bazar regsvr32/rundll32 chain).

### 2.2 Post-exploitation operator C2: CALDERA (primary) — Sliver (optional, conditional) — Havoc (not used by default)

| Criterion | Apache CALDERA v5 (recommended primary) | Sliver (optional) | Havoc (excluded by default) |
|---|---|---|---|
| Install (verified against the upstream README) | `git clone https://github.com/apache/caldera.git --recursive` -> `pip3 install -r requirements.txt` -> `python3 server.py --insecure --build`; Linux/macOS + Python 3.10+ required, 8 GB RAM recommended; UI `http://localhost:8888` (red/admin); **v5.1.0+ mandatory** (CVE-2025-27364) | `curl https://sliver.sh/install \| sudo bash`; server/client on Kali; Windows implant via profile (HTTP(S)/mTLS/DNS), dynamic compile | Go teamserver on Kali/Ubuntu; client needs a Qt build + Python 3.10 (heavier) |
| Role in the lab | Operator layer: sandcat agent on WS01/FS01, adversary profile YAML = the C0015 runbook (exact DFIR commands), operation replay, task/result log as an auxiliary ledger | Interactive operator channel replacing the Cobalt Strike beacon role | — |
| Points to control | Server bound to the lab network only (no public exposure — per MITRE upstream guidance); RAM: install on **ELASTIC01 (Ubuntu 24.04, Azure)** instead of Kali if the Kali VM is tight on RAM | **Transport/tasking only**: never use its process migration/injection/token features (project boundary); the implant is a real agent -> needs a **Defender exclusion inside the lab** (lab configuration, not AV-bypass engineering); telemetry differs from Cobalt Strike (JA3) -> fidelity PARTIAL, recorded explicitly | **Demon agent ships evasion**: Ekko sleep obfuscation, indirect syscalls, AMSI/ETW patching via HW breakpoints — violates the no-EDR/AV-bypass boundary. Not used unless the user revisits with a separate benign custom agent |
| Conclusion | **USE — primary operator C2** | **USE (optional, subject to the conditions above)** | **NOT USED (default)** |

**Role map in the chain:** C2-SIM v3 = beacon channel of the Bazar/143.dll surrogate (S3/S9, signature close to the
campaign); CALDERA = operator orchestration/tasking (S4-S13, mirroring "operator from the runbook"); Sliver (if chosen)
= interactive channel replacing the Cobalt Strike operator session — the three layers do not replace each other; record
the fidelity of each layer. **Hard conditions when using Sliver/CALDERA:** VMnet2 only, only to the WS01/FS01 VMs owned
by the operator, no public exposure, no injection/evasion/credential features of these frameworks, and every tasked
command stays a benign string (allowlist or operator-entered; secrets never on the wire/logs).

## 3. C2-SIM v3 endpoint design (dynamic tasking)

Constrained HTTP server running on the lab host / Kali, playing the C2 role for the surrogate beacon; implementation:
`scripts/c2sim_v2.py` (tested 17/17 offline + end-to-end with `payloads/beacon/c0015_beacon.ps1`).

| Endpoint | Method | Purpose | Conditions (allowlist) |
|---|---|---|---|
| `/dl/<name>` | GET | Deliver the surrogate DLL (T1105 ingress analog) | name in the DL allowlist; file staged in `--dl-dir` |
| `/session/register?stage=&host=&token=&run=` | POST | Register a session (beacon check-in) | stage in `{phase3, phase7-session2, phase4-rundll32}`; host in the per-stage map; token `S[12]-<16 hex>` |
| `/task/next?session=` | GET | Return the next fixed task | session already registered |
| `/result?session=&task=` | POST | Accept a benign result (capped bytes) | task in the allowlist; size <= cap |
| `/checkin` (legacy) | GET | One-shot phase4 callback | `stage=phase4-rundll32&host=FS01` |

- **Task allowlist:** `T-DISCOVER-CORPUS`, `T-BEACON-SLEEP`, `T-NOOP` — **no task accepts a command string**.
- **Session/token:** the token is agent-generated (`S[12]-<16 hex>`), independent of credentials; the server stores
  `{token, stage, host, ip, time}` and, on a valid `phase7-session2` registration, writes an **`ART-07-01` receipt**
  (run-ledger artifact schema) — server-side evidence of session 2; endpoint markers are supplementary only.
- **Not reproduced (fidelity partial):** Malleable C2 / JA3 / cert profile, sleep 60 s / jitter 37, injection into
  svchost/Winlogon (boundary) — replaced by bounded, logged sleep; detections must not rely on a fixed interval.
- **Expected telemetry:** E1 rundll32 (parent wmiprvse), E7 ImageLoad (hash, unsigned), E11, E3 callback (ProcessGuid
  caveat — P1-B lesson), server log + receipt.

## 4. AnyDesk + LSASS in the lab (mandatory study, safe execution)

- **AnyDesk (T1219.002):** install the **genuine AnyDesk portable** into an unusual directory
  (`C:\Users\Public\Videos\` — mirrors the DFIR report) on FS01; run it to capture: E1/E11 (unusual install path),
  E3/E22 toward legitimate AnyDesk IP ranges (matching the DFIR observable "long connection towards legitimately
  registered IPv4 ranges"), service/registry if installed. Any control session is lab-internal only; the public relay
  is never used as a C2 channel.
- **LSASS access (T1003.001-adjacent, `[SUPPLEMENTAL-LAB-TECHNIQUE]`):** a small lab-written benign tool (C#/C) opens
  a handle to `lsass.exe` with **PROCESS_QUERY_LIMITED_INFORMATION** (minimal rights, no memory read) -> a real
  **E10 ProcessAccess** targeting `lsass.exe`; the access-mask analysis lets detection separate low-rights
  (benign/control) from high-rights (`PROCESS_VM_READ` / `PROCESS_ALL_ACCESS` = the attack pattern — present only in
  **fixture replay**, never executed). **NO dump, NO credential read, results never used for WMI.** The `C-LSASS`
  detection and fixtures already exist (`scripts/fixtures/e10_lsass_probe.json`).

## 5. AD model — are three machines enough?

Comparison with common models: **GOAD** (full: 5 VMs / 2 forests / 3 domains; **GOAD-Light: 3 VMs / 2 domains**;
MINILAB: 2 VMs), **DetectionLab** (DC + WEF + Win10, archived 2021), **BadBlood** (injects thousands of
dummy users/groups/computers/OUs into an existing domain — needs only Domain Admin + AD PowerShell; each run produces
different results).

**Conclusion:** DC01 + WS01 + FS01 (+ Kali + remote ELASTIC01) **are sufficient for this campaign** — comparable scope
to GOAD-Light and an exact match to the campaign structure (1 workstation beachhead + 1 file/backup server + a DC
**that is never touched** — as in the DFIR report). The current weakness is that the AD is **too empty** (2 users,
2 shares): discovery returns little data. Recommendations, in order:

1. **BadBlood on DC01** — inject ~2500 dummy users/groups/computers/OUs so `net group`, `net view /all /domain`,
   ShareFinder and `found_shares` produce real, rich output (best value/cost upgrade; no new VM needed).
2. **A fourth machine (DATA01/WS02) only if RAM allows** — the 16 GB host already runs 4 VMs; one more 2 GB Windows
   VM is the threshold. If added: DATA01 (a second file server) restores the "exfiltrate from a different server than
   the backup server" fidelity (S10).
3. No second forest/trust needed (T1482 `nltest` still runs and returns valid results in a single domain — record the
   limitation).

## 6. M-1 additions, in order (on approval to run)

1. Env verify (as `docs/implementation-plan.md` Section 5 M-1) + install **CALDERA v5.1.0+ on ELASTIC01** (or Kali)
   per Section 2.2, sandcat agent on WS01/FS01, create the C0015 adversary profile = the exact S4 DFIR commands.
2. Deploy payloads: build the DLL (mingw) -> per-run `config.ini` -> docm macro -> run S1-S3 with C2-SIM v2 + beacon.
3. BadBlood on DC01 (if richer discovery data is desired).
4. (Optional) Sliver per the Section 2.2 conditions — only after CALDERA is running stably.