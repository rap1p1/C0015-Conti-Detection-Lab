# payloads/beacon — session beacon

`c0015_beacon.ps1` — the lab C2 agent (T1071.001 surrogate for BazarLoader/Cobalt Strike).

## Behavior

- Session token: read from env `C0015_SESSION_TOKEN` or generated per run (`S1-<16 hex>`);
  written to `token.txt` beside the config.
- Loop: POST `/register`, then poll `/poll?session=<token>`; executed tasks are `/cmd`
  (raw command through `cmd /c`, result echoed back) or `/runbook` batches.
- Config-driven via `-Config <ini>`: `[c2sim] c2_url/stage/host_alias/token_env/token_file`,
  `[beacon] loop_count/loop_sleep_sec/loop_sleep_jitter_sec/result_cap_bytes`,
  `[public_ip] check_url/enabled`.
- Elevated/second-session instances run from `config-phase7.ini` (`[beacon] beacon_cmd`)
  after the DLL surrogate spawns them.

## Key code

- `Get-IniValue` — hand-rolled INI parser (no external module; the loop runs on an edge
  host with blocked PSGallery).
- Result posting caps output size (`result_cap_bytes`) so a chatty command cannot wedge
  the loop; failures are reported as `task error: <message>` (visible in `/results`).

## Usage

```
powershell -NoProfile -ExecutionPolicy Bypass -File c0015_beacon.ps1 -Config C:\C0015\config.ini
```

Telemetry produced: E1 (beacon run), E3 (poll traffic to `:8080`), E11 (token/marker writes).