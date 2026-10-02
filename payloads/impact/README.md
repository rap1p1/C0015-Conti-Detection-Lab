# payloads/impact — bounded impact surrogate

`c0015_impact.ps1` — T1486 surrogate (rename + extension change + note) and T1083
post-impact listing, fully reversible.

## Actions (manifest-driven, `-Manifest <json>`)

| Action | Behavior |
|---|---|
| `Prepare` | create the allowlist corpus (`corpus_root`, `backup_dir`) with dummy files + full backup copy |
| `Run` | rename files to `<name>.<extension>` (default `.c0015`), drop the note file (`note_name`), within `max_files/max_bytes/max_seconds` caps |
| `Verify` | T1083-style listing + hash comparison (mismatch count = impact proof) |
| `Rollback` | restore every file from the backup, then `Verify` again → hash-OK |

## Safety (enforced in code)

- Refuses drive roots, Windows/ProgramFiles/ProgramData/Users paths, reparse points,
  non-allowlist roots, and cap violations (file/byte/time).
- No real encryption, no propagation; the corpus lives apart from lab evidence.

## Usage

```
powershell -File c0015_impact.ps1 -Manifest impact-manifest.json -Action Prepare
powershell -File c0015_impact.ps1 -Manifest impact-manifest.json -Action Run
powershell -File c0015_impact.ps1 -Manifest impact-manifest.json -Action Verify
powershell -File c0015_impact.ps1 -Manifest impact-manifest.json -Action Rollback
```

Telemetry: high-rate E11 (renames/note), E2 changes; Impact writes are monitored through the corpus E11 sweep.
