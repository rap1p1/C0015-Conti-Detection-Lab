# Runtime configuration templates

| Template | Role |
|---|---|
| [c0015.example.ini](c0015.example.ini) | Base lab/bootstrap/C2/beacon settings |
| [c0015-phase7.example.ini](c0015-phase7.example.ini) | Pivot/second-session settings, marker path and beacon command |

[make_config.ps1](../packaging/make_config.ps1) generates a base configuration at its
selected output path; it does not automatically generate every phase7 variant.
Concrete runtime copies conventionally use `config.ini` / `config-phase7.ini` in
gitignored staging. Replace symbolic values before using a template.

These templates are intended to carry configuration, not account credentials.
Session tokens are runtime lab identifiers. The beacon's current `loop_count`
setting is advisory; consult its [README](../beacon/README.md) for loop behavior.
