# payloads/docm — Word macro base

`macro_payload.vba` — the canonical entry macro (S1, T1204.002/T1059.005): reads
`%PUBLIC%\C0015\config.ini`, and if `hta_path`/`mshta_path` are present launches
`mshta` on the HTA — with a `m_bootstrapStarted` guard so only one chain starts per
document open.

The **generated** self-write variant (macro that creates config/HTA/beacon from embedded
blobs) is produced by `../packaging/gen_macro_embedded.ps1`; installation into a `.docm`
is done by `../packaging/install_macro_docm.ps1` (standard module `c0015Payload`,
`AutoOpen` trigger). Details and the debugging history (Document Recovery, ThisDocument
collision, standard-module decision) are in
`../../phases/phase1-initial-access/rerun-v2-remote-operator-design.md`.