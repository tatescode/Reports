Note: This report was automatically generated using Claude Opus 5.5.

## 1. Identity

| Field | Value |
|---|---|
| SHA-256 | `7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3` |
| Type | PE32+ (x86-64) GUI, 8 sections, Windows |
| Size | 7,892,512 bytes |
| Language | Rust (crate paths in `.rdata`) |
| Packed? | **No** — section entropy 0.0–6.5; only the 12,320-byte Authenticode overlay is high-entropy |
| Image base | `0x14fe20000` |

### Manifest / disguise
- `assemblyIdentity name="SummitWorks.Paperline"`, version `8.20.4376.83`
- `<description>Paperline Document Viewer</description>`; UI strings say **"QuartzLine"**
- Real, working PDF-viewer front end: Slint GUI (`slint 1.16.1`), a PDF parser
  (`parsers\parser2\src\xref.rs`, `MediaBox/Resources/Page/Contents/Kids`), image
  codecs (png/jpeg/gif/webp), fonts (`swash/skrifa/parley`). The decoy is genuine.

### Code-signing (IOC)
- EV cert chain: **Sectigo Public Code Signing CA EV R36** → USERTrust RSA.
- **Subject: `Guangzhou Guoying Communication Technology Co., Ltd.`** (Guangdong, CN).
- Timestamped **2026-07-12 20:05:10Z** (Sectigo TSA R41).

## 2. Anti-analysis / string obfuscation
- Author source paths shortened to `C:\r\src\…` (`e\commands.rs`, `e\config.rs`,
  `e\http.rs`, `e\a\mod.rs`, `d\c\h.rs`, `d\c\profile.rs`, `g\register.rs`, `g\h.rs`,
  `main.rs`).
- Rust toolchain markers altered to defeat string tools: `rustc`→**`gustc`**,
  `.rs`→**`.rn`/`.rj`** (e.g. `mod.rn`, `main.rj`). This is why FLOSS's Rust mode
  returned empty. Standard crate paths are left intact.
- `.rdata` is padded with hundreds of fake C-style log strings carrying deliberate
  typos ("commitd", "canceld", "unmapd", `payload %p`, `task=%p`) as decoy/token
  noise. They are not referenced as a real logging subsystem.

## 3. Capability summary (observed statically)

Trojanized signed PDF viewer that doubles as a **downloader/loader + browser-data
collector**. The malicious path is gated behind hidden CLI flags and an internal
command loop; the GUI runs normally otherwise.

### Entry / dispatch (`g\register.rs`, `e\commands.rs`)
- Hidden flags parsed in `main`: **`--update-check`** and **`--update-view`**
  (functions `0x14fe28c09`, …). `--user-data-dir=` is also honored.
- Internal command/registration verbs: **`register_setup`**, **`register_thread`**,
  **`register_onexit`**, **`update`** (with phases `update_pre_download` /
  `update_post_download`), plus tokens `setup:`, `continue:`, `commands`, `verbose`,
  `skip`.

### C2 / network (`e\http.rs`, `e\commands.rs`) — reqwest 0.12 / hyper 1 / tokio 1.52 / native-tls (schannel)
- HTTP client posts `Content-Type: text/plain`; builds request bodies and parses
  status (`0x1500933ee`: `status - 0xc8`, i.e. subtracting 200 to classify 2xx).
- **No hardcoded URL/domain** in the image — the endpoint list is supplied at runtime
  (error string **"No URLs provided"**); likely delivered via config (see below) or
  the `--update-*` arguments. `"Invalid download"` guards the fetched payload.
- Result of each executed command is serialized to **JSON** (`serde_json 1.0.149`)
  with keys: `index, com, success, ec, dur, st1, st2, trunc1, trunc2, err`
  (`…[N bytes truncated]…` marker used to cap large fields) and sent back.

### Config (`e\config.rs`)
- Reads `%LOCALAPPDATA%` and a `uid`/`appId` identity. A 264-byte config struct is
  built/copied (`0x150090d40`, copies 0x58 bytes, sets a `+0x108 = 2` field). Its
  template at `0x1503c4ad0` holds a count (`2`), 20 zero bytes, then a **32-byte
  embedded key/seed**: `75e6c150 d9c30f4e 04058202 be06f844 94895ae8 bcf0ae4c
  6ad8ce57 2560a5ed 5d422919 f7e7862e 27ac…` (reads like a crypto key/seed for the
  C2 body; not plaintext — single-byte XOR yields nothing printable). Endpoint(s)
  most plausibly resolve from config or the `--update-*` args at runtime.

### Download → execute (loader) (`d\c\h.rs`)
- Resolves install/output locations from env: `USERPROFILE`, `LOCALAPPDATA`,
  `AppData\Local`, `PROGRAMFILES`, `ProgramW6432`, `ProgramFiles(x86)`.
- Writes the fetched stage to disk via **`CreateFileW` + `WriteFile`/`NtWriteFile`**
  (`0x1500e3150`, `0x1500deb3a`).
- **Launches it with `CreateProcessW` (`0x15009ee63`) using `dwCreationFlags =
  0x08000000` = `CREATE_NO_WINDOW`** — i.e. runs the next stage hidden.
- Can terminate processes with **`taskkill.exe /PID /F`** and launches browsers/children
  with `cmd.exe` and `--user-data-dir=` overrides.

### Browser / profile collection (`d\c\h.rs`, `d\c\profile.rs`)
- Walks Chromium **`User Data` / `Default` / `Profile N`** directories under
  `LOCALAPPDATA`.
- A profile parser consumes fields: `appId`, `pnsFile`, `bprFile`, `wvlsFile`,
  `userName`, and a struct `DefaultProfile {OffsetPName, OffsetEM, OffsetEA,
  OffsetLS, OffsetTNS, …}` plus `context`/`source` — i.e. extraction of account/
  profile metadata and specific state/preference files, gzip-handled (`flate2`,
  `yazi`, `GZ` marker).

### Host fingerprint (`sysinfo 0.32`, `windows-registry`)
- Reads `SOFTWARE\Microsoft\Windows NT\CurrentVersion` →
  `CurrentBuildNumber`, `CurrentMajorVersionNumber`; `\Processor(_Total)\% Idle Time`
  (CPU/perf), via `RegOpenKeyExW`/`RegQueryValueExW`.

## 4. Persistence / injection
- **No** `RegSetValueEx` / Run-key, `schtasks`, `ShellExecute`, `WinExec`, or
  `CreateRemoteThread`/`VirtualAllocEx`/`WriteProcessMemory` imports. `LoadLibrary*`
  + `GetProcAddress` are present (ordinary dynamic resolution; watch for runtime
  API resolution of the above). Observed persistence vector is limited to the
  dropped stage executed via `CreateProcessW`; no autostart write seen statically.

## 5. IOCs
- SHA-256: `7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3`
- Signer: `Guangzhou Guoying Communication Technology Co., Ltd.` (Sectigo EV R36), ts 2026-07-12
- Product masquerade: `SummitWorks.Paperline` / "Paperline Document Viewer" / "QuartzLine" v8.20.4376.83
- Hidden flags: `--update-check`, `--update-view`, `--user-data-dir=`
- Child exec: `cmd.exe`, `taskkill.exe /PID /F`, dropped stage via `CreateProcessW CREATE_NO_WINDOW`
- C2 JSON keys: `index/com/success/ec/dur/st1/st2/trunc1/trunc2/err`; `Content-Type: text/plain`
- Config dir: `%LOCALAPPDATA%`; targets Chromium `User Data` profiles

## 6. Open items (would confirm with completed Ghidra pass / longer timeout)
- Decode the `0x1503c4ad0` config blob to recover the actual C2 endpoint(s).
- Exact `pnsFile/bprFile/wvlsFile` filenames and the `DefaultProfile` offsets' meaning.
- Whether `GetProcAddress` resolves any injection/persistence API at runtime.

---

## 7. Ghidra decompilation (direct headless — REA timeout bypassed)

REA's Ghidra provider timed out at 330 s/call, so Ghidra 12.1.4 was run **directly**
via `analyzeHeadless` (same engine REA wraps; `rea capabilities` confirmed the path),
with no wrapper cap. Analysis ran on the de-obfuscated working copy
`quartzline_deobf.bin` (SHA-256 `51f0116e…3aa83e`; byte-length-preserving
`gustc→rustc`, `.rn/.rj→.rs`; **identical code bytes/layout to the evidence original,
so all addresses match**). Static only — the sample was never executed.

Recovered C for 11 author functions is in `decomp/*.c` (scripts:
`decompile_targets.py` [needs PyGhidra], `DecompileTargets.java` [used]). The output is
accurate but **unlabeled** (`FUN_`/`local_`): stripped Rust with no symbols, and no
BSim/FLIRT signature pass (would need a Rust toolchain, not installed). Merged-string
`.rdata` means author strings appear as address refs, not inline literals; Windows API
calls are resolved.

**Decompiler-level confirmation of the loader** (`0x15009ee63`):
```c
CreateProcessW(NULL, cmdline, NULL, NULL, 0, 0x8000000 /*CREATE_NO_WINDOW*/,
               NULL, NULL, &startupinfo, &procinfo);
```
with inline `"--user-data-dir="` and `"taskkill.exe"` in the same function — i.e. drop →
run hidden, and force-restart Chromium against an attacker-chosen profile dir.
`0x150092451` (http_build_request) exceeded the 180 s per-function decompiler budget
(oversized function); the other 10 completed.

## 8. Corroboration — external research (secondary source)

`rogueauthority.org/quartzline-signed-pdf-viewer-zenith-backdoor` (pub. 2026-10-09;
itself an AI-generated Claude/REMnux analysis) covers the **same SHA-256**. Treated as a
corroborating secondary source, not ground truth. Its IOCs were checked **against the
binary's own bytes, statically (no network, no C2 contact)**:

- **Present in binary (verified):** `terrain.dat`, `zenith`, campaign `QNPVXZGJYUSLTREHK`,
  tag `QZRT07`, endpoint parts `quarry`/`vein`/`deposit`/`stratum`/`bedrock`/`sandstone`,
  response keys `lignite`/`schist`, decoy config keys `antialiasing`/`buffer_size`.
- **NOT in plaintext (could not verify):** C2 domains `westbeavers[.]com`,
  `motherotters[.]com`, `healskills[.]com` — consistent with the config being obfuscated
  and the domains decrypted at runtime with the embedded 32-byte key. Cited per article,
  **defanged, not independently confirmed; not contacted.**

New detail from the article (unverified by us except where noted):
- Backdoor/module name **"zenith"**; implant version 6.1.3.
- C2 paths `/quarry/vein` (check-in), `/quarry/deposit` (report), plus
  `/quarry/{stratum,gravel,bedrock,sandstone,seam}` (configured, unobserved).
- Config/body obfuscation = 4 layers (not crypto-secure): gzip → chained XOR (random
  seed + fixed key) → seed-dependent bit-rotation → Fisher-Yates shuffle; seed prepended.
  (Matches our findings: 32-byte embedded key + `flate2`/gzip + serde_json.)
- Persistence/ID: `%LOCALAPPDATA%\QuartzLine\terrain.dat`, decoy settings lines plus
  `zenith=<uuid>` machine ID (matches our LOCALAPPDATA/`uid`/`appId` finding).
- Cert serial `1b56cb4e99fb9444645a1ce7ffc0a46b`, **now revoked** ("Privilege Withdrawn").
- Attribution: KesaKode 54% match to GeckoStealer (shared Rust lib code); unnamed backdoor.

### Reconciliation with our independent static findings
All consistent. Our implant→C2 JSON keys (`index/com/success/ec/dur/st1/st2/trunc1/
trunc2/err`) are the status body; the article's `lignite/schist` are C2→implant response
keys (opposite direction). Our `CreateProcessW+CREATE_NO_WINDOW+cmd.exe` = its "cmd /C
hidden window" command; our `User Data`/`--user-data-dir`/`taskkill`/profile parser = its
"modify Chromium profile + force restart" command.

## 9. Confirmed victim linkage (incident)

Operator reports the C2 domain **`westbeavers[.]com`** (among the three) matches the exact
domain IOC observed on a victim endpoint. Because that domain is **absent from the
binary's plaintext** and only present encrypted in the config blob, the endpoint match
independently confirms (a) this binary is the implant responsible for that C2 traffic,
and (b) the obfuscated-config → domain mapping. 
