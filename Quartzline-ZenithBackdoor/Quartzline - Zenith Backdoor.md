# QuartzLine / ZENITH: Static Analysis Findings

**Sample:** `7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3`
**Date:** 2026-10-16
**Method:** Static analysis only. The sample was never executed and no C2 infrastructure was contacted. Tooling: Ghidra 12.1.4 (headless), capstone, radare2, custom Python.

> This analysis was done with AI assistance (Claude + REA). Everything marked **confirmed** was checked directly against the binary's bytes or disassembly. Behavior marked **observed** comes from endpoint telemetry in an investigated environment. Third-party claims are called out separately and are only marked as matching where checked them directly.

---

## TL;DR

This is a trojanized, validly code-signed PDF viewer written in Rust. It really works as a viewer, which is the disguise. Hidden inside is a backdoor/loader that only activates when launched with a hidden flag. After the user runs it once, it sets up an hourly scheduled task to keep relaunching itself in C2 mode. From there it checks in to its C2 over HTTPS, takes commands, downloads/updates follow-on payloads, and can steal or hijack Chromium browser profiles.

It's **not a typical stealer**. Stealers usually smash-and-grab once and exit. This one keeps a persistent victim ID, talks to its C2 both ways, takes operator tasking, and delivers additional stages. The bulk data theft looks like it's handed off to separate modules.

**Classification:** Trojanized signed application → backdoor/loader (first stage of a modular kit, "ZENITH").

---

## 1. Sample Overview

| Field | Value |
|---|---|
| SHA-256 | `7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3` |
| Type | PE32+ x86-64 GUI, Windows |
| Size | 7,892,512 bytes |
| Language | Rust (stripped; toolchain strings tampered: `rustc`→`gustc`, `.rs`→`.rn`/`.rj`) |
| Packed | No |
| Masquerade | `SummitWorks.Paperline` / "Paperline Document Viewer" / "QuartzLine" v8.20.4376.83 |
| Signer | `Guangzhou Guoying Communication Technology Co., Ltd.` (Sectigo Public Code Signing CA EV R36). Reported as revoked |
| Key crates | slint 1.16.1, reqwest 0.12 / hyper 1 / tokio, native-tls (schannel), serde_json, flate2, sysinfo |

---

## 2. Execution Flow

### Initial execution + persistence (observed)
- Needs the user to run it the first time.
- On execution it writes an **XML task definition** and registers a scheduled task named **`QuartzlineUpdateCheck`**.
- The task runs `Quartzline.exe --update-check` **every hour with a random delay of up to 15 minutes**.
- Statically, there's no plaintext `schtasks` string or task-related API import. The registration logic is probably hidden behind the same string scrambling used for the C2 domains (see §3). Not yet located in code.

### Launch gate (confirmed)
`main` checks for two exact arguments:
- **`--update-check`**: check in, then download/update.
- **`--update-view`**: check in, then run operator commands.

With neither flag, the normal PDF viewer GUI runs and nothing malicious happens. That's why it scores low in sandboxes.

### `--update-check` mode (confirmed)
1. Builds a check-in and POSTs it to the C2 (see §4 for the encoding).
2. Retries up to 3 times, rotating through the C2 URL list with a sleep in between. Any 2xx counts as success.
3. Parses the JSON reply, which includes a download URL, a file path, and a type string.
4. Downloads the file (GET, up to 3 attempts, 2xx required).
5. If the type is **`exe`**, the file must start with `MZ` or it reports `"Invalid download"`.
6. Writes the file to the server-supplied path and reports the result back.

### `--update-view` mode (confirmed)
1. Builds a check-in from config fields, encodes it, and POSTs it to the C2.
2. Decodes the reply and parses it as JSON.
3. Walks a table of **registered command handlers**. For each one, it looks for a matching JSON key in the reply and calls that handler. This is a modular, plugin-style design (`g\register.rs` in the author's source paths).

---

## 3. C2 Configuration (confirmed)

The C2 domains are **not stored in plaintext**. Strings/FLOSS won't find them. The config loader (`0x14fffc21e`) decodes them at runtime with a simple byte-shift:

```
out[i] = (in[i] + 0xED + 0xF5 * i) & 0xFF
```

Decoded statically from the binary:

| Encoded bytes | Decoded |
|---|---|
| `8a839ca8a1afb6d6d0e8f4` | `westbeavers` |
| `808d9d9ca4bcc4d4dfdbf3ff` | `motherotters` |
| `7b838aa0b2b5beccd7e9` | `healskills` |
| `768d96` | `com` |

Each entry is built as `https://<host>.com`.

Hardcoded in the same config loader:
- Campaign ID: `QNPVXZGJYUSLTREHK`
- App folder: `QuartzLine`
- Victim ID file: `terrain.dat` (in `%LOCALAPPDATA%\QuartzLine\`, contains `zenith=<uuid>` alongside decoy viewer settings)
- URL path component: `quarry`
- Traffic encoding parameters (see §4)

Other strings present in the binary: `vein`, `deposit`, `sinter`, `stratum`, `bedrock`, `sandstone`, `lignite`, `schist`, `zenith`, `QZRT07`, `6.1.3`.

---

## 4. C2 Traffic Encoding (confirmed)

All C2 request bodies go through this scheme (`0x150092451`). It's reversible and not real cryptography, so captured bodies can be decoded offline.

1. **Gzip** the JSON body.
2. Generate a **4-byte random seed** (`BCryptGenRandom`, falling back to `RtlGenRandom`).
3. **Chained XOR**:
   - `out[0] = in[0] ^ 0xD7 ^ seed[0]`
   - `out[i] = in[i] ^ out[i-1] ^ (i & 0xFF) ^ seed[i % 4]`
4. **Bit rotation**: `out[i] = rol8(out[i], (seed + i) & 7)`
5. **Shuffle** (Fisher-Yates driven by a 32-bit LCG):
   - `state = seed ^ len`
   - for `i = len-1` down to 1: `state = state * 0xA36DF9D1 + 0x36BBBE6F`, `j = state % (i+1)`, swap
   - bytes are placed at `dst[perm[i]] = out[i]`
6. **Frame**: `[0x4C 'L'] [seed, 4 bytes] [payload]`
7. **Base64**, sent as `Content-Type: text/plain`.

Detection note: a C2 body Base64-decodes to a blob whose first byte is `0x4C`.

Caveats:
- Server→implant replies are decoded with the same parameters (`0x150096948`), but that function hasn't been fully reviewed yet.
- A decoder based on this hasn't been validated against real captured traffic yet.
- C2 is HTTPS, so you need decrypted bodies (TLS inspection, host telemetry, or memory) to use it.

---

## 5. Capabilities (confirmed)

- **Remote command execution** via `cmd.exe` (spawned with no window).
- **Download + write** of follow-on payloads / self-update.
- **Process termination** via `taskkill.exe /PID <pid> /F`.
- **Chromium profile theft/tampering**: walks `User Data\{Default, Profile N}`, can upload profile data, overwrite it with server-supplied versions, kill the browser, and relaunch it pointed at an attacker-chosen `--user-data-dir=`. This looks aimed at session theft/hijacking rather than local credential decryption. We didn't find local decryption, but we didn't specifically hunt for it either.
- **Host fingerprinting**: Windows build/version from the registry, CPU idle stats.
- **Result reporting** as JSON (`index, com, success, ec, dur, st1, st2, trunc1, trunc2, err`), with large output truncated.

Not observed in this sample: VM/sandbox detection, PowerShell, or process injection APIs. These may exist in other builds.

---

## 6. Related Components (observed)

Seen alongside this sample in the investigated environment:

| File | SHA-256 | Notes |
|---|---|---|
| Second `Quartzline.exe` (different signer) | `25ea334b75beede8dcab4c4460313c3013c35e55c16cd066231d80ecfe4c0653` | Likely delivered via the `--update-check` update path (inferred, not yet confirmed). Reported by Blackfish as "QuartzLine build 2". Not analyzed. |
| `chrome-history-summarizer` | `069fd1e710b341fbe92337116779e6b50a40408f55f6547252cd2c05fe9c0527` | Observed exporting data to AWS S3. Likely the data-theft stage. Not analyzed. |

Likely chain (inferred): user runs the signed viewer → scheduled task → hourly `--update-check` → follow-on payloads delivered → browser data exported to S3.

---

## 7. Comparison With Public Reporting

**Blackfish Security, "ZENITH kit" (2026-10-15)**, checked against this sample:

| Claim | In this sample? |
|---|---|
| `/quarry/vein`, `/quarry/deposit`, `/quarry/sinter` | Yes |
| C2 `westbeavers`, `motherotters`, `healskills` | Yes (decoded) |
| C2 `flawlessgradecheered`, `tabbyottercub`, `topsmagnificentgrade` | No, likely other builds |
| `/piglet/flange`, `/piglet/trestle` | No |
| Trigger flags `--check` / `--check-gui` | No. This build uses `--update-check` / `--update-view` |
| S3 bucket `chrome-history-backup`, `beatramiro[.]com` | Not in this binary |
| VM / analysis-tool detection | No plaintext evidence in this build |

The report seems to combine multiple builds (QuartzLine 1 and 2, CAIRA). Its details don't all apply to this sample.

**rogueauthority.org** writeup: its strings are present here, and its 4-layer encoding description matches what we recovered from the code.

**Correction to earlier internal notes:** a 32-byte "embedded config key" at `0x1503C4AD0` was previously reported. It's actually the HTTP method constants (GET/POST) for the Rust HTTP stack, followed by Rust `TypeId` values. It's not key material.

---

## 8. IOCs

**Hashes (SHA-256)**
```
7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3  QuartzLine (this sample)
25ea334b75beede8dcab4c4460313c3013c35e55c16cd066231d80ecfe4c0653  QuartzLine build 2
069fd1e710b341fbe92337116779e6b50a40408f55f6547252cd2c05fe9c0527  chrome-history-summarizer
```

**Network**
```
westbeavers[.]com          (decoded from this sample)
motherotters[.]com         (decoded from this sample)
healskills[.]com           (decoded from this sample)
flawlessgradecheered[.]com (third-party)
tabbyottercub[.]com        (third-party)
topsmagnificentgrade[.]com (third-party)
beatramiro[.]com           (third-party, delivery/referral)
chrome-history-backup.s3.us-east-2.amazonaws[.]com (third-party)
URI paths: /quarry/vein, /quarry/deposit, /quarry/sinter
HTTP: POST, Content-Type: text/plain, Base64 body
```

**Host**
```
Scheduled task:   QuartzlineUpdateCheck  (hourly, 15 min random delay)
Command line:     Quartzline.exe --update-check | --update-view
File:             %LOCALAPPDATA%\QuartzLine\terrain.dat  (contains zenith=<uuid>)
Child processes:  cmd.exe, taskkill.exe /PID <pid> /F
Browser relaunch: chrome.exe ... --user-data-dir=<unusual path>
Campaign ID:      QNPVXZGJYUSLTREHK
Signer:           Guangzhou Guoying Communication Technology Co., Ltd.
```

---

## 9. Detection

### YARA

```yara
rule QuartzLine_Zenith_Loader
{
    meta:
        description = "QuartzLine / ZENITH trojanized Rust PDF viewer backdoor-loader"
        hash = "7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3"
        date = "2026-10-16"

    strings:
        // encoded C2 hosts (byte-shift +0xED +0xF5*i)
        $c2_1 = { 8A 83 9C A8 A1 AF B6 D6 D0 E8 F4 }        // westbeavers
        $c2_2 = { 80 8D 9D 9C A4 BC C4 D4 DF DB F3 FF }     // motherotters
        $c2_3 = { 7B 83 8A A0 B2 B5 BE CC D7 E9 }           // healskills

        // traffic encoding constants stored into config
        $k1 = { 28 0C 00 00 D1 F9 6D A3 }   // mov dword [r8+0xc28], 0xA36DF9D1
        $k2 = { 2C 0C 00 00 6F BE BB 36 }   // mov dword [r8+0xc2c], 0x36BBBE6F

        $s1 = "QNPVXZGJYUSLTREHK" ascii
        $s2 = "terrain.dat" ascii
        $s3 = "--update-check" ascii
        $s4 = "--update-view" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($c2_*) or
            ($k1 and $k2) or
            (3 of ($s*))
        )
}
```

### Hunting ideas (Sigma-style logic)
- `schtasks.exe /create ... /xml` launched by a non-installer process, especially a document viewer.
- A scheduled task whose action passes `--update-check` or `--update-view` (or `--check`/`--check-gui`) to a binary in a user-writable path.
- Task name `QuartzlineUpdateCheck`.
- `Quartzline.exe` / `Paperline` spawning `cmd.exe` or `taskkill.exe`.
- Chromium relaunched with `--user-data-dir=` by a non-browser parent.
- HTTPS POSTs with `Content-Type: text/plain` to newly registered domains on `/quarry/*`.
- Uploads to unfamiliar `*.s3.*.amazonaws.com` buckets from user workstations.

---

## 10. MITRE ATT&CK

| Technique | ID |
|---|---|
| User Execution: Malicious File | T1204.002 |
| Masquerading (trojanized app / task name) | T1036, T1036.004 |
| Subvert Trust Controls: Code Signing | T1553.002 |
| Scheduled Task | T1053.005 |
| Obfuscated Files or Information (scrambled C2 strings) | T1027 |
| Application Layer Protocol: Web Protocols | T1071.001 |
| Data Encoding / Data Obfuscation | T1132, T1001 |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Ingress Tool Transfer (download / self-update) | T1105 |
| System Information Discovery | T1082 |
| Steal Web Session Cookie / Browser Session Hijacking | T1539, T1185 |
| Exfiltration to Cloud Storage (follow-on module) | T1567.002 |

---

## 11. Open Questions

- Locate the persistence code in this sample (encoded XML template / `schtasks` invocation).
- Names of the registered command handlers and their URL paths.
- Exact check-in body fields.
- Confirm the server→implant decoder matches the request encoding.
- Analyze `25ea334b…` and `069fd1e7…` (flags, C2, what the summarizer collects, S3 destination).
- Validate a traffic decoder against real captured bodies.

## 12. Extra Resources
- https://blackfish-defended.com/research/zenith-kit/
- https://threatfox.abuse.ch/ioc/1966842/
- https://rogueauthority.org/quartzline-signed-pdf-viewer-zenith-backdoor
