# Valkyrie Control — WebHID & Desktop Hardware Suite

Browser-native **WebHID** and **Tauri v2 Desktop** configurator, macro studio, 32-byte register inspector, and live telemetry suite for **Valkyrie VK M3 Lite** and **VK M3** wireless gaming mice — built as a zero-dependency vanilla ES module web application with offline **model preview** support.

**Live GitHub Pages App:** [https://jgsphaela.github.io/valkyrie-control/](https://jgsphaela.github.io/valkyrie-control/)

---

## Supported Hardware (`VID: 0x248A` / `0x249A`)

Both **M220** (`VK M3 Lite`) and **E023** (`VK M3`) 32-byte HID command architectures are supported over USB wired and 2.4 GHz wireless receiver connections:

| Model | `devId` | Connection | VID | PID | Sensor | Polling Rate |
|---|---|---|---|---|---|---|
| Valkyrie VK M3 Lite | `M220` | USB Wired | `0x248A` | `0x5C2E`, `0x5D2E` | PAW3311 (`12,000` native CPI; curve `0x11` interpolated `> 12,000`) | Up to 1000 Hz |
| Valkyrie VK M3 | `E023` | USB Wired | `0x248A` | `0x5C2E`, `0x5D2E`, `0x5E2E` | PAW3395 (`26,000` native CPI; curve `0x11`) | Capability-gated (`125–8000 Hz`) |
| Valkyrie VK M3 Series | `M220` / `E023` | 2.4 GHz Dongle | `0x249A`, `0x248A` | `0x5C2F` | PAW3311 / PAW3395 | Capability-gated (`handshake[11]`) |

Runtime `0x10` handshake ASCII `devId` (`M220` vs `E023`) is authoritative when differentiating models that share USB/dongle PIDs.

---

## Workspaces & Features

1. **Performance (`performance`)**:
   - 1–6 DPI stages with linked or independent X/Y DPI (`0x03`), per-stage indicator RGB swatches (`0x04`), and optional curve `0x11` **26,000 DPI** unlock (`0xE8` -> `0xEA`; values above `12,000 DPI` on `VK M3 Lite` `PAW3311` are firmware-interpolated rather than native sensor CPI).
   - Capability-gated polling rate selector (`125–8000 Hz` via `0x02` + `handshake[11]`), Lift-Off Distance (`1 / 2 / 3 mm`), Angle Snapping, Ripple Control, read-only firmware `MotionSync` lock detection (`0x16`), unlocked `0..30 ms` debounce (`0x07`), sleep timeout, Move Wake, Move Light-Off, and factory reset.
2. **Buttons (`buttons`)**:
   - Interactive 6-slot schematic overlay on [assets/models/vk_m3_lite.png](assets/models/vk_m3_lite.png) (`Left`, `Right`, `Middle`, `Back`, `Forward`, `DPI Cycle`) with live action summaries.
   - Full `0x11` / `0x09` remapping for Mouse Click/Scroll/Double-Click, Keyboard Chords, Consumer Media (`0x0C`), Rapid-Fire, Onboard Macros (`toggle` / `count` / `hold`), DPI Control, and Disabled.
3. **Lighting (`lighting`)**:
   - Direct access to onboard `0x15` / `0x05` lighting registers (`Off`, `Flowing` with CW/CCW direction, `7-Color Breathing`, `Constant`, `Neon`, `Waves`), brightness/speed controls, and `light="0"` firmware behavior notes.
4. **Macros (`macros`)**:
   - Live keyboard and mouse event recorder, editable Timeline Studio with little-endian inter-event delay preview, Win-key (`0x5B`/`0x5D`) release fix, 27-byte `0x08` multi-chunk uploader, and JSON import/export.
5. **Inspector (`inspector`)**:
   - Decoded register dump table (`[0x10..0x17, 0x20]`), baseline EEPROM snapshot export/import (`virgin_backup.json` compatible), safe rollback (`[0x02..0x07, 0x09]`), **256-bit / 32-byte Diff Grid**, allowlisted raw command runner, and exportable `TX` / `RX` / `EVT` (`0xC0`/`0xC2`) hex console.
6. **Firmware (`firmware`)**:
   - Live device identity and telemetry matrix (`devId`, `sensor`, `VID/PID`, `FW`, `RF FW`, `handshake[11]` capability byte, active HID collection, active transport, battery/charging state) plus the `0xFFEF` OTA lockout notice and compatibility guide trigger.
7. **Multi-Language UI (`i18n`)**:
   - Automatic browser locale detection with persistent switching across 10 languages (`en`, `zh-CN`, `zh-TW`, `ja`, `ko`, `es`, `de`, `fr`, `pt-BR`, `ru`).

---

## Desktop App (Windows) vs. GitHub Pages (WebHID)

### Recommended on Windows: Valkyrie Control Desktop App (Tauri v2)

Windows Chrome `157+` and Edge `157+` hide the mouse's `MI_02` command interface over WebHID (see below). For Windows users, the simplest solution is the standalone **Valkyrie Control Desktop App** (`valkyrie-control.exe` or NSIS installer from GitHub Releases, built via [.github/workflows/build-desktop.yml](.github/workflows/build-desktop.yml)):

- Connects directly to `MI_02` via native Rust `hidapi` ([src-tauri/src/hid.rs](src-tauri/src/hid.rs)) — **no browser WebHID picker restrictions** and **no separate background helper process**.
- Leaves the inbox Windows `hidusb.sys` driver and official `VK M3 Series.exe` untouched.

### GitHub Pages Web App (`https://jgsphaela.github.io/valkyrie-control/`)

- **macOS, Linux, & Windows Chrome `<= 156`**: Work natively over WebHID (`Chromium 89+` over **HTTPS** or `http://localhost`). Chromium's `hid_collection.cc` on macOS/Linux parses raw USB HID descriptors directly; on Linux, add standard `hidraw` `udev` rules for `0x248A` and `0x249A`.
- **Offline Model Preview**: Works in any modern browser without a physical mouse attached, allowing full inspection of `VK M3 Lite` and `VK M3` layouts, factory defaults, and macro/protocol tools.
- **Why Windows Edge `157+` / Chrome `157+` Hide `MI_02`**: On Windows, the 32-byte command interface (`MI_02`, `0x0001 / 0x0000`) declares constant HID report items that yield an empty `_HIDP_PREPARSED_DATA` item list. Windows Chromium builds incorporating commit `f09e4b4651` (`FinishRequestDevice()`, `CVE-2026-79003`) prune empty-item collections, hiding `MI_02` and leaving only `MI_01` (`0xFFEF` / consumer control).
- **Why `WebUSB` + `WinUSB` (Zadig) Is Not Viable**: `IFACE 2` (`MI_02`) declares `bInterfaceClass = 0x03` (`HID`), which Chromium WebUSB unconditionally blocks (`IsProtectedInterfaceClass`, `CVE-2018-6125`). Swapping Windows USB drivers with Zadig breaks the official Windows driver without unlocking WebUSB.
- **2.4 GHz Wireless Stability**: `2.4 GHz` wireless configuration may be less stable than wired USB. If transfers time out over wireless, connect the mouse directly via USB cable.

---

## Optional Browser Fallback: Windows Local Companion Helper (`companion/`)

If you prefer running **GitHub Pages** directly in Windows Edge `157+` / Chrome `157+` instead of the Desktop App, `companion/` provides an optional localhost-only HTTP + NDJSON bridge over `hidusb.sys`:

- **Option 1 — Standalone `.exe` (`valkyrie-helper.exe`)**: Built on GitHub Actions via [.github/workflows/build-helper.yml](.github/workflows/build-helper.yml) from [companion/valkyrie_helper.cpp](companion/valkyrie_helper.cpp) (dependency-free Win32/Winsock2).
- **Option 2 — Python Script**: Zero-dependency standard library + `ctypes` Win32 overlapped HID server:
  ```powershell
  py companion/valkyrie_helper.py
  ```
- **Zero Background Polling**: The web app never probes `127.0.0.1` automatically on page load. When WebHID fails on Windows (`OTA_COLLECTION_BLOCKED` or `NO_COMMAND_INTERFACE`), an inline compatibility card offers **Download Desktop App (Windows)** alongside the optional **Connect via Local Helper** fallback (triggering the browser's one-time Local Network Access prompt on HTTPS GitHub Pages) and a built-in **Compatibility guide**.
- **Security Boundaries**:
  - Binds strictly to `127.0.0.1:19480` (`--port N` optional; never `0.0.0.0`) and sends `Access-Control-Allow-Private-Network: true`.
  - Probes HID attributes/caps with `dwDesiredAccess = 0` first and opens `GENERIC_READ | GENERIC_WRITE` only on `MI_02` (`0xFF01/0x0010` or `0x0001/0x0000`, 33-byte input/output reports). Never opens `0xFFEF`.
  - Enforces `reportId === 0` and the `0x18..0x2A` (except `0x20`) stall guard before `WriteFile`, returning HTTP `403` (`STALL_GUARD_BLOCKED`) for disallowed opcodes.

---

## Safety Architecture

- **`0x18..0x2A` Stall Guard**: `buildCommandPacket()`, `sendCommand()`, `TauriBridgeHidDevice` ([src-tauri/src/hid.rs](src-tauri/src/hid.rs)), `LocalBridgeHidDevice`, and both `companion/` helpers enforce a strict outbound opcode allowlist (`[0x02..0x0F, 0x10..0x17, 0x20]`), blocking unmapped opcodes (`0x18..0x2A` except `0x20`) before transmission to prevent `MI_02` HID interface lockups.
- **`0xFFEF` OTA Lockout**: `WebHidManager`, `ValkyrieM220Device`, `src-tauri/src/hid.rs`, and both `companion/` helpers match only the 32-byte `(0xFF01, 0x0010)` or `(0x0001, 0x0000)` command collections and refuse to open or write the 64-byte `(0xFFEF, 0x0000)` DFU/OTA collection.
- **EEPROM Snapshot & Safe Rollback**: Baseline register snapshots (`[0x10..0x17, 0x20]`) can be exported, diffed at bit granularity, and restored safely using only `[0x02..0x07, 0x09]`.

---

## Local Development & Tests

### Web App (Static Server)

Serve the repository over HTTP on `localhost` (required for ES modules and WebHID):

```powershell
# Windows (via Python Launcher) or macOS/Linux (python3 -m http.server 8000)
py -m http.server 8000
```

### Tauri v2 Desktop App

```powershell
npm install
npm run tauri dev
npm run tauri build
```

### Automated Tests & Syntax Checks

```powershell
node --check js/app.js js/devices.js js/models.js js/hid/webhid-manager.js `
  js/hid/local-bridge-device.js js/hid/tauri-bridge-device.js `
  js/protocol/m220-device.js js/protocol/macro-compiler.js js/i18n/index.js
py -m py_compile companion/valkyrie_helper.py
node --test tests/protocol.test.mjs tests/i18n.test.mjs
cargo test --manifest-path src-tauri/Cargo.toml
```

---

## Repository Layout

- [index.html](index.html) — Zero-dependency application shell, compatibility guide modal, and 6-workspace layout
- [app.css](app.css) — Anodized slate dark/light theme tokens and component styles
- [package.json](package.json) — Tauri v2 CLI scripts (`stage:web`, `tauri`) and test runner
- [scripts/stage-web.mjs](scripts/stage-web.mjs) & [scripts/dev-server.mjs](scripts/dev-server.mjs) — Tauri frontend asset stager (`dist-web/`) and localhost dev server
- [js/app.js](js/app.js) — `ValkyrieControlApp` UI controller and state bindings
- [js/devices.js](js/devices.js) — Official VID/PID registry, HID collection constants, and `M220`/`E023` specs
- [js/models.js](js/models.js) — Schematic callout coordinates (`PAW3311` / `PAW3395`) and factory defaults for offline preview
- [js/hid/webhid-manager.js](js/hid/webhid-manager.js) — WebHID, Tauri, and Local Helper connection manager + `0xFFEF` OTA guard
- [js/hid/tauri-bridge-device.js](js/hid/tauri-bridge-device.js) — Tauri v2 IPC `HIDDevice`-compatible transport adapter
- [js/hid/local-bridge-device.js](js/hid/local-bridge-device.js) — HTTP + NDJSON `HIDDevice`-compatible transport adapter for `127.0.0.1:19480`
- [js/protocol/m220-device.js](js/protocol/m220-device.js) — 32-byte protocol driver, 11 sensor curves, stall guard, and 256-bit snapshot diffing
- [js/protocol/macro-compiler.js](js/protocol/macro-compiler.js) — Macro bytecode compiler (`0x08` 27-byte chunking) and button descriptor codecs
- [js/i18n/index.js](js/i18n/index.js) & [js/i18n/locales/](js/i18n/locales/) — 10-language i18n runtime and locale catalogs
- [src-tauri/Cargo.toml](src-tauri/Cargo.toml), [src-tauri/tauri.conf.json](src-tauri/tauri.conf.json), & [src-tauri/src/hid.rs](src-tauri/src/hid.rs) — Native Rust Tauri v2 `hidapi` backend
- [companion/valkyrie_helper.cpp](companion/valkyrie_helper.cpp) — Dependency-free Win32/Winsock2 local HID bridge (`valkyrie-helper.exe` source)
- [companion/valkyrie_helper.py](companion/valkyrie_helper.py) — Zero-dependency Python stdlib + `ctypes` Win32 local HID bridge
- [.github/workflows/build-desktop.yml](.github/workflows/build-desktop.yml) — GitHub Actions Windows x64 build workflow for `valkyrie-control.exe` & NSIS installer
- [.github/workflows/build-helper.yml](.github/workflows/build-helper.yml) — GitHub Actions MSVC x64 build workflow for `valkyrie-helper.exe`
- [assets/models/vk_m3_lite.png](assets/models/vk_m3_lite.png) — Mouse schematic render (`260x506`)
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — Complete M220 / E023 reverse-engineered protocol specification
- [tests/protocol.test.mjs](tests/protocol.test.mjs) & [tests/i18n.test.mjs](tests/i18n.test.mjs) — Protocol and localization test suites
- [LICENSE](LICENSE) — MIT License
