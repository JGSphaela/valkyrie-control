# Valkyrie M220 / E023 WebHID Protocol Specification

Technical reference for the **Valkyrie VK M3 Lite (`M220`)** and **VK M3 (`E023`)** 32-byte HID protocol, reverse-engineered from `VK M3 Series.exe` + `VK M3 Series.pdb` and verified against live `M220 v3.17` hardware captures.

---

## 1. USB / 2.4 GHz Hardware Identifiers & HID Collections

### Supported VIDs & PIDs

| Model | Firmware `devId` | Connection | Vendor ID (`VID`) | Product ID (`PID`) | Max Official Polling |
|---|---|---|---|---|---|
| VK M3 Lite | `M220` (`deviceType: 101`) | USB Wired | `0x248A` | `0x5C2E`, `0x5D2E` | 1000 Hz |
| VK M3 | `E023` (`deviceType: 102`) | USB Wired | `0x248A` | `0x5C2E`, `0x5D2E`, `0x5E2E` | 1000 Hz (cap-gated up to 8000 Hz) |
| VK M3 Series | `M220` / `E023` | 2.4 GHz Dongle | `0x249A`, `0x248A` | `0x5C2F` | Capability-gated (`handshake[11]`) |

Because `M220` and `E023` share several USB and 2.4 GHz PIDs, the runtime `0x10` handshake ASCII `devId` (`bytes[4..7]`) is authoritative for model identification.

### Dual Command Collection Matching

In `js/hid/webhid-manager.js`, `selectCommandCollection()` matches the 32-byte command interface (`reportId: 0x00`) in priority order:

1. **Vendor Command Collection**: `usagePage: 0xFF01`, `usage: 0x0010` (32-byte input/output reports)
2. **Generic Desktop Command Collection**: `usagePage: 0x0001`, `usage: 0x0000` (32-byte input/output reports)

### Mandatory `0xFFEF / 0x0000` DFU / OTA Exclusion

Both `WebHidManager` and `ValkyrieM220Device` strictly exclude and refuse to open or write the 64-byte **`(usagePage: 0xFFEF, usage: 0x0000)`** DFU/OTA collection (`OTA_COLLECTION_BLOCKED`). Boot mouse (`0x0002`), boot keyboard (`0x0006`), and consumer control (`0x000C`) collections are likewise ignored.

---

## 2. 32-Byte Packet Format, Checksum & Stall Guard

### Frame Layout (`Report ID: 0x00`, `32` bytes)

```text
Byte  | Field      | Description
------+------------+-------------------------------------------------------------
0     | cmd        | Command opcode (0x10..0x20 read, 0x02..0x0F write)
1     | status     | 0x00 on request; 0x00 = OK, 0x03 = hardware rejected on RX
2     | seqByte    | 0x01 for single-packet commands; (chunkIdx << 4) | totalChunks on 0x08
3     | len        | Payload byte count N
4..30 | payload    | Command payload (27 bytes max, zero-padded)
31    | checksum   | sum(bytes[4..30]) & 0xFF
```

On Windows, `_hid_write` prepends the leading `0x00` Report ID (33 bytes on the wire). WebHID `sendReport(0x00, packet32)` transmits the 32-byte payload directly; `oninputreport` strips a leading `0x00` if a 33-byte buffer is received.

### Checksum Formula

```js
sum(packet[4..30]) & 0xFF
```

### Transport Timing & Serialization

- **Serialized Queue**: All outbound commands are serialized through `#ioChain` so only one command awaits a response at a time (`READ_TIMEOUT_MS = 1200 ms`).
- **Write Settle Window (`>= 50 ms`)**: After every write command (`0x02..0x0F`), `ValkyrieM220Device` waits `WRITE_SETTLE_DELAY_MS = 55 ms` (enforced floor `>= 50 ms`) before issuing subsequent reads or writes.

### Critical `0x18..0x2A` Stall Hazard & Strict Allowlist

> [!CAUTION]
> Live hardware probes on `VK M3 Lite` (`MI_02`) demonstrated that sending unmapped opcodes in the **`0x18..0x2A`** range (aside from `0x20`) causes the HID command interface to **stall with zero responses until the mouse is physically replugged**.

To prevent interface lockups, `buildCommandPacket()` and `#sendAndWait()` enforce a strict outbound allowlist (`ALLOWED_OUTBOUND_OPCODES`):

```text
[0x02..0x0F, 0x10..0x17, 0x20]
```

Any opcode outside this set throws `STALL_GUARD_BLOCKED` before `sendReport()` is called. Safe read-only register dumps (`SAFE_DUMP_OPCODES`) use `[0x10..0x17, 0x20]`, and safe snapshot rollback (`SAFE_ROLLBACK_WRITE_PAIRS`) writes only `[0x02..0x07, 0x09]`.

---

## 3. Complete Opcode Reference

### Read Commands (`0x10..0x17, 0x20`)

| Opcode | Name | Response Payload (`bytes[4..30]`) |
|---|---|---|
| `0x10` | Handshake | `bytes[4..7]` ASCII `devId` (`M220`/`E023`), `[8]` `fwMinor`, `[9]` `fwMajor` (`0x17 0x03` = `v3.17`), `[10]` `sensorId`, `[11]` `pollingCaps` (`0x10`=2K, `0x20`=4K, `0x40`=8K, `0x07`=8K, else 1K), `[12]` `charging` (`0`/`1`), `[13]` `batteryPct` (`0..100`), `[14]` `online` (`0`/`1`) |
| `0x11` | Button Bindings | `byte[3]=0x12`, `bytes[4..21]` = 6 x 3-byte button descriptors `[Left, Right, Middle, Back, Forward, DPI]` |
| `0x12` | Polling Rate | `byte[3]=0x01`, `byte[4]` = rate code (`0x08`=125Hz, `0x04`=250Hz, `0x02`=500Hz, `0x01`=1000Hz, `0x10`=2000Hz, `0x20`=4000Hz, `0x40`=8000Hz) |
| `0x13` | DPI Stages | `byte[3]=0x19`, `byte[4] = (activeStage << 4) \| stageCount`, `bytes[5..28]` = 6 x 4-byte LE `[xLo, xHi, yLo, yHi]` |
| `0x14` | DPI Colors | `byte[3]=0x12`, `bytes[4..21]` = 6 x 3-byte `[R, G, B]` stage indicator colors |
| `0x15` | Lighting Config | `byte[4]` mode (`0`=Off, `1`=Flowing, `2`=Breathing, `3`=Constant, `4`=Neon, `5`=Waves), `byte[5] = (speed << 4) \| brightness`, `byte[6..]` direction (`mode 1`), RGB (`mode 3`), or 7-color stops (`mode 2`, `byte[6]=7`, `bytes[7..27]`) |
| `0x16` | Sensor & LOD | `byte[3]=0x05`, `byte[4]` LOD (`1`=1mm, `2`=2mm, `3`=3mm), `byte[5]` Angle Snap (`0`/`1`), `byte[6]` Ripple Control (`0`/`1`), `byte[7]` Motion Sync (`0`/`1`), `byte[8]` reserved (`0x00`) |
| `0x17` | Sleep & Debounce | `byte[3]=0x05`, `byte[4]` Sleep (`unit * 10s`), `byte[5]` Move Wake (`0`/`1`), `byte[6]` Move Light-Off (`0`/`1`), `byte[7]` Debounce (`ms`) |
| `0x20` | Dongle / RF Info | `byte[3]=0x02`, `byte[4]` `rfMinor`, `byte[5]` `rfMajor` (`0x17 0x03` = `v3.17`) |

### Write Commands (`0x02..0x09, 0x0E, 0x0F`)

| Opcode | Name | Payload Layout (`bytes[3..]`) |
|---|---|---|
| `0x02` | Set Polling Rate | `len=0x01`, `byte[4]=rateCode` (`0x08`/`0x04`/`0x02`/`0x01`/`0x10`/`0x20`/`0x40`). Firmware ACKs `status=0x03` if rate exceeds `handshake[11]` capability. |
| `0x03` | Set DPI Stages | `len=0x19` (`25`), `byte[4]=(activeIdx << 4) \| count`, `bytes[5..28]` = 6 x `(xLo, xHi, yLo, yHi)` |
| `0x04` | Set DPI Colors | `len=0x12` (`18`), `bytes[4..21]` = 6 x `(R, G, B)` |
| `0x05` | Set Lighting | Modes `0/4/5`: `len=2` `[mode, packed]`; Mode `1` (Flowing): `len=3` `[1, packed, dir]`; Mode `3` (Constant): `len=5` `[3, packed, R, G, B]`; Mode `2` (7-Color Breathing): `len=0x18` `[2, packed, 0x07, 7xRGB]` |
| `0x06` | Set Sensor Tuning | `len=0x05`, `[lod, angleSnap, ripple, motionSync, 0x00]` |
| `0x07` | Set Sleep & Debounce | `len=0x04`, `[sleep10s, moveWake, moveCloseLight, debounceMs]` |
| `0x08` | Upload Macro | Multi-chunk transfer: `byte[2]=(chunkIdx << 4) \| totalChunks`, `byte[3]=chunkLen` (`<= 27`), `bytes[4..]` chunk data |
| `0x09` | Set Buttons | `len=0x0F` (`15` header per official driver, `bytes[4..21]` carries all 6 x 3-byte descriptors) |
| `0x0E` | Light Reset | `len=0x01`, `byte[4]=0x01` (or `0x42` during factory reset) |
| `0x0F` | Factory Reset | `len=0x01`, `byte[4]=0xFF` |

> [!NOTE]
> The official Windows driver's `ResetMouseKeyData` sends `[0x52, 0x52, keyIdx, 0x00]`, which is a broken legacy stub. Valkyrie Control replaces this with explicit `0x09` button descriptor restoration.

### Unsolicited Push Notifications (`0xC0`, `0xC2`)

| Opcode | Kind | Payload Layout |
|---|---|---|
| `0xC0` | Wireless / Battery | `byte[1]` online (`0x01` = online), `byte[2]` battery % (`0..100`), `byte[3]` charge state (`0x01` = charging) |
| `0xC2` | Live DPI Stage | `byte[1] >> 4` = active stage (`0..5`), `byte[1] & 0x0F` = active stage count (`1..6`) |

### Live Verified Captures (`VK M3 Lite`, `M220 v3.17`)

| Opcode | Captured 32-Byte Response (Hex) |
|---|---|
| `0x10` | `10 00 01 0b 4d 32 32 30 17 03 11 01 02 64 01 00 ... 74` |
| `0x11` | `11 00 01 12 10 01 00 10 02 00 10 04 00 10 08 00 10 10 00 40 01 00 ... b0` |
| `0x12` | `12 00 01 01 01 00 ... 01` |
| `0x13` | `13 00 01 19 06 10 00 10 00 18 00 18 00 28 00 28 00 64 00 64 00 a0 00 a0 00 dc 00 dc 00 00 00 66` |
| `0x14` | `14 00 01 12 ff ff 00 00 ff ff 00 ff 00 ff 00 ff 00 00 ff ff 00 00 ... f7` |
| `0x15` | `15 00 01 03 01 42 01 00 ... 44` |
| `0x16` | `16 00 01 05 02 00 00 01 00 ... 03` |
| `0x17` | `17 00 01 05 1e 01 01 08 00 ... 28` |
| `0x20` | `20 00 01 02 17 03 00 ... 1a` |

---

## 4. Sensor DPI Curves (All 11 Families)

`byte[10]` of `0x10` selects the sensor curve (`encodeDpiCode` / `decodeDpiCode` in `js/protocol/m220-device.js`):

| `sensorId` | Profile | Official Range | Step | Encode Formula | Decode Formula |
|---|---|---|---|---|---|
| `0x11` | PAW3395 (`E023`) / PAW3311 (`M220` curve `0x11`) | `50 .. 24,000` (unlocks to `26,000`; `12,000` native on PAW3311) | `50` | `>=13000`: `(dpi-13000)/1000 + 0xDD`; `>10000`: `(dpi-10000)/100 + 0xC8`; else `dpi/50` | `>=0xDD`: `(code-0xDD)*1000 + 13000`; `>=0xC8`: `(code-0xC8)*100 + 10000`; else `code*50` |
| `0x05` | Sensor `0x05` | `50 .. 12,000` | `50` | `>6400`: `(dpi-6400)/100 + 0x80`; else `dpi/50` | `>=0x81`: `(code-64)*100`; else `code*50` |
| `0x19` | PAW3950 / `0x19` | `100 .. 30,000` | `100` | `>16000`: `(dpi-16000)/1000 + 0xA0`; else `dpi/100` | `>=0xA0`: `(code-0x90)*1000`; else `code*100` |
| `0x25` | Sensor `0x25` | `100 .. 10,000` | `100` | `>5000`: `(dpi-5000)/500 + 0x32`; else `dpi/100` | `>=0x32`: `(code-0x28)*500`; else `code*100` |
| `0x26` | Sensor `0x26` | `200 .. 10,000` | `200` | `>5000`: `(dpi-5000)/500 + 0x32`; else `dpi/100 - 1` | `>=0x32`: `(code-0x27)*500`; else `code*100` |
| `0x04` | Sensor `0x04` | `100 .. 8,000` | `100` | `>4000`: `(dpi-4000)/500 + 0x27`; else `dpi/100` | `<=0x27`: `code*100`; else `(code-0x1F)*500` |
| `0x95` | Sensor `0x95` | `100 .. 26,000` | `100` | `dpi/50 - 1` | `(code+1)*50` |
| `0x96` | Sensor `0x96` | `100 .. 32,000` | `100` | `dpi/50 - 1` | `code*50` |
| `0x10` | Sensor `0x10` | `100 .. 4,800` | `100` | `dpi/100` | `code*100` |
| `0x12` | Sensor `0x12` | `100 .. 4,800` | `100` | `dpi/100` | `code*100` |
| `0x35` | Sensor `0x35` | `100 .. 16,000` | `100` | `dpi/100` | `code*100` |

### Curve `0x11` Sensor Mapping (`PAW3311` vs `PAW3395`) & `26,000 DPI` Unlock

- **VK M3 Lite (`M220`)**: Physically houses the **PixArt PAW3311** sensor (`12,000` native CPI, matching `mouse_vk m3 lite.xml` factory max `12,000 DPI` and `show_lod="0" show_sensor="0"`). However, `M220 v3.17` firmware reports handshake `byte[10] = 0x11` to reuse DPI curve `0x11`, which supports firmware-interpolated DPI above `12,000` up to `24,000` (`0xE8`) and unlocked `26,000` (`0xEA`).
- **VK M3 (`E023`)**: Physically houses the **PixArt PAW3395** sensor (`26,000` native CPI) using the same `0x11` curve.

On curve `0x11`, the official Windows slider caps at `0xE8` (`24,000 DPI`). Setting `unlockMax: true` allows encoding up to `0xEA` (`26,000 DPI`), which the live `M220 v3.17` firmware persists and echoes in `0x13`.

---

## 5. Macro Compiler & Button Descriptor Format

### Macro Binary Stream (`0x08`)

`compileMacroStream(events, keyIdx)` in `js/protocol/macro-compiler.js` produces:

```text
[keyIdx, op0, delayLo0, delayHi0, code0, op1, delayLo1, delayHi1, code1, ...]
```

- **Byte 0**: Target `keyIdx` (`0..5`).
- **4-Byte Event Tuples**: `[op, delayLo, delayHi, code]`
  - `0x10`: `MOUSE_DOWN` (`code` = button mask `0x01` Left, `0x02` Right, `0x04` Middle, `0x08` Back, `0x10` Forward)
  - `0x90`: `MOUSE_UP`
  - `0x20`: `MOD_DOWN` (`code` = modifier bitmask `0x01..0x80`)
  - `0xA0`: `MOD_UP` (**Win-key fix**: `0x5B` `VK_LWIN` and `0x5D`/`0x5C` `VK_RWIN` emit `0xA0` on release, fixing the official driver's missing Win-key release branch)
  - `0x30`: `KEY_DOWN` (`code` = USB HID Usage Page `0x07` keycode)
  - `0xB0`: `KEY_UP`
- **Little-Endian Inter-Event Delay**: `[delayLo, delayHi]` is a uint16 (`1..65535 ms`, default `1 ms`) stored on the **previous** hardware event; trailing delays after the final event update the final event.
- **27-Byte Chunking**: `frameMacroChunks(keyIdx, stream)` splits the stream into 27-byte slices across `0x08` packets (`byte[2] = (chunkIdx << 4) | totalChunks`, `byte[3] = slice.length`), up to 15 chunks (`405` bytes max).

### Button Descriptors (`[b0, b1, b2]` in `0x11` / `0x09`)

| `b0` | Category | `b1`, `b2` Encoding |
|---|---|---|
| `0x10` | Mouse Click / H-Scroll | `b1` = mask (`0x01..0x10`), `b2 = 0x00`; or `[0x10, 0x00, 0xF5]` (Scroll Left), `[0x10, 0x00, 0xF6]` (Scroll Right) |
| `0x20` | Vertical Scroll | `[0x20, 0x01, 0x00]` (Up), `[0x20, 0xFF, 0x00]` (Down) |
| `0x30` | Double-Click / Fire | `[0x30, 0x32, 0x03]` (Double-Click) or `[0x30, repeatCount (0..255), intervalMs (5..255)]` |
| `0x40` | DPI Control | `b1 = 0x01` (Cycle), `0x02` (Up), `0x03` (Down) |
| `0x60` | Disabled / Report Rate | `[0x60, 0x00, 0x00]` (Disabled) or `[0x60, 0x04/0x01, 0x00]` (Report Rate step) |
| `0x70` | Keyboard / Chord | `b1` = modifier mask (`0x01..0x80`), `b2` = HID keycode (`0x00` for standalone modifier) |
| `0x80` | Consumer Media | `[0x80, usageLo, usageHi]` (USB HID Usage Page `0x0C`) |
| `0x90` | Onboard Macro | `b1 = modeFlag \| slotIndex` (`0x10`=toggle, `0x20`=count, `0x40`=hold), `b2 = loopCount` |

---

## 6. Empirical Hardware Discoveries Beyond Official Software

Probing the live `VK M3 Lite` (`M220 v3.17`) firmware revealed several capabilities and quirks not exposed or mishandled by `VK M3 Series.exe`:

1. **Unlocked `0..30 ms` Debounce**: The official UI clamps debounce to `4..20 ms`, whereas `0x07` -> `0x17` cleanly persists `0..30 ms` (`0x00..0x1E`).
2. **Asymmetric X/Y DPI**: `0x03` -> `0x13` independently stores and returns separate 16-bit X and Y stage codes.
3. **`26,000 DPI` Curve `0x11` Unlock (Interpolated on `PAW3311`)**: `0x03` accepts `0xEA` (`26,000 DPI`) beyond the official `0xE8` (`24,000 DPI`) ceiling; on `M220` (`PAW3311`), values above `12,000 DPI` are firmware-interpolated rather than native sensor CPI.
4. **Hidden `light="0"` / `show_lod="0"` / `show_sensor="0"` Registers**: Even though `mouse_vk m3 lite.xml` disables these UI tabs, `M220 v3.17` responds to `0x14`, `0x15`, `0x16`, and `0x17`. On `VK M3 Lite`, `0x15` Flowing (`Mode 1`) persists custom `(speed << 4) | brightness` and direction `byte[6]`, whereas Modes `2..5` echo factory color/speed presets on read-back.
5. **Read-Only `MotionSync` Lock on `M220 v3.17`**: `0x16 byte[7]` returns `0x01` even when `0x06` writes `0x00` for `MotionSync`; `setSensorSettings()` detects this mismatch and flags `state.motionSyncLocked = true`.
6. **Hardware 1K Polling Cap Enforcement**: Sending `2000`/`4000`/`8000 Hz` (`0x10`/`0x20`/`0x40`) to a `handshake[11] = 0x01` mouse returns `ACK status = 0x03` (`HARDWARE_REJECTED`).
