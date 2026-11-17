use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use hidapi::{HidApi, HidDevice, HidResult};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

pub const USB_VID: u16 = 0x248A;
pub const DONGLE_ALT_VID: u16 = 0x249A;

pub const PID_M3_WIRED_1: u16 = 0x5C2E;
pub const PID_M3_WIRED_2: u16 = 0x5D2E;
pub const PID_M3_WIRED_3: u16 = 0x5E2E;
pub const PID_M3_DONGLE: u16 = 0x5C2F;

pub const FORBIDDEN_OTA_USAGE_PAGE: u16 = 0xFFEF;
pub const REPORT_SIZE: usize = 32;
pub const HID_FRAME_SIZE: usize = 33;
pub const READ_TIMEOUT_MS: i32 = 50;

pub const EVENT_INPUT_REPORT: &str = "valkyrie://inputreport";
pub const EVENT_DISCONNECT: &str = "valkyrie://disconnect";

#[derive(Debug, Clone, Copy)]
struct SupportedSpec {
    vid: u16,
    pid: u16,
    fallback_name: &'static str,
    is_wireless: bool,
}

const SUPPORTED_SPECS: &[SupportedSpec] = &[
    SupportedSpec {
        vid: USB_VID,
        pid: PID_M3_WIRED_1,
        fallback_name: "Valkyrie VK M3 / M3 Lite (USB)",
        is_wireless: false,
    },
    SupportedSpec {
        vid: USB_VID,
        pid: PID_M3_WIRED_2,
        fallback_name: "Valkyrie VK M3 Lite (USB)",
        is_wireless: false,
    },
    SupportedSpec {
        vid: USB_VID,
        pid: PID_M3_WIRED_3,
        fallback_name: "Valkyrie VK M3 (USB)",
        is_wireless: false,
    },
    SupportedSpec {
        vid: USB_VID,
        pid: PID_M3_DONGLE,
        fallback_name: "Valkyrie VK M3 Series (2.4 GHz)",
        is_wireless: true,
    },
    SupportedSpec {
        vid: DONGLE_ALT_VID,
        pid: PID_M3_DONGLE,
        fallback_name: "Valkyrie VK M3 Series (2.4 GHz)",
        is_wireless: true,
    },
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValkyrieDeviceInfo {
    pub id: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub product_name: String,
    pub usage_page: u16,
    pub usage: u16,
    pub input_report_bytes: usize,
    pub output_report_bytes: usize,
    pub is_wireless: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InputReportEvent {
    pub id: String,
    pub report_id: u8,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DisconnectEvent {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
struct RawCandidate {
    id: String,
    vendor_id: u16,
    product_id: u16,
    product_name: Option<String>,
    usage_page: u16,
    usage: u16,
}

enum ReaderTarget {
    Dedicated(HidDevice),
    Shared(Arc<Mutex<HidDevice>>),
}

impl ReaderTarget {
    fn read_timeout(&self, buf: &mut [u8], timeout_ms: i32) -> HidResult<usize> {
        match self {
            Self::Dedicated(device) => device.read_timeout(buf, timeout_ms),
            Self::Shared(mutex) => {
                let guard = mutex
                    .lock()
                    .map_err(|_| hidapi::HidError::HidApiError {
                        message: "HID_STATE_POISONED".to_string(),
                    })?;
                guard.read_timeout(buf, timeout_ms)
            }
        }
    }
}

struct ActiveSession {
    writer: Arc<Mutex<HidDevice>>,
    stop_flag: Arc<AtomicBool>,
    reader_handle: Option<JoinHandle<()>>,
}

impl ActiveSession {
    fn shutdown(mut self) {
        self.stop_flag.store(true, Ordering::Release);
        if let Some(handle) = self.reader_handle.take() {
            let _ = handle.join();
        }
        drop(self.writer);
    }
}

#[derive(Default)]
pub struct HidState {
    session: Mutex<Option<ActiveSession>>,
}

impl Drop for HidState {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.session.lock() {
            if let Some(session) = guard.take() {
                session.shutdown();
            }
        }
    }
}

fn find_supported_spec(vid: u16, pid: u16) -> Option<SupportedSpec> {
    SUPPORTED_SPECS
        .iter()
        .copied()
        .find(|spec| spec.vid == vid && spec.pid == pid)
}

pub fn interface_priority(usage_page: u16, usage: u16) -> Option<u8> {
    if usage_page == FORBIDDEN_OTA_USAGE_PAGE {
        return None;
    }
    match (usage_page, usage) {
        (0xFF01, 0x0010) => Some(0),
        (0x0001, 0x0000) => Some(1),
        _ => None,
    }
}

pub fn is_allowed_command_interface(usage_page: u16, usage: u16) -> bool {
    interface_priority(usage_page, usage).is_some()
}

pub fn is_allowed_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x02..=0x0F | 0x10..=0x17 | 0x20)
}

pub fn validate_outbound_report(
    report_id: u8,
    payload: &[u8],
) -> Result<[u8; HID_FRAME_SIZE], String> {
    if report_id != 0 {
        return Err(format!(
            "STALL_GUARD_BLOCKED: report_id must be 0x00, got 0x{report_id:02X}"
        ));
    }
    if payload.len() != REPORT_SIZE {
        return Err(format!(
            "INVALID_REPORT_LENGTH: expected {REPORT_SIZE} payload bytes, got {}",
            payload.len()
        ));
    }
    let opcode = payload[0];
    if !is_allowed_opcode(opcode) {
        return Err(format!(
            "STALL_GUARD_BLOCKED: opcode 0x{opcode:02X} is outside allowlist [0x02..=0x0F, 0x10..=0x17, 0x20]"
        ));
    }

    let mut frame = [0u8; HID_FRAME_SIZE];
    frame[0] = 0x00;
    frame[1..HID_FRAME_SIZE].copy_from_slice(payload);
    Ok(frame)
}

pub fn normalize_input_report(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() {
        return None;
    }
    if raw.len() == HID_FRAME_SIZE && raw[0] == 0x00 {
        return Some(raw[1..HID_FRAME_SIZE].to_vec());
    }
    let limit = raw.len().min(REPORT_SIZE);
    Some(raw[..limit].to_vec())
}

fn filter_and_sort_candidates(candidates: Vec<RawCandidate>) -> Vec<ValkyrieDeviceInfo> {
    let mut accepted: Vec<(u8, ValkyrieDeviceInfo)> = candidates
        .into_iter()
        .filter_map(|cand| {
            let spec = find_supported_spec(cand.vendor_id, cand.product_id)?;
            let priority = interface_priority(cand.usage_page, cand.usage)?;
            let product_name = cand
                .product_name
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| spec.fallback_name.to_string());

            Some((
                priority,
                ValkyrieDeviceInfo {
                    id: cand.id,
                    vendor_id: cand.vendor_id,
                    product_id: cand.product_id,
                    product_name,
                    usage_page: cand.usage_page,
                    usage: cand.usage,
                    input_report_bytes: REPORT_SIZE,
                    output_report_bytes: REPORT_SIZE,
                    is_wireless: spec.is_wireless,
                },
            ))
        })
        .collect();

    accepted.sort_by(|(prio_a, dev_a), (prio_b, dev_b)| {
        prio_a
            .cmp(prio_b)
            .then_with(|| dev_a.is_wireless.cmp(&dev_b.is_wireless))
            .then_with(|| dev_a.vendor_id.cmp(&dev_b.vendor_id))
            .then_with(|| dev_a.product_id.cmp(&dev_b.product_id))
            .then_with(|| dev_a.id.cmp(&dev_b.id))
    });

    accepted.into_iter().map(|(_, dev)| dev).collect()
}

fn validate_open_candidate(
    device_id: &str,
    candidates: &[RawCandidate],
) -> Result<ValkyrieDeviceInfo, String> {
    if device_id.trim().is_empty() {
        return Err("NO_COMMAND_INTERFACE: device_id must not be empty".to_string());
    }

    let matched: Vec<&RawCandidate> = candidates
        .iter()
        .filter(|cand| cand.id == device_id)
        .collect();

    if matched.is_empty() {
        return Err(format!(
            "NO_COMMAND_INTERFACE: No matching Valkyrie command interface found for id '{device_id}'"
        ));
    }

    if matched
        .iter()
        .any(|cand| cand.usage_page == FORBIDDEN_OTA_USAGE_PAGE)
    {
        return Err(
            "OTA_COLLECTION_BLOCKED: Refusing to open forbidden 0xFFEF DFU/OTA collection"
                .to_string(),
        );
    }

    let filtered = filter_and_sort_candidates(matched.into_iter().cloned().collect());
    filtered.into_iter().next().ok_or_else(|| {
        format!(
            "NO_COMMAND_INTERFACE: Device '{device_id}' is not an allowlisted 32-byte Valkyrie command interface"
        )
    })
}

fn collect_hid_candidates(api: &HidApi) -> Vec<RawCandidate> {
    api.device_list()
        .map(|dev| RawCandidate {
            id: dev.path().to_string_lossy().into_owned(),
            vendor_id: dev.vendor_id(),
            product_id: dev.product_id(),
            product_name: dev.product_string().map(str::to_string),
            usage_page: dev.usage_page(),
            usage: dev.usage(),
        })
        .collect()
}

fn close_existing_session(state: &HidState) -> Result<(), String> {
    let previous = {
        let mut guard = state
            .session
            .lock()
            .map_err(|_| "HID_STATE_POISONED: failed to lock HID session state".to_string())?;
        guard.take()
    };
    if let Some(session) = previous {
        session.shutdown();
    }
    Ok(())
}

#[tauri::command]
pub fn list_valkyrie_devices() -> Result<Vec<ValkyrieDeviceInfo>, String> {
    let api = HidApi::new().map_err(|e| format!("HID_INIT_FAILED: {e}"))?;
    let candidates = collect_hid_candidates(&api);
    Ok(filter_and_sort_candidates(candidates))
}

#[tauri::command]
pub fn open_valkyrie_device(
    app: AppHandle,
    state: State<'_, HidState>,
    device_id: String,
) -> Result<ValkyrieDeviceInfo, String> {
    close_existing_session(&state)?;

    let api = HidApi::new().map_err(|e| format!("HID_INIT_FAILED: {e}"))?;
    let candidates = collect_hid_candidates(&api);
    let info = validate_open_candidate(&device_id, &candidates)?;

    let c_path = CString::new(info.id.as_str())
        .map_err(|_| "NO_COMMAND_INTERFACE: HID device path contains null byte".to_string())?;
    let reader_device = api
        .open_path(c_path.as_c_str())
        .map_err(|e| format!("HID_OPEN_FAILED: {e}"))?;

    reader_device
        .set_blocking_mode(true)
        .map_err(|e| format!("HID_CONFIG_FAILED: failed to set blocking mode: {e}"))?;

    let (reader_target, writer) = match api.open_path(c_path.as_c_str()) {
        Ok(writer_device) => (
            ReaderTarget::Dedicated(reader_device),
            Arc::new(Mutex::new(writer_device)),
        ),
        Err(_) => {
            let shared = Arc::new(Mutex::new(reader_device));
            (ReaderTarget::Shared(Arc::clone(&shared)), shared)
        }
    };

    let stop_flag = Arc::new(AtomicBool::new(false));
    let reader_stop = Arc::clone(&stop_flag);
    let reader_id = info.id.clone();
    let reader_app = app.clone();

    let reader_handle = thread::Builder::new()
        .name("valkyrie-hid-reader".to_string())
        .spawn(move || {
            let mut buf = [0u8; HID_FRAME_SIZE];
            while !reader_stop.load(Ordering::Acquire) {
                match reader_target.read_timeout(&mut buf, READ_TIMEOUT_MS) {
                    Ok(0) => continue,
                    Ok(n) => {
                        if let Some(bytes) = normalize_input_report(&buf[..n]) {
                            let _ = reader_app.emit(
                                EVENT_INPUT_REPORT,
                                InputReportEvent {
                                    id: reader_id.clone(),
                                    report_id: 0,
                                    bytes,
                                },
                            );
                        }
                    }
                    Err(err) => {
                        if !reader_stop.load(Ordering::Acquire) {
                            let _ = reader_app.emit(
                                EVENT_DISCONNECT,
                                DisconnectEvent {
                                    id: reader_id.clone(),
                                    reason: err.to_string(),
                                },
                            );
                        }
                        break;
                    }
                }
            }
        })
        .map_err(|e| format!("HID_READER_SPAWN_FAILED: {e}"))?;

    let mut guard = state
        .session
        .lock()
        .map_err(|_| "HID_STATE_POISONED: failed to lock HID session state".to_string())?;
    *guard = Some(ActiveSession {
        writer,
        stop_flag,
        reader_handle: Some(reader_handle),
    });

    Ok(info)
}

#[tauri::command]
pub fn close_valkyrie_device(state: State<'_, HidState>) -> Result<(), String> {
    close_existing_session(&state)
}

#[tauri::command]
pub fn send_valkyrie_report(
    state: State<'_, HidState>,
    report_id: u8,
    payload: Vec<u8>,
) -> Result<(), String> {
    let frame = validate_outbound_report(report_id, &payload)?;

    let writer = {
        let guard = state
            .session
            .lock()
            .map_err(|_| "HID_STATE_POISONED: failed to lock HID session state".to_string())?;
        let session = guard
            .as_ref()
            .ok_or_else(|| "HID_NOT_CONNECTED: no Valkyrie HID device is currently open".to_string())?;
        Arc::clone(&session.writer)
    };

    let guard = writer
        .lock()
        .map_err(|_| "HID_STATE_POISONED: failed to lock HID writer".to_string())?;

    // Note: on hidapi windows_native, synchronous WriteFile returns Ok(0) while overlapped
    // returns Ok(bytes_written). Any Ok(_) indicates the 33-byte report was submitted.
    guard
        .write(&frame)
        .map_err(|e| format!("HID_WRITE_FAILED: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate(
        id: &str,
        vid: u16,
        pid: u16,
        usage_page: u16,
        usage: u16,
    ) -> RawCandidate {
        RawCandidate {
            id: id.to_string(),
            vendor_id: vid,
            product_id: pid,
            product_name: Some("Valkyrie Test Device".to_string()),
            usage_page,
            usage,
        }
    }

    #[test]
    fn rejects_0xffef_ota_collection_and_non_command_pages() {
        assert!(!is_allowed_command_interface(0xFFEF, 0x0000));
        assert!(!is_allowed_command_interface(0xFFEF, 0x0010));
        assert!(!is_allowed_command_interface(0x0001, 0x0002));
        assert!(!is_allowed_command_interface(0x000C, 0x0001));
        assert!(!is_allowed_command_interface(0xFF01, 0x0001));

        assert!(is_allowed_command_interface(0xFF01, 0x0010));
        assert!(is_allowed_command_interface(0x0001, 0x0000));

        let candidates = vec![
            make_candidate("ota-node", USB_VID, PID_M3_WIRED_2, 0xFFEF, 0x0000),
            make_candidate("boot-mouse", USB_VID, PID_M3_WIRED_2, 0x0001, 0x0002),
            make_candidate("consumer", USB_VID, PID_M3_WIRED_2, 0x000C, 0x0001),
            make_candidate("unknown-vid", 0x1234, 0x5678, 0xFF01, 0x0010),
        ];
        assert!(filter_and_sort_candidates(candidates.clone()).is_empty());

        let err = validate_open_candidate("ota-node", &candidates).unwrap_err();
        assert!(
            err.starts_with("OTA_COLLECTION_BLOCKED:"),
            "unexpected error: {err}"
        );

        let missing_err = validate_open_candidate("missing", &candidates).unwrap_err();
        assert!(
            missing_err.starts_with("NO_COMMAND_INTERFACE:"),
            "unexpected error: {missing_err}"
        );
    }

    #[test]
    fn prioritizes_0xff01_before_0x0001_and_allows_all_supported_vid_pids() {
        let candidates = vec![
            make_candidate("generic-desktop", DONGLE_ALT_VID, PID_M3_DONGLE, 0x0001, 0x0000),
            make_candidate("ota", USB_VID, PID_M3_WIRED_1, 0xFFEF, 0x0000),
            make_candidate("vendor-cmd", USB_VID, PID_M3_WIRED_2, 0xFF01, 0x0010),
            make_candidate("wired-5e2e", USB_VID, PID_M3_WIRED_3, 0x0001, 0x0000),
            make_candidate("dongle-248a", USB_VID, PID_M3_DONGLE, 0xFF01, 0x0010),
        ];

        let filtered = filter_and_sort_candidates(candidates);
        assert_eq!(filtered.len(), 4);
        assert_eq!(filtered[0].usage_page, 0xFF01);
        assert_eq!(filtered[0].usage, 0x0010);
        assert_eq!(filtered[0].id, "vendor-cmd");
        assert!(!filtered[0].is_wireless);

        assert_eq!(filtered[1].usage_page, 0xFF01);
        assert_eq!(filtered[1].id, "dongle-248a");
        assert!(filtered[1].is_wireless);

        assert_eq!(filtered[2].usage_page, 0x0001);
        assert_eq!(filtered[2].id, "wired-5e2e");

        assert_eq!(filtered[3].usage_page, 0x0001);
        assert_eq!(filtered[3].id, "generic-desktop");
        assert!(filtered[3].is_wireless);
    }

    #[test]
    fn enforces_opcode_stall_guard_boundaries_and_report_shape() {
        for op in 0x02u8..=0x0F {
            let mut payload = vec![0u8; REPORT_SIZE];
            payload[0] = op;
            let frame = validate_outbound_report(0, &payload).expect("opcode should be allowed");
            assert_eq!(frame[0], 0x00);
            assert_eq!(frame[1], op);
        }

        for op in 0x10u8..=0x17 {
            let mut payload = vec![0u8; REPORT_SIZE];
            payload[0] = op;
            assert!(validate_outbound_report(0, &payload).is_ok());
        }

        {
            let mut payload = vec![0u8; REPORT_SIZE];
            payload[0] = 0x20;
            assert!(validate_outbound_report(0, &payload).is_ok());
        }

        for blocked in (0x18u8..=0x1F)
            .chain(0x21u8..=0x2A)
            .chain([0x00u8, 0x01u8, 0x80u8, 0xFFu8])
        {
            let mut payload = vec![0u8; REPORT_SIZE];
            payload[0] = blocked;
            let err = validate_outbound_report(0, &payload)
                .expect_err(&format!("opcode 0x{blocked:02X} must be blocked"));
            assert!(
                err.starts_with("STALL_GUARD_BLOCKED:"),
                "unexpected error for 0x{blocked:02X}: {err}"
            );
        }

        let mut valid_payload = vec![0u8; REPORT_SIZE];
        valid_payload[0] = 0x10;
        let bad_report_id = validate_outbound_report(1, &valid_payload).unwrap_err();
        assert!(bad_report_id.starts_with("STALL_GUARD_BLOCKED:"));

        let short_payload = vec![0x10u8; 31];
        let bad_len = validate_outbound_report(0, &short_payload).unwrap_err();
        assert!(bad_len.starts_with("INVALID_REPORT_LENGTH:"));
    }

    #[test]
    fn normalizes_33_byte_prefixed_and_32_byte_raw_input_reports() {
        let mut with_prefix = vec![0x00u8];
        with_prefix.extend((1u8..=32u8).collect::<Vec<_>>());
        let normalized = normalize_input_report(&with_prefix).unwrap();
        assert_eq!(normalized.len(), 32);
        assert_eq!(normalized[0], 1);
        assert_eq!(normalized[31], 32);

        let raw_32 = (10u8..42u8).collect::<Vec<_>>();
        let normalized_raw = normalize_input_report(&raw_32).unwrap();
        assert_eq!(normalized_raw, raw_32);
    }
}
