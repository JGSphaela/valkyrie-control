#!/usr/bin/env python3
"""
Valkyrie Local Companion Helper (Zero-Dependency Python Stdlib)

Exposes a localhost-only (127.0.0.1) HTTP/1.1 + NDJSON bridge for static web
browsers (Chrome/Edge 157+ on Windows) to communicate with the Valkyrie
VK M3 / M3 Lite MI_02 32-byte HID configuration collection without modifying
Windows USB drivers.

Security invariants:
1. Binds strictly to 127.0.0.1 (never 0.0.0.0).
2. Enumerates and opens ONLY supported Valkyrie VID/PID devices:
   (0x248A: 0x5C2E, 0x5D2E, 0x5E2E, 0x5C2F) and (0x249A: 0x5C2F).
3. Enumerates attributes/caps with dwDesiredAccess=0 first; opens RW ONLY on
   MI_02 collections ((0xFF01/0x0010) or (0x0001/0x0000)) with 33-byte reports,
   strictly excluding 0xFFEF (OTA/DFU).
4. Enforces outbound opcode allowlist (0x02..0x0F, 0x10..0x17, 0x20) and
   reportId == 0 BEFORE WriteFile (rejects others with HTTP 403).
5. Uses FILE_FLAG_OVERLAPPED with a dedicated background reader thread and
   separate OVERLAPPED+Event for concurrent WriteFile.
"""

from __future__ import annotations

import argparse
import ctypes
import http.server
import json
import queue
import signal
import socket
import sys
import threading
import time
import urllib.parse

SERVICE_NAME = "valkyrie-helper"
SERVICE_VERSION = "1.0.0"
DEFAULT_PORT = 19480

# Supported (VID, PID) -> (fallback product name, is_wireless)
SUPPORTED_DEVICES = {
    (0x248A, 0x5C2E): ("Valkyrie VK M3 / M3 Lite (USB)", False),
    (0x248A, 0x5D2E): ("Valkyrie VK M3 Lite (USB)", False),
    (0x248A, 0x5E2E): ("Valkyrie VK M3 Pro (USB)", False),
    (0x248A, 0x5C2F): ("Valkyrie VK M3 Wireless Dongle", True),
    (0x249A, 0x5C2F): ("Valkyrie VK M3 Wireless Dongle", True),
}

FORBIDDEN_OTA_USAGE_PAGE = 0xFFEF
HID_REPORT_BYTE_LENGTH = 33  # 1-byte Report ID + 32-byte payload
MAX_JSON_BODY_BYTES = 1024 * 1024
PING_INTERVAL_SECONDS = 15.0
MAX_EVENT_QUEUE_SIZE = 1024


def is_allowed_opcode(opcode: int) -> bool:
    """Allow only safe configuration/read opcodes before WriteFile."""
    return (0x02 <= opcode <= 0x0F) or (0x10 <= opcode <= 0x17) or (opcode == 0x20)


def is_allowed_command_caps(usage_page: int, usage: int, in_len: int, out_len: int) -> bool:
    """Enforce MI_02 command collection filter and strictly forbid 0xFFEF OTA."""
    if usage_page == FORBIDDEN_OTA_USAGE_PAGE:
        return False
    if in_len != HID_REPORT_BYTE_LENGTH or out_len != HID_REPORT_BYTE_LENGTH:
        return False
    return (usage_page == 0xFF01 and usage == 0x0010) or (usage_page == 0x0001 and usage == 0x0000)


def make_device_id(vid: int, pid: int, usage_page: int, path: str) -> str:
    """Generate a deterministic, URL-safe ID matching the C++ helper."""
    norm = path.lower().encode("utf-8")
    h = 0xCBF29CE484222325
    prime = 0x100000001B3
    for b in norm:
        h = ((h ^ b) * prime) & 0xFFFFFFFFFFFFFFFF
    return f"vk-{vid:04x}-{pid:04x}-{usage_page:04x}-{h:016x}"


def validate_origin(origin: str | None) -> str | None:
    """Echo Origin header cleanly only when scheme is http:// or https://."""
    if not origin:
        return None
    cleaned = origin.strip()
    if not cleaned:
        return None
    if any(ch in cleaned for ch in ("\r", "\n", "\x00", " ", "\t")):
        return None
    low = cleaned.lower()
    if (low.startswith("http://") and len(cleaned) > 7) or (low.startswith("https://") and len(cleaned) > 8):
        return cleaned
    return None


# ---------------------------------------------------------------------------
# Win32 SetupAPI / HID / Overlapped I/O bindings (loaded lazily on Windows)
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    import ctypes.wintypes as w

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    FILE_FLAG_OVERLAPPED = 0x40000000
    DIGCF_PRESENT = 0x00000002
    DIGCF_DEVICEINTERFACE = 0x00000010

    ERROR_OPERATION_ABORTED = 995
    ERROR_IO_PENDING = 997
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102
    INFINITE = 0xFFFFFFFF
    INVALID_HANDLE_VALUE = w.HANDLE(-1).value

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", w.DWORD),
            ("Data2", w.WORD),
            ("Data3", w.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
        _fields_ = [
            ("cbSize", w.DWORD),
            ("InterfaceClassGuid", GUID),
            ("Flags", w.DWORD),
            ("Reserved", ctypes.c_void_p),
        ]

    class HIDD_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Size", w.DWORD),
            ("VendorID", w.USHORT),
            ("ProductID", w.USHORT),
            ("VersionNumber", w.USHORT),
        ]

    class HIDP_CAPS(ctypes.Structure):
        _fields_ = [
            ("Usage", w.USHORT),
            ("UsagePage", w.USHORT),
            ("InputReportByteLength", w.USHORT),
            ("OutputReportByteLength", w.USHORT),
            ("FeatureReportByteLength", w.USHORT),
            ("Reserved", w.USHORT * 17),
            ("NumberLinkCollectionNodes", w.USHORT),
            ("NumberInputButtonCaps", w.USHORT),
            ("NumberInputValueCaps", w.USHORT),
            ("NumberInputDataIndices", w.USHORT),
            ("NumberOutputButtonCaps", w.USHORT),
            ("NumberOutputValueCaps", w.USHORT),
            ("NumberOutputDataIndices", w.USHORT),
            ("NumberFeatureButtonCaps", w.USHORT),
            ("NumberFeatureValueCaps", w.USHORT),
            ("NumberFeatureDataIndices", w.USHORT),
        ]

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", w.DWORD),
            ("OffsetHigh", w.DWORD),
            ("hEvent", w.HANDLE),
        ]

    _setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
    _hid = ctypes.WinDLL("hid", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), w.LPCWSTR, w.HWND, w.DWORD]
    _setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
    _setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
    _setupapi.SetupDiDestroyDeviceInfoList.restype = w.BOOL
    _setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(GUID),
        w.DWORD,
        ctypes.POINTER(SP_DEVICE_INTERFACE_DATA),
    ]
    _setupapi.SetupDiEnumDeviceInterfaces.restype = w.BOOL
    _setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(SP_DEVICE_INTERFACE_DATA),
        ctypes.c_void_p,
        w.DWORD,
        ctypes.POINTER(w.DWORD),
        ctypes.c_void_p,
    ]
    _setupapi.SetupDiGetDeviceInterfaceDetailW.restype = w.BOOL

    _hid.HidD_GetHidGuid.argtypes = [ctypes.POINTER(GUID)]
    _hid.HidD_GetHidGuid.restype = None
    _hid.HidD_GetAttributes.argtypes = [w.HANDLE, ctypes.POINTER(HIDD_ATTRIBUTES)]
    _hid.HidD_GetAttributes.restype = w.BOOLEAN
    _hid.HidD_GetPreparsedData.argtypes = [w.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
    _hid.HidD_GetPreparsedData.restype = w.BOOLEAN
    _hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
    _hid.HidD_FreePreparsedData.restype = w.BOOLEAN
    _hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDP_CAPS)]
    _hid.HidP_GetCaps.restype = ctypes.c_long
    _hid.HidD_GetProductString.argtypes = [w.HANDLE, ctypes.c_void_p, w.ULONG]
    _hid.HidD_GetProductString.restype = w.BOOLEAN
    _hid.HidD_SetNumInputBuffers.argtypes = [w.HANDLE, w.ULONG]
    _hid.HidD_SetNumInputBuffers.restype = w.BOOLEAN

    _kernel32.CreateFileW.argtypes = [
        w.LPCWSTR,
        w.DWORD,
        w.DWORD,
        ctypes.c_void_p,
        w.DWORD,
        w.DWORD,
        w.HANDLE,
    ]
    _kernel32.CreateFileW.restype = w.HANDLE
    _kernel32.CloseHandle.argtypes = [w.HANDLE]
    _kernel32.CloseHandle.restype = w.BOOL
    _kernel32.CreateEventW.argtypes = [ctypes.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
    _kernel32.CreateEventW.restype = w.HANDLE
    _kernel32.ReadFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
    _kernel32.ReadFile.restype = w.BOOL
    _kernel32.WriteFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
    _kernel32.WriteFile.restype = w.BOOL
    _kernel32.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    _kernel32.WaitForSingleObject.restype = w.DWORD
    _kernel32.GetOverlappedResult.argtypes = [
        w.HANDLE,
        ctypes.POINTER(OVERLAPPED),
        ctypes.POINTER(w.DWORD),
        w.BOOL,
    ]
    _kernel32.GetOverlappedResult.restype = w.BOOL
    _kernel32.CancelIoEx.argtypes = [w.HANDLE, ctypes.c_void_p]
    _kernel32.CancelIoEx.restype = w.BOOL


def _probe_hid_metadata(path: str) -> tuple[dict, str] | None:
    """
    Open a HID interface with dwDesiredAccess=0 (metadata only, never RW) and
    verify VID/PID and MI_02 collection constraints.
    """
    if sys.platform != "win32":
        return None

    h = _kernel32.CreateFileW(
        path,
        0,  # dwDesiredAccess = 0: metadata-only open; NEVER open RW on 0xFFEF!
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if not h or h == INVALID_HANDLE_VALUE:
        return None

    try:
        attrs = HIDD_ATTRIBUTES()
        attrs.Size = ctypes.sizeof(attrs)
        if not _hid.HidD_GetAttributes(h, ctypes.byref(attrs)):
            return None

        key = (int(attrs.VendorID), int(attrs.ProductID))
        if key not in SUPPORTED_DEVICES:
            return None

        pp = ctypes.c_void_p()
        if not _hid.HidD_GetPreparsedData(h, ctypes.byref(pp)) or not pp.value:
            return None

        caps = HIDP_CAPS()
        try:
            status = _hid.HidP_GetCaps(pp, ctypes.byref(caps))
            if status < 0:
                return None
        finally:
            _hid.HidD_FreePreparsedData(pp)

        usage_page = int(caps.UsagePage)
        usage = int(caps.Usage)
        in_len = int(caps.InputReportByteLength)
        out_len = int(caps.OutputReportByteLength)
        if not is_allowed_command_caps(usage_page, usage, in_len, out_len):
            return None

        fallback_name, is_wireless = SUPPORTED_DEVICES[key]
        product_name = fallback_name
        str_buf = ctypes.create_unicode_buffer(128)
        if _hid.HidD_GetProductString(h, str_buf, ctypes.sizeof(str_buf)):
            candidate = str_buf.value.strip()
            if candidate:
                product_name = candidate

        vid, pid = key
        info = {
            "id": make_device_id(vid, pid, usage_page, path),
            "vendorId": vid,
            "productId": pid,
            "productName": product_name,
            "usagePage": usage_page,
            "usage": usage,
            "inputReportBytes": in_len - 1,
            "outputReportBytes": out_len - 1,
            "isWireless": is_wireless,
        }
        return info, path
    finally:
        _kernel32.CloseHandle(h)


def enumerate_valkyrie_devices() -> list[tuple[dict, str]]:
    """Enumerate all valid Valkyrie MI_02 command interfaces cleanly."""
    if sys.platform != "win32":
        return []

    hid_guid = GUID()
    _hid.HidD_GetHidGuid(ctypes.byref(hid_guid))
    hdev = _setupapi.SetupDiGetClassDevsW(
        ctypes.byref(hid_guid),
        None,
        None,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
    )
    if not hdev or hdev == INVALID_HANDLE_VALUE:
        return []

    results: list[tuple[dict, str]] = []
    try:
        idx = 0
        did = SP_DEVICE_INTERFACE_DATA()
        did.cbSize = ctypes.sizeof(did)
        detail_cb_size = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6

        while _setupapi.SetupDiEnumDeviceInterfaces(hdev, None, ctypes.byref(hid_guid), idx, ctypes.byref(did)):
            idx += 1
            req = w.DWORD(0)
            _setupapi.SetupDiGetDeviceInterfaceDetailW(hdev, ctypes.byref(did), None, 0, ctypes.byref(req), None)
            if req.value < 8:
                continue

            buf = ctypes.create_string_buffer(req.value)
            ctypes.cast(buf, ctypes.POINTER(w.DWORD))[0] = detail_cb_size
            if not _setupapi.SetupDiGetDeviceInterfaceDetailW(
                hdev, ctypes.byref(did), buf, req, None, None
            ):
                continue

            path = ctypes.wstring_at(ctypes.addressof(buf) + 4)
            low = path.lower()
            if "vid_248a" not in low and "vid_249a" not in low:
                continue

            item = _probe_hid_metadata(path)
            if item is not None:
                results.append(item)
    finally:
        _setupapi.SetupDiDestroyDeviceInfoList(hdev)

    results.sort(
        key=lambda item: (
            0 if item[0]["usagePage"] == 0xFF01 else 1,
            1 if item[0]["isWireless"] else 0,
            item[0]["id"],
        )
    )
    return results


class EventBroadcaster:
    """Thread-safe pub/sub fan-out for GET /api/events NDJSON streams."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: set[queue.Queue[str]] = set()

    def subscribe(self) -> queue.Queue[str]:
        q: queue.Queue[str] = queue.Queue(maxsize=MAX_EVENT_QUEUE_SIZE)
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue[str]) -> None:
        with self._lock:
            self._subscribers.discard(q)

    def publish(self, event_obj: dict) -> None:
        line = json.dumps(event_obj, separators=(",", ":")) + "\n"
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(line)
            except queue.Full:
                # Drop oldest message or evict stalled subscriber on disconnect
                if event_obj.get("type") == "disconnect":
                    try:
                        q.get_nowait()
                        q.put_nowait(line)
                    except queue.Empty:
                        pass


class DeviceSession:
    """Manages one open overlapped MI_02 HID handle and its reader thread."""

    def __init__(
        self,
        handle: int,
        device_info: dict,
        broadcaster: EventBroadcaster,
        on_unplug,
    ) -> None:
        self._handle: int | None = handle
        self.device_info = device_info
        self._broadcaster = broadcaster
        self._on_unplug = on_unplug
        self._stop_event = threading.Event()
        self._write_lock = threading.Lock()
        self._handle_lock = threading.Lock()
        self._closed = False
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

    @property
    def is_open(self) -> bool:
        return not self._closed and self._handle is not None

    def _close_handle_locked(self) -> None:
        if self._handle is not None:
            _kernel32.CloseHandle(self._handle)
            self._handle = None

    def write_report(self, payload32: bytes) -> tuple[bool, str | None]:
        """Write [0x00, ...32 bytes...] using a dedicated OVERLAPPED+Event."""
        if len(payload32) != 32:
            return False, "INVALID_PAYLOAD"
        if not is_allowed_opcode(payload32[0]):
            return False, "STALL_GUARD_BLOCKED"

        packet = bytes([0x00]) + payload32
        wbuf = (ctypes.c_ubyte * HID_REPORT_BYTE_LENGTH).from_buffer_copy(packet)

        with self._write_lock:
            if self._closed or self._handle is None:
                return False, "DEVICE_NOT_OPEN"

            h = self._handle
            h_event = _kernel32.CreateEventW(None, True, False, None)
            if not h_event:
                return False, "WRITE_FAILED"

            try:
                ov_w = OVERLAPPED()
                ov_w.hEvent = h_event
                written = w.DWORD(0)

                ok = _kernel32.WriteFile(
                    h, wbuf, HID_REPORT_BYTE_LENGTH, ctypes.byref(written), ctypes.byref(ov_w)
                )
                if ok:
                    return written.value == HID_REPORT_BYTE_LENGTH, None if written.value == HID_REPORT_BYTE_LENGTH else "WRITE_FAILED"

                err = ctypes.get_last_error()
                if err != ERROR_IO_PENDING:
                    return False, "WRITE_FAILED"

                wait_rc = _kernel32.WaitForSingleObject(h_event, 2000)
                if wait_rc == WAIT_OBJECT_0:
                    if _kernel32.GetOverlappedResult(h, ctypes.byref(ov_w), ctypes.byref(written), False):
                        if written.value == HID_REPORT_BYTE_LENGTH:
                            return True, None
                    return False, "WRITE_FAILED"

                _kernel32.CancelIoEx(h, ctypes.byref(ov_w))
                _kernel32.GetOverlappedResult(h, ctypes.byref(ov_w), ctypes.byref(written), True)
                return False, "WRITE_FAILED"
            finally:
                _kernel32.CloseHandle(h_event)

    def close(self, emit_disconnect: bool = True) -> None:
        with self._handle_lock:
            if self._closed:
                return
            self._closed = True
            self._stop_event.set()
            h = self._handle

        if h is not None:
            _kernel32.CancelIoEx(h, None)

        if threading.current_thread() is not self._reader_thread:
            self._reader_thread.join(timeout=2.0)

        with self._write_lock:
            with self._handle_lock:
                self._close_handle_locked()

        if emit_disconnect:
            self._broadcaster.publish({"type": "disconnect"})

    def _reader_loop(self) -> None:
        rbuf = ctypes.create_string_buffer(HID_REPORT_BYTE_LENGTH)
        h_event = _kernel32.CreateEventW(None, True, False, None)
        if not h_event:
            return

        unexpected_disconnect = False
        try:
            while not self._stop_event.is_set():
                with self._handle_lock:
                    h = self._handle
                if h is None or self._closed:
                    break

                _kernel32.ResetEvent(h_event)
                ov_r = OVERLAPPED()
                ov_r.hEvent = h_event
                rbytes = w.DWORD(0)

                ok = _kernel32.ReadFile(
                    h, rbuf, HID_REPORT_BYTE_LENGTH, ctypes.byref(rbytes), ctypes.byref(ov_r)
                )
                if not ok:
                    err = ctypes.get_last_error()
                    if err == ERROR_IO_PENDING:
                        completed = False
                        while not self._stop_event.is_set():
                            wait_rc = _kernel32.WaitForSingleObject(h_event, 100)
                            if wait_rc == WAIT_OBJECT_0:
                                if _kernel32.GetOverlappedResult(h, ctypes.byref(ov_r), ctypes.byref(rbytes), False):
                                    completed = True
                                else:
                                    gerr = ctypes.get_last_error()
                                    if gerr != ERROR_OPERATION_ABORTED and not self._stop_event.is_set():
                                        unexpected_disconnect = True
                                break
                            if wait_rc != WAIT_TIMEOUT:
                                if not self._stop_event.is_set():
                                    unexpected_disconnect = True
                                break

                        if self._stop_event.is_set() and not completed:
                            _kernel32.CancelIoEx(h, ctypes.byref(ov_r))
                            _kernel32.GetOverlappedResult(h, ctypes.byref(ov_r), ctypes.byref(rbytes), True)
                            break

                        if unexpected_disconnect:
                            break
                        if not completed:
                            continue
                    elif err == ERROR_OPERATION_ABORTED or self._stop_event.is_set():
                        break
                    else:
                        unexpected_disconnect = True
                        break

                count = int(rbytes.value)
                if count <= 0:
                    continue
                raw = bytes(rbuf.raw[:count])
                if count == HID_REPORT_BYTE_LENGTH and raw[0] == 0x00:
                    report_id = 0
                    payload = list(raw[1:33])
                elif count == HID_REPORT_BYTE_LENGTH:
                    report_id = raw[0]
                    payload = list(raw[1:33])
                else:
                    report_id = 0
                    payload = list(raw[:32])
                    if len(payload) < 32:
                        payload.extend([0] * (32 - len(payload)))

                self._broadcaster.publish(
                    {
                        "type": "inputreport",
                        "reportId": report_id,
                        "data": payload,
                    }
                )
        finally:
            _kernel32.CloseHandle(h_event)

        if unexpected_disconnect:
            with self._handle_lock:
                self._closed = True
            with self._write_lock:
                with self._handle_lock:
                    self._close_handle_locked()
            self._on_unplug(self)
            self._broadcaster.publish({"type": "disconnect"})


class DeviceManager:
    """Coordinates device enumeration, active session lifecycle, and events."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.broadcaster = EventBroadcaster()
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._session: DeviceSession | None = None

    def list_devices(self) -> list[dict]:
        return [info for info, _ in enumerate_valkyrie_devices()]

    def open_device(self, device_id: str | None) -> tuple[dict | None, int, str | None]:
        candidates = enumerate_valkyrie_devices()
        chosen: tuple[dict, str] | None = None
        if device_id:
            for info, path in candidates:
                if info["id"] == device_id:
                    chosen = (info, path)
                    break
        elif candidates:
            chosen = candidates[0]

        if chosen is None:
            return None, 404, "NO_COMMAND_INTERFACE"

        info, path = chosen
        # Defense-in-depth re-check before ever requesting GENERIC_READ|GENERIC_WRITE
        if not is_allowed_command_caps(
            info["usagePage"],
            info["usage"],
            info["inputReportBytes"] + 1,
            info["outputReportBytes"] + 1,
        ):
            return None, 404, "NO_COMMAND_INTERFACE"

        with self._lock:
            old_session = self._session
            self._session = None

        if old_session is not None:
            old_session.close(emit_disconnect=True)

        if sys.platform != "win32":
            return None, 404, "NO_COMMAND_INTERFACE"

        h = _kernel32.CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )
        if not h or h == INVALID_HANDLE_VALUE:
            return None, 404, "NO_COMMAND_INTERFACE"

        _hid.HidD_SetNumInputBuffers(h, 64)
        session = DeviceSession(h, info, self.broadcaster, self._on_session_unplugged)
        with self._lock:
            self._session = session
        return info, 200, None

    def _on_session_unplugged(self, session: DeviceSession) -> None:
        with self._lock:
            if self._session is session:
                self._session = None

    def close_device(self) -> None:
        with self._lock:
            session = self._session
            self._session = None
        if session is not None:
            session.close(emit_disconnect=True)

    def send_report(self, payload32: bytes) -> tuple[bool, int, str | None]:
        with self._lock:
            session = self._session
        if session is None or not session.is_open:
            return False, 409, "DEVICE_NOT_OPEN"
        ok, err = session.write_report(payload32)
        if not ok:
            if err == "STALL_GUARD_BLOCKED":
                return False, 403, err
            if err == "DEVICE_NOT_OPEN":
                return False, 409, err
            self.close_device()
            return False, 502, err or "WRITE_FAILED"
        return True, 200, None

    def shutdown(self) -> None:
        self.stop_event.set()
        with self._lock:
            had_session = self._session is not None
        self.close_device()
        if not had_session:
            self.broadcaster.publish({"type": "disconnect"})


class HelperRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"{SERVICE_NAME}/{SERVICE_VERSION}"

    def log_message(self, format: str, *args) -> None:
        return

    def _send_cors_pna_headers(self) -> None:
        origin = validate_origin(self.headers.get("Origin"))
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Access-Control-Request-Private-Network",
        )
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Vary", "Origin")

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._send_cors_pna_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _read_json_body(self) -> tuple[dict | None, str | None]:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            return {}, None
        try:
            length = int(raw_len.strip())
        except ValueError:
            return None, "INVALID_CONTENT_LENGTH"
        if length < 0 or length > MAX_JSON_BODY_BYTES:
            return None, "PAYLOAD_TOO_LARGE"
        if length == 0:
            return {}, None
        raw = self.rfile.read(length)
        if len(raw) != length:
            return None, "INCOMPLETE_BODY"
        if not raw.strip():
            return {}, None
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "INVALID_JSON"
        if not isinstance(parsed, dict):
            return None, "INVALID_JSON"
        return parsed, None

    def _route_path(self) -> str:
        return urllib.parse.urlsplit(self.path).path

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_cors_pna_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        manager: DeviceManager = self.server.manager  # type: ignore[attr-defined]
        path = self._route_path()

        if path == "/api/health":
            self._send_json(
                200,
                {
                    "ok": True,
                    "service": SERVICE_NAME,
                    "version": SERVICE_VERSION,
                    "port": manager.port,
                },
            )
            return

        if path == "/api/devices":
            devices = manager.list_devices()
            self._send_json(200, {"ok": True, "devices": devices})
            return

        if path == "/api/events":
            self._handle_events_stream(manager)
            return

        self._send_json(404, {"ok": False, "error": "NOT_FOUND"})

    def _method_not_allowed(self) -> None:
        self._send_json(405, {"ok": False, "error": "METHOD_NOT_ALLOWED"})

    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed

    def do_POST(self) -> None:
        manager: DeviceManager = self.server.manager  # type: ignore[attr-defined]
        path = self._route_path()

        if path == "/api/open":
            body, err = self._read_json_body()
            if err is not None or body is None:
                self._send_json(400, {"ok": False, "error": err or "INVALID_JSON"})
                return

            device_id = body.get("deviceId")
            if device_id is not None and not isinstance(device_id, str):
                self._send_json(404, {"ok": False, "error": "NO_COMMAND_INTERFACE"})
                return

            device, status, open_err = manager.open_device(device_id)
            if device is None:
                self._send_json(status, {"ok": False, "error": open_err or "NO_COMMAND_INTERFACE"})
                return
            self._send_json(200, {"ok": True, "device": device})
            return

        if path == "/api/close":
            _, err = self._read_json_body()
            if err is not None:
                self._send_json(400, {"ok": False, "error": err})
                return
            manager.close_device()
            self._send_json(200, {"ok": True})
            return

        if path == "/api/report":
            body, err = self._read_json_body()
            if err is not None or body is None:
                self._send_json(400, {"ok": False, "error": err or "INVALID_JSON"})
                return

            report_id = body.get("reportId", 0)
            if isinstance(report_id, bool) or not isinstance(report_id, int) or report_id != 0:
                self._send_json(403, {"ok": False, "error": "STALL_GUARD_BLOCKED"})
                return

            data = body.get("data")
            if not isinstance(data, list) or not (1 <= len(data) <= 32):
                self._send_json(400, {"ok": False, "error": "INVALID_PAYLOAD"})
                return

            for item in data:
                if isinstance(item, bool) or not isinstance(item, int) or not (0 <= item <= 255):
                    self._send_json(400, {"ok": False, "error": "INVALID_PAYLOAD"})
                    return

            opcode = data[0]
            if not is_allowed_opcode(opcode):
                self._send_json(403, {"ok": False, "error": "STALL_GUARD_BLOCKED"})
                return

            padded = bytes(data) + bytes(32 - len(data))
            ok, status, send_err = manager.send_report(padded)
            if not ok:
                self._send_json(status, {"ok": False, "error": send_err or "WRITE_FAILED"})
                return

            self._send_json(200, {"ok": True})
            return

        self._send_json(404, {"ok": False, "error": "NOT_FOUND"})

    def _method_not_allowed(self) -> None:
        self._send_json(405, {"ok": False, "error": "METHOD_NOT_ALLOWED"})

    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed

    def _handle_events_stream(self, manager: DeviceManager) -> None:
        self.close_connection = True
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        self.send_response(200)
        self._send_cors_pna_headers()
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        q = manager.broadcaster.subscribe()
        try:
            self.wfile.write(b'{"type":"ready"}\n')
            self.wfile.flush()
            last_activity = time.monotonic()

            while not manager.stop_event.is_set():
                try:
                    line = q.get(timeout=1.0)
                except queue.Empty:
                    now = time.monotonic()
                    if now - last_activity >= PING_INTERVAL_SECONDS:
                        self.wfile.write(b'{"type":"ping"}\n')
                        self.wfile.flush()
                        last_activity = now
                    continue

                self.wfile.write(line.encode("utf-8"))
                self.wfile.flush()
                last_activity = time.monotonic()
                if '"type":"disconnect"' in line:
                    break
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        finally:
            manager.broadcaster.unsubscribe(q)


class LocalHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    address_family = socket.AF_INET

    def __init__(self, server_address: tuple[str, int], handler_cls, manager: DeviceManager) -> None:
        self.manager = manager
        super().__init__(server_address, handler_cls)

    def server_bind(self) -> None:
        if sys.platform == "win32":
            so_exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
            if so_exclusive is not None:
                self.socket.setsockopt(socket.SOL_SOCKET, so_exclusive, 1)
        super().server_bind()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="valkyrie_helper.py",
        description="Valkyrie Local Companion Helper (localhost-only HTTP+NDJSON HID bridge)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Loopback TCP port to listen on (default: {DEFAULT_PORT})",
    )
    args = parser.parse_args(argv)
    if not (1 <= args.port <= 65535):
        parser.error("--port must be between 1 and 65535")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if sys.platform != "win32":
        print("valkyrie_helper.py requires Windows (Win32 HID / SetupAPI).", file=sys.stderr)
        return 1

    manager = DeviceManager(args.port)
    # Strictly bind 127.0.0.1 — never 0.0.0.0.
    server = LocalHTTPServer(("127.0.0.1", args.port), HelperRequestHandler, manager)

    def _request_stop(_signum=None, _frame=None) -> None:
        manager.stop_event.set()

    signal.signal(signal.SIGINT, _request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _request_stop)

    serve_thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.25}, daemon=True)
    serve_thread.start()
    print(f"{SERVICE_NAME} listening on http://127.0.0.1:{args.port}", flush=True)

    try:
        while not manager.stop_event.is_set():
            time.sleep(0.2)
    except KeyboardInterrupt:
        manager.stop_event.set()
    finally:
        manager.shutdown()
        server.shutdown()
        server.server_close()
        serve_thread.join(timeout=2.0)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
