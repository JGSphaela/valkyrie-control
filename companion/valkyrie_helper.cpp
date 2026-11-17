/*
 * Valkyrie Local Companion Helper (Single-File Dependency-Free Win32/Winsock C++14)
 *
 * Exposes a localhost-only (127.0.0.1) HTTP/1.1 + NDJSON bridge for static web
 * browsers (Chrome/Edge 157+ on Windows) to communicate with the Valkyrie
 * VK M3 / M3 Lite MI_02 32-byte HID configuration collection without modifying
 * Windows USB drivers.
 *
 * Security invariants:
 * 1. Binds strictly to 127.0.0.1 (never 0.0.0.0).
 * 2. Enumerates and opens ONLY supported Valkyrie VID/PID devices:
 *    (0x248A: 0x5C2E, 0x5D2E, 0x5E2E, 0x5C2F) and (0x249A: 0x5C2F).
 * 3. Enumerates attributes/caps with dwDesiredAccess=0 first; opens RW ONLY on
 *    MI_02 collections ((0xFF01/0x0010) or (0x0001/0x0000)) with 33-byte reports,
 *    strictly excluding 0xFFEF (OTA/DFU).
 * 4. Enforces outbound opcode allowlist (0x02..0x0F, 0x10..0x17, 0x20) and
 *    reportId == 0 BEFORE WriteFile (rejects others with HTTP 403).
 * 5. Uses FILE_FLAG_OVERLAPPED with a dedicated background reader thread and
 *    separate OVERLAPPED+Event for concurrent WriteFile.
 *
 * Build (MSVC x64):
 *   cl.exe /O2 /EHsc /MT /W3 /Fe:dist/valkyrie-helper.exe companion/valkyrie_helper.cpp hid.lib setupapi.lib ws2_32.lib user32.lib
 */

#ifndef _WIN32
#error "valkyrie_helper.cpp targets Windows (Win32 HID + Winsock2)."
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <setupapi.h>
extern "C" {
#include <hidsdi.h>
#include <hidpi.h>
}

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

const char* SERVICE_NAME = "valkyrie-helper";
const char* SERVICE_VERSION = "1.0.0";
const int DEFAULT_PORT = 19480;
const uint16_t FORBIDDEN_OTA_USAGE_PAGE = 0xFFEF;
const uint16_t HID_REPORT_BYTE_LENGTH = 33; // 1-byte Report ID + 32-byte payload
const size_t MAX_HEADER_BYTES = 64 * 1024;
const size_t MAX_BODY_BYTES = 1024 * 1024;
const size_t MAX_EVENT_QUEUE_SIZE = 1024;
const int PING_INTERVAL_SECONDS = 15;

struct SupportedSpec {
    uint16_t vid;
    uint16_t pid;
    const char* fallback_name;
    bool is_wireless;
};

const SupportedSpec SUPPORTED_SPECS[] = {
    {0x248A, 0x5C2E, "Valkyrie VK M3 / M3 Lite (USB)", false},
    {0x248A, 0x5D2E, "Valkyrie VK M3 Lite (USB)", false},
    {0x248A, 0x5E2E, "Valkyrie VK M3 Pro (USB)", false},
    {0x248A, 0x5C2F, "Valkyrie VK M3 Wireless Dongle", true},
    {0x249A, 0x5C2F, "Valkyrie VK M3 Wireless Dongle", true},
};

const SupportedSpec* find_supported_spec(uint16_t vid, uint16_t pid) {
    for (size_t i = 0; i < sizeof(SUPPORTED_SPECS) / sizeof(SUPPORTED_SPECS[0]); ++i) {
        if (SUPPORTED_SPECS[i].vid == vid && SUPPORTED_SPECS[i].pid == pid) {
            return &SUPPORTED_SPECS[i];
        }
    }
    return nullptr;
}

bool is_allowed_opcode(uint8_t op) {
    return (op >= 0x02 && op <= 0x0F) || (op >= 0x10 && op <= 0x17) || (op == 0x20);
}

bool is_allowed_command_caps(uint16_t usage_page, uint16_t usage, uint16_t in_len, uint16_t out_len) {
    if (usage_page == FORBIDDEN_OTA_USAGE_PAGE) {
        return false;
    }
    if (in_len != HID_REPORT_BYTE_LENGTH || out_len != HID_REPORT_BYTE_LENGTH) {
        return false;
    }
    return (usage_page == 0xFF01 && usage == 0x0010) || (usage_page == 0x0001 && usage == 0x0000);
}

std::string ascii_lower(const std::string& s) {
    std::string out = s;
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(out[i]);
        if (c >= 'A' && c <= 'Z') {
            out[i] = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

std::string trim_whitespace(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n')) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n')) {
        --end;
    }
    return s.substr(start, end - start);
}

std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) {
        return "";
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return "";
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &out[0], needed, nullptr, nullptr);
    return out;
}

std::string make_device_id(uint16_t vid, uint16_t pid, uint16_t usage_page, const std::wstring& path_w) {
    std::string utf8 = ascii_lower(wide_to_utf8(path_w));
    uint64_t h = 0xCBF29CE484222325ULL;
    const uint64_t prime = 0x100000001B3ULL;
    for (size_t i = 0; i < utf8.size(); ++i) {
        h ^= static_cast<uint8_t>(utf8[i]);
        h *= prime;
    }
    char buf[64];
    std::snprintf(
        buf,
        sizeof(buf),
        "vk-%04x-%04x-%04x-%016llx",
        static_cast<unsigned int>(vid),
        static_cast<unsigned int>(pid),
        static_cast<unsigned int>(usage_page),
        static_cast<unsigned long long>(h));
    return std::string(buf);
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    std::snprintf(esc, sizeof(esc), "\\u%04x", static_cast<unsigned int>(c));
                    out += esc;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

std::string validate_origin(const std::string& raw) {
    std::string cleaned = trim_whitespace(raw);
    if (cleaned.empty()) {
        return "";
    }
    for (size_t i = 0; i < cleaned.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(cleaned[i]);
        if (c == '\r' || c == '\n' || c == '\0' || c == ' ' || c == '\t') {
            return "";
        }
    }
    std::string low = ascii_lower(cleaned);
    if ((low.compare(0, 7, "http://") == 0 && cleaned.size() > 7) ||
        (low.compare(0, 8, "https://") == 0 && cleaned.size() > 8)) {
        return cleaned;
    }
    return "";
}

// ---------------------------------------------------------------------------
// Minimal C++14 Recursive-Descent JSON Parser
// ---------------------------------------------------------------------------

struct JsonValue {
    enum Type { JNull, JBool, JNumber, JString, JArray, JObject };

    Type type;
    bool bool_val;
    bool is_int;
    int64_t int_val;
    double num_val;
    std::string str_val;
    std::vector<JsonValue> arr_val;
    std::vector<std::pair<std::string, JsonValue> > obj_val;

    JsonValue() : type(JNull), bool_val(false), is_int(false), int_val(0), num_val(0.0) {}

    const JsonValue* get(const std::string& key) const {
        if (type != JObject) {
            return nullptr;
        }
        // Return last matching key if duplicated
        for (size_t i = obj_val.size(); i > 0; --i) {
            if (obj_val[i - 1].first == key) {
                return &obj_val[i - 1].second;
            }
        }
        return nullptr;
    }
};

class JsonParser {
public:
    explicit JsonParser(const std::string& src) : src_(src), pos_(0) {}

    bool parse(JsonValue& out) {
        skip_ws();
        if (!parse_value(out, 0)) {
            return false;
        }
        skip_ws();
        return pos_ == src_.size();
    }

private:
    const std::string& src_;
    size_t pos_;

    void skip_ws() {
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    static void append_utf8(std::string& out, uint32_t cp) {
        if (cp <= 0x7F) {
            out += static_cast<char>(cp);
        } else if (cp <= 0x7FF) {
            out += static_cast<char>(0xC0 | ((cp >> 6) & 0x1F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp <= 0xFFFF) {
            out += static_cast<char>(0xE0 | ((cp >> 12) & 0x0F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp <= 0x10FFFF) {
            out += static_cast<char>(0xF0 | ((cp >> 18) & 0x07));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    bool parse_hex4(uint32_t& val) {
        if (pos_ + 4 > src_.size()) {
            return false;
        }
        val = 0;
        for (int i = 0; i < 4; ++i) {
            char c = src_[pos_++];
            val <<= 4;
            if (c >= '0' && c <= '9') {
                val |= static_cast<uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                val |= static_cast<uint32_t>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                val |= static_cast<uint32_t>(c - 'A' + 10);
            } else {
                return false;
            }
        }
        return true;
    }

    bool parse_string(std::string& out) {
        if (pos_ >= src_.size() || src_[pos_] != '"') {
            return false;
        }
        ++pos_;
        out.clear();
        while (pos_ < src_.size()) {
            unsigned char c = static_cast<unsigned char>(src_[pos_++]);
            if (c == '"') {
                return true;
            }
            if (c < 0x20) {
                return false;
            }
            if (c == '\\') {
                if (pos_ >= src_.size()) {
                    return false;
                }
                char esc = src_[pos_++];
                switch (esc) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        uint32_t cp = 0;
                        if (!parse_hex4(cp)) {
                            return false;
                        }
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (pos_ + 2 <= src_.size() && src_[pos_] == '\\' && src_[pos_ + 1] == 'u') {
                                pos_ += 2;
                                uint32_t low = 0;
                                if (!parse_hex4(low) || low < 0xDC00 || low > 0xDFFF) {
                                    return false;
                                }
                                cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
                            } else {
                                return false;
                            }
                        }
                        append_utf8(out, cp);
                        break;
                    }
                    default:
                        return false;
                }
            } else {
                out += static_cast<char>(c);
            }
        }
        return false;
    }

    bool parse_number(JsonValue& out) {
        size_t start = pos_;
        if (src_[pos_] == '-') {
            ++pos_;
        }
        if (pos_ >= src_.size()) {
            return false;
        }
        if (src_[pos_] == '0') {
            ++pos_;
        } else if (src_[pos_] >= '1' && src_[pos_] <= '9') {
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') {
                ++pos_;
            }
        } else {
            return false;
        }

        bool has_frac_or_exp = false;
        if (pos_ < src_.size() && src_[pos_] == '.') {
            has_frac_or_exp = true;
            ++pos_;
            if (pos_ >= src_.size() || src_[pos_] < '0' || src_[pos_] > '9') {
                return false;
            }
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') {
                ++pos_;
            }
        }
        if (pos_ < src_.size() && (src_[pos_] == 'e' || src_[pos_] == 'E')) {
            has_frac_or_exp = true;
            ++pos_;
            if (pos_ < src_.size() && (src_[pos_] == '+' || src_[pos_] == '-')) {
                ++pos_;
            }
            if (pos_ >= src_.size() || src_[pos_] < '0' || src_[pos_] > '9') {
                return false;
            }
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') {
                ++pos_;
            }
        }

        std::string token = src_.substr(start, pos_ - start);
        out.type = JsonValue::JNumber;
        if (!has_frac_or_exp) {
            char* endp = nullptr;
            errno = 0;
            long long iv = std::strtoll(token.c_str(), &endp, 10);
            if (errno == 0 && endp == token.c_str() + token.size()) {
                out.is_int = true;
                out.int_val = static_cast<int64_t>(iv);
                out.num_val = static_cast<double>(iv);
                return true;
            }
        }

        char* endp = nullptr;
        errno = 0;
        double dv = std::strtod(token.c_str(), &endp);
        if (errno != 0 || endp != token.c_str() + token.size()) {
            return false;
        }
        out.is_int = false;
        out.int_val = 0;
        out.num_val = dv;
        return true;
    }

    bool parse_value(JsonValue& out, int depth) {
        if (depth > 64) {
            return false;
        }
        skip_ws();
        if (pos_ >= src_.size()) {
            return false;
        }
        char c = src_[pos_];
        if (c == 'n') {
            if (src_.compare(pos_, 4, "null") == 0) {
                pos_ += 4;
                out = JsonValue();
                out.type = JsonValue::JNull;
                return true;
            }
            return false;
        }
        if (c == 't') {
            if (src_.compare(pos_, 4, "true") == 0) {
                pos_ += 4;
                out = JsonValue();
                out.type = JsonValue::JBool;
                out.bool_val = true;
                return true;
            }
            return false;
        }
        if (c == 'f') {
            if (src_.compare(pos_, 5, "false") == 0) {
                pos_ += 5;
                out = JsonValue();
                out.type = JsonValue::JBool;
                out.bool_val = false;
                return true;
            }
            return false;
        }
        if (c == '"') {
            out = JsonValue();
            out.type = JsonValue::JString;
            return parse_string(out.str_val);
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            out = JsonValue();
            return parse_number(out);
        }
        if (c == '[') {
            ++pos_;
            out = JsonValue();
            out.type = JsonValue::JArray;
            skip_ws();
            if (pos_ < src_.size() && src_[pos_] == ']') {
                ++pos_;
                return true;
            }
            while (true) {
                JsonValue elem;
                if (!parse_value(elem, depth + 1)) {
                    return false;
                }
                out.arr_val.push_back(std::move(elem));
                skip_ws();
                if (pos_ >= src_.size()) {
                    return false;
                }
                if (src_[pos_] == ']') {
                    ++pos_;
                    return true;
                }
                if (src_[pos_] != ',') {
                    return false;
                }
                ++pos_;
            }
        }
        if (c == '{') {
            ++pos_;
            out = JsonValue();
            out.type = JsonValue::JObject;
            skip_ws();
            if (pos_ < src_.size() && src_[pos_] == '}') {
                ++pos_;
                return true;
            }
            while (true) {
                skip_ws();
                std::string key;
                if (!parse_string(key)) {
                    return false;
                }
                skip_ws();
                if (pos_ >= src_.size() || src_[pos_] != ':') {
                    return false;
                }
                ++pos_;
                JsonValue val;
                if (!parse_value(val, depth + 1)) {
                    return false;
                }
                out.obj_val.push_back(std::make_pair(std::move(key), std::move(val)));
                skip_ws();
                if (pos_ >= src_.size()) {
                    return false;
                }
                if (src_[pos_] == '}') {
                    ++pos_;
                    return true;
                }
                if (src_[pos_] != ',') {
                    return false;
                }
                ++pos_;
            }
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// HID Enumeration & Device Model
// ---------------------------------------------------------------------------

struct DeviceInfo {
    std::string id;
    uint16_t vendor_id;
    uint16_t product_id;
    std::string product_name;
    uint16_t usage_page;
    uint16_t usage;
    uint16_t input_report_bytes;
    uint16_t output_report_bytes;
    bool is_wireless;
    std::wstring path_w;

    std::string to_json() const {
        std::ostringstream oss;
        oss << "{\"id\":\"" << json_escape(id) << "\""
            << ",\"vendorId\":" << vendor_id
            << ",\"productId\":" << product_id
            << ",\"productName\":\"" << json_escape(product_name) << "\""
            << ",\"usagePage\":" << usage_page
            << ",\"usage\":" << usage
            << ",\"inputReportBytes\":" << input_report_bytes
            << ",\"outputReportBytes\":" << output_report_bytes
            << ",\"isWireless\":" << (is_wireless ? "true" : "false")
            << "}";
        return oss.str();
    }
};

bool probe_hid_metadata(const std::wstring& path_w, DeviceInfo& out) {
    // Open with dwDesiredAccess = 0 (metadata-only; NEVER open RW on 0xFFEF!).
    HANDLE h = CreateFileW(
        path_w.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool matched = false;
    do {
        HIDD_ATTRIBUTES attrs;
        std::memset(&attrs, 0, sizeof(attrs));
        attrs.Size = sizeof(attrs);
        if (!HidD_GetAttributes(h, &attrs)) {
            break;
        }

        const SupportedSpec* spec = find_supported_spec(attrs.VendorID, attrs.ProductID);
        if (!spec) {
            break;
        }

        PHIDP_PREPARSED_DATA pp = nullptr;
        if (!HidD_GetPreparsedData(h, &pp) || pp == nullptr) {
            break;
        }

        HIDP_CAPS caps;
        std::memset(&caps, 0, sizeof(caps));
        NTSTATUS status = HidP_GetCaps(pp, &caps);
        HidD_FreePreparsedData(pp);
        if (status < 0) {
            break;
        }

        if (!is_allowed_command_caps(
                caps.UsagePage,
                caps.Usage,
                caps.InputReportByteLength,
                caps.OutputReportByteLength)) {
            break;
        }

        std::string product_name = spec->fallback_name;
        wchar_t name_buf[128];
        std::memset(name_buf, 0, sizeof(name_buf));
        if (HidD_GetProductString(h, name_buf, sizeof(name_buf))) {
            name_buf[127] = L'\0';
            std::string trimmed = trim_whitespace(wide_to_utf8(std::wstring(name_buf)));
            if (!trimmed.empty()) {
                product_name = trimmed;
            }
        }

        out.id = make_device_id(attrs.VendorID, attrs.ProductID, caps.UsagePage, path_w);
        out.vendor_id = attrs.VendorID;
        out.product_id = attrs.ProductID;
        out.product_name = product_name;
        out.usage_page = caps.UsagePage;
        out.usage = caps.Usage;
        out.input_report_bytes = static_cast<uint16_t>(caps.InputReportByteLength - 1);
        out.output_report_bytes = static_cast<uint16_t>(caps.OutputReportByteLength - 1);
        out.is_wireless = spec->is_wireless;
        out.path_w = path_w;
        matched = true;
    } while (false);

    CloseHandle(h);
    return matched;
}

std::vector<DeviceInfo> enumerate_valkyrie_devices() {
    std::vector<DeviceInfo> devices;
    GUID hid_guid;
    HidD_GetHidGuid(&hid_guid);

    HDEVINFO hdev = SetupDiGetClassDevsW(
        &hid_guid,
        nullptr,
        nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hdev == INVALID_HANDLE_VALUE) {
        return devices;
    }

    SP_DEVICE_INTERFACE_DATA did;
    std::memset(&did, 0, sizeof(did));
    did.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD idx = 0; SetupDiEnumDeviceInterfaces(hdev, nullptr, &hid_guid, idx, &did); ++idx) {
        DWORD req = 0;
        SetupDiGetDeviceInterfaceDetailW(hdev, &did, nullptr, 0, &req, nullptr);
        if (req < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
            continue;
        }

        std::vector<uint8_t> buf(req, 0);
        SP_DEVICE_INTERFACE_DETAIL_DATA_W* detail =
            reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buf.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        if (!SetupDiGetDeviceInterfaceDetailW(hdev, &did, detail, req, nullptr, nullptr)) {
            continue;
        }

        std::wstring path_w(detail->DevicePath);
        std::string low = ascii_lower(wide_to_utf8(path_w));
        if (low.find("vid_248a") == std::string::npos && low.find("vid_249a") == std::string::npos) {
            continue;
        }

        DeviceInfo info;
        if (probe_hid_metadata(path_w, info)) {
            devices.push_back(std::move(info));
        }
    }

    SetupDiDestroyDeviceInfoList(hdev);

    std::sort(devices.begin(), devices.end(), [](const DeviceInfo& a, const DeviceInfo& b) {
        int pa = (a.usage_page == 0xFF01) ? 0 : 1;
        int pb = (b.usage_page == 0xFF01) ? 0 : 1;
        if (pa != pb) return pa < pb;
        if (a.is_wireless != b.is_wireless) return !a.is_wireless && b.is_wireless;
        return a.id < b.id;
    });

    return devices;
}

// ---------------------------------------------------------------------------
// NDJSON Event Broadcaster
// ---------------------------------------------------------------------------

struct Subscriber {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<std::string> queue;
    bool closed;

    Subscriber() : closed(false) {}
};

class EventBroadcaster {
public:
    std::shared_ptr<Subscriber> subscribe() {
        std::shared_ptr<Subscriber> sub = std::make_shared<Subscriber>();
        std::lock_guard<std::mutex> lock(mu_);
        subscribers_.insert(sub);
        return sub;
    }

    void unsubscribe(const std::shared_ptr<Subscriber>& sub) {
        std::lock_guard<std::mutex> lock(mu_);
        subscribers_.erase(sub);
    }

    void publish_line(const std::string& json_line, bool is_disconnect = false) {
        std::vector<std::shared_ptr<Subscriber> > subs;
        {
            std::lock_guard<std::mutex> lock(mu_);
            subs.assign(subscribers_.begin(), subscribers_.end());
        }
        for (size_t i = 0; i < subs.size(); ++i) {
            std::shared_ptr<Subscriber>& sub = subs[i];
            std::lock_guard<std::mutex> slock(sub->mu);
            if (sub->closed) {
                continue;
            }
            if (sub->queue.size() >= MAX_EVENT_QUEUE_SIZE) {
                if (is_disconnect) {
                    sub->queue.pop_front();
                } else {
                    continue;
                }
            }
            sub->queue.push_back(json_line);
            sub->cv.notify_all();
        }
    }

    void wake_all_closed() {
        std::vector<std::shared_ptr<Subscriber> > subs;
        {
            std::lock_guard<std::mutex> lock(mu_);
            subs.assign(subscribers_.begin(), subscribers_.end());
        }
        for (size_t i = 0; i < subs.size(); ++i) {
            std::lock_guard<std::mutex> slock(subs[i]->mu);
            subs[i]->closed = true;
            subs[i]->cv.notify_all();
        }
    }

private:
    std::mutex mu_;
    std::set<std::shared_ptr<Subscriber> > subscribers_;
};

// ---------------------------------------------------------------------------
// Overlapped HID Device Session
// ---------------------------------------------------------------------------

class DeviceManager;

class DeviceSession : public std::enable_shared_from_this<DeviceSession> {
public:
    DeviceSession(
        HANDLE handle,
        const DeviceInfo& info,
        EventBroadcaster& broadcaster,
        DeviceManager* manager)
        : handle_(handle),
          info_(info),
          broadcaster_(broadcaster),
          manager_(manager),
          stop_requested_(false),
          closed_(false) {}

    ~DeviceSession() {
        if (reader_thread_.joinable() && std::this_thread::get_id() != reader_thread_.get_id()) {
            stop_requested_ = true;
            reader_thread_.join();
        }
        std::lock_guard<std::mutex> wlock(write_mu_);
        std::lock_guard<std::mutex> hlock(handle_mu_);
        close_handle_locked();
    }

    void start() {
        std::shared_ptr<DeviceSession> self = shared_from_this();
        reader_thread_ = std::thread([self]() {
            self->reader_loop();
        });
    }

    bool is_open() {
        std::lock_guard<std::mutex> hlock(handle_mu_);
        return !closed_ && handle_ != INVALID_HANDLE_VALUE;
    }

    bool write_report(const uint8_t payload32[32], std::string& out_err, int& out_http_status) {
        if (!is_allowed_opcode(payload32[0])) {
            out_err = "STALL_GUARD_BLOCKED";
            out_http_status = 403;
            return false;
        }

        uint8_t pkt[HID_REPORT_BYTE_LENGTH];
        pkt[0] = 0x00;
        std::memcpy(pkt + 1, payload32, 32);

        std::lock_guard<std::mutex> wlock(write_mu_);
        HANDLE h = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> hlock(handle_mu_);
            if (closed_ || handle_ == INVALID_HANDLE_VALUE) {
                out_err = "DEVICE_NOT_OPEN";
                out_http_status = 409;
                return false;
            }
            h = handle_;
        }

        HANDLE h_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!h_event) {
            out_err = "WRITE_FAILED";
            out_http_status = 502;
            return false;
        }

        OVERLAPPED ov_w;
        std::memset(&ov_w, 0, sizeof(ov_w));
        ov_w.hEvent = h_event;
        DWORD written = 0;

        BOOL ok = WriteFile(h, pkt, HID_REPORT_BYTE_LENGTH, &written, &ov_w);
        bool success = false;
        if (ok) {
            success = (written == HID_REPORT_BYTE_LENGTH);
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                DWORD wait_rc = WaitForSingleObject(h_event, 2000);
                if (wait_rc == WAIT_OBJECT_0) {
                    if (GetOverlappedResult(h, &ov_w, &written, FALSE)) {
                        success = (written == HID_REPORT_BYTE_LENGTH);
                    }
                } else {
                    CancelIoEx(h, &ov_w);
                    GetOverlappedResult(h, &ov_w, &written, TRUE);
                }
            }
        }

        CloseHandle(h_event);
        if (!success) {
            out_err = "WRITE_FAILED";
            out_http_status = 502;
            return false;
        }
        return true;
    }

    void close(bool emit_disconnect) {
        HANDLE h = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> hlock(handle_mu_);
            if (closed_) {
                return;
            }
            closed_ = true;
            stop_requested_ = true;
            h = handle_;
        }

        if (h != INVALID_HANDLE_VALUE) {
            CancelIoEx(h, nullptr);
        }

        if (reader_thread_.joinable() && std::this_thread::get_id() != reader_thread_.get_id()) {
            reader_thread_.join();
        }

        {
            std::lock_guard<std::mutex> wlock(write_mu_);
            std::lock_guard<std::mutex> hlock(handle_mu_);
            close_handle_locked();
        }

        if (emit_disconnect) {
            broadcaster_.publish_line("{\"type\":\"disconnect\"}\n", true);
        }
    }

private:
    HANDLE handle_;
    DeviceInfo info_;
    EventBroadcaster& broadcaster_;
    DeviceManager* manager_;
    std::atomic<bool> stop_requested_;
    bool closed_;
    std::mutex handle_mu_;
    std::mutex write_mu_;
    std::thread reader_thread_;

    void close_handle_locked() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    void reader_loop();
};

class DeviceManager {
public:
    explicit DeviceManager(int port) : port_(port), running_(true) {}

    int port() const { return port_; }

    bool is_running() const { return running_.load(); }

    EventBroadcaster& broadcaster() { return broadcaster_; }

    std::vector<DeviceInfo> list_devices() {
        return enumerate_valkyrie_devices();
    }

    bool open_device(const std::string& device_id, bool has_device_id, DeviceInfo& out_info, int& out_status, std::string& out_err) {
        std::vector<DeviceInfo> candidates = enumerate_valkyrie_devices();
        const DeviceInfo* chosen = nullptr;

        if (has_device_id && !device_id.empty()) {
            for (size_t i = 0; i < candidates.size(); ++i) {
                if (candidates[i].id == device_id) {
                    chosen = &candidates[i];
                    break;
                }
            }
        } else if (!candidates.empty()) {
            chosen = &candidates[0];
        }

        if (!chosen) {
            out_status = 404;
            out_err = "NO_COMMAND_INTERFACE";
            return false;
        }

        // Defense-in-depth re-check before requesting GENERIC_READ|GENERIC_WRITE
        if (!is_allowed_command_caps(
                chosen->usage_page,
                chosen->usage,
                static_cast<uint16_t>(chosen->input_report_bytes + 1),
                static_cast<uint16_t>(chosen->output_report_bytes + 1))) {
            out_status = 404;
            out_err = "NO_COMMAND_INTERFACE";
            return false;
        }

        DeviceInfo chosen_copy = *chosen;

        std::shared_ptr<DeviceSession> old_session;
        {
            std::lock_guard<std::mutex> lock(mu_);
            old_session = session_;
            session_.reset();
        }
        if (old_session) {
            old_session->close(true);
        }

        HANDLE h = CreateFileW(
            chosen_copy.path_w.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            out_status = 404;
            out_err = "NO_COMMAND_INTERFACE";
            return false;
        }

        HidD_SetNumInputBuffers(h, 64);

        std::shared_ptr<DeviceSession> new_session =
            std::make_shared<DeviceSession>(h, chosen_copy, broadcaster_, this);
        new_session->start();

        {
            std::lock_guard<std::mutex> lock(mu_);
            session_ = new_session;
        }

        out_info = chosen_copy;
        out_status = 200;
        return true;
    }

    void close_device() {
        std::shared_ptr<DeviceSession> old;
        {
            std::lock_guard<std::mutex> lock(mu_);
            old = session_;
            session_.reset();
        }
        if (old) {
            old->close(true);
        }
    }

    bool send_report(const uint8_t payload32[32], int& out_status, std::string& out_err) {
        std::shared_ptr<DeviceSession> active;
        {
            std::lock_guard<std::mutex> lock(mu_);
            active = session_;
        }
        if (!active || !active->is_open()) {
            out_status = 409;
            out_err = "DEVICE_NOT_OPEN";
            return false;
        }
        if (!active->write_report(payload32, out_err, out_status)) {
            if (out_status >= 500) {
                close_device();
            }
            return false;
        }
        out_status = 200;
        return true;
    }

    void on_session_unplugged(DeviceSession* unplugged) {
        std::lock_guard<std::mutex> lock(mu_);
        if (session_.get() == unplugged) {
            session_.reset();
        }
    }

    void shutdown() {
        running_.store(false);
        bool had_session = false;
        {
            std::lock_guard<std::mutex> lock(mu_);
            had_session = static_cast<bool>(session_);
        }
        close_device();
        if (!had_session) {
            broadcaster_.publish_line("{\"type\":\"disconnect\"}\n", true);
        }
        broadcaster_.wake_all_closed();
    }

private:
    int port_;
    std::atomic<bool> running_;
    EventBroadcaster broadcaster_;
    std::mutex mu_;
    std::shared_ptr<DeviceSession> session_;
};

void DeviceSession::reader_loop() {
    uint8_t rbuf[HID_REPORT_BYTE_LENGTH];
    HANDLE h_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!h_event) {
        return;
    }

    bool unexpected_disconnect = false;
    while (!stop_requested_.load()) {
        HANDLE h = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> hlock(handle_mu_);
            if (closed_ || handle_ == INVALID_HANDLE_VALUE) {
                break;
            }
            h = handle_;
        }

        ResetEvent(h_event);
        OVERLAPPED ov_r;
        std::memset(&ov_r, 0, sizeof(ov_r));
        ov_r.hEvent = h_event;
        DWORD rbytes = 0;

        BOOL ok = ReadFile(h, rbuf, HID_REPORT_BYTE_LENGTH, &rbytes, &ov_r);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                bool completed = false;
                while (!stop_requested_.load()) {
                    DWORD wait_rc = WaitForSingleObject(h_event, 100);
                    if (wait_rc == WAIT_OBJECT_0) {
                        if (GetOverlappedResult(h, &ov_r, &rbytes, FALSE)) {
                            completed = true;
                        } else {
                            DWORD gerr = GetLastError();
                            if (gerr != ERROR_OPERATION_ABORTED && !stop_requested_.load()) {
                                unexpected_disconnect = true;
                            }
                        }
                        break;
                    }
                    if (wait_rc != WAIT_TIMEOUT) {
                        if (!stop_requested_.load()) {
                            unexpected_disconnect = true;
                        }
                        break;
                    }
                }

                if (stop_requested_.load() && !completed) {
                    CancelIoEx(h, &ov_r);
                    GetOverlappedResult(h, &ov_r, &rbytes, TRUE);
                    break;
                }
                if (unexpected_disconnect) {
                    break;
                }
                if (!completed) {
                    continue;
                }
            } else if (err == ERROR_OPERATION_ABORTED || stop_requested_.load()) {
                break;
            } else {
                unexpected_disconnect = true;
                break;
            }
        }

        if (rbytes == 0) {
            continue;
        }

        uint8_t report_id = 0;
        uint8_t payload[32];
        std::memset(payload, 0, sizeof(payload));

        if (rbytes == HID_REPORT_BYTE_LENGTH && rbuf[0] == 0x00) {
            report_id = 0;
            std::memcpy(payload, rbuf + 1, 32);
        } else if (rbytes == HID_REPORT_BYTE_LENGTH) {
            report_id = rbuf[0];
            std::memcpy(payload, rbuf + 1, 32);
        } else {
            report_id = 0;
            size_t copy_len = rbytes < 32 ? static_cast<size_t>(rbytes) : 32;
            std::memcpy(payload, rbuf, copy_len);
        }

        std::ostringstream oss;
        oss << "{\"type\":\"inputreport\",\"reportId\":" << static_cast<unsigned int>(report_id) << ",\"data\":[";
        for (int i = 0; i < 32; ++i) {
            if (i > 0) oss << ",";
            oss << static_cast<unsigned int>(payload[i]);
        }
        oss << "]}\n";
        broadcaster_.publish_line(oss.str());
    }

    CloseHandle(h_event);

    if (unexpected_disconnect) {
        {
            std::lock_guard<std::mutex> hlock(handle_mu_);
            closed_ = true;
        }
        {
            std::lock_guard<std::mutex> wlock(write_mu_);
            std::lock_guard<std::mutex> hlock(handle_mu_);
            close_handle_locked();
        }
        if (manager_) {
            manager_->on_session_unplugged(this);
        }
        broadcaster_.publish_line("{\"type\":\"disconnect\"}\n", true);
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 Server over Winsock2
// ---------------------------------------------------------------------------

std::mutex g_srv_mu;
SOCKET g_listen_sock = INVALID_SOCKET;
std::set<SOCKET> g_client_socks;
std::condition_variable g_clients_cv;
DeviceManager* g_manager_ptr = nullptr;

bool send_all(SOCKET sock, const char* data, size_t len) {
    size_t sent_total = 0;
    while (sent_total < len) {
        int chunk = static_cast<int>(std::min<size_t>(len - sent_total, 65536));
        int rc = send(sock, data + sent_total, chunk, 0);
        if (rc == SOCKET_ERROR || rc == 0) {
            return false;
        }
        sent_total += static_cast<size_t>(rc);
    }
    return true;
}

bool send_str(SOCKET sock, const std::string& s) {
    return send_all(sock, s.data(), s.size());
}

struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::string origin;
    std::string connection;
    bool has_content_length;
    bool is_chunked;
    size_t content_length;
    std::string body;

    HttpRequest() : has_content_length(false), is_chunked(false), content_length(0) {}
};

const char* http_reason(int status) {
    switch (status) {
        case 200: return "OK";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 413: return "Payload Too Large";
        case 502: return "Bad Gateway";
        default: return "Internal Server Error";
    }
}

void append_cors_pna_headers(std::ostringstream& oss, const std::string& req_origin) {
    std::string valid_origin = validate_origin(req_origin);
    if (!valid_origin.empty()) {
        oss << "Access-Control-Allow-Origin: " << valid_origin << "\r\n";
    }
    oss << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        << "Access-Control-Allow-Headers: Content-Type, Access-Control-Request-Private-Network\r\n"
        << "Access-Control-Allow-Private-Network: true\r\n"
        << "Vary: Origin\r\n";
}

bool send_json_response(SOCKET sock, int status, const std::string& json_body, const std::string& req_origin, bool close_conn) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << " " << http_reason(status) << "\r\n";
    append_cors_pna_headers(oss, req_origin);
    oss << "Content-Type: application/json; charset=utf-8\r\n"
        << "Cache-Control: no-store\r\n"
        << "Content-Length: " << json_body.size() << "\r\n";
    if (close_conn) {
        oss << "Connection: close\r\n";
    }
    oss << "\r\n" << json_body;
    return send_str(sock, oss.str());
}

bool send_no_content_response(SOCKET sock, const std::string& req_origin, bool close_conn) {
    std::ostringstream oss;
    oss << "HTTP/1.1 204 No Content\r\n";
    append_cors_pna_headers(oss, req_origin);
    oss << "Content-Length: 0\r\n";
    if (close_conn) {
        oss << "Connection: close\r\n";
    }
    oss << "\r\n";
    return send_str(sock, oss.str());
}

bool read_http_request(SOCKET sock, std::string& carry_buf, HttpRequest& req, bool& out_too_large) {
    out_too_large = false;
    req = HttpRequest();

    size_t hdr_end = std::string::npos;
    while (true) {
        hdr_end = carry_buf.find("\r\n\r\n");
        if (hdr_end != std::string::npos) {
            break;
        }
        if (carry_buf.size() >= MAX_HEADER_BYTES) {
            out_too_large = true;
            return false;
        }
        char tmp[4096];
        int n = recv(sock, tmp, sizeof(tmp), 0);
        if (n <= 0) {
            return false;
        }
        carry_buf.append(tmp, static_cast<size_t>(n));
    }

    std::string header_block = carry_buf.substr(0, hdr_end);
    carry_buf.erase(0, hdr_end + 4);

    size_t line_end = header_block.find("\r\n");
    std::string request_line = (line_end == std::string::npos) ? header_block : header_block.substr(0, line_end);

    size_t sp1 = request_line.find(' ');
    if (sp1 == std::string::npos) {
        return false;
    }
    size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) {
        return false;
    }

    req.method = request_line.substr(0, sp1);
    std::string target = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
    req.version = request_line.substr(sp2 + 1);

    size_t qpos = target.find('?');
    req.path = (qpos == std::string::npos) ? target : target.substr(0, qpos);

    if (line_end != std::string::npos) {
        size_t pos = line_end + 2;
        while (pos < header_block.size()) {
            size_t next = header_block.find("\r\n", pos);
            std::string hline = (next == std::string::npos)
                ? header_block.substr(pos)
                : header_block.substr(pos, next - pos);
            pos = (next == std::string::npos) ? header_block.size() : next + 2;

            size_t colon = hline.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            std::string hname = ascii_lower(trim_whitespace(hline.substr(0, colon)));
            std::string hval = trim_whitespace(hline.substr(colon + 1));

            if (hname == "origin") {
                req.origin = hval;
            } else if (hname == "connection") {
                req.connection = ascii_lower(hval);
            } else if (hname == "transfer-encoding") {
                if (ascii_lower(hval).find("chunked") != std::string::npos) {
                    req.is_chunked = true;
                }
            } else if (hname == "content-length") {
                char* endp = nullptr;
                errno = 0;
                unsigned long long cl = std::strtoull(hval.c_str(), &endp, 10);
                if (errno == 0 && endp != hval.c_str() && *endp == '\0') {
                    if (cl > MAX_BODY_BYTES) {
                        out_too_large = true;
                        return false;
                    }
                    req.has_content_length = true;
                    req.content_length = static_cast<size_t>(cl);
                } else {
                    return false;
                }
            }
        }
    }

    if (req.is_chunked) {
        while (true) {
            size_t line_cr = std::string::npos;
            while ((line_cr = carry_buf.find("\r\n")) == std::string::npos) {
                if (carry_buf.size() >= MAX_HEADER_BYTES) {
                    out_too_large = true;
                    return false;
                }
                char tmp[4096];
                int n = recv(sock, tmp, sizeof(tmp), 0);
                if (n <= 0) {
                    return false;
                }
                carry_buf.append(tmp, static_cast<size_t>(n));
            }
            std::string sz_line = carry_buf.substr(0, line_cr);
            carry_buf.erase(0, line_cr + 2);
            size_t semi = sz_line.find(';');
            if (semi != std::string::npos) {
                sz_line = sz_line.substr(0, semi);
            }
            sz_line = trim_whitespace(sz_line);
            if (sz_line.empty()) {
                return false;
            }
            char* endp = nullptr;
            errno = 0;
            unsigned long long chunk_sz = std::strtoull(sz_line.c_str(), &endp, 16);
            if (errno != 0 || endp == sz_line.c_str() || *endp != '\0') {
                return false;
            }
            if (chunk_sz > MAX_BODY_BYTES || req.body.size() + chunk_sz > MAX_BODY_BYTES) {
                out_too_large = true;
                return false;
            }
            if (chunk_sz == 0) {
                while (carry_buf.size() < 2) {
                    char tmp[64];
                    int n = recv(sock, tmp, sizeof(tmp), 0);
                    if (n <= 0) {
                        return false;
                    }
                    carry_buf.append(tmp, static_cast<size_t>(n));
                }
                if (carry_buf.compare(0, 2, "\r\n") == 0) {
                    carry_buf.erase(0, 2);
                }
                break;
            }
            while (carry_buf.size() < static_cast<size_t>(chunk_sz) + 2) {
                char tmp[4096];
                int n = recv(sock, tmp, sizeof(tmp), 0);
                if (n <= 0) {
                    return false;
                }
                carry_buf.append(tmp, static_cast<size_t>(n));
            }
            req.body.append(carry_buf, 0, static_cast<size_t>(chunk_sz));
            carry_buf.erase(0, static_cast<size_t>(chunk_sz) + 2);
        }
    } else if (req.has_content_length && req.content_length > 0) {
        while (carry_buf.size() < req.content_length) {
            char tmp[4096];
            int n = recv(sock, tmp, sizeof(tmp), 0);
            if (n <= 0) {
                return false;
            }
            carry_buf.append(tmp, static_cast<size_t>(n));
        }
        req.body = carry_buf.substr(0, req.content_length);
        carry_buf.erase(0, req.content_length);
    }

    return true;
}

bool socket_is_disconnected(SOCKET sock) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    int rc = select(0, &rfds, nullptr, nullptr, &tv);
    if (rc > 0 && FD_ISSET(sock, &rfds)) {
        char ch = 0;
        int n = recv(sock, &ch, 1, MSG_PEEK);
        if (n <= 0) {
            return true;
        }
    }
    return false;
}

void handle_events_stream(SOCKET sock, DeviceManager& manager, const std::string& req_origin) {
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n";
    append_cors_pna_headers(oss, req_origin);
    oss << "Content-Type: application/x-ndjson\r\n"
        << "Cache-Control: no-cache\r\n"
        << "Connection: close\r\n\r\n";

    if (!send_str(sock, oss.str())) {
        return;
    }
    if (!send_str(sock, "{\"type\":\"ready\"}\n")) {
        return;
    }

    std::shared_ptr<Subscriber> sub = manager.broadcaster().subscribe();
    std::chrono::steady_clock::time_point last_activity = std::chrono::steady_clock::now();

    while (manager.is_running()) {
        std::string pending_line;
        bool has_line = false;
        bool is_closed = false;

        {
            std::unique_lock<std::mutex> lock(sub->mu);
            if (sub->queue.empty() && !sub->closed) {
                sub->cv.wait_for(lock, std::chrono::seconds(1));
            }
            if (!sub->queue.empty()) {
                pending_line = std::move(sub->queue.front());
                sub->queue.pop_front();
                has_line = true;
            }
            is_closed = sub->closed;
        }

        if (has_line) {
            if (!send_str(sock, pending_line)) {
                break;
            }
            last_activity = std::chrono::steady_clock::now();
            if (pending_line.find("\"type\":\"disconnect\"") != std::string::npos) {
                break;
            }
            continue;
        }

        if (is_closed || !manager.is_running()) {
            break;
        }

        if (socket_is_disconnected(sock)) {
            break;
        }

        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_activity).count() >= PING_INTERVAL_SECONDS) {
            if (!send_str(sock, "{\"type\":\"ping\"}\n")) {
                break;
            }
            last_activity = now;
        }
    }

    manager.broadcaster().unsubscribe(sub);
}

void handle_client_connection(SOCKET sock, DeviceManager* manager) {
    BOOL nodelay = TRUE;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    DWORD rcv_timeout_ms = 15000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&rcv_timeout_ms), sizeof(rcv_timeout_ms));

    std::string carry_buf;
    while (manager->is_running()) {
        HttpRequest req;
        bool too_large = false;
        if (!read_http_request(sock, carry_buf, req, too_large)) {
            if (too_large) {
                send_json_response(sock, 413, "{\"ok\":false,\"error\":\"PAYLOAD_TOO_LARGE\"}", "", true);
            }
            break;
        }

        bool close_conn = (req.connection == "close") || (req.version == "HTTP/1.0" && req.connection != "keep-alive");

        if (req.method == "OPTIONS") {
            if (!send_no_content_response(sock, req.origin, close_conn) || close_conn) {
                break;
            }
            continue;
        }

        if (req.method == "GET" && req.path == "/api/health") {
            std::ostringstream oss;
            oss << "{\"ok\":true,\"service\":\"" << SERVICE_NAME << "\",\"version\":\"" << SERVICE_VERSION
                << "\",\"port\":" << manager->port() << "}";
            if (!send_json_response(sock, 200, oss.str(), req.origin, close_conn) || close_conn) {
                break;
            }
            continue;
        }

        if (req.method == "GET" && req.path == "/api/devices") {
            std::vector<DeviceInfo> devs = manager->list_devices();
            std::ostringstream oss;
            oss << "{\"ok\":true,\"devices\":[";
            for (size_t i = 0; i < devs.size(); ++i) {
                if (i > 0) oss << ",";
                oss << devs[i].to_json();
            }
            oss << "]}";
            if (!send_json_response(sock, 200, oss.str(), req.origin, close_conn) || close_conn) {
                break;
            }
            continue;
        }

        if (req.method == "GET" && req.path == "/api/events") {
            handle_events_stream(sock, *manager, req.origin);
            break;
        }

        if (req.method == "POST" && req.path == "/api/open") {
            std::string trimmed = trim_whitespace(req.body);
            JsonValue parsed;
            if (!trimmed.empty()) {
                JsonParser parser(trimmed);
                if (!parser.parse(parsed) || parsed.type != JsonValue::JObject) {
                    if (!send_json_response(sock, 400, "{\"ok\":false,\"error\":\"INVALID_JSON\"}", req.origin, close_conn) || close_conn) {
                        break;
                    }
                    continue;
                }
            } else {
                parsed.type = JsonValue::JObject;
            }

            std::string device_id;
            bool has_device_id = false;
            const JsonValue* dev_val = parsed.get("deviceId");
            if (dev_val != nullptr && dev_val->type != JsonValue::JNull) {
                if (dev_val->type != JsonValue::JString) {
                    if (!send_json_response(sock, 404, "{\"ok\":false,\"error\":\"NO_COMMAND_INTERFACE\"}", req.origin, close_conn) || close_conn) {
                        break;
                    }
                    continue;
                }
                device_id = dev_val->str_val;
                has_device_id = !device_id.empty();
            }

            DeviceInfo opened;
            int status = 200;
            std::string err;
            if (!manager->open_device(device_id, has_device_id, opened, status, err)) {
                std::string body = std::string("{\"ok\":false,\"error\":\"") + json_escape(err) + "\"}";
                if (!send_json_response(sock, status, body, req.origin, close_conn) || close_conn) {
                    break;
                }
                continue;
            }

            std::string body = std::string("{\"ok\":true,\"device\":") + opened.to_json() + "}";
            if (!send_json_response(sock, 200, body, req.origin, close_conn) || close_conn) {
                break;
            }
            continue;
        }

        if (req.method == "POST" && req.path == "/api/close") {
            std::string trimmed = trim_whitespace(req.body);
            if (!trimmed.empty()) {
                JsonValue parsed;
                JsonParser parser(trimmed);
                if (!parser.parse(parsed) || parsed.type != JsonValue::JObject) {
                    if (!send_json_response(sock, 400, "{\"ok\":false,\"error\":\"INVALID_JSON\"}", req.origin, close_conn) || close_conn) {
                        break;
                    }
                    continue;
                }
            }
            manager->close_device();
            if (!send_json_response(sock, 200, "{\"ok\":true}", req.origin, close_conn) || close_conn) {
                break;
            }
            continue;
        }

        if (req.method == "POST" && req.path == "/api/report") {
            std::string trimmed = trim_whitespace(req.body);
            JsonValue parsed;
            if (trimmed.empty()) {
                parsed.type = JsonValue::JObject;
            } else {
                JsonParser parser(trimmed);
                if (!parser.parse(parsed) || parsed.type != JsonValue::JObject) {
                    if (!send_json_response(sock, 400, "{\"ok\":false,\"error\":\"INVALID_JSON\"}", req.origin, close_conn) || close_conn) {
                        break;
                    }
                    continue;
                }
            }

            const JsonValue* rid_val = parsed.get("reportId");
            if (rid_val != nullptr) {
                if (rid_val->type != JsonValue::JNumber || !rid_val->is_int || rid_val->int_val != 0) {
                    if (!send_json_response(sock, 403, "{\"ok\":false,\"error\":\"STALL_GUARD_BLOCKED\"}", req.origin, close_conn) || close_conn) {
                        break;
                    }
                    continue;
                }
            }

            const JsonValue* data_val = parsed.get("data");
            if (data_val == nullptr || data_val->type != JsonValue::JArray ||
                data_val->arr_val.empty() || data_val->arr_val.size() > 32) {
                if (!send_json_response(sock, 400, "{\"ok\":false,\"error\":\"INVALID_PAYLOAD\"}", req.origin, close_conn) || close_conn) {
                    break;
                }
                continue;
            }

            uint8_t payload[32];
            std::memset(payload, 0, sizeof(payload));
            bool payload_valid = true;
            for (size_t i = 0; i < data_val->arr_val.size(); ++i) {
                const JsonValue& item = data_val->arr_val[i];
                if (item.type != JsonValue::JNumber || !item.is_int || item.int_val < 0 || item.int_val > 255) {
                    payload_valid = false;
                    break;
                }
                payload[i] = static_cast<uint8_t>(item.int_val);
            }
            if (!payload_valid) {
                if (!send_json_response(sock, 400, "{\"ok\":false,\"error\":\"INVALID_PAYLOAD\"}", req.origin, close_conn) || close_conn) {
                    break;
                }
                continue;
            }

            if (!is_allowed_opcode(payload[0])) {
                if (!send_json_response(sock, 403, "{\"ok\":false,\"error\":\"STALL_GUARD_BLOCKED\"}", req.origin, close_conn) || close_conn) {
                    break;
                }
                continue;
            }

            int status = 200;
            std::string err;
            if (!manager->send_report(payload, status, err)) {
                std::string body = std::string("{\"ok\":false,\"error\":\"") + json_escape(err) + "\"}";
                if (!send_json_response(sock, status, body, req.origin, close_conn) || close_conn) {
                    break;
                }
                continue;
            }

            if (!send_json_response(sock, 200, "{\"ok\":true}", req.origin, close_conn) || close_conn) {
                break;
            }
            continue;
        }

        if (req.path == "/api/health" || req.path == "/api/devices" || req.path == "/api/events" ||
            req.path == "/api/open" || req.path == "/api/close" || req.path == "/api/report") {
            if (!send_json_response(sock, 405, "{\"ok\":false,\"error\":\"METHOD_NOT_ALLOWED\"}", req.origin, close_conn) || close_conn) {
                break;
            }
        } else {
            if (!send_json_response(sock, 404, "{\"ok\":false,\"error\":\"NOT_FOUND\"}", req.origin, close_conn) || close_conn) {
                break;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_srv_mu);
        g_client_socks.erase(sock);
    }
    shutdown(sock, SD_BOTH);
    closesocket(sock);
    g_clients_cv.notify_all();
}

BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT: {
            if (g_manager_ptr) {
                g_manager_ptr->shutdown();
            }
            std::lock_guard<std::mutex> lock(g_srv_mu);
            if (g_listen_sock != INVALID_SOCKET) {
                SOCKET s = g_listen_sock;
                g_listen_sock = INVALID_SOCKET;
                closesocket(s);
            }
            return TRUE;
        }
        default:
            return FALSE;
    }
}

void print_usage(const char* argv0) {
    std::printf(
        "Usage: %s [--port N]\n"
        "Valkyrie Local Companion Helper (binds strictly to 127.0.0.1, default port %d)\n",
        argv0 ? argv0 : "valkyrie-helper.exe",
        DEFAULT_PORT);
}

bool parse_port_str(const char* s, int& out_port) {
    if (!s || !*s) {
        return false;
    }
    char* endp = nullptr;
    errno = 0;
    long v = std::strtol(s, &endp, 10);
    if (errno != 0 || endp == s || *endp != '\0' || v < 1 || v > 65535) {
        return false;
    }
    out_port = static_cast<int>(v);
    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    int port = DEFAULT_PORT;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        if (arg == "--port") {
            if (i + 1 >= argc || !parse_port_str(argv[i + 1], port)) {
                std::fprintf(stderr, "Invalid --port value (expected 1..65535)\n");
                return 2;
            }
            ++i;
        } else if (arg.compare(0, 7, "--port=") == 0) {
            if (!parse_port_str(arg.c_str() + 7, port)) {
                std::fprintf(stderr, "Invalid --port value (expected 1..65535)\n");
                return 2;
            }
        } else {
            std::fprintf(stderr, "Unknown argument: %s\n", arg.c_str());
            print_usage(argv[0]);
            return 2;
        }
    }

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        std::fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    BOOL exclusive = TRUE;
    setsockopt(listen_sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    // Strictly bind 127.0.0.1 -- never 0.0.0.0.
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        std::fprintf(stderr, "bind(127.0.0.1:%d) failed: %d\n", port, WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        std::fprintf(stderr, "listen() failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    DeviceManager manager(port);
    {
        std::lock_guard<std::mutex> lock(g_srv_mu);
        g_listen_sock = listen_sock;
        g_manager_ptr = &manager;
    }
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    std::printf("%s listening on http://127.0.0.1:%d\n", SERVICE_NAME, port);
    std::fflush(stdout);

    while (manager.is_running()) {
        SOCKET client_sock = accept(listen_sock, nullptr, nullptr);
        if (client_sock == INVALID_SOCKET) {
            break;
        }
        {
            std::lock_guard<std::mutex> lock(g_srv_mu);
            if (!manager.is_running()) {
                closesocket(client_sock);
                break;
            }
            g_client_socks.insert(client_sock);
        }
        std::thread(handle_client_connection, client_sock, &manager).detach();
    }

    manager.shutdown();
    {
        std::lock_guard<std::mutex> lock(g_srv_mu);
        if (g_listen_sock != INVALID_SOCKET) {
            closesocket(g_listen_sock);
            g_listen_sock = INVALID_SOCKET;
        }
        for (std::set<SOCKET>::iterator it = g_client_socks.begin(); it != g_client_socks.end(); ++it) {
            shutdown(*it, SD_BOTH);
        }
    }

    {
        std::unique_lock<std::mutex> lock(g_srv_mu);
        g_clients_cv.wait_for(lock, std::chrono::seconds(2), []() {
            return g_client_socks.empty();
        });
        g_manager_ptr = nullptr;
    }

    WSACleanup();
    return 0;
}
