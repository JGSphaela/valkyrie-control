pub mod hid;

use hid::{
    close_valkyrie_device, list_valkyrie_devices, open_valkyrie_device, send_valkyrie_report,
    HidState,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(HidState::default())
        .invoke_handler(tauri::generate_handler![
            list_valkyrie_devices,
            open_valkyrie_device,
            close_valkyrie_device,
            send_valkyrie_report,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Valkyrie Control");
}
