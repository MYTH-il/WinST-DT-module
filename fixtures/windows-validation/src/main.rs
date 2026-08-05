#![windows_subsystem = "windows"]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{ffi::c_void, fs, mem, path::PathBuf, ptr, thread, time::Duration};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, HWND},
    Networking::{
        WinHttp::{
            WINHTTP_ACCESS_TYPE_NO_PROXY, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen,
            WinHttpOpenRequest, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
        },
        WinSock::{ADDRINFOW, FreeAddrInfoW, GetAddrInfoW},
    },
    Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        OPEN_EXISTING, ReadFile,
    },
    System::{
        DataExchange::{
            CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
        },
        Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
        WindowsProgramming::GetComputerNameW,
    },
    UI::WindowsAndMessaging::{FindWindowW, MB_OK, MessageBoxW, SendMessageW, WM_CLOSE},
};

const HOST: &str = "validation.winstdt.test";
const MARKER: &str = "WINSTDT-CONTROLLED-CANARY/1";
const CF_UNICODETEXT: u32 = 13;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn sha(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn show_window() -> thread::JoinHandle<()> {
    thread::spawn(|| unsafe {
        let text = wide("Harmless controlled validation is running. No personal data is accessed.");
        let title = wide("WinST/DT Controlled Validation Fixture");
        MessageBoxW(0 as HWND, text.as_ptr(), title.as_ptr(), MB_OK);
    })
}

fn close_window() {
    unsafe {
        let title = wide("WinST/DT Controlled Validation Fixture");
        let window = FindWindowW(ptr::null(), title.as_ptr());
        if !window.is_null() {
            SendMessageW(window, WM_CLOSE, 0, 0);
        }
    }
}

fn canary_file(directory: &PathBuf, canary: &str) -> Result<(), String> {
    let path = directory.join("canary.txt");
    let path_w = wide(path.to_str().ok_or("path encoding")?);
    unsafe {
        let handle = CreateFileW(
            path_w.as_ptr(),
            FILE_GENERIC_WRITE,
            0,
            ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0 as HANDLE,
        );
        if handle == -1isize as HANDLE {
            return Err("CreateFileW failed".into());
        }
        let mut written = 0;
        let ok = windows_sys::Win32::Storage::FileSystem::WriteFile(
            handle,
            canary.as_ptr(),
            canary.len() as u32,
            &mut written,
            ptr::null_mut(),
        );
        CloseHandle(handle);
        if ok == 0 || written as usize != canary.len() {
            return Err("WriteFile failed".into());
        }
        let handle = CreateFileW(
            path_w.as_ptr(),
            FILE_GENERIC_READ,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0 as HANDLE,
        );
        if handle == -1isize as HANDLE {
            return Err("CreateFileW read failed".into());
        }
        let mut bytes = vec![0u8; canary.len()];
        let mut read = 0;
        let ok = ReadFile(
            handle,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            &mut read,
            ptr::null_mut(),
        );
        CloseHandle(handle);
        if ok == 0 || &bytes[..read as usize] != canary.as_bytes() {
            return Err("canary read mismatch".into());
        }
    }
    Ok(())
}

fn clipboard(canary: &str) -> Result<(), String> {
    let value = wide(canary);
    unsafe {
        if OpenClipboard(0 as HWND) == 0 {
            return Err("OpenClipboard failed".into());
        }
        EmptyClipboard();
        let allocation = GlobalAlloc(GMEM_MOVEABLE, value.len() * 2);
        if allocation.is_null() {
            CloseClipboard();
            return Err("GlobalAlloc failed".into());
        }
        let memory = GlobalLock(allocation) as *mut u16;
        ptr::copy_nonoverlapping(value.as_ptr(), memory, value.len());
        GlobalUnlock(allocation);
        if SetClipboardData(CF_UNICODETEXT, allocation as HANDLE).is_null() {
            CloseClipboard();
            return Err("SetClipboardData failed".into());
        }
        let stored = GetClipboardData(CF_UNICODETEXT);
        let pointer = GlobalLock(stored as _) as *const u16;
        let mut length = 0;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        let equal = std::slice::from_raw_parts(pointer, length) == &value[..value.len() - 1];
        GlobalUnlock(stored as _);
        EmptyClipboard();
        CloseClipboard();
        if !equal {
            return Err("clipboard mismatch".into());
        }
    }
    Ok(())
}

fn system_info() -> Result<String, String> {
    let mut name = [0u16; 256];
    let mut size = name.len() as u32;
    unsafe {
        if GetComputerNameW(name.as_mut_ptr(), &mut size) == 0 {
            return Err("GetComputerNameW failed".into());
        }
    }
    Ok(String::from_utf16_lossy(&name[..size as usize]))
}

fn resolve_private_host() -> Result<(), String> {
    let host = wide(HOST);
    let service = wide("8080");
    let mut result = ptr::null_mut();
    let hints: ADDRINFOW = unsafe { mem::zeroed() };
    let status = unsafe { GetAddrInfoW(host.as_ptr(), service.as_ptr(), &hints, &mut result) };
    if status != 0 || result.is_null() {
        return Err("private DNS resolution failed".into());
    }
    unsafe { FreeAddrInfoW(result) };
    Ok(())
}

fn post(request: &Value) -> Result<Value, String> {
    let body = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    unsafe {
        let agent = wide("WinSTDT-Controlled-Validation/1");
        let session = WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            ptr::null(),
            ptr::null(),
            0,
        );
        if session.is_null() {
            return Err("WinHttpOpen failed".into());
        }
        let host = wide(HOST);
        let connection = WinHttpConnect(session, host.as_ptr(), 8080, 0);
        let method = wide("POST");
        let path = wide("/");
        let request_handle = WinHttpOpenRequest(
            connection,
            method.as_ptr(),
            path.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
        );
        let headers = wide("Content-Type: application/json\r\n");
        let sent = WinHttpSendRequest(
            request_handle,
            headers.as_ptr(),
            u32::MAX,
            body.as_ptr() as *mut c_void,
            body.len() as u32,
            body.len() as u32,
            0,
        );
        if sent == 0 || WinHttpReceiveResponse(request_handle, ptr::null_mut()) == 0 {
            WinHttpCloseHandle(request_handle);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return Err("WinHTTP request failed".into());
        }
        let mut response = Vec::new();
        loop {
            let mut buffer = [0u8; 4096];
            let mut read = 0;
            if WinHttpReadData(
                request_handle,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut read,
            ) == 0
            {
                break;
            }
            if read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..read as usize]);
        }
        WinHttpCloseHandle(request_handle);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        serde_json::from_slice(&response).map_err(|e| format!("invalid receipt: {e}"))
    }
}

fn run() -> Result<(), String> {
    let run_id = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "controlled-validation".into());
    if !run_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
    {
        return Err("invalid run id".into());
    }
    let directory = std::env::temp_dir().join("WinSTDT").join("Validation");
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let canary = format!("{MARKER}:{run_id}:deterministic-generated-data");
    canary_file(&directory, &canary)?;
    clipboard(&canary)?;
    let computer = system_info()?;
    resolve_private_host()?;
    let mut receipts = Vec::new();
    for sequence in 1..=3 {
        let request = json!({"marker":MARKER,"run_id":run_id,"sequence":sequence,"canary":canary});
        let receipt = post(&request)?;
        if receipt["run_id"] != run_id
            || receipt["sequence"] != sequence
            || receipt["canary_sha256"] != sha(canary.as_bytes())
        {
            return Err("responder receipt mismatch".into());
        }
        receipts.push(receipt);
        thread::sleep(Duration::from_millis(750));
    }
    let completion = json!({"schema_version":"1.0","status":"complete","run_id":run_id,
        "canary_sha256":sha(canary.as_bytes()),"receipt_count":receipts.len(),
        "system_information_queried_not_transmitted":!computer.is_empty(),"transmitted_fields":["marker","run_id","sequence","canary"]});
    fs::write(
        directory.join("completion.json"),
        serde_json::to_vec_pretty(&completion).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    let window = show_window();
    let result = run();
    close_window();
    let _ = window.join();
    if let Err(error) = result {
        let _ = fs::write(
            std::env::temp_dir().join("WinSTDT-validation-error.txt"),
            error,
        );
        std::process::exit(1);
    }
}
