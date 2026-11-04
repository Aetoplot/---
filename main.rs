#![cfg_attr(windows, windows_subsystem = "windows")]

mod exposure;
mod guide;
mod hsts;
mod ldb;
mod locate;
mod open;
mod redact;
mod report;
mod scan;
mod timeline;
mod ui;

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
NIKKE Launcher Check (한국어판): 2026년 11월 니케 PC 런처 침해 사고의 흔적을 찾습니다.
읽기 전용. 네트워크에 접속하지 않습니다.

사용법:
  nikke-check                  창 열기
  nikke-check 경로             창을 열고 이 폴더 점검
  nikke-check --cli            이 PC 빠른 점검, 보고서로 출력
  nikke-check --cli --full     전체 점검: 모든 로컬 드라이브의 모든 폴더 확인
  nikke-check --cli 경로...    이 폴더들만 전부 점검하고 보고서 출력
  nikke-check --cli --redact   보고서에서 컴퓨터 이름, 사용자 이름, 에이전트 ID,
                               홈 폴더를 가림 (모든 --cli 형식에 사용 가능)
  nikke-check --help           이 도움말 표시

종료 코드 (--cli):
  0  흔적 없음
  1  노출 (주의 사항만 있음)
  2  감염 (위험 흔적)
  3  니케 설치 폴더나 런처 데이터를 찾지 못함
  4  잘못된 인자, 또는 읽을 수 없는 폴더
";

fn main() -> ExitCode {
    quiet_drive_errors();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(first) = args.first() else {
        return window(None);
    };
    match first.to_str() {
        Some("--help" | "-h") => {
            attach_console();
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("--cli") => {
            attach_console();
            cli(&args[1..])
        }
        // Items dropped on the .exe in Explorer arrive here with no console to print to,
        // so the window opens and says what is wrong with a path that is not a folder.
        // shortcut: only the first dropped item is scanned, take a list if users drop several.
        arg if !arg.is_some_and(|a| a.starts_with('-')) => {
            let path = PathBuf::from(first);
            window(Some(std::path::absolute(&path).unwrap_or(path)))
        }
        _ => {
            attach_console();
            eprintln!("알 수 없는 인자: {}\n\n{USAGE}", first.to_string_lossy());
            ExitCode::from(4)
        }
    }
}

fn window(folder: Option<PathBuf>) -> ExitCode {
    skip_opengl();
    match run_window(folder) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("창을 열 수 없습니다: {err}");
            error_box(&err);
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn run_window(folder: Option<PathBuf>) -> Result<(), String> {
    ui::run(folder).map_err(|e| e.to_string())
}

/// The Windows build has no console, so a panic would close the window without
/// a word. The hook keeps the panic message for the error box.
#[cfg(windows)]
fn run_window(folder: Option<PathBuf>) -> Result<(), String> {
    use std::sync::{Arc, Mutex};
    let message = Arc::new(Mutex::new(String::new()));
    let kept = message.clone();
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Ok(mut m) = kept.lock() {
            *m = info.to_string();
        }
        default(info);
    }));
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ui::run(folder)))
        .map_err(|_| message.lock().map(|m| m.clone()).unwrap_or_default())?
        .map_err(|e| e.to_string())
}

/// Says what went wrong when the window cannot open, and how to get the report anyway.
#[cfg(windows)]
fn error_box(err: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let text = format!(
        "창을 열 수 없습니다:\n{err}\n\n창 없이 보고서를 보려면, 이 프로그램이 있는 폴더에서 PowerShell을 열고 다음을 실행하세요:\n\n{}",
        guide::powershell_cli("")
    );
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (text, title) = (wide(&text), wide(report::APP_NAME));
    // SAFETY: both strings are NUL-terminated and outlive the call; no owner window.
    unsafe {
        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
    }
}

#[cfg(not(windows))]
fn error_box(_: &str) {}

/// The absolute path of a folder argument, or exit code 4.
fn folder(path: &OsString) -> Result<PathBuf, ExitCode> {
    let path = PathBuf::from(path);
    match std::path::absolute(&path) {
        Ok(full) if full.is_dir() => {
            // A folder that cannot be listed would otherwise read as "NIKKE not found".
            if let Err(err) = std::fs::read_dir(&full) {
                eprintln!("폴더를 읽을 수 없습니다 {}: {err}", path.display());
                return Err(ExitCode::from(4));
            }
            Ok(full)
        }
        _ => {
            eprintln!("폴더가 아닙니다: {}", path.display());
            Err(ExitCode::from(4))
        }
    }
}

fn cli(args: &[OsString]) -> ExitCode {
    let redact = args.iter().any(|a| a == "--redact");
    let full = args.iter().any(|a| a == "--full");
    let mut folders = Vec::new();
    for path in args.iter().filter(|a| *a != "--redact" && *a != "--full") {
        match folder(path) {
            Ok(full) => folders.push(full),
            Err(code) => return code,
        }
    }
    let progress = locate::Progress::default();
    let result = if folders.is_empty() {
        scan::scan_computer(full, &progress)
    } else {
        scan::scan_folders(&folders, &progress)
    };
    let mut text = report::render(&result);
    if redact {
        text = redact::Secrets::of(&result).apply(&text);
    }
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
    ExitCode::from(result.verdict.exit_code())
}

/// The Windows build is a GUI program; reuse the console it was started from.
#[cfg(windows)]
fn attach_console() {
    use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
    // SAFETY: plain Win32 call with a constant argument; failure only means no console.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(windows))]
fn attach_console() {}

/// Stops Windows from showing "There is no disk in the drive" boxes when the
/// scan probes empty card readers and optical drives.
#[cfg(windows)]
fn quiet_drive_errors() {
    use windows_sys::Win32::System::Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SEM_NOOPENFILEERRORBOX, SetErrorMode};
    // SAFETY: plain Win32 call with constant flags.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    }
}

#[cfg(not(windows))]
fn quiet_drive_errors() {}

/// AMD's OpenGL driver (atio6axx.dll) can crash the process while wgpu probes its
/// backends, so on Windows the window uses DirectX 12 or Vulkan unless WGPU_BACKEND is set.
/// With neither, iced falls back to its software renderer.
#[cfg(windows)]
fn skip_opengl() {
    if std::env::var_os("WGPU_BACKEND").is_none() {
        // SAFETY: runs before the window starts any thread, so nothing reads the environment concurrently.
        unsafe { std::env::set_var("WGPU_BACKEND", "dx12,vulkan") };
    }
}

#[cfg(not(windows))]
fn skip_opengl() {}
