//! The result in plain words, for the window and the report: four answers
//! ("What happened") and the steps to take ("What to do"), built only from
//! what the scan found.

use std::path::{Path, PathBuf};

use crate::exposure::Exposure;
use crate::locate::TargetKind;
use crate::report;
use crate::scan::{self, ATTACKER_IPS, CLSID, Finding, FindingKind as K, ScanResult, Verdict};
use crate::timeline::{AgentRun, KNOWN_BUILDS, PayloadBuild, RunKind};

/// How an answer reads for the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Bad,
    Unsure,
    Good,
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub question: &'static str,
    pub reply: &'static str,
    pub tone: Tone,
    pub lines: Vec<String>,
    /// The agent's logged runs, one line each (first answer only).
    pub runs: Vec<String>,
}

/// Kinds that show the agent itself reached this computer.
const RAN: [K; 11] = [
    K::AgentRan,
    K::AgentState,
    K::PayloadDownloaded,
    K::PayloadFile,
    K::AgentServerContacted,
    K::TempFile,
    K::ChromeDll,
    K::RegistryKey,
    K::RegistryLeftover,
    K::LegacyDll,
    K::DllLoaded,
];
const PERSISTENCE: [K; 5] = [K::ChromeDll, K::RegistryKey, K::RegistryLeftover, K::LegacyDll, K::DllLoaded];
const CACHE_TRACES: [K; 4] = [K::AgentState, K::AgentServerContacted, K::LoaderCached, K::LauncherContacted];

fn findings(r: &ScanResult) -> impl Iterator<Item = &Finding> {
    r.groups.iter().flat_map(|g| &g.findings)
}

fn of<'a>(r: &'a ScanResult, kinds: &'a [K]) -> impl Iterator<Item = &'a Finding> {
    findings(r).filter(|f| kinds.contains(&f.kind))
}

fn any(r: &ScanResult, kinds: &[K]) -> bool {
    of(r, kinds).next().is_some()
}

fn push_new(lines: &mut Vec<String>, line: String) {
    if !lines.contains(&line) {
        lines.push(line);
    }
}

fn has_target(r: &ScanResult, kind: TargetKind) -> bool {
    r.targets.iter().any(|t| t.kind == kind)
}

pub fn answers(r: &ScanResult) -> [Answer; 4] {
    [did_it_run(r), still_active(r), to_clean(r), protected(r)]
}

fn answer(question: &'static str, reply: &'static str, tone: Tone, lines: Vec<String>) -> Answer {
    Answer { question, reply, tone, lines, runs: Vec::new() }
}

fn did_it_run(r: &ScanResult) -> Answer {
    const Q: &str = "이 PC에서 악성코드가 실행되었나요?";
    let mut lines = Vec::new();
    if any(r, &RAN) {
        for f in of(r, &RAN) {
            push_new(&mut lines, format!("{}.", f.title));
        }
        let mut a = answer(Q, "예", Tone::Bad, lines);
        a.runs = r.runs.iter().map(run_line).collect();
        return a;
    }
    let loader = any(r, &[K::LoaderCached, K::LauncherContacted]);
    if r.verdict == Verdict::NotFound {
        lines.push("니케 설치 폴더나 런처 데이터를 찾지 못해 확인할 대상이 없었습니다.".into());
        return answer(Q, "알 수 없음", Tone::Unsure, lines);
    }
    if r.verdict == Verdict::Infected {
        for f in findings(r).filter(|f| f.severity == scan::Severity::Critical) {
            push_new(&mut lines, format!("{}.", f.title));
        }
        lines.push("에이전트가 시작된 기록은 없지만, 로그는 삭제되거나 잘릴 수 있습니다.".into());
        return answer(Q, "알 수 없음", Tone::Unsure, lines);
    }
    if loader {
        lines.push("런처가 악성 스크립트를 불러왔지만 에이전트의 흔적은 발견되지 않았습니다.".into());
        lines.push("에이전트는 늦어도 2026년 10월 23일부터 일부 실행에서만 전송되었습니다. 그날 이후 런처를 연 적이 있다면 실행된 것으로 간주하고 대응하세요.".into());
    } else {
        lines.push("악성 스크립트나 에이전트의 흔적이 발견되지 않았습니다.".into());
    }
    if !has_target(r, TargetKind::InstallDir) {
        lines.push("니케 설치 폴더를 찾지 못해 debug.log와 다운로드 로그는 확인하지 못했습니다.".into());
    }
    let gaps = any(r, &[K::Coverage]);
    if gaps {
        lines.push("이 점검의 일부를 수행하지 못했습니다. [세부 정보]의 \"이 점검에서 확인하지 못한 것\"을 참고하세요.".into());
    }
    // A quick scan can miss an old install deeper down, so its "No" is not a clean result.
    if let Some(depth) = r.stats.depth_limit {
        lines.push(format!("빠른 점검이었으므로 {depth}단계 깊이의 폴더까지만 열었습니다. 전체 점검은 더 깊은 폴더도 확인합니다."));
    }
    if !loader {
        lines.push("아무것도 발견되지 않았다고 해서 PC가 깨끗하다는 증거는 아닙니다.".into());
    }
    let unsure = loader || gaps || r.stats.depth_limit.is_some();
    answer(Q, "아니요", if unsure { Tone::Unsure } else { Tone::Good }, lines)
}

/// One logged step of an agent run. "Hide my info" replaces the computer name
/// in the copied or saved report.
pub fn run_line(run: &AgentRun) -> String {
    let time = run.time.as_deref().unwrap_or("시각 기록 없음");
    let what = match run.kind {
        RunKind::Downloaded => match &run.file {
            Some(file) => format!("런처가 에이전트를 내려받아 {file}(으)로 저장함"),
            None => "런처가 에이전트를 내려받음".into(),
        },
        RunKind::Adopted => "에이전트가 이 PC에서 처음 실행되어 ID를 만듦".into(),
        RunKind::Resumed => "에이전트가 저장해 둔 ID로 다시 실행됨".into(),
        RunKind::Started => match &run.host {
            Some(host) => format!("에이전트가 컴퓨터 이름 {host}을(를) 공격자에게 보냄"),
            None => "에이전트가 컴퓨터 이름을 공격자에게 보냄".into(),
        },
    };
    let source = run.source.file_name().map(|n| format!(" (출처: {})", n.to_string_lossy())).unwrap_or_default();
    format!("{time}: {what}{source}")
}

fn still_active(r: &ScanResult) -> Answer {
    const Q: &str = "지금도 작동 중인 것이 있나요?";
    let mut lines = Vec::new();
    for f in findings(r) {
        let line = match f.kind {
            K::LauncherRunning => "니케 런처가 지금 실행 중입니다. 실행되는 동안 공격자가 명령을 보낼 수 있습니다.".to_string(),
            K::DllLoaded => format!("지금 {}에 악성코드의 DLL이 로드되어 있습니다.", program_names(f).join(", ")),
            K::RegistryKey => "브라우저가 악성 DLL을 불러오게 만드는 레지스트리 키가 설정되어 있습니다.".to_string(),
            K::ChromeDll | K::LegacyDll => format!("{}.", f.title),
            _ => continue,
        };
        push_new(&mut lines, line);
    }
    if lines.is_empty() {
        lines.push("런처가 실행 중이지 않고, 설치되었거나 로드되도록 설정된 DLL도 없습니다.".into());
        return answer(Q, "아니요", Tone::Good, lines);
    }
    answer(Q, "예", Tone::Bad, lines)
}

fn to_clean(r: &ScanResult) -> Answer {
    const Q: &str = "정리해야 할 것이 있나요?";
    let mut lines = Vec::new();
    for f in findings(r) {
        let line = match f.kind {
            K::ChromeDll => format!("{} DLL 폴더: {}", browser(f), dll_folder(f).display()),
            K::RegistryKey => format!("HKCU 레지스트리 키 {CLSID}."),
            K::RegistryLeftover => format!("비어 있는 HKCU 레지스트리 키 {CLSID} (악성코드가 DLL 경로를 지운 뒤 남은 것)."),
            K::LegacyDll => format!("{}의 이전 버전 DLL 파일", shown(f.path.as_deref())),
            K::TempFile => format!("{}의 k2f 파일", shown(f.path.as_deref().and_then(Path::parent))),
            _ => continue,
        };
        push_new(&mut lines, line);
    }
    for c in caches(r).iter().filter(|c| c.traces) {
        push_new(&mut lines, format!("악성코드 흔적이 남아 있는 런처 캐시: {}", c.tbs.display()));
    }
    if !lines.is_empty() {
        return answer(Q, "예", Tone::Bad, lines);
    }
    if has_target(r, TargetKind::LauncherData) {
        lines.push("악성코드가 남긴 파일은 발견되지 않았습니다. 그래도 런처를 다시 열기 전에 런처 캐시(tbs_cache)를 삭제하세요. 수정 이전의 악성 스크립트가 남아 있을 수 있습니다.".into());
    } else {
        lines.push("악성코드가 남긴 것은 발견되지 않았습니다.".into());
    }
    answer(Q, "아니요", Tone::Good, lines)
}

fn ip_line() -> String {
    format!(
        "hosts 파일로는 IP 주소를 막을 수 없고, 이 점검은 방화벽을 확인할 수 없습니다. {}와 {}를 방화벽이나 공유기에서 차단하세요.",
        ATTACKER_IPS[0], ATTACKER_IPS[1]
    )
}

fn protected(r: &ScanResult) -> Answer {
    const Q: &str = "다음을 위해 대비되어 있나요?";
    let Some(h) = &r.hosts else {
        return answer(Q, "알 수 없음", Tone::Unsure, vec!["hosts 파일을 확인하지 못했습니다.".into(), ip_line()]);
    };
    let mut lines: Vec<String> = h.note.iter().map(|n| n.to_string()).collect();
    lines.extend(h.domains.iter().map(|(d, b)| format!("{d}: hosts 파일에서 {}.", report::block_state(*b))));
    lines.push(ip_line());
    let blocked = h.domains.iter().filter(|(_, b)| *b == Some(true)).count();
    let (reply, tone) = if h.domains.iter().any(|(_, b)| b.is_none()) {
        ("알 수 없음", Tone::Unsure)
    } else if blocked == h.domains.len() {
        ("예", Tone::Good)
    } else if blocked > 0 {
        ("일부", Tone::Unsure)
    } else {
        ("아니요", Tone::Bad)
    };
    answer(Q, reply, tone, lines)
}

/// "6ae90538-3214f, uploaded ..., 205,135 bytes, one of the 5 known builds."
pub fn build_line(b: &PayloadBuild) -> String {
    let mut s = b.etag.clone().unwrap_or_else(|| "ETag 없음".into());
    match (&b.uploaded, &b.last_modified) {
        (Some(t), _) => s += &format!(", 업로드 {t}"),
        (None, Some(t)) => s += &format!(", 마지막 수정 {t}"),
        _ => {}
    }
    if let Some(size) = b.size {
        s += &format!(", {}바이트", report::thousands(size));
    }
    s += &if b.known {
        format!(", 알려진 빌드 {}개 중 하나입니다.", KNOWN_BUILDS.len())
    } else {
        format!(". 알려진 빌드 {}개 중 어느 것과도 다릅니다.", KNOWN_BUILDS.len())
    };
    if let Some(t) = &b.time {
        s += &format!(" 런처가 받은 시각: {t}.");
    }
    s
}

// ------------------------------------------------------------------ steps

#[derive(Debug, Clone)]
pub struct Step {
    pub title: String,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone)]
pub enum Part {
    Text(String),
    /// One line of a list.
    Item(String),
    /// Text to copy or type exactly: a path, a registry key, a command.
    Code(String),
    /// Buttons in the window. The report prints only a `Reveal` path that no `Code` part shows.
    Actions(Vec<Action>),
}

#[derive(Debug, Clone)]
pub enum Action {
    /// Shows this file or folder selected in the file manager.
    Reveal(PathBuf),
    Copy(&'static str, String),
    TaskManager,
    RegistryEditor,
    SaveReport,
    CopyReport,
    ScanFolder,
    FullScan,
}

fn text(s: impl Into<String>) -> Part {
    Part::Text(s.into())
}

fn step(title: impl Into<String>, parts: Vec<Part>) -> Step {
    Step { title: title.into(), parts }
}

/// The launcher runs or a program has the DLL loaded: the window opens on the steps.
pub fn act_now(r: &ScanResult) -> bool {
    any(r, &[K::LauncherRunning, K::DllLoaded])
}

pub fn steps(r: &ScanResult) -> Vec<Step> {
    let found = r.verdict != Verdict::NotFound;
    // Scanning the install reads debug.log, which can turn the result into Infected.
    let rescan = found && !has_target(r, TargetKind::InstallDir);
    let mut out = Vec::new();
    if !found {
        out.push(scan_folder_step(r));
    }
    if act_now(r) {
        out.push(close_step(r));
    }
    if matches!(r.verdict, Verdict::Infected | Verdict::Exposed) {
        // Before the DLL step: its restart closes this window.
        out.push(save_step(r, restart_first(r)));
    }
    // After a quick scan without proof of the agent, the full scan is the next check.
    let quick_unsure = matches!(r.verdict, Verdict::NoTraces | Verdict::Exposed) && r.stats.depth_limit.is_some();
    if rescan && r.verdict != Verdict::Infected {
        out.push(scan_folder_step(r));
    } else if quick_unsure {
        out.push(step("전체 점검 실행", full_scan_parts(r)));
    }
    if any(r, &PERSISTENCE) {
        out.push(dll_step(r));
    }
    if found {
        out.push(cache_step(r));
        out.push(password_step(r));
    }
    out.push(block_step(r));
    if rescan && r.verdict == Verdict::Infected {
        out.push(scan_folder_step(r));
    }
    out.push(wait_step(r.verdict == Verdict::Infected && any(r, &RAN)));
    out
}

/// The PowerShell command that runs this program with `--cli`, from the folder
/// that holds it. A browser saves a second download as "<name> (1).exe".
pub fn powershell_cli(args: &str) -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "nikke-check-windows-x86_64.exe".into());
    ps_command(&exe, args)
}

fn ps_command(exe: &str, args: &str) -> String {
    format!("& '.\\{}' --cli{args} | Out-Host", exe.replace('\'', "''"))
}

fn scan_folder_step(r: &ScanResult) -> Step {
    const INTRO: &str = "다른 드라이브 등 이 점검이 보지 않은 곳에 니케가 설치되어 있다면, 그 폴더를 점검하세요";
    let mut parts = if cfg!(windows) {
        let cmd = powershell_cli(r" 'D:\Games\NIKKE'");
        vec![
            text(format!("{INTRO}. \"폴더 점검...\" 버튼을 쓰거나, 이 프로그램이 있는 폴더에서 PowerShell로 아래 명령을 실행해도 됩니다. D:\\Games\\NIKKE 자리에 니케 폴더 경로를 넣으세요.")),
            Part::Code(cmd.clone()),
            Part::Actions(vec![Action::ScanFolder, Action::Copy("명령 복사", cmd)]),
        ]
    } else {
        vec![
            text(format!("{INTRO}: 창에서 \"폴더 점검...\"을 쓰거나, 터미널에서 nikke-check --cli <폴더> 를 실행하세요.")),
            Part::Actions(vec![Action::ScanFolder]),
        ]
    };
    parts.extend(full_scan_parts(r));
    step("니케가 설치된 폴더 점검", parts)
}

/// After a quick scan: what the full scan adds, its button and its command.
fn full_scan_parts(r: &ScanResult) -> Vec<Part> {
    let Some(depth) = r.stats.depth_limit else {
        return Vec::new();
    };
    let mut parts = vec![text(format!("빠른 점검이었으므로 {depth}단계 깊이의 폴더까지만 열었습니다. 니케 위치를 모르거나 이전 설치본이 더 깊은 곳에 있을 수 있다면, 전체 점검으로 모든 로컬 드라이브의 모든 폴더를 확인하세요. 큰 드라이브에서는 오래 걸릴 수 있습니다."))];
    if cfg!(windows) {
        let cmd = powershell_cli(" --full");
        parts.push(text("이 프로그램이 있는 폴더에서 PowerShell로:"));
        parts.push(Part::Code(cmd.clone()));
        parts.push(Part::Actions(vec![Action::FullScan, Action::Copy("명령 복사", cmd)]));
    } else {
        parts.push(text("터미널에서: nikke-check --cli --full"));
        parts.push(Part::Actions(vec![Action::FullScan]));
    }
    parts
}

fn close_step(r: &ScanResult) -> Step {
    let mut parts = Vec::new();
    let mut programs = Vec::new();
    if any(r, &[K::LauncherRunning]) {
        parts.push(text("니케 런처가 실행 중입니다. 실행되는 동안 공격자가 이 PC에 명령을 보낼 수 있습니다. 지금 바로 런처를 종료하고 인터넷 연결을 끊으세요."));
        programs.push("nikke_launcher.exe".to_string());
    }
    let mut explorer = false;
    for f in of(r, &[K::DllLoaded]) {
        let names = program_names(f);
        let (has, them) = if names.len() == 1 { ("", "") } else { ("", "") };
        parts.push(text(format!("{}에 악성코드의 DLL이 로드되어 있습니다{has}. 가능하면 종료하세요{them}. 이후 단계의 재부팅으로 모든 프로그램에서 DLL이 내려갑니다.", names.join(", "))));
        for name in names {
            if name.eq_ignore_ascii_case("explorer.exe") {
                explorer = true;
            } else {
                push_new(&mut programs, name);
            }
        }
    }
    if explorer {
        parts.push(text("explorer.exe는 종료하지 마세요. 작업 표시줄과 바탕화면을 실행하는 프로그램입니다. 재부팅하면 DLL이 내려갑니다."));
    }
    if !programs.is_empty() {
        parts.push(text(format!("종료할 프로그램: {}.", programs.join(", "))));
    }
    if cfg!(windows) {
        if !programs.is_empty() {
            parts.push(text("프로그램이 종료되지 않으면 작업 관리자(Ctrl+Shift+Esc)를 열고 [세부 정보] 탭에서 해당 프로그램을 선택한 뒤 [작업 끝내기]를 누르세요."));
            parts.push(Part::Actions(vec![Action::TaskManager]));
        }
    } else {
        let cmd = "pkill -f nikke_launcher.exe";
        parts.push(text("런처가 종료되지 않으면 터미널에서 이 명령을 실행하세요:"));
        parts.push(Part::Code(cmd.into()));
        parts.push(Part::Actions(vec![Action::Copy("명령 복사", cmd.into())]));
    }
    let title = if any(r, &[K::LauncherRunning]) { "런처 종료" } else { "악성코드를 실행 중인 프로그램 종료" };
    step(title, parts)
}

fn save_step(r: &ScanResult, restart: bool) -> Step {
    let mut why = String::new();
    if any(r, &[K::AgentState]) {
        why += " tbs_cache를 삭제하면 k2f.agent.state 흔적도 함께 지워집니다.";
    } else if caches(r).iter().any(|c| c.traces) {
        why += " tbs_cache를 삭제하면 이 점검이 그 안에서 찾은 흔적도 함께 지워집니다.";
    }
    if restart {
        why += " 다음 단계의 재부팅으로 이 창이 닫힙니다.";
    }
    step(
        "삭제하기 전에 보고서 저장",
        vec![
            text(format!("보고서는 이 점검에서 발견한 내용의 기록입니다.{why}")),
            text("다른 사람과 공유하기 전에 \"내 정보 가리기\"(명령줄에서는 --redact)를 켜세요. 복사·저장되는 보고서에서 컴퓨터 이름, 사용자 이름, 에이전트 ID, 홈 폴더를 가립니다. 창에는 그대로 표시됩니다."),
            Part::Actions(vec![Action::SaveReport, Action::CopyReport]),
        ],
    )
}

/// The browser name from a ChromeDll title ("Edge persistence is installed").
fn browser(f: &Finding) -> &str {
    f.title.strip_suffix(" 지속성 장치가 설치됨").unwrap_or("Chrome")
}

/// The folder to delete for a ChromeDll finding: the 64-hex folder that holds the DLL.
fn dll_folder(f: &Finding) -> PathBuf {
    let Some(open) = f.open_path.as_deref().or(f.path.as_deref()) else {
        return PathBuf::new();
    };
    let is_dll = open.file_name().is_some_and(|n| n.eq_ignore_ascii_case("platform_experience_helper.dll"));
    match open.parent() {
        Some(parent) if is_dll && parent.file_name().is_some_and(|n| is_hex64(&n.to_string_lossy())) => parent.to_path_buf(),
        _ => open.to_path_buf(),
    }
}

fn is_hex64(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Outside Windows, the files of `f` are in a Wine prefix or on a Windows drive
/// seen from this system.
fn in_prefix(r: &ScanResult, f: &Finding) -> bool {
    f.path.as_deref().is_some_and(|p| {
        r.targets.iter().any(|t| t.kind == TargetKind::WinePrefix && p.starts_with(&t.path))
            || p.components().any(|c| c.as_os_str().eq_ignore_ascii_case("drive_c"))
    })
}

/// On Windows, the files can be deleted only after a restart while the key is
/// set or a program has the DLL loaded: Windows keeps a loaded DLL locked.
fn restart_first(r: &ScanResult) -> bool {
    cfg!(windows) && (any(r, &[K::DllLoaded]) || (any(r, &[K::RegistryKey]) && any(r, &[K::ChromeDll, K::LegacyDll])))
}

/// `'text'` for a POSIX shell.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The Steam game ID of a Proton prefix (`compatdata/<id>/pfx`).
fn steam_game_id(prefix: &Path) -> Option<String> {
    let parts: Vec<String> = prefix.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    parts
        .windows(3)
        .find(|w| w[0] == "compatdata" && w[2] == "pfx" && !w[1].is_empty() && w[1].bytes().all(|b| b.is_ascii_digit()))
        .map(|w| w[1].clone())
}

fn dll_step(r: &ScanResult) -> Step {
    let mut browsers: Vec<&str> = Vec::new();
    for f in of(r, &[K::ChromeDll]) {
        if !browsers.contains(&browser(f)) {
            browsers.push(browser(f));
        }
    }
    if browsers.is_empty() {
        browsers.push("Chrome");
    }
    let keys: Vec<String> = of(r, &[K::RegistryKey, K::RegistryLeftover])
        .filter_map(|f| f.copy_text.as_deref())
        .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
        .fold(Vec::new(), |mut v, k| {
            push_new(&mut v, k);
            v
        });
    let leftover = any(r, &[K::RegistryLeftover]);
    let (dll, legacy, loaded) = (any(r, &[K::ChromeDll]), any(r, &[K::LegacyDll]), any(r, &[K::DllLoaded]));
    let files = dll || legacy || loaded;
    let restart = restart_first(r);
    let wine = !cfg!(windows) && of(r, &PERSISTENCE).any(|f| in_prefix(r, f));
    let drive = !cfg!(windows) && of(r, &[K::ChromeDll, K::LegacyDll]).any(|f| !in_prefix(r, f));
    let mut parts = Vec::new();
    let mut n = 0;
    let mut num = |s: &str| {
        n += 1;
        text(format!("{n}. {s}"))
    };
    if cfg!(windows) {
        if any(r, &[K::RegistryKey]) || loaded {
            let why = if loaded { "지금 프로그램에 DLL이 로드되어 있음" } else { "키가 설정되어 있는 동안 브라우저가 시작할 때마다 DLL을 불러옴" };
            parts.push(text(format!("이 단계를 마칠 때까지 PC를 오프라인으로 유지하세요: {why}.")));
        }
        if restart && !keys.is_empty() {
            parts.push(text("이 순서대로 하세요. Windows는 재부팅 전까지 DLL을 잠가 두므로 레지스트리 키를 먼저 지웁니다."));
        }
        if !keys.is_empty() {
            parts.push(num("레지스트리 키를 삭제하세요. 레지스트리 편집기를 열고(Win+R → regedit 입력 → Enter), 아래 키 경로를 위쪽 주소 표시줄에 붙여 넣고 Enter를 누르세요. 왼쪽에서 선택된 키를 마우스 오른쪽 버튼으로 클릭하고 [삭제]를 고르세요."));
            for (i, key) in keys.iter().enumerate() {
                parts.push(Part::Code(key.clone()));
                let mut actions = vec![Action::Copy("키 경로 복사", key.clone())];
                if i == 0 {
                    actions.push(Action::RegistryEditor);
                }
                parts.push(Part::Actions(actions));
            }
            if leftover {
                parts.push(text("비어 있는 키는 남은 찌꺼기입니다. 악성코드가 DLL 경로는 지웠지만 키는 남겨 두었습니다. 같은 방법으로 삭제하세요."));
            }
        }
        if restart {
            parts.push(num("Windows를 다시 시작하세요. 그다음 이 도구를 다시 열어 점검하면 남은 삭제 대상이 표시됩니다."));
        }
    } else {
        if wine {
            let what = if files { "이 파일들은" } else { "이 키는" };
            parts.push(text(format!("{what} Wine 프리픽스 안에 있습니다. 먼저 런처와 그 프리픽스의 다른 프로그램을 모두 종료하세요.")));
        }
        if drive {
            parts.push(text("이 파일들은 이 시스템에서 보이는 Windows 드라이브에 있습니다. 그 Windows가 실행 중이 아니므로 DLL이 잠겨 있지 않아 여기서 삭제할 수 있습니다. 이 시스템에서 그 드라이브의 파일을 지울 수 없다면(Windows 빠른 시작이 드라이브를 읽기 전용으로 남겨 둠) 그 Windows에서 이 단계를 하세요: 키 삭제 → 재부팅 → 파일 삭제."));
        }
    }
    let delete = if restart { "재부팅한 뒤" } else { "지금" };
    let in_use = if cfg!(windows) && !restart { " Windows에서 파일이 사용 중이라고 하면 Windows를 다시 시작한 뒤 다시 삭제하세요." } else { "" };
    if dll {
        parts.push(num(&format!("{delete} 아래의 DLL 폴더(64자리 16진수 이름의 폴더)를 삭제하세요. PlatformExperienceHelper 폴더의 나머지는 그대로 두세요. Chrome이 자체 platform_experience_helper.exe와 LoadFeatures를 그곳에 둡니다.{in_use}")));
        for f in of(r, &[K::ChromeDll]) {
            let folder = dll_folder(f);
            parts.push(Part::Code(folder.display().to_string()));
            parts.push(Part::Actions(vec![Action::Reveal(folder)]));
        }
    }
    if legacy {
        parts.push(num(&format!("아래 폴더에서 {} platform_experience_helper.dll, platform_experience_helper.dll.old, old-clsid.txt 중 있는 것만 삭제하세요. platform_experience_helper.exe는 Chrome 것이므로 남겨 두세요.{in_use}", delete.to_lowercase())));
        for f in of(r, &[K::LegacyDll]) {
            parts.push(Part::Code(shown(f.path.as_deref())));
            parts.extend(f.open_path.clone().map(|p| Part::Actions(vec![Action::Reveal(p)])));
        }
    }
    // The files can be gone while a program still has the DLL loaded.
    if loaded && !dll && !legacy {
        parts.push(num(&format!("{delete} 아래의 DLL 파일을 삭제하세요.{in_use}")));
        for f in of(r, &[K::DllLoaded]) {
            parts.push(Part::Code(shown(f.open_path.as_deref())));
            parts.extend(f.open_path.clone().map(|p| Part::Actions(vec![Action::Reveal(p)])));
        }
    }
    if wine && !keys.is_empty() {
        parts.push(num(&format!("프리픽스의 user.reg 파일에서 레지스트리 키를 삭제하세요. 아래 명령으로 그 프리픽스의 Wine regedit를 열고 HKEY_CURRENT_USER\\Software\\Classes\\CLSID로 가서 {CLSID} 키를 삭제하세요.")));
        for f in of(r, &[K::RegistryKey, K::RegistryLeftover]) {
            let Some(reg) = f.path.as_deref() else {
                continue;
            };
            let prefix = reg.parent().unwrap_or(reg);
            let cmd = format!("WINEPREFIX={} wine regedit", sh_quote(&prefix.display().to_string()));
            parts.push(Part::Code(cmd.clone()));
            parts.push(Part::Actions(vec![Action::Copy("명령 복사", cmd), Action::Reveal(reg.to_path_buf())]));
            if let Some(id) = steam_game_id(prefix) {
                let cmd = format!("protontricks -c 'wine regedit' {id}");
                parts.push(text("Steam Deck처럼 Wine이 설치되어 있지 않으면, protontricks로 이 Proton 프리픽스의 regedit를 열 수 있습니다:"));
                parts.push(Part::Code(cmd.clone()));
                parts.push(Part::Actions(vec![Action::Copy("명령 복사", cmd)]));
            }
        }
    }
    if drive {
        parts.push(num("그 Windows를 시작해서 아래 레지스트리 키(그리고 있으면 WOW6432Node 사본)를 삭제하세요. 이 점검은 그 Windows의 레지스트리를 읽을 수 없었습니다. 레지스트리 편집기를 열고(Win+R → regedit 입력 → Enter), 키 경로를 위쪽 주소 표시줄에 붙여 넣고 Enter를 누르세요. 왼쪽에서 선택된 키를 마우스 오른쪽 버튼으로 클릭하고 [삭제]를 고르세요."));
        for key in scan::CLSID_KEYS {
            parts.push(Part::Code(key.into()));
            parts.push(Part::Actions(vec![Action::Copy("키 경로 복사", key.into())]));
        }
    }
    let defender = if cfg!(windows) || drive {
        " 감염된 PC 한 대에서 Microsoft Defender가 이 DLL을 탐지하지 못했습니다. 백신 검사 결과가 깨끗하다고 해서 DLL이 사라졌다는 뜻은 아닙니다."
    } else {
        ""
    };
    parts.push(text(format!("그다음 다시 점검하세요. 이 발견 사항들이 사라져야 합니다.{defender}")));
    let title = if files {
        format!("{} DLL 제거", browsers.join(", "))
    } else if leftover && !any(r, &[K::RegistryKey]) {
        "남은 레지스트리 키 삭제".into()
    } else {
        "레지스트리 키 삭제".into()
    };
    step(title, parts)
}

/// A launcher data folder and its browser cache.
struct Cache {
    tbs: PathBuf,
    traces: bool,
}

fn caches(r: &ScanResult) -> Vec<Cache> {
    r.targets
        .iter()
        .filter(|t| t.kind == TargetKind::LauncherData)
        .map(|t| Cache {
            tbs: t.path.join("tbs_cache"),
            traces: r
                .groups
                .iter()
                .filter(|g| g.path.as_deref() == Some(t.path.as_path()))
                .flat_map(|g| &g.findings)
                .any(|f| CACHE_TRACES.contains(&f.kind)),
        })
        .collect()
}

fn cache_step(r: &ScanResult) -> Step {
    let mut parts = vec![text("먼저 런처를 종료하세요. 그다음 런처 내장 브라우저의 캐시인 tbs_cache 폴더를 삭제하세요. 수정 이전의 악성 스크립트가 남아 있을 수 있고, 런처가 그것을 다시 불러올 수 있습니다.")];
    let caches = caches(r);
    if caches.is_empty() {
        parts.push(text("이 점검에서 런처 데이터 폴더를 찾지 못했습니다. Windows에서는 %APPDATA%\\nikke_launcher\\tbs_cache(HMT 런처는 nikke_launcher_hmt)이고, Proton·Wine 프리픽스 안에서는 drive_c/users/<user>/AppData/Roaming/nikke_launcher/tbs_cache 입니다."));
    }
    for c in caches {
        parts.push(Part::Code(c.tbs.display().to_string()));
        parts.push(Part::Actions(vec![Action::Reveal(c.tbs)]));
    }
    step("런처 캐시 삭제", parts)
}

/// The accounts and secrets to change, from what the agent could read.
pub fn password_list(r: &ScanResult) -> Vec<String> {
    let none = Exposure::default();
    let e = r.exposure.as_ref().unwrap_or(&none);
    let mut out = vec!["니케 / 레벨 인피니트 계정을 가장 먼저, 그다음 이메일, Discord, 은행.".to_string()];
    let mut browsers: Vec<(&str, Vec<&str>)> = Vec::new();
    for l in &e.logins {
        match browsers.iter_mut().find(|(b, _)| *b == l.browser) {
            Some((_, profiles)) => profiles.push(&l.profile),
            None => browsers.push((l.browser, vec![&l.profile])),
        }
    }
    if browsers.is_empty() {
        out.push("브라우저에 저장된 모든 비밀번호.".into());
    }
    for (b, profiles) in browsers {
        let label = if profiles.len() == 1 { "프로필" } else { "프로필" };
        out.push(format!("{b}에 저장된 모든 비밀번호 ({label} {}).", profiles.join(", ")));
    }
    out.push("그 서비스들의 모든 세션에서 로그아웃하세요. 에이전트는 브라우저 쿠키를 수집할 수 있고, 훔친 쿠키는 비밀번호 없이도 작동합니다.".into());
    if e.wallets.is_empty() {
        out.push("암호화폐가 있다면, 다른 기기에서 새 시드 구문으로 만든 새 지갑으로 옮기세요.".into());
    }
    for w in &e.wallets {
        out.push(format!("{} ({}, 프로필 {}): 다른 기기에서 새 시드 구문으로 만든 새 지갑으로 자금을 옮기세요.", w.name, w.browser, w.profile));
    }
    if e.secrets.is_empty() {
        out.push("이 PC에 저장된 API 토큰과 SSH 키를 폐기하세요.".into());
    }
    for s in &e.secrets {
        out.push(format!("폐기 후 재발급: {}, {}.", s.what, s.path.display()));
    }
    if !e.wallets.is_empty() || !e.secrets.is_empty() {
        out.push("이 PC에 저장된 그 밖의 모든 비밀번호, API 토큰, SSH 키, 지갑.".into());
    }
    if cfg!(unix) && has_target(r, TargetKind::WinePrefix) {
        out.push("Wine에서는 에이전트가 Wine 프리픽스뿐 아니라 Z: 드라이브를 통해 홈 폴더 전체와 런처 프로세스의 환경 변수까지 읽을 수 있었습니다.".into());
    }
    out.extend(home_note(r).map(str::to_string));
    out
}

/// A folder scan that found a Wine prefix also checks this computer's home
/// folder, but the prefix may have been copied from another computer.
pub fn home_note(r: &ScanResult) -> Option<&'static str> {
    (cfg!(unix) && r.scope != scan::COMPUTER_SCOPE && r.exposure.is_some() && has_target(r, TargetKind::WinePrefix)).then_some(
        "Wine 프리픽스가 발견되어 이 PC의 홈 폴더를 확인했습니다. 점검한 프리픽스가 다른 PC에서 실행된 것이라면 그 PC를 확인하세요.",
    )
}

fn password_step(r: &ScanResult) -> Step {
    let intro = match r.verdict {
        Verdict::Infected => "니케 런처를 한 번도 실행하지 않은 휴대폰이나 다른 PC를 쓰세요. 에이전트가 실행되는 동안 그 명령으로 이 PC의 파일과 브라우저 데이터를 읽을 수 있었습니다. 다음을 변경하거나 교체하세요:",
        Verdict::Exposed => "에이전트는 늦어도 2026년 10월 23일부터 일부 실행에서만 전송되었습니다. 그날 이후 런처를 연 적이 있다면 실행된 것으로 간주하고, 런처를 실행한 적 없는 휴대폰이나 다른 PC에서 다음을 변경하거나 교체하세요:",
        _ => {
            return step(
                "10월 23일 이후 런처를 열었다면 니케 비밀번호 변경",
                vec![text("2026년 10월 23일 이후 런처를 연 적이 있다면, 런처를 실행한 적 없는 휴대폰이나 다른 PC에서 니케 / 레벨 인피니트 비밀번호를 바꾸세요.")],
            );
        }
    };
    let list = password_list(r);
    let mut parts = vec![text(intro)];
    parts.extend(list.iter().cloned().map(Part::Item));
    if r.exposure.as_ref().is_some_and(|e| !e.logins.is_empty() || !e.wallets.is_empty() || !e.secrets.is_empty()) {
        parts.push(text("이 점검은 이 파일들이 있는지만 확인했습니다. 파일을 열지는 않았습니다."));
    }
    parts.push(Part::Actions(vec![Action::Copy("목록 복사", list.join("\n"))]));
    step("다른 기기에서 비밀번호 변경", parts)
}

fn block_step(r: &ScanResult) -> Step {
    let lines = match &r.hosts {
        Some(h) => report::block_lines(h),
        None => scan::DOMAINS.iter().map(|d| format!("0.0.0.0 {d}")).collect(),
    };
    let mut parts = Vec::new();
    let title = if lines.is_empty() {
        parts.push(text("hosts 파일이 세 도메인을 모두 차단하고 있습니다."));
        "공격자 IP 주소 차단"
    } else {
        if cfg!(windows) {
            let hosts = scan::hosts_path().display().to_string();
            parts.push(text("시작 메뉴에서 메모장을 검색해 마우스 오른쪽 버튼 → [관리자 권한으로 실행]을 고르세요. 메모장에서 [파일] > [열기]를 누르고, 아래 hosts 파일 경로를 [파일 이름] 칸에 붙여 넣은 뒤 Enter를 누르세요."));
            parts.push(Part::Code(hosts.clone()));
            parts.push(Part::Actions(vec![Action::Copy("hosts 경로 복사", hosts)]));
            parts.push(text("파일 맨 끝에 아래 줄을 붙여 넣고 저장하세요:"));
            parts.push(Part::Code(lines.join("\n")));
            parts.push(Part::Actions(vec![Action::Copy("이 줄 복사", lines.join("\n"))]));
        } else {
            let cmd = format!("printf '\\n{}\\n' | sudo tee -a /etc/hosts", lines.join("\\n"));
            let deck = if cfg!(target_os = "macos") { "" } else { " Steam Deck에서 비밀번호를 정한 적이 없다면 먼저 passwd로 정하세요." };
            parts.push(text(format!("터미널에서 이 명령을 실행하세요. /etc/hosts에 줄을 추가하며 비밀번호를 묻습니다.{deck}")));
            parts.push(Part::Code(cmd.clone()));
            parts.push(Part::Actions(vec![Action::Copy("명령 복사", cmd)]));
        }
        parts.push(text("그다음 다시 점검하면 [세부 정보]의 보호 항목에 각 도메인이 차단됨으로 표시됩니다."));
        "도메인 차단"
    };
    let [a, b] = ATTACKER_IPS;
    parts.push(text(format!("hosts 파일로는 IP 주소를 막을 수 없습니다. {a}와 {b}를 방화벽이나 공유기에서 차단하세요.")));
    if cfg!(windows) {
        let cmd = format!("New-NetFirewallRule -DisplayName \"Block NIKKE malware servers\" -Direction Outbound -RemoteAddress {a},{b} -Action Block");
        parts.push(text("Windows 방화벽 규칙을 추가하려면 시작 버튼을 마우스 오른쪽 버튼으로 클릭해 [터미널(관리자)] 또는 [Windows PowerShell(관리자)]를 고르고 다음을 실행하세요:"));
        parts.push(Part::Code(cmd.clone()));
        parts.push(Part::Actions(vec![Action::Copy("명령 복사", cmd)]));
    } else if cfg!(target_os = "macos") {
        parts.push(text("macOS에서는 공유기 설정에서 차단하세요."));
    } else {
        let cmd = format!("sudo ufw deny out to {a} && sudo ufw deny out to {b}");
        parts.push(text("ufw가 있다면 이 명령을 실행하세요. ufw가 꺼져 있으면 규칙이 아무것도 막지 않습니다. sudo ufw status에 \"Status: active\"가 보여야 하며, sudo ufw enable로 켤 수 있습니다. ufw가 없다면 공유기 설정에서 차단하세요."));
        parts.push(Part::Code(cmd.clone()));
        parts.push(Part::Actions(vec![Action::Copy("명령 복사", cmd)]));
    }
    step(title, parts)
}

fn wait_step(agent_ran: bool) -> Step {
    let mut parts = vec![text("2026년 11월 3일에도 레벨 인피니트의 일부 서버가 악성 파일을 보냈습니다. 수정 이전 상태로 실행하면 스크립트를 다시 불러올 수 있습니다.")];
    if agent_ran {
        parts.push(text("에이전트는 어떤 명령이든 실행할 수 있었으므로, 운영체제를 다시 설치하는 것이 이 PC가 깨끗하다고 확신할 수 있는 가장 안전한 방법입니다."));
    }
    step("레벨 인피니트가 수정을 확인하기 전까지 런처를 열지 마세요", parts)
}

fn shown(path: Option<&Path>) -> String {
    path.map(|p| p.display().to_string()).unwrap_or_default()
}

/// Program names from DllLoaded evidence ("PID 12: chrome.exe (C:\...) has ... loaded").
fn program_names(f: &Finding) -> Vec<String> {
    let mut names: Vec<String> = f
        .evidence
        .iter()
        .filter_map(|e| e.strip_prefix("PID ")?.split_once(": ")?.1.split(" (").next().map(str::to_string))
        .collect();
    names.sort();
    names.dedup();
    names
}

// ---------------------------------------------------------------- details

/// The groups of the Details tab, in order. Exposure comes after `Signs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Proof,
    Cleanup,
    Signs,
    Info,
    Coverage,
}

impl Section {
    pub const ALL: [Section; 5] = [Section::Proof, Section::Cleanup, Section::Signs, Section::Info, Section::Coverage];

    pub fn of(kind: K) -> Self {
        match kind {
            K::AgentRan | K::PayloadDownloaded | K::PayloadFile | K::AgentState | K::AgentServerContacted => Section::Proof,
            K::ChromeDll | K::RegistryKey | K::RegistryLeftover | K::LegacyDll | K::DllLoaded | K::TempFile | K::LauncherRunning => {
                Section::Cleanup
            }
            K::LoaderCached | K::LauncherContacted => Section::Signs,
            K::Coverage => Section::Coverage,
            K::Info => Section::Info,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Section::Proof => "악성코드가 실행된 증거",
            Section::Cleanup => "정리할 것",
            Section::Signs => "노출 징후",
            Section::Info => "참고 정보",
            Section::Coverage => "이 점검에서 확인하지 못한 것",
        }
    }
}

pub const EXPOSURE_TITLE: &str = "악성코드가 접근할 수 있었던 내 데이터";

/// One line on what a finding means for the user.
pub fn meaning(kind: K) -> &'static str {
    match kind {
        K::AgentRan => "런처 안에서 에이전트가 실행되었습니다. 런처가 열려 있는 동안 공격자가 이 PC를 제어할 수 있었습니다.",
        K::PayloadDownloaded => "런처가 공격자 서버에서 에이전트를 받았습니다.",
        K::PayloadFile => "에이전트 사본이 아직 런처의 로그 폴더에 있습니다.",
        K::AgentState => "에이전트가 런처의 브라우저 저장소에 ID를 저장했으므로, 최소 한 번은 실행되었습니다.",
        K::AgentServerContacted => "런처가 에이전트를 보내는 서버에 접속했으므로, 에이전트를 요청하는 단계까지 진행되었습니다.",
        K::LoaderCached => "런처에서 악성 스크립트가 실행되었습니다. 이것만으로는 에이전트가 전송되었다는 뜻은 아닙니다.",
        K::LauncherContacted => "런처가 공격자의 도메인에 접속했습니다.",
        K::ChromeDll => "브라우저가 시작할 때 이 DLL을 불러오므로, 런처 없이도 악성코드가 다시 실행될 수 있습니다. 악성코드는 Chrome이 설치되어 있지 않아도 Chrome 폴더를 만듭니다.",
        K::RegistryKey => "이 키가 브라우저로 하여금 악성코드의 DLL을 불러오게 합니다.",
        K::RegistryLeftover => "이 키에서 DLL 경로는 지워졌지만 키는 아직 남아 있습니다. 삭제하세요.",
        K::LegacyDll => "이전 버전의 에이전트가 이곳에 DLL을 두었습니다.",
        K::DllLoaded => "이 프로그램들이 지금 악성코드의 DLL을 실행하고 있습니다. 프로그램이 종료되거나 Windows가 다시 시작될 때까지 로드된 상태로 남습니다.",
        K::TempFile => "에이전트가 브라우저 자격 증명이나 스크린샷을 수집하면서 이 파일들을 만들었습니다.",
        K::LauncherRunning => "런처가 실행되는 동안 공격자가 명령을 보낼 수 있습니다.",
        K::Coverage => "이 점검의 일부를 수행하지 못했습니다. 위의 안내를 따르세요.",
        K::Info => "참고용입니다. 판정에는 영향을 주지 않습니다.",
    }
}

/// The exposure lists of the Details tab: (heading, [(what, path)]).
pub fn exposure_lists(e: &Exposure) -> [(&'static str, Vec<(String, PathBuf)>); 3] {
    [
        (
            "저장된 비밀번호",
            e.logins.iter().map(|l| (format!("{}, 프로필 {} ({})", l.browser, l.profile, l.files.join(", ")), l.path.clone())).collect(),
        ),
        (
            "지갑 확장 프로그램",
            e.wallets.iter().map(|w| (format!("{} ({}) — {}, 프로필 {}", w.name, w.id, w.browser, w.profile), w.path.clone())).collect(),
        ),
        ("비밀 정보 파일", e.secrets.iter().map(|s| (s.what.to_string(), s.path.clone())).collect()),
    ]
}

pub const EXPOSURE_NOTE: &str = "이 점검은 이 파일들이 있는지만 확인했고, 열지는 않았습니다. 에이전트가 실행되는 동안에는 그 명령으로 이 파일들을 읽을 수 있었습니다.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locate::{Target, WalkStats};
    use crate::scan::{Group, HostsStatus, Severity};

    fn finding(kind: K, severity: Severity, title: &str) -> Finding {
        Finding {
            kind,
            severity,
            title: title.into(),
            detail: String::new(),
            path: None,
            open_path: None,
            copy_text: None,
            evidence: Vec::new(),
            time: None,
        }
    }

    fn result(verdict: Verdict, findings: Vec<Finding>, targets: Vec<(TargetKind, &str)>) -> ScanResult {
        ScanResult {
            scope: "test".into(),
            started: "2026-11-04 10:00:00 UTC".into(),
            verdict,
            targets: targets.into_iter().map(|(kind, p)| Target { kind, path: PathBuf::from(p), host: false }).collect(),
            groups: vec![Group { label: "Launcher data".into(), path: Some(PathBuf::from("/d/nikke_launcher")), findings }],
            hosts: Some(HostsStatus {
                path: PathBuf::from("/etc/hosts"),
                note: None,
                domains: vec![("insightjs.com", Some(true)), ("analytics.insightjs.com", Some(false)), ("insightjs.org", Some(false))],
            }),
            stats: WalkStats::default(),
            seconds: 0.0,
            runs: Vec::new(),
            builds: Vec::new(),
            exposure: None,
        }
    }

    fn titles(r: &ScanResult) -> Vec<String> {
        steps(r).into_iter().map(|s| s.title).collect()
    }

    #[test]
    fn steps_follow_the_findings() {
        let mut dll = finding(K::ChromeDll, Severity::Critical, "Edge persistence is installed");
        let hash = "a".repeat(64);
        dll.path = Some(PathBuf::from("/p/PlatformExperienceHelper"));
        dll.open_path = Some(PathBuf::from(format!("/p/PlatformExperienceHelper/{hash}/platform_experience_helper.dll")));
        let mut loaded = finding(K::DllLoaded, Severity::Critical, "The persistence DLL is loaded now");
        loaded.evidence = vec!["PID 9: msedge.exe (C:\\e\\msedge.exe) has C:\\x.dll loaded".into(), "PID 4: explorer.exe (C:\\explorer.exe) has C:\\x.dll loaded".into()];
        let infected = result(
            Verdict::Infected,
            vec![dll, loaded, finding(K::AgentState, Severity::Critical, "Agent state")],
            vec![(TargetKind::InstallDir, "/n"), (TargetKind::LauncherData, "/d/nikke_launcher")],
        );
        assert_eq!(
            titles(&infected),
            [
                "Close the programs that run the malware",
                "Save the report before you delete anything",
                "Remove the Edge DLL",
                "Clear the launcher cache",
                "Change your passwords from another device",
                "Block the domains",
                "Do not open the launcher until Level Infinite confirms a fix",
            ]
        );
        let all = steps(&infected);
        let codes: Vec<&str> = all.iter().flat_map(|s| &s.parts).filter_map(|p| if let Part::Code(c) = p { Some(c.as_str()) } else { None }).collect();
        assert!(codes.contains(&format!("/p/PlatformExperienceHelper/{hash}").as_str()), "{codes:?}");
        let cache = Path::new("/d/nikke_launcher").join("tbs_cache").display().to_string();
        assert!(codes.contains(&cache.as_str()), "{codes:?}");
        let close = format!("{:?}", all[0].parts);
        assert!(close.contains("Programs to end: msedge.exe.") && close.contains("Do not end explorer.exe"), "{close}");
        let [ran, active, clean, protect] = answers(&infected);
        assert_eq!((ran.reply, active.reply, clean.reply, protect.reply), ("Yes", "Yes", "Yes", "Partly"));
        assert!(clean.lines.iter().any(|l| l.contains("tbs_cache")), "{:?}", clean.lines);

        // A quick scan's "No" is unsure, and its steps offer the full scan.
        let mut quick_clean = result(Verdict::NoTraces, vec![], vec![(TargetKind::InstallDir, "/n"), (TargetKind::LauncherData, "/d/nikke_launcher")]);
        quick_clean.stats.depth_limit = Some(5);
        let [ran, ..] = answers(&quick_clean);
        assert_eq!((ran.reply, ran.tone), ("No", Tone::Unsure));
        assert_eq!(titles(&quick_clean)[0], "Run the full scan");

        let clean_scan = result(Verdict::NoTraces, vec![], vec![(TargetKind::InstallDir, "/n"), (TargetKind::LauncherData, "/d/nikke_launcher")]);
        assert_eq!(
            titles(&clean_scan),
            [
                "Clear the launcher cache",
                "Change your NIKKE password if the launcher was open on or after October 23",
                "Block the domains",
                "Do not open the launcher until Level Infinite confirms a fix",
            ]
        );
        let [ran, active, clean, _] = answers(&clean_scan);
        assert_eq!((ran.reply, active.reply, clean.reply), ("No", "No", "No"));
        assert_eq!(ran.tone, Tone::Good);

        let exposed = result(Verdict::Exposed, vec![finding(K::LoaderCached, Severity::Warning, "Loader")], vec![(TargetKind::LauncherData, "/d/nikke_launcher")]);
        let t = titles(&exposed);
        // Scanning the install can change the result, so it comes before the cleanup.
        assert_eq!(t[..3], ["Save the report before you delete anything", "Scan the folder where NIKKE is installed", "Clear the launcher cache"]);
        assert!(t.contains(&"Change your passwords from another device".to_string()));
        let ran = &answers(&exposed)[0];
        assert_eq!(ran.reply, "No");
        assert!(!ran.lines.iter().any(|l| l.starts_with("Finding nothing")), "{:?}", ran.lines);

        let none = result(Verdict::NotFound, vec![], vec![]);
        assert_eq!(titles(&none)[0], "Scan the folder where NIKKE is installed");
        assert_eq!(answers(&none)[0].reply, "Cannot tell");
        // Only a quick scan offers the full scan.
        let offers_full = |r: &ScanResult| {
            steps(r)[0].parts.iter().any(|p| matches!(p, Part::Actions(a) if a.iter().any(|a| matches!(a, Action::FullScan))))
        };
        let mut quick = result(Verdict::NotFound, vec![], vec![]);
        quick.stats.depth_limit = Some(5);
        assert!(offers_full(&quick) && !offers_full(&none));

        // A part of the scan that failed makes "No" unsure.
        let gap = result(
            Verdict::NoTraces,
            vec![finding(K::Coverage, Severity::Info, "debug.log could not be read")],
            vec![(TargetKind::InstallDir, "/n")],
        );
        assert_eq!(answers(&gap)[0].tone, Tone::Unsure);
    }

    fn texts(s: &Step) -> String {
        s.parts.iter().map(|p| format!("{p:?}\n")).collect()
    }

    #[cfg(not(windows))]
    fn dll_at(title: &str, path: &str) -> Finding {
        let mut f = finding(K::ChromeDll, Severity::Critical, title);
        f.path = Some(PathBuf::from(path));
        f.open_path = Some(PathBuf::from(format!("{path}/{}/platform_experience_helper.dll", "b".repeat(64))));
        f
    }

    #[cfg(not(windows))]
    #[test]
    fn dll_step_outside_windows() {
        // Two profiles of a Windows drive mounted under Linux: no prefix, and the key is in that Windows.
        let a = "/mnt/win/Users/A/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper";
        let e = "/mnt/win/Users/A/AppData/Local/Microsoft/Edge/User Data/PlatformExperienceHelper";
        let b = "/mnt/win/Users/B/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper";
        let found = vec![
            dll_at("Chrome persistence is installed", a),
            dll_at("Edge persistence is installed", e),
            dll_at("Chrome persistence is installed", b),
        ];
        let drive = result(Verdict::Infected, found, vec![(TargetKind::UserProfile, "/mnt/win/Users/A")]);
        let step = dll_step(&drive);
        assert_eq!(step.title, "Remove the Chrome and Edge DLL");
        let t = texts(&step);
        assert!(t.contains("on a Windows drive seen from this system") && !t.contains("Wine prefix"), "{t}");
        // Debug output doubles the backslashes.
        assert!(scan::CLSID_KEYS.iter().all(|k| t.contains(&format!("Code({k:?})"))), "{t}");
        assert!(t.contains("1. Delete the DLL folder below, the one named with 64 hex characters"), "{t}");
        assert!(t.contains("2. Start that Windows and delete the registry key"), "{t}");
        assert!(!t.contains("Restart Windows."), "{t}");

        // A Proton prefix with only the empty key the malware's uninstall leaves.
        let pfx = "/s/steamapps/compatdata/123/pfx";
        let mut key = finding(K::RegistryLeftover, Severity::Critical, "Registry leftover of the persistence (HKCU CLSID)");
        key.path = Some(PathBuf::from(format!("{pfx}/user.reg")));
        key.copy_text = Some(scan::CLSID_KEYS[0].into());
        let wine = result(Verdict::Infected, vec![key], vec![(TargetKind::WinePrefix, pfx)]);
        let step = dll_step(&wine);
        assert_eq!(step.title, "Delete the leftover registry key");
        let t = texts(&step);
        assert!(t.contains("The key is inside a Wine prefix") && !t.contains("Windows drive"), "{t}");
        assert!(t.contains("WINEPREFIX='/s/steamapps/compatdata/123/pfx' wine regedit"), "{t}");
        assert!(t.contains("protontricks -c 'wine regedit' 123"), "{t}");
        assert!(!t.contains("Defender"), "{t}");
        let [_, active, clean, _] = answers(&wine);
        assert_eq!(active.reply, "No");
        assert!(clean.lines[0].contains("left after the malware cleared the DLL path"), "{:?}", clean.lines);

        // Only the files of the older version: no 64-hex folder to point at.
        let mut legacy = finding(K::LegacyDll, Severity::Critical, "Files of an older Chrome persistence are installed");
        legacy.path = Some(PathBuf::from(format!("{pfx}/drive_c/Program Files/Google/Chrome/Application/PlatformExperienceHelper")));
        let step = dll_step(&result(Verdict::Infected, vec![legacy], vec![(TargetKind::WinePrefix, pfx)]));
        let t = texts(&step);
        assert!(!t.contains("64 hex") && t.contains("1. In the folder below, delete only platform_experience_helper.dll"), "{t}");
    }

    #[test]
    fn password_list_keeps_the_general_lines() {
        use crate::exposure::SecretFile;
        let mut r = result(Verdict::Infected, vec![finding(K::AgentRan, Severity::Critical, "The malware agent ran")], vec![(TargetKind::InstallDir, "/n")]);
        let step = password_step(&r);
        assert!(!texts(&step).contains("only checked that these files exist"), "{}", texts(&step));
        r.exposure = Some(Exposure { secrets: vec![SecretFile { what: "npm token", path: PathBuf::from("/h/.npmrc") }], ..Exposure::default() });
        let list = password_list(&r);
        assert!(list.iter().any(|l| l == "Revoke and replace: npm token, /h/.npmrc."), "{list:?}");
        assert!(list.iter().any(|l| l.starts_with("Any other password, API token, SSH key or wallet")), "{list:?}");
        assert!(texts(&password_step(&r)).contains("only checked that these files exist"));
    }

    #[test]
    fn powershell_names_are_quoted() {
        assert_eq!(ps_command("nikke-check-windows-x86_64 (1).exe", ""), r"& '.\nikke-check-windows-x86_64 (1).exe' --cli | Out-Host");
        assert_eq!(ps_command("it's.exe", " 'D:\\x'"), r"& '.\it''s.exe' --cli 'D:\x' | Out-Host");
    }

    #[test]
    fn run_lines() {
        let run = AgentRun { kind: RunKind::Started, time: Some("11-03 01:47:36".into()), agent_id: None, host: Some("COLONY".into()), file: None, source: PathBuf::new() };
        assert_eq!(run_line(&run), "11-03 01:47:36: the agent sent the computer name COLONY to the attacker");
        let run = AgentRun { source: PathBuf::from("/n/debug.log"), host: None, ..run };
        assert_eq!(run_line(&run), "11-03 01:47:36: the agent sent the computer name to the attacker (from debug.log)");
    }
}
