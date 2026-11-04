//! Plain-text report (CLI output, "Copy report" and "Save report...") and the
//! texts the window shares with it.

use std::fmt::Write;

use crate::guide::{self, Action, EXPOSURE_NOTE, EXPOSURE_TITLE, Part, Section};
use crate::locate::TargetKind;
use crate::scan::{ATTACKER_IPS, COMPUTER_SCOPE, Finding, FindingKind, Group, HostsStatus, ScanResult, Verdict};

pub const APP_NAME: &str = "니케 런처 감염 점검";
pub const GIST_URL: &str = "https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5";

/// What was scanned, with "quick scan" or "full scan" for this computer.
pub fn scope(r: &ScanResult) -> String {
    match (r.scope == COMPUTER_SCOPE, r.stats.depth_limit) {
        (true, Some(_)) => format!("{} (빠른 점검)", r.scope),
        (true, None) => format!("{} (전체 점검)", r.scope),
        _ => r.scope.clone(),
    }
}

pub const ABOUT: &str = "2026-09-27, 레벨 인피니트 CDN의 파일 4개가 변조되어 니케 PC 런처 안에서 insightjs.com의 스크립트를 불러오게 되었습니다. 늦어도 2026년 10월 23일부터 이 스크립트는 명령 실행, 파일 읽기, 스크린샷, 브라우저 데이터 수집이 가능한 원격 제어 에이전트(insight.bundle)를 내려받았습니다. 파일 3개는 11월 3일에 교체되었고, 네 번째 파일은 10월 28일에 정리되었지만 일부 CDN 서버는 11월 3일에도 이전 사본을 전달했습니다. 이 도구는 로더와 에이전트가 디스크에 남긴 흔적을 찾습니다.";

pub const READ_ONLY: &str = "읽기 전용. 네트워크에 접속하지 않습니다.";

pub const CAVEATS: [&str; 3] = [
    "니케 폴더를 삭제하거나 다시 설치하면 debug.log는 사라집니다. 런처 데이터의 k2f.agent.state 점검은 이와 관계없이 동작합니다.",
    "아무것도 발견되지 않았다고 해서 PC가 깨끗하다는 증거는 아닙니다.",
    "에이전트가 실행한 명령은 로그를 남기지 않으므로, 이 도구는 공격자가 무엇을 했는지 알 수 없습니다.",
];

pub fn headline(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Infected => "감염",
        Verdict::Exposed => "노출",
        Verdict::NoTraces => "흔적 없음",
        Verdict::NotFound => "니케를 찾지 못함",
    }
}

pub fn summary(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Infected => "위험한 흔적이 발견되었습니다. 에이전트가 다운로드되었거나 실행되었거나, 지속성 장치를 남겼거나, 런처가 지금 실행 중입니다. 이 PC는 침해된 것으로 간주하세요.",
        Verdict::Exposed => "런처가 악성 스크립트를 불러왔거나 insightjs.com에 접속했지만, 에이전트가 실행된 흔적은 발견되지 않았습니다.",
        Verdict::NoTraces => "이 점검이 찾은 니케 파일에서 악성 스크립트나 에이전트의 흔적이 발견되지 않았습니다.",
        Verdict::NotFound => "이 점검이 확인한 위치에서 니케 설치 폴더나 런처 데이터를 찾지 못했습니다.",
    }
}

/// Lines to paste into the hosts file, for the domains it does not block yet.
pub fn block_lines(h: &HostsStatus) -> Vec<String> {
    h.domains
        .iter()
        .filter(|(_, blocked)| *blocked != Some(true))
        .map(|(d, _)| format!("0.0.0.0 {d}"))
        .collect()
}

pub fn block_state(blocked: Option<bool>) -> &'static str {
    match blocked {
        Some(true) => "차단됨",
        Some(false) => "차단 안 됨",
        None => "알 수 없음",
    }
}

pub const BLOCK_LINES_INTRO: &str = "차단됨으로 표시되지 않은 도메인을 막으려면, hosts 파일에 다음 줄을 추가하세요:";

pub const HOSTS_NOTE: &str = "hosts 파일을 수정하려면 관리자 권한이 필요합니다. 이 도구는 hosts 파일을 절대 수정하지 않습니다.";

pub fn ip_note() -> String {
    format!(
        "IP {}와 {}는 hosts 파일로 막을 수 없습니다. 방화벽이나 공유기에서 차단하세요.",
        ATTACKER_IPS[0], ATTACKER_IPS[1]
    )
}

/// 1234567 to "1,234,567".
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// "1 NIKKE install, 2 Wine prefixes, ..." for the targets that were checked.
pub fn checked_summary(r: &ScanResult) -> String {
    let kinds = [
        (TargetKind::InstallDir, "니케 설치 폴더", "니케 설치 폴더"),
        (TargetKind::LauncherData, "런처 데이터 폴더", "런처 데이터 폴더"),
        (TargetKind::WinePrefix, "Wine 프리픽스", "Wine 프리픽스"),
        (TargetKind::UserProfile, "사용자 프로필", "사용자 프로필"),
    ];
    let parts: Vec<String> = kinds
        .iter()
        .filter_map(|(kind, one, many)| {
            let n = r.targets.iter().filter(|t| t.kind == *kind).count();
            match n {
                0 => None,
                1 => Some(format!("{one} 1개")),
                _ => Some(format!("{many} {n}개")),
            }
        })
        .collect();
    if parts.is_empty() { "확인할 대상 없음".into() } else { parts.join(", ") }
}

pub fn stats_line(r: &ScanResult) -> String {
    let s = &r.stats;
    let cap = if s.cap_hit {
        " 항목 수 한도에 도달해 일부 폴더는 방문하지 못했습니다."
    } else {
        ""
    };
    let skipped = match s.skipped_mounts.len() {
        0 => String::new(),
        1 => ", 네트워크 드라이브 1개 건너뜀".into(),
        n => format!(", 네트워크 드라이브 {n}개 건너뜀"),
    };
    format!(
        "항목 {}개 방문 (폴더 {}개), 권한 오류 {}개{skipped}, {:.1}초.{cap}",
        s.entries, s.folders, s.permission_errors, r.seconds
    )
}

/// The findings of one Details section, with the location group of each.
pub fn section(r: &ScanResult, s: Section) -> Vec<(usize, usize, &Group, &Finding)> {
    let mut out: Vec<(usize, usize, &Group, &Finding)> = r
        .groups
        .iter()
        .enumerate()
        .flat_map(|(gi, g)| g.findings.iter().enumerate().map(move |(fi, f)| (gi, fi, g, f)))
        .filter(|(_, _, _, f)| Section::of(f.kind) == s)
        .collect();
    out.sort_by_key(|(_, _, _, f)| std::cmp::Reverse(f.severity));
    out
}

/// "NIKKE install: /path", the location a finding was found in.
pub fn location(g: &Group) -> String {
    match &g.path {
        Some(p) => format!("{}: {}", g.label, p.display()),
        None => g.label.clone(),
    }
}

/// The label of a finding's copy text.
pub fn copy_label(f: &Finding) -> &'static str {
    match f.kind {
        FindingKind::RegistryKey | FindingKind::RegistryLeftover => "레지스트리 키",
        _ => "텍스트",
    }
}

pub fn render(r: &ScanResult) -> String {
    let mut out = String::new();
    let o = &mut out;
    let _ = writeln!(o, "{APP_NAME} {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(o, "점검 위치: {}", scope(r));
    let _ = writeln!(o, "시작: {}", r.started);
    let _ = writeln!(o);
    let _ = writeln!(o, "판정: {}", headline(r.verdict).to_uppercase());
    let _ = writeln!(o, "{}", summary(r.verdict));
    let _ = writeln!(o);

    let _ = writeln!(o, "무슨 일이 있었나");
    for a in guide::answers(r) {
        let _ = writeln!(o, "  {} {}.", a.question, a.reply);
        for line in &a.lines {
            let _ = writeln!(o, "    - {line}");
        }
        if !a.runs.is_empty() {
            let _ = writeln!(o, "    로그에 기록된 에이전트 실행:");
            for run in &a.runs {
                let _ = writeln!(o, "      {run}");
            }
        }
    }
    for b in &r.builds {
        let _ = writeln!(o, "  페이로드 빌드: {}", guide::build_line(b));
    }
    let _ = writeln!(o);

    let _ = writeln!(o, "해야 할 일");
    for (i, s) in guide::steps(r).iter().enumerate() {
        let _ = writeln!(o, "  {}. {}", i + 1, s.title);
        for part in &s.parts {
            match part {
                Part::Text(t) => {
                    let _ = writeln!(o, "     {t}");
                }
                Part::Item(t) => {
                    let _ = writeln!(o, "     - {t}");
                }
                Part::Code(c) => {
                    for line in c.lines() {
                        let _ = writeln!(o, "       {line}");
                    }
                }
                // Buttons only, except a folder to open that the step does not show already.
                Part::Actions(actions) => {
                    for a in actions {
                        if let Action::Reveal(p) = a
                            && !s.parts.iter().any(|q| matches!(q, Part::Code(c) if *c == p.display().to_string()))
                        {
                            let _ = writeln!(o, "     열기: {}", p.display());
                        }
                    }
                }
            }
        }
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "세부 정보");
    let _ = writeln!(o, "  확인한 위치: {}", checked_summary(r));
    for t in &r.targets {
        let _ = writeln!(o, "    [{}] {}", t.kind.label(), t.path.display());
    }
    for s in Section::ALL {
        if s == Section::Info
            && let Some(e) = &r.exposure
        {
            let _ = writeln!(o, "\n  {EXPOSURE_TITLE}");
            let _ = writeln!(o, "    {EXPOSURE_NOTE}");
            if let Some(note) = guide::home_note(r) {
                let _ = writeln!(o, "    {note}");
            }
            for (heading, items) in guide::exposure_lists(e) {
                if items.is_empty() {
                    let _ = writeln!(o, "    {heading}: 발견되지 않음.");
                    continue;
                }
                let _ = writeln!(o, "    {heading}:");
                for (what, path) in items {
                    let _ = writeln!(o, "      {what}: {}", path.display());
                }
            }
            let _ = writeln!(o, "    확인한 폴더:");
            for p in &e.checked {
                let _ = writeln!(o, "      {}", p.display());
            }
        }
        let found = section(r, s);
        if found.is_empty() {
            continue;
        }
        let _ = writeln!(o, "\n  {}", s.title());
        for (_, _, g, f) in found {
            write_finding(o, g, f);
        }
    }
    if r.groups.is_empty() {
        let _ = writeln!(o, "\n  발견 사항 없음.");
    }
    let _ = writeln!(o);

    if let Some(h) = &r.hosts {
        let _ = writeln!(o, "보호 (hosts 파일: {})", h.path.display());
        let _ = writeln!(o, "  감염 여부 점검이 아닙니다. 도메인이 차단되어 있는지 보여줍니다.");
        if let Some(note) = h.note {
            let _ = writeln!(o, "  {note}");
        }
        for (domain, blocked) in &h.domains {
            let _ = writeln!(o, "  {domain}: {}", block_state(*blocked));
        }
        let lines = block_lines(h);
        if !lines.is_empty() {
            let _ = writeln!(o, "  {BLOCK_LINES_INTRO}");
            for line in lines {
                let _ = writeln!(o, "    {line}");
            }
        }
        let _ = writeln!(o, "  {HOSTS_NOTE}");
        let _ = writeln!(o, "  {}", ip_note());
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "이 점검의 한계");
    for c in CAVEATS {
        let _ = writeln!(o, "  - {c}");
    }
    let _ = writeln!(o, "  분석 보고서: {GIST_URL}");
    let _ = writeln!(o);
    let _ = writeln!(o, "점검 통계: {}", stats_line(r));
    out
}

fn write_finding(o: &mut String, g: &Group, f: &Finding) {
    let _ = writeln!(o, "    [{}] {}", f.severity.tag(), f.title);
    let _ = writeln!(o, "      {}", f.detail);
    let _ = writeln!(o, "      의미: {}", guide::meaning(f.kind));
    let _ = writeln!(o, "      발견 위치: {}", location(g));
    if let Some(p) = &f.path {
        let _ = writeln!(o, "      경로: {}", p.display());
    }
    if let Some(p) = f.open_path.as_ref().filter(|p| f.path.as_ref() != Some(*p)) {
        let _ = writeln!(o, "      열기: {}", p.display());
    }
    if let Some(t) = &f.time {
        let _ = writeln!(o, "      시각: {t}");
    }
    for line in f.copy_text.iter().flat_map(|t| t.lines()) {
        let _ = writeln!(o, "      {}: {line}", copy_label(f));
    }
    for e in &f.evidence {
        let _ = writeln!(o, "      | {e}");
    }
}
