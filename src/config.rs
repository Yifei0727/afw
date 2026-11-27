// 配置：/etc/afw.d/<名字>.conf 的读写

use std::fs;
use std::path::{Path, PathBuf};

pub const CONF_DIR: &str = "/etc/afw.d";
pub const BIN_PATH: &str = "/usr/local/bin/afw";
pub const UNIT_TEMPLATE: &str = "/etc/systemd/system/afw@.service";

/// 监视目标，三选一
#[derive(Clone, Debug)]
pub enum Target {
    Pid(i32),
    Name(String),
    Service(String),
}

/// 一个 afw 单元（对应 /etc/afw.d 下一个 conf，也对应一个 systemd 实例 afw@<name>）
#[derive(Clone, Debug)]
pub struct UnitConf {
    pub target: Target,
    /// 轮询间隔（毫秒，最低 100ms）
    pub interval_ms: u64,
    pub backend: Option<String>,
    /// UDP 端口策略: "server"(默认，过滤临时端口范围内的绑定) | "all"(全部放行)
    pub udp_mode: String,
    /// 是否递归跟踪目标进程的 fork 子孙进程（仅对 pid/name 模式有意义；service 模式 cgroup 已覆盖）
    pub with_fork: bool,
}

/// 将秒数字符串（支持整数或小数，如 "1" / "0.5"）解析为毫秒，最低 100ms
pub fn parse_interval_ms(raw: &str) -> Result<u64, String> {
    let secs: f64 = raw
        .parse()
        .map_err(|_| format!("无效间隔: {}", raw))?;
    if !secs.is_finite() || secs <= 0.0 {
        return Err(format!("间隔必须为正数: {}", raw));
    }
    let ms = (secs * 1000.0).round() as u64;
    Ok(ms.max(100))
}

/// 将毫秒格式化为可读秒数字符串（整数秒不带小数点，如 1000 -> "1", 500 -> "0.5"）
#[allow(clippy::manual_is_multiple_of)]
pub fn fmt_interval_secs(ms: u64) -> String {
    if ms % 1000 == 0 {
        (ms / 1000).to_string()
    } else {
        let s = format!("{:.3}", (ms as f64) / 1000.0);
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

impl Target {
    /// systemd 单元全名（service 目标补 .service 后缀）
    pub fn unit_name(&self) -> Option<String> {
        match self {
            Target::Service(s) => Some(normalize_unit(s)),
            _ => None,
        }
    }

    /// 配置文件名 / systemd 实例名（不含 .conf）
    pub fn conf_name(&self) -> String {
        match self {
            Target::Pid(p) => format!("pid-{}", p),
            Target::Name(n) => sanitize(n),
            Target::Service(s) => {
                let u = normalize_unit(s);
                sanitize(
                    u.trim_end_matches(".service")
                        .trim_end_matches(".scope")
                        .trim_end_matches(".slice"),
                )
            }
        }
    }

    pub fn desc(&self) -> String {
        match self {
            Target::Pid(p) => format!("pid={}", p),
            Target::Name(n) => format!("name={}", n),
            Target::Service(s) => format!("service={}", s),
        }
    }
}

fn normalize_unit(s: &str) -> String {
    if s.ends_with(".service") || s.ends_with(".scope") || s.ends_with(".slice") {
        s.to_string()
    } else {
        format!("{}.service", s)
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

impl UnitConf {
    pub fn new(target: Target, interval_ms: u64, backend: Option<String>, with_fork: bool) -> Self {
        UnitConf {
            target,
            interval_ms: interval_ms.max(100),
            backend,
            udp_mode: "server".to_string(),
            with_fork,
        }
    }

    pub fn path(&self) -> PathBuf {
        Path::new(CONF_DIR).join(format!("{}.conf", self.target.conf_name()))
    }

    pub fn name(&self) -> String {
        self.target.conf_name()
    }

    pub fn interval_display(&self) -> String {
        fmt_interval_secs(self.interval_ms)
    }

    pub fn render(&self) -> String {
        let target_line = match &self.target {
            Target::Pid(p) => format!("pid = {}", p),
            Target::Name(n) => format!("name = {}", n),
            Target::Service(s) => format!("service = {}", s),
        };
        format!(
            "# afw 单元配置\n\
             # 由 afw 自动生成，对应 systemd 实例 afw@{name}.service\n\
             #\n\
             # 监视目标三选一：service（systemd 服务 cgroup 内全部进程）/\n\
             #                name（按进程名，可多实例）/ pid（单个 PID）\n\
             {target}\n\
             # 轮询间隔（秒，支持小数如 0.5，最低 0.1）：检测延迟 = 该值\n\
             interval = {interval}\n\
             # 防火墙后端：nft（推荐）或 iptables，留空自动选择\n\
             backend = {backend}\n\
             # UDP 端口策略: server = 过滤临时端口范围内的绑定（客户端 socket 不放行，默认）\n\
             #               all    = 放行进程绑定的所有 UDP 端口（含随机端口，注意规则会随客户端 socket 增减而抖动）\n\
             udp_mode = {udp_mode}\n\
             # 是否递归跟踪 fork 出来的子孙进程（pid/name 模式生效；service 模式 cgroup 已覆盖）\n\
             with_fork = {with_fork}\n",
            name = self.name(),
            target = target_line,
            interval = self.interval_display(),
            backend = self.backend.clone().unwrap_or_else(|| "auto".to_string()),
            udp_mode = self.udp_mode,
            with_fork = self.with_fork,
        )
    }

    pub fn parse_str(s: &str, path: &str) -> Result<UnitConf, String> {
        let mut target: Option<Target> = None;
        let mut interval_ms: u64 = 1000;
        let mut backend: Option<String> = None;
        let mut udp_mode = "server".to_string();
        let mut with_fork = false;
        for (idx, raw) in s.lines().enumerate() {
            let line = match raw.find('#') {
                Some(p) => &raw[..p],
                None => raw,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = match line.find('=') {
                Some(p) => (
                    line[..p].trim().to_lowercase(),
                    line[p + 1..].trim().to_string(),
                ),
                None => {
                    return Err(format!(
                        "{}: 第 {} 行不是 key = value 格式: {}",
                        path,
                        idx + 1,
                        line
                    ))
                }
            };
            if v.is_empty() {
                continue;
            }
            match k.as_str() {
                "service" => target = Some(Target::Service(v)),
                "name" | "process" | "proc" => target = Some(Target::Name(v)),
                "pid" => {
                    target = Some(Target::Pid(
                        v.parse::<i32>()
                            .map_err(|_| format!("{}: pid 不是整数: {}", path, v))?,
                    ))
                }
                "interval" => {
                    interval_ms = parse_interval_ms(&v)
                        .map_err(|e| format!("{}: {}", path, e))?;
                }
                "backend" => {
                    let b = v.to_lowercase();
                    if b != "nft" && b != "iptables" && b != "auto" {
                        return Err(format!("{}: backend 只能是 nft/iptables/auto: {}", path, v));
                    }
                    backend = if b == "auto" { None } else { Some(b) };
                }
                "udp_mode" | "udp" => {
                    let m = v.to_lowercase();
                    if m != "server" && m != "all" {
                        return Err(format!("{}: udp_mode 只能是 server/all: {}", path, v));
                    }
                    udp_mode = m;
                }
                "with_fork" | "with-fork" => {
                    with_fork = parse_bool(&v).ok_or_else(|| {
                        format!("{}: with_fork 只能是 true/false: {}", path, v)
                    })?;
                }
                other => return Err(format!("{}: 未知配置项 {}", path, other)),
            }
        }
        let target = target.ok_or_else(|| {
            format!("{}: 未指定监视目标（service/name/pid 三选一）", path)
        })?;
        Ok(UnitConf {
            target,
            interval_ms,
            backend,
            udp_mode,
            with_fork,
        })
    }

    pub fn load(path: &str) -> Result<UnitConf, String> {
        let s = fs::read_to_string(path).map_err(|e| format!("读取配置 {} 失败: {}", path, e))?;
        Self::parse_str(&s, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_parse_and_format() {
        assert_eq!(parse_interval_ms("1").unwrap(), 1000);
        assert_eq!(parse_interval_ms("0.5").unwrap(), 500);
        assert_eq!(parse_interval_ms("0.01").unwrap(), 100); // clamped to 100ms
        assert!(parse_interval_ms("0").is_err());
        assert!(parse_interval_ms("-1").is_err());
        assert!(parse_interval_ms("abc").is_err());

        assert_eq!(fmt_interval_secs(1000), "1");
        assert_eq!(fmt_interval_secs(500), "0.5");
        assert_eq!(fmt_interval_secs(250), "0.25");
    }

    #[test]
    fn test_render_and_parse_roundtrip() {
        let mut conf = UnitConf::new(Target::Name("myapp".to_string()), 500, Some("nft".to_string()), true);
        conf.udp_mode = "all".to_string();
        let rendered = conf.render();
        let parsed = UnitConf::parse_str(&rendered, "test.conf").unwrap();
        assert_eq!(parsed.name(), "myapp");
        assert_eq!(parsed.interval_ms, 500);
        assert_eq!(parsed.backend.as_deref(), Some("nft"));
        assert_eq!(parsed.udp_mode, "all");
        assert!(parsed.with_fork);
    }

    #[test]
    fn test_backward_compat_without_with_fork() {
        let legacy = "service = nginx\ninterval = 2\nbackend = auto\n";
        let parsed = UnitConf::parse_str(legacy, "legacy.conf").unwrap();
        assert_eq!(parsed.interval_ms, 2000);
        assert_eq!(parsed.backend, None);
        assert_eq!(parsed.udp_mode, "server");
        assert!(!parsed.with_fork);
    }
}
