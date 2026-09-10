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
    pub interval: u64,
    pub backend: Option<String>,
    /// UDP 端口策略: "server"(默认，过滤临时端口范围内的绑定) | "all"(全部放行)
    pub udp_mode: String,
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
                sanitize(u.trim_end_matches(".service").trim_end_matches(".scope").trim_end_matches(".slice"))
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
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

impl UnitConf {
    pub fn new(target: Target, interval: u64, backend: Option<String>) -> Self {
        UnitConf {
            target,
            interval: interval.max(1),
            backend,
            udp_mode: "server".to_string(),
        }
    }

    pub fn path(&self) -> PathBuf {
        Path::new(CONF_DIR).join(format!("{}.conf", self.target.conf_name()))
    }

    pub fn name(&self) -> String {
        self.target.conf_name()
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
             # 轮询间隔（秒）：检测延迟 = 该值\n\
             interval = {interval}\n\
             # 防火墙后端：nft（推荐）或 iptables，留空自动选择\n\
             backend = {backend}\n\
             # UDP 端口策略: server = 过滤临时端口范围内的绑定（客户端 socket 不放行，默认）\n\
             #               all    = 放行进程绑定的所有 UDP 端口（含随机端口，注意规则会随客户端 socket 增减而抖动）\n\
             udp_mode = {udp_mode}\n",
            name = self.name(),
            target = target_line,
            interval = self.interval,
            backend = self.backend.clone().unwrap_or_else(|| "auto".to_string()),
            udp_mode = self.udp_mode,
        )
    }

    pub fn load(path: &str) -> Result<UnitConf, String> {
        let s = fs::read_to_string(path).map_err(|e| format!("读取配置 {} 失败: {}", path, e))?;
        let mut target: Option<Target> = None;
        let mut interval: u64 = 1;
        let mut backend: Option<String> = None;
        let mut udp_mode = "server".to_string();
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
                Some(p) => (line[..p].trim().to_lowercase(), line[p + 1..].trim().to_string()),
                None => return Err(format!("{}: 第 {} 行不是 key = value 格式: {}", path, idx + 1, line)),
            };
            if v.is_empty() {
                continue;
            }
            match k.as_str() {
                "service" => target = Some(Target::Service(v)),
                "name" | "process" | "proc" => target = Some(Target::Name(v)),
                "pid" => target = Some(Target::Pid(
                    v.parse::<i32>().map_err(|_| format!("{}: pid 不是整数: {}", path, v))?,
                )),
                "interval" => {
                    interval = v
                        .parse::<u64>()
                        .map_err(|_| format!("{}: interval 不是整数: {}", path, v))?
                        .max(1)
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
                other => return Err(format!("{}: 未知配置项 {}", path, other)),
            }
        }
        let target = target.ok_or_else(|| format!("{}: 未指定监视目标（service/name/pid 三选一）", path))?;
        Ok(UnitConf {
            target,
            interval,
            backend,
            udp_mode,
        })
    }
}
