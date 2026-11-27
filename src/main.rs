// afw - Auto Firewall
// 监视指定进程（按 PID、进程名或 systemd 服务），自动检测其绑定的端口，
// 动态在 nftables（首选）或 iptables/ip6tables 中放行；解绑后自动撤销。
//
// 检测原理（无需 eBPF）：
//   /proc/<pid>/fd/* -> "socket:[inode]" 收集进程持有的 socket inode
//   /proc/net/{tcp,tcp6,udp,udp6} 中按 inode 匹配，解析本地 IP 与端口：
//   - 仅绑定回环地址（127.0.0.0/8、::1、::ffff:127.0.0.0/104）的端口不对外放行
//   - TCP 只认 LISTEN(0A) 状态；UDP 认绑定的非临时端口（或 --udp-mode all）
//   - 按地址族区分 IPv4 / IPv6（:: 在 net.ipv6.bindv6only=0 时按双栈处理）
// 同步策略：
//   每次轮询计算期望端口集合，与当前已应用集合 diff，只在变化时原子更新本单元独立规则链。

mod config;
mod install;

use crate::config::{parse_interval_ms, Target, UnitConf};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// 端口键：(地址族, 协议, 端口号)
type PortKey = (Family, Proto, u16);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: i32) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

fn now() -> String {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("[{}.{:03}]", d.as_secs(), d.subsec_millis())
}

fn log(msg: &str) {
    eprintln!("{} {}", now(), msg);
}

/// 生成供 nftables/iptables 使用的合法、按单元隔离的链名（仅 [a-zA-Z0-9_]，最长 28 字节满足 xtables 限制）
fn make_chain_name(unit: &str) -> String {
    let clean: String = unit
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    let base = if clean.is_empty() { "default" } else { clean.as_str() };
    // "afw_" (4) + <= 24 = <= 28
    if base.len() <= 24 {
        format!("afw_{}", base)
    } else {
        // FNV-1a 32-bit 哈希避免长名截断冲突: "afw_" (4) + 15 + "_" (1) + 8 = 28
        let mut h: u32 = 0x811c9dc5;
        for b in unit.as_bytes() {
            h ^= *b as u32;
            h = h.wrapping_mul(0x01000193);
        }
        format!("afw_{}_{:08x}", &base[..15], h)
    }
}

/// 生成按单元隔离的注释标记（如 "afw:nginx"）
fn make_comment(unit: &str) -> String {
    let clean: String = unit
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.is_empty() {
        "afw:default".to_string()
    } else {
        format!("afw:{}", clean)
    }
}

// ---------------- 参数 ----------------

struct Opts {
    pid: Option<i32>,
    name: Option<String>,
    service: Option<String>,
    config: Option<String>,
    interval_ms: u64,
    backend: Option<String>,
    udp_mode: Option<String>,
    with_fork: bool,
    dry_run: bool,
    once: bool,
    gen: bool,
    install: bool,
    uninstall: bool,
    list: bool,
    force: bool,
}

const USAGE: &str = "\
afw - 根据进程绑定的端口动态开关防火墙

用法（直接运行）:
  afw -p <pid>                 监视指定 PID
  afw -p <pid> --with-fork     监视指定 PID 及其所有 fork 子孙进程
  afw -n <进程名>              监视进程名 (匹配 comm / exe / argv[0]，可多实例)
  afw -n <进程名> --with-fork  监视进程名及其所有 fork 子孙进程
  afw -s <服务名>              监视 systemd 服务 cgroup 内的全部进程（天然含子进程）
  afw -c /etc/afw.d/nginx.conf 按配置文件运行
  afw -n myapp --once          检测并应用一次后退出
  afw -n myapp --dry-run       只打印将执行的防火墙命令，不改系统

用法（配置与 systemd 安装）:
  afw -s nginx --gen           生成 /etc/afw.d/nginx.conf
  afw -s nginx --install       生成配置 + 装 systemd 实例 afw@nginx，跟随 nginx 启停
  afw -s nginx --uninstall     停用并删除该单元
  afw --list                   列出 /etc/afw.d 下所有单元及运行状态

选项:
  -p, --pid <pid>        目标进程 PID
  -n, --name <name>      目标进程名
  -s, --service <name>   systemd 服务 (nginx 或 nginx.service；递归含子 cgroup)
  -c, --config <file>    从配置文件运行
  -i, --interval <sec>   轮询间隔秒数 (默认 1，支持小数如 0.5，最低 0.1)
  -b, --backend <b>      nft | iptables (默认自动: 有 nft 用 nft)
      --udp-mode <m>     server=过滤临时端口范围内的 UDP 绑定(默认，防客户端
                         socket 误放行) | all=放行全部绑定 UDP 端口
      --with-fork        配合 -p/-n 递归跟踪 fork 出来的子孙进程
      --gen              生成配置文件到 /etc/afw.d/<name>.conf
      --install          生成配置并安装为 systemd 实例（含二进制与开机自启）
      --uninstall        停用并删除对应 systemd 实例与配置
      --list             列出所有已配置单元
      --force            配置已存在时强制覆盖
      --once             应用一次后退出
      --dry-run          不实际修改防火墙/系统
  -h, --help             帮助

配置文件格式 (/etc/afw.d/<name>.conf):
  service = nginx        # 三选一：service / name / pid
  interval = 1           # 轮询间隔（秒，支持小数如 0.5）
  backend = nft          # nft | iptables | auto
  udp_mode = server      # server（默认，过滤临时端口）| all（全部 UDP）
  with_fork = false      # 是否递归跟踪 fork 子孙进程（pid/name 模式生效）

说明:
  - 需要 root (CAP_NET_ADMIN) 才能修改防火墙；--install 需要 root 写 /etc 与 /usr/local/bin。
  - 开放 4 层端口；仅绑定回环地址（127.0.0.0/8、::1）的监听端口不会对外开放。
  - TCP 仅放行 LISTEN 端口；UDP 放行绑定的非临时端口（过滤 ip_local_port_range 内的
    客户端随机端口）；支持 IPv4、IPv6 及 :: 双栈监听。
  - 每个单元使用独立的子链与标记，多实例并行互不干扰。
  - --install 会写入 systemd 模板 afw@.service；service 目标额外生成 drop-in 声明
    BindsTo=<目标服务>，因此目标服务停止时 afw 也停止并撤销规则，目标起来后自动跟随。
  - 进程退出(PID 模式)后自动删除全部 afw 规则并退出；
    进程名/服务模式下进程消失则规则清空、等进程再次出现。
  - 收到 SIGINT/SIGTERM 时清理规则后退出。
";

fn parse_args() -> Opts {
    let mut o = Opts {
        pid: None,
        name: None,
        service: None,
        config: None,
        interval_ms: 1000,
        backend: None,
        udp_mode: None,
        with_fork: false,
        dry_run: false,
        once: false,
        gen: false,
        install: false,
        uninstall: false,
        list: false,
        force: false,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-h" | "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            "-p" | "--pid" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| die("缺少 -p 的 PID 参数"));
                o.pid = Some(v.parse::<i32>().unwrap_or_else(|_| die(&format!("无效 PID: {}", v))));
            }
            "-n" | "--name" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| die("缺少 -n 的进程名参数"));
                o.name = Some(v.clone());
            }
            "-s" | "--service" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| die("缺少 -s 的服务名参数"));
                o.service = Some(v.clone());
            }
            "-c" | "--config" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| die("缺少 -c 的配置文件路径"));
                o.config = Some(v.clone());
            }
            "-i" | "--interval" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| die("缺少 -i 的秒数参数"));
                o.interval_ms = parse_interval_ms(v).unwrap_or_else(|e| die(&e));
            }
            "-b" | "--backend" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| die("缺少 -b 参数")).to_lowercase();
                if v != "nft" && v != "iptables" {
                    die("backend 只能是 nft 或 iptables");
                }
                o.backend = Some(v);
            }
            "--udp-mode" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| die("缺少 --udp-mode 参数")).to_lowercase();
                if v != "server" && v != "all" {
                    die("--udp-mode 只能是 server 或 all");
                }
                o.udp_mode = Some(v);
            }
            "--with-fork" => o.with_fork = true,
            "--once" => o.once = true,
            "--dry-run" => o.dry_run = true,
            "--gen" => o.gen = true,
            "--install" => o.install = true,
            "--uninstall" => o.uninstall = true,
            "--list" => o.list = true,
            "--force" => o.force = true,
            other => die(&format!("未知参数: {} (-h 看帮助)", other)),
        }
        i += 1;
    }
    let n_targets = [o.pid.is_some(), o.name.is_some(), o.service.is_some()]
        .iter()
        .filter(|&&x| x)
        .count();
    if n_targets > 1 {
        die("-p、-n、-s 只能指定一个");
    }
    if o.config.is_some() && n_targets > 0 {
        die("-c 与 -p/-n/-s 不能同时使用");
    }
    // --list 不需要目标；其余必须有目标（-s/-n/-p 或 -c）
    if !o.list && n_targets == 0 && o.config.is_none() {
        eprintln!("{}", USAGE);
        std::process::exit(2);
    }
    o
}

fn die(msg: &str) -> ! {
    eprintln!("afw: {}", msg);
    std::process::exit(2);
}

// ---------------- 进程采集与子进程树 ----------------

/// 解析 /proc/<pid>/stat，返回 (进程状态字符, ppid)。
/// 通过 rfind(')') 兼容 comm 中包含空格和右括号的情况。
fn parse_proc_stat_line(content: &str) -> Option<(char, i32)> {
    let rparen = content.rfind(')')?;
    let rest = content.get(rparen + 1..)?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid = fields.next()?.parse::<i32>().ok()?;
    Some((state, ppid))
}

fn read_proc_stat(pid: i32) -> Option<(char, i32)> {
    let content = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    parse_proc_stat_line(&content)
}

fn is_alive_state(state: char) -> bool {
    !matches!(state, 'Z' | 'X' | 'x')
}

/// 进程存在且非僵尸/已死亡状态
fn is_pid_alive(pid: i32) -> bool {
    read_proc_stat(pid).map(|(st, _)| is_alive_state(st)).unwrap_or(false)
}

/// 从 (pid, ppid) 边表递归收集 roots 及其全部子孙 PID（带环保护）
fn collect_descendants(roots: &[i32], edges: &[(i32, i32)]) -> Vec<i32> {
    if roots.is_empty() {
        return Vec::new();
    }
    let mut children_map: HashMap<i32, Vec<i32>> = HashMap::new();
    for &(pid, ppid) in edges {
        children_map.entry(ppid).or_default().push(pid);
    }
    let mut visited: HashSet<i32> = HashSet::new();
    let mut queue: VecDeque<i32> = VecDeque::new();
    for &r in roots {
        if visited.insert(r) {
            queue.push_back(r);
        }
    }
    while let Some(cur) = queue.pop_front() {
        if let Some(kids) = children_map.get(&cur) {
            for &kid in kids {
                if visited.insert(kid) {
                    queue.push_back(kid);
                }
            }
        }
    }
    let mut out: Vec<i32> = visited.into_iter().collect();
    out.sort_unstable();
    out
}

/// 扫描 /proc/*/stat 构建父子关系树，展开 roots 及其所有存活的 fork 子孙进程。
/// 使用 /proc/*/stat 而非 /proc/<pid>/task/*/children，兼容未开启 CONFIG_PROC_CHILDREN 的老内核（如 2.6/3.10）。
fn expand_with_children(roots: &[i32]) -> Vec<i32> {
    if roots.is_empty() {
        return Vec::new();
    }
    let mut edges = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let Some(s) = fname.to_str() else { continue };
            let Ok(pid) = s.parse::<i32>() else { continue };
            if let Some((state, ppid)) = read_proc_stat(pid) {
                if is_alive_state(state) {
                    edges.push((pid, ppid));
                }
            }
        }
    }
    collect_descendants(roots, &edges)
}

fn pids_by_name(name: &str) -> Vec<i32> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let fname = match fname.to_str() {
                Some(s) => s,
                None => continue,
            };
            let pid: i32 = match fname.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !is_pid_alive(pid) {
                continue;
            }
            // 1. 精确匹配 comm
            if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", pid)) {
                if comm.trim_end() == name {
                    out.push(pid);
                    continue;
                }
            }
            // 2. 匹配 /proc/<pid>/exe 实际可执行文件名（去掉升级残留的 " (deleted)" 后缀）
            if let Ok(exe) = fs::read_link(format!("/proc/{}/exe", pid)) {
                let exe_str = exe.to_string_lossy();
                let exe_clean = exe_str.strip_suffix(" (deleted)").unwrap_or(&exe_str);
                let base = exe_clean.rsplit('/').next().unwrap_or(exe_clean);
                if base == name {
                    out.push(pid);
                    continue;
                }
            }
            // 3. 匹配 cmdline 第一段（argv[0]）的文件名
            if let Ok(cmdline) = fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
                if let Some(arg0) = cmdline.split('\0').next() {
                    let base = arg0.rsplit('/').next().unwrap_or(arg0);
                    if base == name {
                        out.push(pid);
                    }
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

// ---------------- systemd 服务 cgroup 监视 ----------------

fn normalize_unit(name: &str) -> String {
    if name.ends_with(".service") || name.ends_with(".scope") || name.ends_with(".slice") {
        name.to_string()
    } else {
        format!("{}.service", name)
    }
}

/// 列出给定相对 cgroup 路径在 cgroup v2 与 v1 下可能的挂载目录
fn cgroup_dirs(rel: &str) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from(format!("/sys/fs/cgroup/{}", rel))];
    // cgroup v1 控制器层级（systemd 层级优先）
    for ctl in ["systemd", "name=systemd", "pids", "cpu", "memory", "blkio"] {
        dirs.push(PathBuf::from(format!("/sys/fs/cgroup/{}/{}", ctl, rel)));
    }
    dirs
}

fn cgroup_exists(rel: &str) -> bool {
    cgroup_dirs(rel).iter().any(|p| p.exists())
}

/// 解析服务的 cgroup 相对路径（相对 /sys/fs/cgroup 或 v1 控制器根）。
/// 优先问 systemd（覆盖非 /system.slice 场景），失败则按标准布局猜；同时兼容 cgroup v2 与 v1。
fn resolve_cgroup(svc: &str) -> Option<String> {
    let unit = normalize_unit(svc);
    if let Ok(out) = Command::new("systemctl")
        .args(["show", &unit, "-p", "ControlGroup", "--value"])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout)
                .trim()
                .trim_start_matches('/')
                .to_string();
            if !s.is_empty() && cgroup_exists(&s) {
                return Some(s);
            }
        }
    }
    let guess = format!("system.slice/{}", unit);
    if cgroup_exists(&guess) {
        return Some(guess);
    }
    None
}

fn read_cgroup_procs_rec(dir: &Path, out: &mut Vec<i32>) {
    if let Ok(s) = fs::read_to_string(dir.join("cgroup.procs")) {
        for line in s.lines() {
            if let Ok(p) = line.trim().parse::<i32>() {
                out.push(p);
            }
        }
    }
    // 递归子 cgroup：服务内部自行委派/再分组的进程也能覆盖到
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                read_cgroup_procs_rec(&p, out);
            }
        }
    }
}

struct ServiceWatcher {
    name: String,
    cgroup: Option<String>,
    last_try: Option<std::time::Instant>,
}

impl ServiceWatcher {
    fn new(name: String) -> Self {
        let cgroup = resolve_cgroup(&name);
        ServiceWatcher {
            name,
            cgroup,
            last_try: Some(std::time::Instant::now()),
        }
    }

    fn pids(&mut self) -> Vec<i32> {
        // cgroup 尚未出现（服务未启动/刚重启）时限流重试，每 5 秒一次，避免狂拉 systemctl
        if self.cgroup.is_none() {
            let retry = self
                .last_try
                .map(|t| t.elapsed() >= Duration::from_secs(5))
                .unwrap_or(true);
            if retry {
                self.cgroup = resolve_cgroup(&self.name);
                self.last_try = Some(std::time::Instant::now());
            }
        }
        let cg = match &self.cgroup {
            Some(c) => c.clone(),
            None => return Vec::new(),
        };
        let mut pids = Vec::new();
        let mut found = false;
        for c in cgroup_dirs(&cg) {
            if c.exists() {
                found = true;
                read_cgroup_procs_rec(&c, &mut pids);
                if !pids.is_empty() {
                    break;
                }
            }
        }
        if !found {
            // cgroup 整个没了（服务被停止/删除），下次重试解析
            self.cgroup = None;
        }
        pids.sort_unstable();
        pids.dedup();
        pids
    }
}

// ---------------- 端口检测（含回环过滤与 IPv4/IPv6 地址族区分） ----------------

fn socket_inodes(pid: i32) -> BTreeSet<u64> {
    let mut set = BTreeSet::new();
    if let Ok(entries) = fs::read_dir(format!("/proc/{}/fd", pid)) {
        for entry in entries.flatten() {
            if let Ok(link) = fs::read_link(entry.path()) {
                let s = link.to_string_lossy();
                if let Some(rest) = s.strip_prefix("socket:[") {
                    if let Some(n) = rest.strip_suffix(']') {
                        if let Ok(ino) = n.parse::<u64>() {
                            set.insert(ino);
                        }
                    }
                }
            }
        }
    }
    set
}

fn ephemeral_range() -> (u16, u16) {
    // 默认 Linux 临时端口范围（Linux 下 IPv4 与 IPv6 共享该范围）
    let mut range = (32768u16, 60999u16);
    if let Ok(s) = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") {
        let mut it = s.split_whitespace();
        if let (Some(a), Some(b)) = (it.next(), it.next()) {
            if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
                range = (a, b);
            }
        }
    }
    range
}

fn read_bindv6only() -> bool {
    fs::read_to_string("/proc/sys/net/ipv6/bindv6only")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .map(|v| v != 0)
        .unwrap_or(false)
}

#[derive(Debug, PartialEq, Eq)]
enum BoundFamily {
    V4Only,
    V6Only,
    /// 绑定 "::"（未指定 IPv6 地址），在 net.ipv6.bindv6only=0 时可接收 IPv4-mapped 与 IPv6 双栈连接
    V6Any,
}

/// 解析 /proc/net/{tcp,tcp6,udp,udp6} 中的 local_address（"HEXIP:HEXPORT"）。
/// 返回 None 表示端口为 0、格式无效，或仅绑定在回环地址（127.0.0.0/8、::1、::ffff:127.0.0.0/104）。
fn parse_proc_addr(local_addr: &str) -> Option<(BoundFamily, u16)> {
    let (ip_hex, port_hex) = local_addr.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if port == 0 {
        return None;
    }
    match ip_hex.len() {
        8 => {
            // Linux /proc/net/tcp 按本机字节序输出 32 位地址，to_ne_bytes() 在大小端上均可还原网络字节序
            let raw = u32::from_str_radix(ip_hex, 16).ok()?;
            let ip = Ipv4Addr::from(raw.to_ne_bytes());
            if ip.is_loopback() {
                return None;
            }
            Some((BoundFamily::V4Only, port))
        }
        32 => {
            // Linux /proc/net/tcp6 按 4 个本机字节序 32 位字输出 s6_addr32[0..4]
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&ip_hex[i * 8..(i + 1) * 8], 16).ok()?;
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
            }
            let ip = Ipv6Addr::from(bytes);
            if ip.is_loopback() {
                return None;
            }
            if let Some(v4) = ip.to_ipv4_mapped() {
                if v4.is_loopback() {
                    return None;
                }
                return Some((BoundFamily::V4Only, port));
            }
            if ip.is_unspecified() {
                Some((BoundFamily::V6Any, port))
            } else {
                Some((BoundFamily::V6Only, port))
            }
        }
        _ => None,
    }
}

fn parse_proc_net_str(
    content: &str,
    proto: Proto,
    listen_only: bool,
    bindv6only: bool,
    inodes: &BTreeSet<u64>,
    out: &mut BTreeSet<PortKey>,
) {
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let inode: u64 = match f[9].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !inodes.contains(&inode) {
            continue;
        }
        if listen_only && f[3] != "0A" {
            continue;
        }
        let Some((bfam, port)) = parse_proc_addr(f[1]) else {
            continue;
        };
        match bfam {
            BoundFamily::V4Only => {
                out.insert((Family::V4, proto, port));
            }
            BoundFamily::V6Only => {
                out.insert((Family::V6, proto, port));
            }
            BoundFamily::V6Any => {
                out.insert((Family::V6, proto, port));
                if !bindv6only {
                    out.insert((Family::V4, proto, port));
                }
            }
        }
    }
}

fn parse_proc_net(
    path: &str,
    proto: Proto,
    listen_only: bool,
    bindv6only: bool,
    inodes: &BTreeSet<u64>,
    out: &mut BTreeSet<PortKey>,
) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    parse_proc_net_str(&content, proto, listen_only, bindv6only, inodes, out);
}

fn detect_ports(pids: &[i32], eph: (u16, u16), udp_all: bool, bindv6only: bool) -> BTreeSet<PortKey> {
    let mut inodes = BTreeSet::new();
    for &pid in pids {
        inodes.extend(socket_inodes(pid));
    }
    let mut ports = BTreeSet::new();
    if inodes.is_empty() {
        return ports;
    }
    parse_proc_net("/proc/net/tcp", Proto::Tcp, true, bindv6only, &inodes, &mut ports);
    parse_proc_net("/proc/net/tcp6", Proto::Tcp, true, bindv6only, &inodes, &mut ports);
    parse_proc_net("/proc/net/udp", Proto::Udp, false, bindv6only, &inodes, &mut ports);
    parse_proc_net("/proc/net/udp6", Proto::Udp, false, bindv6only, &inodes, &mut ports);
    // udp_mode=server：过滤 UDP 临时端口，避免把客户端出站 socket 的随机源端口也放行
    if !udp_all {
        ports.retain(|&(_, proto, port)| !(proto == Proto::Udp && port >= eph.0 && port <= eph.1));
    }
    ports
}

fn fmt_ports(ports: &BTreeSet<PortKey>) -> String {
    if ports.is_empty() {
        return "(无)".to_string();
    }
    let mut grouped: BTreeMap<(Proto, u16), (bool, bool)> = BTreeMap::new();
    for &(fam, proto, port) in ports {
        let entry = grouped.entry((proto, port)).or_insert((false, false));
        match fam {
            Family::V4 => entry.0 = true,
            Family::V6 => entry.1 = true,
        }
    }
    grouped
        .into_iter()
        .map(|((proto, port), (v4, v6))| {
            let fam_tag = match (v4, v6) {
                (true, true) => "v4+v6",
                (true, false) => "v4",
                (false, true) => "v6",
                (false, false) => "",
            };
            format!("{}/{}({})", proto.as_str(), port, fam_tag)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------- 防火墙后端抽象 ----------------

trait FirewallBackend {
    fn sync(&mut self, ports: &BTreeSet<PortKey>) -> std::io::Result<()>;
}

// ---------------- nftables 后端 ----------------

#[derive(Debug, Default, PartialEq, Eq)]
struct NftBaseChain {
    name: String,
    is_input_hook: bool,
    my_jump_handles: Vec<u64>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct NftInputTable {
    family: String,
    table: String,
    input_chains: Vec<NftBaseChain>,
    /// 本单元在其他非 input 链中可能残留的跳转规则（用于清理）
    other_jump_chains: Vec<(String, Vec<u64>)>,
    has_my_chain: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct NftState {
    /// 系统中已有 type filter hook input 链的表（如 inet filter / inet firewalld / ip filter / ip6 filter）
    tables: Vec<NftInputTable>,
    /// 本单元的独立回退表（table inet <my_chain>）是否存在
    has_standalone_table: bool,
    /// 非 input 表中残留的本单元孤立链 (family, table)
    orphan_chains: Vec<(String, String)>,
}

fn is_filter_input_hook(trimmed: &str) -> bool {
    if let Some(rest) = trimmed.strip_prefix("type filter hook input") {
        rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') || rest.starts_with(';')
    } else {
        false
    }
}

fn extract_nft_handle(line: &str) -> Option<u64> {
    let (_, tail) = line.rsplit_once("# handle ")?;
    tail.trim().parse::<u64>().ok()
}

/// 统计单行在大括号引号之外的净 `{` - `}` 变化，避免受 `tcp dport { 80, 443 }` 或 `set { ... }` 干扰
fn brace_delta(line: &str) -> i32 {
    let mut delta = 0i32;
    let mut in_quotes = false;
    let mut prev_escape = false;
    for ch in line.chars() {
        if in_quotes {
            if ch == '"' && !prev_escape {
                in_quotes = false;
            }
            prev_escape = ch == '\\' && !prev_escape;
            continue;
        }
        match ch {
            '"' => {
                in_quotes = true;
                prev_escape = false;
            }
            '#' => break,
            '{' => delta += 1,
            '}' => delta -= 1,
            _ => {}
        }
    }
    delta
}

/// 解析 `nft -a list ruleset` 输出，定位现有 filter input 基链与本单元已有链/跳转句柄
fn parse_nft_ruleset(ruleset: &str, my_chain: &str, my_comment: &str) -> NftState {
    let mut state = NftState::default();
    let comment_needle = format!("comment \"{}\"", my_comment);

    let mut depth: i32 = 0;
    let mut cur_table: Option<NftInputTable> = None;
    let mut skip_table = false;
    let mut cur_chain: Option<NftBaseChain> = None;

    for raw_line in ruleset.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let prev_depth = depth;
        let delta = brace_delta(raw_line);

        if prev_depth == 0 {
            if let Some(rest) = trimmed.strip_prefix("table ") {
                let mut parts = rest.split_whitespace();
                if let (Some(fam), Some(tname)) = (parts.next(), parts.next()) {
                    let tname = tname.trim_end_matches('{');
                    if fam == "inet" && tname == my_chain {
                        state.has_standalone_table = true;
                        skip_table = true;
                    } else if matches!(fam, "inet" | "ip" | "ip6") && !tname.starts_with("afw_") {
                        cur_table = Some(NftInputTable {
                            family: fam.to_string(),
                            table: tname.to_string(),
                            ..Default::default()
                        });
                        skip_table = false;
                    } else {
                        skip_table = true;
                    }
                }
            }
            depth += delta;
            if depth <= 0 {
                depth = 0;
                cur_table = None;
                skip_table = false;
            }
            continue;
        }

        if !skip_table {
            if prev_depth == 1 {
                if let Some(rest) = trimmed.strip_prefix("chain ") {
                    if let Some(cname) = rest.split_whitespace().next() {
                        let cname = cname.trim_end_matches('{');
                        if let Some(tbl) = cur_table.as_mut() {
                            if cname == my_chain {
                                tbl.has_my_chain = true;
                            } else {
                                cur_chain = Some(NftBaseChain {
                                    name: cname.to_string(),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            } else if prev_depth == 2 {
                if let Some(ch) = cur_chain.as_mut() {
                    if is_filter_input_hook(trimmed) {
                        ch.is_input_hook = true;
                    } else if trimmed.contains(&comment_needle) {
                        if let Some(h) = extract_nft_handle(trimmed) {
                            ch.my_jump_handles.push(h);
                        }
                    }
                }
            }
        }

        depth += delta;

        if depth <= 1 {
            if let Some(ch) = cur_chain.take() {
                if let Some(tbl) = cur_table.as_mut() {
                    if ch.is_input_hook {
                        tbl.input_chains.push(ch);
                    } else if !ch.my_jump_handles.is_empty() {
                        tbl.other_jump_chains.push((ch.name, ch.my_jump_handles));
                    }
                }
            }
        }

        if depth <= 0 {
            depth = 0;
            skip_table = false;
            if let Some(tbl) = cur_table.take() {
                if !tbl.input_chains.is_empty() {
                    state.tables.push(tbl);
                } else {
                    if tbl.has_my_chain {
                        state.orphan_chains.push((tbl.family.clone(), tbl.table.clone()));
                    }
                    if !tbl.other_jump_chains.is_empty() {
                        // 极少数情况：非 input 链里有残留跳转，依然推入 tables 以便清理
                        state.tables.push(tbl);
                    }
                }
            }
        }
    }

    state
}

fn port_set(ports: &[u16]) -> String {
    if ports.len() == 1 {
        return ports[0].to_string();
    }
    let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    format!("{{ {} }}", list.join(", "))
}

/// 生成 inet 表的规则语句（精确区分仅 IPv4、仅 IPv6 与双栈端口）
fn inet_rule_exprs(ports: &BTreeSet<PortKey>) -> Vec<String> {
    let mut exprs = Vec::new();
    for proto in [Proto::Tcp, Proto::Udp] {
        let v4: BTreeSet<u16> = ports
            .iter()
            .filter(|&&(f, p, _)| f == Family::V4 && p == proto)
            .map(|&(_, _, n)| n)
            .collect();
        let v6: BTreeSet<u16> = ports
            .iter()
            .filter(|&&(f, p, _)| f == Family::V6 && p == proto)
            .map(|&(_, _, n)| n)
            .collect();

        let both: Vec<u16> = v4.intersection(&v6).copied().collect();
        let only_v4: Vec<u16> = v4.difference(&v6).copied().collect();
        let only_v6: Vec<u16> = v6.difference(&v4).copied().collect();

        if !both.is_empty() {
            exprs.push(format!("{} dport {} accept", proto.as_str(), port_set(&both)));
        }
        if !only_v4.is_empty() {
            exprs.push(format!(
                "meta nfproto ipv4 {} dport {} accept",
                proto.as_str(),
                port_set(&only_v4)
            ));
        }
        if !only_v6.is_empty() {
            exprs.push(format!(
                "meta nfproto ipv6 {} dport {} accept",
                proto.as_str(),
                port_set(&only_v6)
            ));
        }
    }
    exprs
}

/// 生成单地址族（ip / ip6）表的规则语句；使用单端口规则以保持与 iptables-nft/ip6tables-nft 100% 兼容
fn single_family_rule_exprs(ports: &BTreeSet<PortKey>, family: Family) -> Vec<String> {
    let mut exprs = Vec::new();
    for &(f, proto, port) in ports {
        if f == family {
            exprs.push(format!("{} dport {} accept", proto.as_str(), port));
        }
    }
    exprs
}

/// 根据当前规则集快照与目标端口集生成单次原子 `nft -f -` 脚本；无需变更时返回 None
fn build_nft_script(
    state: &NftState,
    ports: &BTreeSet<PortKey>,
    my_chain: &str,
    my_comment: &str,
) -> Option<String> {
    let mut script = String::new();
    let has_system_input = state.tables.iter().any(|t| !t.input_chains.is_empty());

    if has_system_input {
        // 若存在早期遗留的独立回退表，一并清理
        if state.has_standalone_table {
            script.push_str(&format!("delete table inet {}\n", my_chain));
        }

        for tbl in &state.tables {
            // 清理非 input 链里的异常残留跳转
            for (cname, handles) in &tbl.other_jump_chains {
                for h in handles {
                    script.push_str(&format!(
                        "delete rule {} {} {} handle {}\n",
                        tbl.family, tbl.table, cname, h
                    ));
                }
            }

            if tbl.input_chains.is_empty() {
                if tbl.has_my_chain {
                    script.push_str(&format!("flush chain {} {} {}\n", tbl.family, tbl.table, my_chain));
                    script.push_str(&format!("delete chain {} {} {}\n", tbl.family, tbl.table, my_chain));
                }
                continue;
            }

            let exprs = match tbl.family.as_str() {
                "inet" => inet_rule_exprs(ports),
                "ip" => single_family_rule_exprs(ports, Family::V4),
                "ip6" => single_family_rule_exprs(ports, Family::V6),
                _ => Vec::new(),
            };

            if exprs.is_empty() {
                // 本表无需放行规则：先删所有指向本链的 jump，再删本链
                for bc in &tbl.input_chains {
                    for h in &bc.my_jump_handles {
                        script.push_str(&format!(
                            "delete rule {} {} {} handle {}\n",
                            tbl.family, tbl.table, bc.name, h
                        ));
                    }
                }
                if tbl.has_my_chain {
                    script.push_str(&format!("flush chain {} {} {}\n", tbl.family, tbl.table, my_chain));
                    script.push_str(&format!("delete chain {} {} {}\n", tbl.family, tbl.table, my_chain));
                }
            } else {
                // 原子重建本单元子链并确保基链头部存在跳转规则
                script.push_str(&format!("add chain {} {} {}\n", tbl.family, tbl.table, my_chain));
                script.push_str(&format!("flush chain {} {} {}\n", tbl.family, tbl.table, my_chain));
                for expr in &exprs {
                    script.push_str(&format!(
                        "add rule {} {} {} {}\n",
                        tbl.family, tbl.table, my_chain, expr
                    ));
                }
                for bc in &tbl.input_chains {
                    if bc.my_jump_handles.is_empty() {
                        script.push_str(&format!(
                            "insert rule {} {} {} jump {} comment \"{}\"\n",
                            tbl.family, tbl.table, bc.name, my_chain, my_comment
                        ));
                    } else if bc.my_jump_handles.len() > 1 {
                        for h in &bc.my_jump_handles[1..] {
                            script.push_str(&format!(
                                "delete rule {} {} {} handle {}\n",
                                tbl.family, tbl.table, bc.name, h
                            ));
                        }
                    }
                }
            }
        }
    } else {
        // 系统中没有现有 filter input 基链（空防火墙或无 root 权限 dry-run）：使用本单元独立表
        if ports.is_empty() {
            if state.has_standalone_table {
                script.push_str(&format!("delete table inet {}\n", my_chain));
            }
        } else {
            let exprs = inet_rule_exprs(ports);
            if !exprs.is_empty() {
                if state.has_standalone_table {
                    script.push_str(&format!("delete table inet {}\n", my_chain));
                }
                script.push_str(&format!("table inet {} {{\n", my_chain));
                script.push_str("  chain allow {\n");
                script.push_str("    type filter hook input priority -10; policy accept;\n");
                for expr in &exprs {
                    script.push_str(&format!("    {}\n", expr));
                }
                script.push_str("  }\n}\n");
            }
        }
    }

    for (fam, tbl) in &state.orphan_chains {
        script.push_str(&format!("flush chain {} {} {}\n", fam, tbl, my_chain));
        script.push_str(&format!("delete chain {} {} {}\n", fam, tbl, my_chain));
    }

    if script.is_empty() {
        None
    } else {
        Some(script)
    }
}

struct NftBackend {
    chain: String,
    comment: String,
    dry: bool,
    warned_standalone: bool,
}

impl NftBackend {
    fn new(unit_name: &str, dry: bool) -> std::io::Result<Self> {
        Ok(NftBackend {
            chain: make_chain_name(unit_name),
            comment: make_comment(unit_name),
            dry,
            warned_standalone: false,
        })
    }

    fn inspect_ruleset(&self) -> std::io::Result<NftState> {
        let out = Command::new("nft").args(["-a", "list", "ruleset"]).output()?;
        if !out.status.success() {
            if self.dry {
                return Ok(NftState::default());
            }
            return Err(std::io::Error::other(format!(
                "nft -a list ruleset 失败: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(parse_nft_ruleset(&text, &self.chain, &self.comment))
    }

    fn run(&self, script: &str) -> std::io::Result<()> {
        if self.dry {
            eprintln!("{} [dry-run] nft -f - <<<\n{}", now(), script);
            return Ok(());
        }
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .expect("nft stdin")
            .write_all(script.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "nft 失败: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
}

impl FirewallBackend for NftBackend {
    fn sync(&mut self, ports: &BTreeSet<PortKey>) -> std::io::Result<()> {
        let state = self.inspect_ruleset()?;
        let has_system_input = state.tables.iter().any(|t| !t.input_chains.is_empty());
        if !has_system_input && !ports.is_empty() && !self.dry && !self.warned_standalone {
            log(&format!(
                "nft: 未检测到现有 filter input 防火墙链，使用独立表 table inet {}",
                self.chain
            ));
            self.warned_standalone = true;
        }
        if let Some(script) = build_nft_script(&state, ports, &self.chain, &self.comment) {
            self.run(&script)?;
            if ports.is_empty() {
                log(&format!("nft: 单元 {} 规则已清理", self.chain));
            }
        }
        Ok(())
    }
}

// ---------------- iptables / ip6tables 后端 ----------------

/// 解析 `iptables -S <chain>` 输出中的放行端口列表
fn parse_iptables_chain_rules(stdout: &str, chain: &str) -> BTreeSet<(Proto, u16)> {
    let mut set = BTreeSet::new();
    let prefix = format!("-A {} ", chain);
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with(&prefix) {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut proto: Option<Proto> = None;
        let mut dport: Option<u16> = None;
        let mut is_accept = false;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "-p" => {
                    if let Some(&v) = tokens.get(i + 1) {
                        proto = match v {
                            "tcp" => Some(Proto::Tcp),
                            "udp" => Some(Proto::Udp),
                            _ => None,
                        };
                        i += 1;
                    }
                }
                "--dport" => {
                    if let Some(&v) = tokens.get(i + 1) {
                        dport = v.parse::<u16>().ok();
                        i += 1;
                    }
                }
                "-j" if tokens.get(i + 1).copied() == Some("ACCEPT") => {
                    is_accept = true;
                    i += 1;
                }
                _ => {}
            }
            i += 1;
        }
        if let (Some(p), Some(n), true) = (proto, dport, is_accept) {
            set.insert((p, n));
        }
    }
    set
}

fn cmd_ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

struct IptablesBackend {
    chain: String,
    comment: String,
    use_wait: bool,
    has_ip6: bool,
    warned_no_ip6: bool,
    dry_v4: BTreeSet<(Proto, u16)>,
    dry_v6: BTreeSet<(Proto, u16)>,
    dry: bool,
}

impl IptablesBackend {
    fn new(unit_name: &str, dry: bool) -> std::io::Result<Self> {
        let use_wait = if dry {
            false
        } else {
            cmd_ok("iptables", &["-w", "-S", "INPUT"])
        };
        let has_ip6 = if dry {
            cmd_ok("ip6tables", &["--version"])
        } else if use_wait {
            cmd_ok("ip6tables", &["-w", "-S", "INPUT"])
        } else {
            cmd_ok("ip6tables", &["-S", "INPUT"])
        };
        if !has_ip6 {
            log("iptables: ip6tables 不可用（未安装或内核禁用 IPv6），将仅管理 IPv4 规则");
        }
        Ok(IptablesBackend {
            chain: make_chain_name(unit_name),
            comment: make_comment(unit_name),
            use_wait,
            has_ip6,
            warned_no_ip6: false,
            dry_v4: BTreeSet::new(),
            dry_v6: BTreeSet::new(),
            dry,
        })
    }

    fn run_args(&self, cmd: &str, args: &[&str]) -> std::io::Result<()> {
        if self.dry {
            eprintln!("{} [dry-run] {} {}", now(), cmd, args.join(" "));
            return Ok(());
        }
        let mut c = Command::new(cmd);
        if self.use_wait {
            c.arg("-w");
        }
        let out = c.args(args).output()?;
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "{} {:?} 失败: {}",
                cmd,
                args,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    fn check_args(&self, cmd: &str, args: &[&str]) -> bool {
        let mut c = Command::new(cmd);
        if self.use_wait {
            c.arg("-w");
        }
        c.args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn read_chain(&self, cmd: &str) -> Option<BTreeSet<(Proto, u16)>> {
        let mut c = Command::new(cmd);
        if self.use_wait {
            c.arg("-w");
        }
        let out = c.args(["-S", &self.chain]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout);
        Some(parse_iptables_chain_rules(&s, &self.chain))
    }

    fn sync_family(
        &self,
        cmd: &str,
        target: &BTreeSet<(Proto, u16)>,
        dry_applied: &mut BTreeSet<(Proto, u16)>,
    ) -> std::io::Result<()> {
        if self.dry {
            if target.is_empty() {
                if !dry_applied.is_empty() {
                    self.run_args(
                        cmd,
                        &["-D", "INPUT", "-m", "comment", "--comment", &self.comment, "-j", &self.chain],
                    )?;
                    self.run_args(cmd, &["-F", &self.chain])?;
                    self.run_args(cmd, &["-X", &self.chain])?;
                    dry_applied.clear();
                }
                return Ok(());
            }
            let first = dry_applied.is_empty();
            if first {
                self.run_args(cmd, &["-N", &self.chain])?;
            }
            for &(p, n) in target.difference(dry_applied) {
                let ns = n.to_string();
                self.run_args(cmd, &["-A", &self.chain, "-p", p.as_str(), "--dport", &ns, "-j", "ACCEPT"])?;
            }
            if first {
                self.run_args(
                    cmd,
                    &["-I", "INPUT", "1", "-m", "comment", "--comment", &self.comment, "-j", &self.chain],
                )?;
            }
            for &(p, n) in dry_applied.difference(target) {
                let ns = n.to_string();
                self.run_args(cmd, &["-D", &self.chain, "-p", p.as_str(), "--dport", &ns, "-j", "ACCEPT"])?;
            }
            *dry_applied = target.clone();
            return Ok(());
        }

        if target.is_empty() {
            let jump_check = ["-C", "INPUT", "-m", "comment", "--comment", &self.comment, "-j", &self.chain];
            let jump_del = ["-D", "INPUT", "-m", "comment", "--comment", &self.comment, "-j", &self.chain];
            for _ in 0..32 {
                if !self.check_args(cmd, &jump_check) {
                    break;
                }
                self.run_args(cmd, &jump_del)?;
            }
            if self.check_args(cmd, &["-L", &self.chain, "-n"]) {
                self.run_args(cmd, &["-F", &self.chain])?;
                self.run_args(cmd, &["-X", &self.chain])?;
                log(&format!("{}: 单元链 {} 已清理", cmd, self.chain));
            }
            return Ok(());
        }

        // 先确保子链存在并读取已有规则（增量 diff，避免 --once 或更新时出现短暂断流）
        let existing = match self.read_chain(cmd) {
            Some(s) => s,
            None => {
                self.run_args(cmd, &["-N", &self.chain])?;
                BTreeSet::new()
            }
        };

        for &(p, n) in target.difference(&existing) {
            let ns = n.to_string();
            self.run_args(
                cmd,
                &["-A", &self.chain, "-p", p.as_str(), "--dport", &ns, "-j", "ACCEPT"],
            )?;
            log(&format!("{}: 放行 {}/{}", cmd, p.as_str(), n));
        }

        // 插入到 INPUT 顶部（第 1 条），确保优先于系统末尾的 DROP/REJECT 规则
        if !self.check_args(
            cmd,
            &["-C", "INPUT", "-m", "comment", "--comment", &self.comment, "-j", &self.chain],
        ) {
            self.run_args(
                cmd,
                &["-I", "INPUT", "1", "-m", "comment", "--comment", &self.comment, "-j", &self.chain],
            )?;
        }

        for &(p, n) in existing.difference(target) {
            let ns = n.to_string();
            self.run_args(
                cmd,
                &["-D", &self.chain, "-p", p.as_str(), "--dport", &ns, "-j", "ACCEPT"],
            )?;
            log(&format!("{}: 删除放行 {}/{}", cmd, p.as_str(), n));
        }

        Ok(())
    }
}

impl FirewallBackend for IptablesBackend {
    fn sync(&mut self, ports: &BTreeSet<PortKey>) -> std::io::Result<()> {
        let v4: BTreeSet<(Proto, u16)> = ports
            .iter()
            .filter(|&&(f, _, _)| f == Family::V4)
            .map(|&(_, p, n)| (p, n))
            .collect();
        let v6: BTreeSet<(Proto, u16)> = ports
            .iter()
            .filter(|&&(f, _, _)| f == Family::V6)
            .map(|&(_, p, n)| (p, n))
            .collect();

        // 取出 dry 状态避免同时借用 self
        let mut dry_v4 = std::mem::take(&mut self.dry_v4);
        let res_v4 = self.sync_family("iptables", &v4, &mut dry_v4);
        self.dry_v4 = dry_v4;
        res_v4?;

        if self.has_ip6 {
            let mut dry_v6 = std::mem::take(&mut self.dry_v6);
            let res_v6 = self.sync_family("ip6tables", &v6, &mut dry_v6);
            self.dry_v6 = dry_v6;
            res_v6?;
        } else if !v6.is_empty() && !self.warned_no_ip6 {
            log("iptables: 检测到 IPv6 端口，但 ip6tables 不可用，已跳过 IPv6 规则");
            self.warned_no_ip6 = true;
        }
        Ok(())
    }
}

// ---------------- 主循环 ----------------

fn main() {
    let opts = parse_args();

    unsafe {
        signal(2, on_signal); // SIGINT
        signal(15, on_signal); // SIGTERM
    }

    // --list: 列出所有已配置单元后退出
    if opts.list {
        install::list_units();
        return;
    }

    // 组装单元配置：优先读配置文件，否则用命令行参数
    let mut conf: UnitConf = if let Some(path) = &opts.config {
        match UnitConf::load(path) {
            Ok(c) => c,
            Err(e) => die(&e),
        }
    } else {
        let target = if let Some(pid) = opts.pid {
            Target::Pid(pid)
        } else if let Some(name) = opts.name.clone() {
            Target::Name(name)
        } else {
            Target::Service(opts.service.clone().unwrap())
        };
        UnitConf::new(target, opts.interval_ms, opts.backend.clone(), opts.with_fork)
    };
    if let Some(m) = &opts.udp_mode {
        conf.udp_mode = m.clone();
    }
    if opts.with_fork {
        conf.with_fork = true;
    }

    // --gen / --install / --uninstall：只操作配置与 systemd，不进入轮询
    if opts.uninstall {
        if let Err(e) = install::uninstall(&conf, opts.dry_run) {
            die(&e);
        }
        return;
    }
    if opts.install {
        if let Err(e) = install::install(&conf, opts.force, opts.dry_run) {
            die(&e);
        }
        return;
    }
    if opts.gen {
        if let Err(e) = install::gen_conf(&conf, opts.force, opts.dry_run) {
            die(&e);
        }
        return;
    }

    // 选后端
    let backend_name = match &conf.backend {
        Some(b) => b.clone(),
        None => {
            let has_nft = cmd_ok("nft", &["--version"]);
            let has_ipt = cmd_ok("iptables", &["--version"]);
            if has_nft {
                "nft".to_string()
            } else if has_ipt {
                "iptables".to_string()
            } else {
                die("系统里既没有 nft 也没有 iptables");
            }
        }
    };

    if !opts.dry_run && !Path::new("/proc/self").exists() {
        die("不在 Linux 上运行");
    }

    enum Watch {
        Pid(i32),
        Name(String),
        Svc(ServiceWatcher),
    }

    let eph = ephemeral_range();
    let bindv6only = read_bindv6only();
    let (mut watch, target_desc): (Watch, String) = match &conf.target {
        Target::Pid(pid) => {
            if !is_pid_alive(*pid) {
                die(&format!("PID {} 不存在或已退出", pid));
            }
            (Watch::Pid(*pid), format!("pid={}", pid))
        }
        Target::Name(name) => {
            let pids = pids_by_name(name);
            if pids.is_empty() {
                log(&format!("进程 {} 尚未出现，等待中…", name));
            }
            (Watch::Name(name.clone()), format!("name={}", name))
        }
        Target::Service(svc) => {
            let sw = ServiceWatcher::new(svc.clone());
            if sw.cgroup.is_none() {
                log(&format!("未找到服务 {} 的 cgroup（服务未启动？），等待中…", svc));
            }
            (Watch::Svc(sw), format!("service={}", svc))
        }
    };

    let udp_all = conf.udp_mode == "all";
    let unit_name = conf.name();

    log(&format!(
        "启动: 监视 {} | unit={} | backend={} | interval={}s | udp={}{}{}{}{}",
        target_desc,
        unit_name,
        backend_name,
        conf.interval_display(),
        conf.udp_mode,
        if conf.udp_mode == "server" {
            format!("（过滤临时端口 {}-{}，--udp-mode all 可关闭）", eph.0, eph.1)
        } else {
            String::new()
        },
        if conf.with_fork { " | with-fork" } else { "" },
        if opts.dry_run { " | DRY-RUN" } else { "" },
        if opts.once { " | once" } else { "" }
    ));

    let mut backend: Box<dyn FirewallBackend> = match backend_name.as_str() {
        "nft" => match NftBackend::new(&unit_name, opts.dry_run) {
            Ok(b) => Box::new(b),
            Err(e) => die(&format!("初始化 nft 失败: {} (需要 root?)", e)),
        },
        _ => match IptablesBackend::new(&unit_name, opts.dry_run) {
            Ok(b) => Box::new(b),
            Err(e) => die(&format!("初始化 iptables 失败: {} (需要 root?)", e)),
        },
    };

    let mut applied: Option<BTreeSet<PortKey>> = None;

    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }

        // 目标进程存活检查 / 重新收集
        let cur_pids: Vec<i32> = match &mut watch {
            Watch::Pid(pid) => {
                if !is_pid_alive(*pid) {
                    log(&format!("PID {} 已退出", pid));
                    if let Err(e) = backend.sync(&BTreeSet::new()) {
                        log(&format!("清理规则失败: {}", e));
                    } else {
                        log("已清理全部 afw 规则");
                    }
                    std::process::exit(0);
                }
                if conf.with_fork {
                    expand_with_children(&[*pid])
                } else {
                    vec![*pid]
                }
            }
            Watch::Name(name) => {
                let base = pids_by_name(name);
                if conf.with_fork {
                    expand_with_children(&base)
                } else {
                    base
                }
            }
            Watch::Svc(sw) => sw.pids(),
        };

        let ports = detect_ports(&cur_pids, eph, udp_all, bindv6only);
        let changed = applied.as_ref() != Some(&ports);
        if changed {
            // 首次同步若端口为空，静默执行清理以回收上次异常退出可能残留的同单元规则
            if applied.is_some() || !ports.is_empty() {
                let prev = applied.as_ref().map(fmt_ports).unwrap_or_else(|| "(无)".to_string());
                log(&format!("端口变化: {} -> {}", prev, fmt_ports(&ports)));
            }
            if let Err(e) = backend.sync(&ports) {
                log(&format!("应用规则失败: {}", e));
                // 下次轮询会重试
            } else {
                applied = Some(ports);
            }
        }

        if opts.once {
            break;
        }

        // 分片 sleep，便于及时响应信号
        let total = conf.interval_ms;
        let mut waited = 0u64;
        while waited < total && !STOP.load(Ordering::SeqCst) {
            let chunk = (total - waited).min(100);
            sleep(Duration::from_millis(chunk));
            waited += chunk;
        }
    }

    // 信号退出：清理规则
    if STOP.load(Ordering::SeqCst) {
        log("收到退出信号，清理 afw 规则…");
        if let Err(e) = backend.sync(&BTreeSet::new()) {
            log(&format!("清理规则失败: {}", e));
        } else {
            log("已清理全部 afw 规则，退出");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_ipv4(ip: Ipv4Addr) -> String {
        let raw = u32::from_ne_bytes(ip.octets());
        format!("{:08X}", raw)
    }

    fn hex_ipv6(ip: Ipv6Addr) -> String {
        let b = ip.octets();
        let mut out = String::with_capacity(32);
        for i in 0..4 {
            let w = u32::from_ne_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
            out.push_str(&format!("{:08X}", w));
        }
        out
    }

    #[test]
    fn test_parse_proc_addr_loopback_filtering_and_families() {
        // 127.0.0.1 & 127.0.0.53 (loopback) -> filtered out
        assert_eq!(parse_proc_addr(&format!("{}:0050", hex_ipv4(Ipv4Addr::new(127, 0, 0, 1)))), None);
        assert_eq!(parse_proc_addr(&format!("{}:0035", hex_ipv4(Ipv4Addr::new(127, 0, 0, 53)))), None);
        // 0.0.0.0 & non-loopback NIC IP -> V4Only
        assert_eq!(
            parse_proc_addr(&format!("{}:0050", hex_ipv4(Ipv4Addr::UNSPECIFIED))),
            Some((BoundFamily::V4Only, 80))
        );
        assert_eq!(
            parse_proc_addr(&format!("{}:1F90", hex_ipv4(Ipv4Addr::new(192, 168, 1, 10)))),
            Some((BoundFamily::V4Only, 8080))
        );

        // ::1 & ::ffff:127.0.0.1 (IPv6 loopback & IPv4-mapped loopback) -> filtered out
        assert_eq!(parse_proc_addr(&format!("{}:0050", hex_ipv6(Ipv6Addr::LOCALHOST))), None);
        assert_eq!(
            parse_proc_addr(&format!("{}:0050", hex_ipv6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped()))),
            None
        );

        // :: (unspecified IPv6) -> V6Any
        assert_eq!(
            parse_proc_addr(&format!("{}:01BB", hex_ipv6(Ipv6Addr::UNSPECIFIED))),
            Some((BoundFamily::V6Any, 443))
        );

        // ::ffff:10.0.0.5 (IPv4-mapped non-loopback) -> V4Only
        assert_eq!(
            parse_proc_addr(&format!("{}:1F90", hex_ipv6(Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped()))),
            Some((BoundFamily::V4Only, 8080))
        );

        // Specific IPv6 address (fd00::1 / fe80::1) -> V6Only
        assert_eq!(
            parse_proc_addr(&format!("{}:01BB", hex_ipv6("fd00:200::1".parse().unwrap()))),
            Some((BoundFamily::V6Only, 443))
        );

        // Port 0 -> filtered out
        assert_eq!(parse_proc_addr(&format!("{}:0000", hex_ipv4(Ipv4Addr::UNSPECIFIED))), None);
    }

    #[test]
    fn test_parse_proc_net_dual_stack_vs_bindv6only() {
        let tcp6 = format!(
            "  sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
               0: {any}:0050 {any}:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1001 1 0 100 0 0 10 0\n\
               1: {lo}:1F90 {any}:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1002 1 0 100 0 0 10 0\n\
               2: {spec}:01BB {any}:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1003 1 0 100 0 0 10 0\n",
            any = hex_ipv6(Ipv6Addr::UNSPECIFIED),
            lo = hex_ipv6(Ipv6Addr::LOCALHOST),
            spec = hex_ipv6("2001:db8::1".parse().unwrap()),
        );
        let inodes: BTreeSet<u64> = [1001, 1002, 1003].into_iter().collect();

        // bindv6only = false: "::" opens V4+V6, "::1" skipped, "2001:db8::1" opens V6 only
        let mut out = BTreeSet::new();
        parse_proc_net_str(&tcp6, Proto::Tcp, true, false, &inodes, &mut out);
        assert_eq!(
            out,
            [
                (Family::V4, Proto::Tcp, 80),
                (Family::V6, Proto::Tcp, 80),
                (Family::V6, Proto::Tcp, 443),
            ]
            .into_iter()
            .collect()
        );

        // bindv6only = true: "::" opens V6 only
        let mut out_v6only = BTreeSet::new();
        parse_proc_net_str(&tcp6, Proto::Tcp, true, true, &inodes, &mut out_v6only);
        assert_eq!(
            out_v6only,
            [(Family::V6, Proto::Tcp, 80), (Family::V6, Proto::Tcp, 443)]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn test_parse_proc_stat_with_parens_and_spaces() {
        let stat = "1234 (my (weird) proc) S 100 1234 1234 0 -1 4194304";
        assert_eq!(parse_proc_stat_line(stat), Some(('S', 100)));
        let zombie = "5678 (defunct) Z 100 5678 5678";
        let (st, ppid) = parse_proc_stat_line(zombie).unwrap();
        assert_eq!(ppid, 100);
        assert!(!is_alive_state(st));
    }

    #[test]
    fn test_collect_descendants_tree_and_cycle_safety() {
        let edges = vec![
            (10, 1),
            (20, 10),
            (21, 10),
            (30, 20),
            (40, 30),
            (99, 1),  // unrelated
            (10, 40), // artificial cycle
        ];
        assert_eq!(collect_descendants(&[10], &edges), vec![10, 20, 21, 30, 40]);
        assert_eq!(collect_descendants(&[99], &edges), vec![99]);
        assert_eq!(collect_descendants(&[], &edges), Vec::<i32>::new());
    }

    #[test]
    fn test_make_chain_name_length_and_sanitization() {
        assert_eq!(make_chain_name("nginx"), "afw_nginx");
        assert_eq!(make_chain_name("pid-1234"), "afw_pid_1234");
        assert_eq!(make_chain_name("user@1000.service"), "afw_user_1000_service");
        let long_a = make_chain_name("my-very-long-systemd-service-name-alpha");
        let long_b = make_chain_name("my-very-long-systemd-service-name-beta");
        assert!(long_a.len() <= 28);
        assert!(long_b.len() <= 28);
        assert_ne!(long_a, long_b);
    }

    #[test]
    fn test_nft_parse_and_build_multi_instance_isolation() {
        let ruleset = r#"
table inet filter { # handle 1
	set allowed_ips {
		type ipv4_addr
		elements = { 10.0.0.1, 10.0.0.2 }
	}
	chain input { # handle 1
		type filter hook input priority 0; policy drop;
		jump afw_redis comment "afw:redis" # handle 10
		ct state established,related accept # handle 2
	}
	chain afw_redis { # handle 9
		meta nfproto ipv4 tcp dport 6379 accept # handle 11
	}
	chain forward { # handle 3
		type filter hook forward priority 0; policy drop;
	}
}
table ip filter { # handle 2
	chain INPUT { # handle 1
		type filter hook input priority filter; policy drop;
	}
}
"#;
        let state = parse_nft_ruleset(ruleset, "afw_nginx", "afw:nginx");
        assert!(!state.has_standalone_table);
        assert_eq!(state.tables.len(), 2);
        assert_eq!(state.tables[0].family, "inet");
        assert_eq!(state.tables[0].table, "filter");
        assert_eq!(state.tables[0].input_chains.len(), 1);
        assert_eq!(state.tables[0].input_chains[0].name, "input");
        assert!(state.tables[0].input_chains[0].my_jump_handles.is_empty());
        assert!(!state.tables[0].has_my_chain);

        let ports: BTreeSet<PortKey> = [
            (Family::V4, Proto::Tcp, 80),
            (Family::V6, Proto::Tcp, 80),
            (Family::V4, Proto::Tcp, 8080),
            (Family::V6, Proto::Udp, 5353),
        ]
        .into_iter()
        .collect();

        let script = build_nft_script(&state, &ports, "afw_nginx", "afw:nginx").unwrap();
        // inet filter gets dual-stack 80, v4-only 8080, v6-only udp 5353 + jump
        assert!(script.contains("add chain inet filter afw_nginx\n"));
        assert!(script.contains("add rule inet filter afw_nginx tcp dport 80 accept\n"));
        assert!(script.contains("add rule inet filter afw_nginx meta nfproto ipv4 tcp dport 8080 accept\n"));
        assert!(script.contains("add rule inet filter afw_nginx meta nfproto ipv6 udp dport 5353 accept\n"));
        assert!(script.contains("insert rule inet filter input jump afw_nginx comment \"afw:nginx\"\n"));
        // ip filter gets single-port IPv4 rules only (no udp 5353, no anonymous sets)
        assert!(script.contains("add rule ip filter afw_nginx tcp dport 80 accept\n"));
        assert!(script.contains("add rule ip filter afw_nginx tcp dport 8080 accept\n"));
        assert!(!script.contains("5353 accept\nadd rule ip"));
        // Never touches afw_redis!
        assert!(!script.contains("afw_redis"));
        assert!(!script.contains("handle 10"));

        // Cleanup of afw_nginx only deletes afw_nginx handle & chain
        let ruleset_after = r#"
table inet filter { # handle 1
	chain input { # handle 1
		type filter hook input priority 0; policy drop;
		jump afw_nginx comment "afw:nginx" # handle 22
		jump afw_redis comment "afw:redis" # handle 10
	}
	chain afw_nginx { # handle 21
		tcp dport 80 accept # handle 23
	}
	chain afw_redis { # handle 9
		meta nfproto ipv4 tcp dport 6379 accept # handle 11
	}
}
"#;
        let state2 = parse_nft_ruleset(ruleset_after, "afw_nginx", "afw:nginx");
        let cleanup = build_nft_script(&state2, &BTreeSet::new(), "afw_nginx", "afw:nginx").unwrap();
        assert!(cleanup.contains("delete rule inet filter input handle 22\n"));
        assert!(cleanup.contains("flush chain inet filter afw_nginx\n"));
        assert!(cleanup.contains("delete chain inet filter afw_nginx\n"));
        assert!(!cleanup.contains("afw_redis"));
        assert!(!cleanup.contains("handle 10"));
    }

    #[test]
    fn test_parse_iptables_chain_rules() {
        let out = "\
-N afw_nginx
-A afw_nginx -p tcp -m tcp --dport 80 -j ACCEPT
-A afw_nginx -p udp -m udp --dport 53 -j ACCEPT
-A afw_nginx -p tcp --dport 443 -j ACCEPT
";
        let parsed = parse_iptables_chain_rules(out, "afw_nginx");
        assert_eq!(
            parsed,
            [(Proto::Tcp, 80), (Proto::Tcp, 443), (Proto::Udp, 53)]
                .into_iter()
                .collect()
        );
    }
}
