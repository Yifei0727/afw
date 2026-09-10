// afw - Auto Firewall
// 监视指定进程（按 PID 或进程名），自动检测其绑定的端口，
// 动态在 nftables（首选）或 iptables 中放行；解绑后自动撤销。
//
// 检测原理（无需 eBPF）：
//   /proc/<pid>/fd/* -> "socket:[inode]" 收集进程持有的 socket inode
//   /proc/net/{tcp,tcp6,udp,udp6} 中按 inode 匹配，取本地端口
//   TCP 只认 LISTEN(0A) 状态；UDP 认绑定的非临时端口
// 同步策略：
//   每次轮询计算期望端口集合，与当前已应用集合 diff，只在变化时整体重建规则。

mod config;
mod install;

use crate::config::{Target, UnitConf};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 端口键：('t'=TCP, 'u'=UDP, 端口号)
type PortKey = (char, u16);

const NFT_TABLE: &str = "afw";
const IPT_COMMENT: &str = "afw";
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: i32) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

fn now() -> String {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("[{}.{:03}]", d.as_secs(), d.subsec_millis() / 1_000_000)
}

fn log(msg: &str) {
    eprintln!("{} {}", now(), msg);
}

// ---------------- 参数 ----------------

struct Opts {
    pid: Option<i32>,
    name: Option<String>,
    service: Option<String>,
    config: Option<String>,
    interval: u64,
    backend: Option<String>,
    udp_mode: Option<String>,
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
  afw -n <进程名>              监视进程名 (匹配 /proc/*/comm 或可执行文件名，可多实例)
  afw -s <服务名>              监视 systemd 服务 cgroup 内的全部进程
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
  -i, --interval <sec>   轮询间隔秒数 (默认 1，写入配置)
  -b, --backend <b>      nft | iptables (默认自动: 有 nft 用 nft)
      --udp-mode <m>     server=过滤临时端口范围内的 UDP 绑定(默认，防客户端
                         socket 误放行) | all=放行全部绑定 UDP 端口
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
  interval = 1           # 轮询间隔（秒）
  backend = nft          # nft | iptables | auto
  udp_mode = server      # server（默认，过滤临时端口）| all（全部 UDP）

说明:
  - 需要 root (CAP_NET_ADMIN) 才能修改防火墙；--install 需要 root 写 /etc 与 /usr/local/bin。
  - TCP 仅放行 LISTEN 端口；UDP 放行绑定的非临时端口（过滤 ip_local_port_range 内的
    客户端随机端口）。
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
        interval: 1,
        backend: None,
        udp_mode: None,
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
                o.interval = v.parse::<u64>().unwrap_or_else(|_| die(&format!("无效间隔: {}", v)));
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

// ---------------- 端口检测 ----------------

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
            // 先精确匹配 comm，再匹配 cmdline 第一段的文件名
            if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", pid)) {
                if comm.trim_end() == name {
                    out.push(pid);
                    continue;
                }
            }
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

/// 解析服务的 cgroup 相对路径（相对 /sys/fs/cgroup）。
/// 优先问 systemd（覆盖 --user 服务等非 /system.slice 场景），失败则按标准布局猜。
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
            if !s.is_empty() && Path::new(&format!("/sys/fs/cgroup/{}", s)).exists() {
                return Some(s);
            }
        }
    }
    let guess = format!("system.slice/{}", unit);
    if Path::new(&format!("/sys/fs/cgroup/{}", guess)).exists() {
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
        // cgroup v2 挂在根下，v1 在各控制器层级下
        let mut candidates = vec![format!("/sys/fs/cgroup/{}", cg)];
        for ctl in ["pids", "cpu", "memory", "blkio", "systemd", "name=systemd"] {
            candidates.push(format!("/sys/fs/cgroup/{}/{}", ctl, cg));
        }
        let mut pids = Vec::new();
        let mut found = false;
        for c in candidates {
            if Path::new(&c).exists() {
                found = true;
                read_cgroup_procs_rec(Path::new(&c), &mut pids);
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
    // 默认 Linux 临时端口范围
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

fn parse_proc_net(path: &str, proto: char, listen_only: bool, inodes: &BTreeSet<u64>, out: &mut BTreeSet<PortKey>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
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
        let port_hex = match f[1].rsplit(':').next() {
            Some(p) => p,
            None => continue,
        };
        let port: u16 = match u16::from_str_radix(port_hex, 16) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if port == 0 {
            continue;
        }
        out.insert((proto, port));
    }
}

fn detect_ports(pids: &[i32], eph: (u16, u16), udp_all: bool) -> BTreeSet<PortKey> {
    let mut inodes = BTreeSet::new();
    for &pid in pids {
        inodes.extend(socket_inodes(pid));
    }
    let mut ports = BTreeSet::new();
    parse_proc_net("/proc/net/tcp", 't', true, &inodes, &mut ports);
    parse_proc_net("/proc/net/tcp6", 't', true, &inodes, &mut ports);
    parse_proc_net("/proc/net/udp", 'u', false, &inodes, &mut ports);
    parse_proc_net("/proc/net/udp6", 'u', false, &inodes, &mut ports);
    // udp_mode=server：过滤 UDP 临时端口，避免把客户端出站 socket 的随机源端口也放行
    if !udp_all {
        ports.retain(|&(proto, port)| !(proto == 'u' && port >= eph.0 && port <= eph.1));
    }
    ports
}

fn fmt_ports(ports: &BTreeSet<PortKey>) -> String {
    ports
        .iter()
        .map(|&(p, n)| format!("{}{}", if p == 't' { "tcp" } else { "udp" }, n))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------- nftables 后端 ----------------

struct NftBackend {
    table_exists: bool,
    dry: bool,
}

impl NftBackend {
    fn new(dry: bool) -> std::io::Result<Self> {
        let table_exists = Command::new("nft")
            .args(["list", "table", "inet", NFT_TABLE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        Ok(NftBackend { table_exists, dry })
    }

    fn sync(&mut self, ports: &BTreeSet<PortKey>) -> std::io::Result<()> {
        if ports.is_empty() {
            if self.table_exists {
                self.run("delete table inet afw\n")?;
                self.table_exists = false;
                log("nft: 表 inet afw 已删除（无放行端口）");
            }
            return Ok(());
        }
        let tcp: Vec<u16> = ports.iter().filter(|&&(p, _)| p == 't').map(|&(_, n)| n).collect();
        let udp: Vec<u16> = ports.iter().filter(|&&(p, _)| p == 'u').map(|&(_, n)| n).collect();
        let mut script = String::new();
        if self.table_exists {
            script.push_str(&format!("delete table inet {}\n", NFT_TABLE));
        }
        script.push_str(&format!("table inet {} {{\n", NFT_TABLE));
        script.push_str("  chain allow {\n");
        script.push_str("    type filter hook input priority -10; policy accept;\n");
        if !tcp.is_empty() {
            script.push_str(&format!("    tcp dport {} accept\n", port_set(&tcp)));
        }
        if !udp.is_empty() {
            script.push_str(&format!("    udp dport {} accept\n", port_set(&udp)));
        }
        script.push_str("  }\n}\n");
        self.run(&script)?;
        self.table_exists = true;
        Ok(())
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("nft 失败: {}", String::from_utf8_lossy(&out.stderr).trim()),
            ));
        }
        Ok(())
    }
}

fn port_set(ports: &[u16]) -> String {
    if ports.len() == 1 {
        return ports[0].to_string();
    }
    let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    format!("{{ {} }}", list.join(", "))
}

// ---------------- iptables 后端 ----------------

struct IptablesBackend {
    applied: BTreeSet<PortKey>,
    dry: bool,
}

impl IptablesBackend {
    fn new(dry: bool) -> std::io::Result<Self> {
        let mut b = IptablesBackend {
            applied: BTreeSet::new(),
            dry,
        };
        // 清理上次运行残留的同名规则
        for cmd in ["iptables", "ip6tables"] {
            if let Ok(out) = Command::new(cmd).args(["-S", "INPUT"]).output() {
                if out.status.success() {
                    for line in String::from_utf8_lossy(&out.stdout).lines() {
                        if line.contains(IPT_COMMENT) {
                            let del = line.replacen("-A", "-D", 1);
                            let _ = b.run(cmd, &del);
                        }
                    }
                }
            }
        }
        Ok(b)
    }

    fn sync(&mut self, ports: &BTreeSet<PortKey>) -> std::io::Result<()> {
        let to_add: Vec<PortKey> = ports.difference(&self.applied).copied().collect();
        let to_del: Vec<PortKey> = self.applied.difference(ports).copied().collect();
        for &(p, n) in &to_del {
            for cmd in ["iptables", "ip6tables"] {
                let _ = self.run(cmd, &format!("-D INPUT -p {} --dport {} -m comment --comment {} -j ACCEPT", proto_name(p), n, IPT_COMMENT));
            }
            log(&format!("iptables: 删除放行 {}{}", proto_name(p), n));
        }
        for &(p, n) in &to_add {
            for cmd in ["iptables", "ip6tables"] {
                // -C 检查存在则跳过 -A
                if self.dry {
                    eprintln!("{} [dry-run] {} -A INPUT -p {} --dport {} ... ACCEPT", now(), cmd, proto_name(p), n);
                } else {
                    let check = Command::new(cmd)
                        .args(["-C", "INPUT", "-p", proto_name(p), "--dport", &n.to_string(), "-m", "comment", "--comment", IPT_COMMENT, "-j", "ACCEPT"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    if !check {
                        self.run(cmd, &format!("-A INPUT -p {} --dport {} -m comment --comment {} -j ACCEPT", proto_name(p), n, IPT_COMMENT))?;
                    }
                }
            }
            log(&format!("iptables: 放行 {}{}", proto_name(p), n));
        }
        self.applied = ports.clone();
        Ok(())
    }

    fn run(&self, cmd: &str, args: &str) -> std::io::Result<()> {
        if self.dry {
            eprintln!("{} [dry-run] {} {}", now(), cmd, args);
            return Ok(());
        }
        let out = Command::new(cmd).arg(args).output()?;
        if !out.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{} 失败: {}", cmd, String::from_utf8_lossy(&out.stderr).trim()),
            ));
        }
        Ok(())
    }
}

fn proto_name(p: char) -> &'static str {
    if p == 't' {
        "tcp"
    } else {
        "udp"
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
    let conf: UnitConf = if let Some(path) = &opts.config {
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
        UnitConf::new(target, opts.interval, opts.backend.clone())
    };
    let mut conf = conf;
    if let Some(m) = &opts.udp_mode {
        conf.udp_mode = m.clone();
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
            let has_nft = Command::new("nft")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            let has_ipt = Command::new("iptables")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
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
    let (mut watch, target_desc): (Watch, String) = match &conf.target {
        Target::Pid(pid) => {
            if !Path::new(&format!("/proc/{}", pid)).exists() {
                die(&format!("PID {} 不存在", pid));
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
    let mut cur_pids: Vec<i32> = Vec::new();

    let udp_all = conf.udp_mode == "all";

    log(&format!(
        "启动: 监视 {} | backend={} | interval={}s | udp={}{}{}{}",
        target_desc,
        backend_name,
        conf.interval,
        conf.udp_mode,
        if conf.udp_mode == "server" {
            format!("（过滤临时端口 {}-{}，--udp-mode all 可关闭）", eph.0, eph.1)
        } else {
            String::new()
        },
        if opts.dry_run { " | DRY-RUN" } else { "" },
        if opts.once { " | once" } else { "" }
    ));

    let mut backend: Box<dyn FnMut(&BTreeSet<PortKey>) -> std::io::Result<()>> = match backend_name.as_str() {
        "nft" => {
            let mut b = match NftBackend::new(opts.dry_run) {
                Ok(b) => b,
                Err(e) => die(&format!("初始化 nft 失败: {} (需要 root?)", e)),
            };
            Box::new(move |p| b.sync(p))
        }
        _ => {
            let mut b = match IptablesBackend::new(opts.dry_run) {
                Ok(b) => b,
                Err(e) => die(&format!("初始化 iptables 失败: {} (需要 root?)", e)),
            };
            Box::new(move |p| b.sync(p))
        }
    };

    let mut applied: BTreeSet<PortKey> = BTreeSet::new();

    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }

        // 目标进程存活检查 / 重新收集
        match &mut watch {
            Watch::Pid(pid) => {
                if !Path::new(&format!("/proc/{}", pid)).exists() {
                    log(&format!("PID {} 已退出", pid));
                    if let Err(e) = backend(&BTreeSet::new()) {
                        log(&format!("清理规则失败: {}", e));
                    } else {
                        log("已清理全部 afw 规则");
                    }
                    std::process::exit(0);
                }
                cur_pids = vec![*pid];
            }
            Watch::Name(name) => cur_pids = pids_by_name(name),
            Watch::Svc(sw) => cur_pids = sw.pids(),
        }

        let ports = detect_ports(&cur_pids, eph, udp_all);
        if ports != applied {
            log(&format!(
                "端口变化: {} -> {}",
                fmt_ports(&applied),
                if ports.is_empty() { "(无)".to_string() } else { fmt_ports(&ports) }
            ));
            if let Err(e) = backend(&ports) {
                log(&format!("应用规则失败: {}", e));
                // 下次轮询会重试
            } else {
                applied = ports;
            }
        }

        if opts.once {
            break;
        }

        // 分片 sleep，便于及时响应信号
        let total = conf.interval * 1000;
        let mut waited = 0u64;
        while waited < total && !STOP.load(Ordering::SeqCst) {
            sleep(Duration::from_millis(100));
            waited += 100;
        }
    }

    // 信号退出：清理规则
    if STOP.load(Ordering::SeqCst) {
        log("收到退出信号，清理 afw 规则…");
        if let Err(e) = backend(&BTreeSet::new()) {
            log(&format!("清理规则失败: {}", e));
        } else {
            log("已清理全部 afw 规则，退出");
        }
    }
}
