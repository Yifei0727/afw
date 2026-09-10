# afw — Auto Firewall

根据进程绑定的端口，动态开关 Linux 防火墙。指定 PID 或进程名，它轮询该进程当前
bind 的 TCP/UDP 端口，自动在 nftables（首选）或 iptables 里放行；进程解绑或退出后
自动撤销。不需要手工写 iptables/nft 规则，也不依赖 eBPF。

## 原理

- 读 `/proc/<pid>/fd/*` 拿到进程持有的 socket inode
- 与 `/proc/net/{tcp,tcp6,udp,udp6}` 按 inode 匹配，取本地端口
- TCP 只认 LISTEN；UDP 认绑定的非临时端口（读
  `/proc/sys/net/ipv4/ip_local_port_range` 过滤客户端随机源端口，不会误放行）
- 每次轮询对期望端口集合做 diff，只有变化才重建规则；规则放在独立的
  `table inet afw` 里，不碰系统已有防火墙配置
- 收到 SIGINT/SIGTERM、或 PID 模式下进程退出 → 自动清空全部 afw 规则

## 用法

```sh
sudo ./afw -n nginx              # 按进程名监视（可匹配多个实例）
sudo ./afw -p 12345              # 按 PID 监视
sudo ./afw -s nginx              # 监视 systemd 服务 cgroup 内全部进程（含子 cgroup）
sudo ./afw -s user@1000.service  # --user 服务也支持（自动 systemctl 定位 cgroup）
sudo ./afw -n dnsmasq -i 2       # 2 秒轮询
sudo ./afw -n myapp -b iptables  # 强制用 iptables 后端
sudo ./afw -n myapp --dry-run    # 只打印将执行的命令，不动防火墙
sudo ./afw -n myapp --once       # 应用一次就退出（配合 cron/外部编排）
```

需要 root（修改防火墙需要 CAP_NET_ADMIN）。进程名匹配 `/proc/*/comm` 或
可执行文件名，精确匹配。

## 构建

```sh
cargo build --release --target x86_64-unknown-linux-musl
# 产物: target/x86_64-unknown-linux-musl/release/afw （静态链接，任意 x86_64 Linux 可跑）
```

不打 tag 的 push/PR 会在 CI 里做双架构（x86_64 / aarch64）musl 构建校验；
推 `v*` tag 自动构建静态二进制并附到 GitHub Release，直接下载即可用，无需本地装工具链。

## 适应性（不依赖 eBPF 意味着什么）

afw 刻意避开 eBPF，换来的是极宽的运行环境覆盖——本质上它只需要两样东西：
**可读的 `/proc`** 和 **nft 或 iptables 之一**。

- **内核版本：没有下限要求**。`/proc/net/{tcp,udp}` 的文本格式几十年未变，
  3.10（CentOS 7）、2.6 老内核都能跑。eBPF 方案通常要内核 ≥4.x，CO-RE 还要
  ≥5.2 且开启 `CONFIG_DEBUG_INFO_BTF`——afw 全都不需要
- **不需要内核头文件 / clang+LLVM 编译链 / DKMS / 内核模块加载**。
  内核 lockdown（Secure Boot 开启）下 eBPF 常被禁用，afw 不受任何影响
- **发行版无关**：musl 全静态链接、零运行时依赖，Alpine、Debian/Ubuntu、
  RHEL/Rocky、Arch、busybox/嵌入式 Linux 直接扔进去就能跑，不存在 glibc 版本地狱
- **防火墙后端自适应**：有 nft 用 nft（单原子事务），没有则回退 iptables
  （legacy 和 nft 后端都支持）
- **init 系统可选**：`-n`/`-p` 模式完全不依赖 systemd（sysvinit、busybox init、
  裸容器都行）；`-s`/`--install`/`--gen` 是 systemd 增强功能，没有 systemd 的
  环境可以用 `--once` + cron / rc.local 达到同样效果
- **cgroup v1 / v2 都支持**（`--service` 模式递归读 cgroup.procs）
- **双架构**：CI 产出 x86_64 与 aarch64 两个静态二进制
- **权限最小化**：运行只需 root 或 `CAP_NET_ADMIN`，不需要 `SYS_ADMIN`、
  `NET_RAW`、`BPF_*` 等 eBPF 方案通常要的额外 capability

代价也明说：检测延迟 = 轮询间隔（默认 1s）而非 eBPF 的近乎零延迟，
且 `/proc` 无法区分服务端 bind 与客户端出站 socket（见下文 udp_mode）。
对"秒级放行"的场景这个取舍几乎无感。

## 配置文件

配置文件放 `/etc/afw.d/<名字>.conf`，三选一指定目标：

```ini
# /etc/afw.d/nginx.conf  （afw -s nginx --gen 自动生成）
service = nginx        # 三选一：service（systemd 服务 cgroup 内全部进程）
                       #         name（按进程名，可多实例）/ pid（单个 PID）
interval = 1           # 轮询间隔（秒），检测延迟 = 该值
backend = nft          # nft | iptables | auto
udp_mode = server      # server = 过滤临时端口范围内的 UDP 绑定（默认）
                       # all    = 放行全部 UDP 绑定
```

**为什么有些 UDP 端口"看不见"**：`/proc` 无法区分"服务端 bind"和"客户端出站
socket"——后者也绑随机 UDP 端口。afw 默认（`udp_mode = server`）把落在
`ip_local_port_range`（默认 32768-60999，启动日志会打印实际范围）内的 UDP
绑定当作客户端 socket 过滤掉，防止单个客户端查询就把防火墙打开。要让进程绑
定的所有 UDP 端口都放行，设 `udp_mode = all`（注意：客户端 socket 频繁增减
时规则会跟着抖动）。另外两个天然限制：

- 活不过一个轮询周期的短命 socket 采不到（延迟 = interval）
- 容器内进程（非 host 网络）的 socket 在容器 netns 里，宿主上的 afw 看不到；
  能看到的只有 docker-proxy 在宿主侧绑定的发布端口——那正是入站流量实际走的口

按配置运行：`sudo afw -c /etc/afw.d/nginx.conf`

## 装成 systemd 服务（跟随目标服务启停）

```sh
sudo afw -s nginx --gen          # 只生成 /etc/afw.d/nginx.conf
sudo afw -s nginx --install      # 生成配置 + 安装并启用 afw@nginx
sudo afw -s nginx --uninstall    # 停用并删除该单元
sudo afw --list                  # 列出所有单元及运行状态
```

`--install` 会做四件事：

1. 二进制装到 `/usr/local/bin/afw`
2. 生成 `/etc/afw.d/<name>.conf`
3. 写 systemd 模板 `/etc/systemd/system/afw@.service`（`ExecStart=afw -c /etc/afw.d/%i.conf`）
4. 写两处 drop-in，实现与目标服务同步启停：
   - `afw@<name>.service.d/dep.conf`：`After/BindsTo/PartOf=<目标服务>`
     → 目标停止/重启时 afw 一起停（停止前 SIGINT 触发规则清理）
   - `<目标服务>.d/afw.conf`：`Wants=afw@<name>.service`
     → 目标启动时把 afw 一并拉起来

再 `systemctl enable --now afw@<name>.service`，开机自启 + 跟随目标服务。

查看状态：`systemctl status afw@nginx.service`

## 效率与延迟

- 检测延迟 = 轮询间隔（默认 1s），进程 bind 后最迟约 1s 放行；`-i 0.5` 之类可调低
- 单次轮询开销：读 `/proc/<pid>/fd` + 4 个 `/proc/net/*` 文件，纯文本解析。
  以 200 个进程、每进程 50 fd 计，一轮约 1 万次系统调用，实测 CPU 占用 <0.1%
- 规则变更才调用一次 `nft`（单个原子事务，毫秒级）；端口无变化时零内核操作
- 对比 eBPF 方案：eBPF 在 bind 系统调用上挂 hook，延迟趋近 0、无轮询开销，
  但需要内核 ≥4.x 配合、BTF/编译链支持，复杂度高一个量级。对于"一秒内放行"
  的场景，轮询方案完全够用且可移植性最好

## --service 的工作方式

1. `systemctl show <unit> -p ControlGroup` 拿服务 cgroup 路径（--user 服务、
   非 system.slice 单元都能定位）；systemctl 不可用时按 `system.slice/<unit>` 兜底
2. 递归读取该 cgroup（含子 cgroup）下所有 `cgroup.procs` 得到进程列表，
   兼容 cgroup v2 与 v1
3. 对这些 PID 做与 -n 模式相同的端口检测；服务停止 → cgroup 消失 → 规则清空，
   服务重启 → 自动重新定位（限流为每 5s 重试一次）

## 已知边界

- 只管 INPUT 方向的放行，不做拒绝/限速/转发
- nftables 后端对 iptables-legacy 规则不生效（系统是 iptables-nft 或纯 nftables 时没问题）
- UDP 服务端绑定到临时端口范围内的端口会被过滤掉（默认 32768-60999）
- `--install` 会往目标服务的 `.d/` 目录写 `Wants=afw@*.service` drop-in（跟随启动所需）；
  `--uninstall` 会把它删掉
- 多单元各自独立：每个 conf 对应一个 `afw@<name>` 实例，互不干扰
