// 安装：生成配置、写 systemd 单元、enable/start 实例
//   /etc/afw.d/<name>.conf                配置
//   /usr/local/bin/afw                    二进制
//   /etc/systemd/system/afw@.service      通用模板
//   /etc/systemd/system/afw@<name>.service.d/dep.conf
//                                         仅 service 目标：BindsTo=<unit>，跟随目标启停

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::config::{UnitConf, BIN_PATH, CONF_DIR, UNIT_TEMPLATE};
use crate::log;

const UNIT_BODY: &str = "\
[Unit]
Description=afw - 为 %i 动态放行其绑定的端口
Documentation=man:afw(8)
After=network-pre.target
Wants=network-pre.target
Before=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/afw -c /etc/afw.d/%i.conf
# 退出前用 SIGINT 触发 afw 清理自己的防火墙规则
KillSignal=SIGINT
TimeoutStopSec=5
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
";

fn dropin_path(name: &str) -> String {
    format!("/etc/systemd/system/afw@{}.service.d/dep.conf", name)
}

fn dropin_body(unit: &str) -> String {
    format!(
        "[Unit]\n\
         # 跟随目标服务启停：目标停止/重启时 afw 也被停止（并撤销规则）\n\
         After={u}\n\
         BindsTo={u}\n\
         PartOf={u}\n",
        u = unit
    )
}

/// 目标服务自身的 drop-in：让目标启动时把 afw 一并拉起来
fn target_dropin_path(unit: &str) -> String {
    format!("/etc/systemd/system/{}.d/afw.conf", unit)
}

fn target_dropin_body(name: &str) -> String {
    format!(
        "[Unit]\n\
         # 由 afw --install 写入：本服务启动时一并启动 afw@{n}.service\n\
         Wants=afw@{n}.service\n",
        n = name
    )
}

fn sys(args: &[&str], dry: bool) -> Result<bool, String> {
    if dry {
        log(&format!("[dry-run] systemctl {}", args.join(" ")));
        return Ok(true);
    }
    let st = Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|e| format!("执行 systemctl {} 失败: {}", args.join(" "), e))?;
    Ok(st.success())
}

/// 安装二进制到 /usr/local/bin/afw
fn install_bin(dry: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("定位当前可执行文件失败: {}", e))?;
    let need = if Path::new(BIN_PATH).exists() {
        let same = fs::read(&exe)
            .ok()
            .zip(fs::read(BIN_PATH).ok())
            .map(|(a, b)| a == b)
            .unwrap_or(false);
        !same
    } else {
        true
    };
    if !need {
        log(&format!("二进制已是最新: {}", BIN_PATH));
        return Ok(());
    }
    if dry {
        log(&format!("[dry-run] install -m 0755 {} {}", exe.display(), BIN_PATH));
        return Ok(());
    }
    fs::copy(&exe, BIN_PATH).map_err(|e| format!("复制二进制到 {} 失败: {}（需要 root）", BIN_PATH, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(BIN_PATH, fs::Permissions::from_mode(0o755));
    }
    log(&format!("已安装二进制: {}", BIN_PATH));
    Ok(())
}

/// 生成 /etc/afw.d/<name>.conf，返回路径
pub fn gen_conf(conf: &UnitConf, force: bool, dry: bool) -> Result<String, String> {
    let path = conf.path();
    if path.exists() && !force {
        return Err(format!(
            "{} 已存在（加 --force 覆盖）",
            path.display()
        ));
    }
    if dry {
        log(&format!("[dry-run] 写入 {}:\n{}", path.display(), conf.render()));
        return Ok(path.display().to_string());
    }
    fs::create_dir_all(CONF_DIR).map_err(|e| format!("创建 {} 失败: {}（需要 root）", CONF_DIR, e))?;
    fs::write(&path, conf.render()).map_err(|e| format!("写入 {} 失败: {}", path.display(), e))?;
    log(&format!("已生成配置: {}", path.display()));
    Ok(path.display().to_string())
}

/// 完整安装：二进制 + 配置 + systemd 模板 + 依赖 drop-in + enable/start
pub fn install(conf: &UnitConf, force: bool, dry: bool) -> Result<(), String> {
    install_bin(dry)?;
    gen_conf(conf, force, dry)?;

    let name = conf.name();

    // 通用模板
    if !dry && Path::new(UNIT_TEMPLATE).exists() {
        match fs::read_to_string(UNIT_TEMPLATE) {
            Ok(s) if s == UNIT_BODY => log("systemd 模板已存在且一致，跳过"),
            _ => {
                fs::write(UNIT_TEMPLATE, UNIT_BODY)
                    .map_err(|e| format!("写入 {} 失败: {}", UNIT_TEMPLATE, e))?;
                log(&format!("已更新 systemd 模板: {}", UNIT_TEMPLATE));
            }
        }
    } else if dry {
        log(&format!("[dry-run] 写入 {}:\n{}", UNIT_TEMPLATE, UNIT_BODY));
    } else {
        fs::write(UNIT_TEMPLATE, UNIT_BODY).map_err(|e| format!("写入 {} 失败: {}", UNIT_TEMPLATE, e))?;
        log(&format!("已写入 systemd 模板: {}", UNIT_TEMPLATE));
    }

    // service 目标加依赖 drop-in
    if let Some(unit) = conf.target.unit_name() {
        let dp = dropin_path(&name);
        let body = dropin_body(&unit);
        if dry {
            log(&format!("[dry-run] 写入 {}:\n{}", dp, body));
        } else {
            if let Some(parent) = Path::new(&dp).parent() {
                fs::create_dir_all(parent).map_err(|e| format!("创建 {} 失败: {}", parent.display(), e))?;
            }
            fs::write(&dp, body).map_err(|e| format!("写入 {} 失败: {}", dp, e))?;
            log(&format!("已写入依赖: {} (BindsTo={})", dp, unit));
        }

        // 目标服务侧 drop-in：目标启动时把 afw 一起拉起
        let tdp = target_dropin_path(&unit);
        let tbody = target_dropin_body(&name);
        if dry {
            log(&format!("[dry-run] 写入 {}:\n{}", tdp, tbody));
        } else {
            if let Some(parent) = Path::new(&tdp).parent() {
                fs::create_dir_all(parent).map_err(|e| format!("创建 {} 失败: {}", parent.display(), e))?;
            }
            fs::write(&tdp, tbody).map_err(|e| format!("写入 {} 失败: {}", tdp, e))?;
            log(&format!("已写入: {} (Wants=afw@{}.service)", tdp, name));
        }
    }

    sys(&["daemon-reload"], dry)?;
    let inst = format!("afw@{}.service", name);
    sys(&["enable", &inst], dry)?;
    sys(&["restart", &inst], dry)?;
    if !dry {
        log(&format!("已启用并启动 {}", inst));
        log(&format!("查看状态: systemctl status {}", inst));
    }
    Ok(())
}

/// 卸载：停掉实例、删配置与 drop-in
pub fn uninstall(conf: &UnitConf, dry: bool) -> Result<(), String> {
    let name = conf.name();
    let inst = format!("afw@{}.service", name);
    sys(&["stop", &inst], dry)?;
    sys(&["disable", &inst], dry)?;

    let dp = dropin_path(&name);
    if Path::new(&dp).exists() {
        if dry {
            log(&format!("[dry-run] 删除 {}", dp));
        } else {
            fs::remove_file(&dp).map_err(|e| format!("删除 {} 失败: {}", dp, e))?;
            if let Some(parent) = Path::new(&dp).parent() {
                let _ = fs::remove_dir(parent);
            }
            log(&format!("已删除 {}", dp));
        }
    }

    // 目标服务侧的 Wants drop-in
    if let Some(unit) = conf.target.unit_name() {
        let tdp = target_dropin_path(&unit);
        if Path::new(&tdp).exists() {
            if dry {
                log(&format!("[dry-run] 删除 {}", tdp));
            } else {
                fs::remove_file(&tdp).map_err(|e| format!("删除 {} 失败: {}", tdp, e))?;
                if let Some(parent) = Path::new(&tdp).parent() {
                    let _ = fs::remove_dir(parent);
                }
                log(&format!("已删除 {}", tdp));
            }
        }
    }

    let p = conf.path();
    if p.exists() {
        if dry {
            log(&format!("[dry-run] 删除 {}", p.display()));
        } else {
            fs::remove_file(&p).map_err(|e| format!("删除 {} 失败: {}", p.display(), e))?;
            log(&format!("已删除 {}", p.display()));
        }
    }
    sys(&["daemon-reload"], dry)?;
    if !dry {
        log(&format!("已卸载 {}", inst));
    }
    Ok(())
}

/// 列出 /etc/afw.d 下的单元及运行状态
pub fn list_units() {
    let dir = Path::new(CONF_DIR);
    if !dir.exists() {
        log(&format!("{} 不存在，还没有任何单元", CONF_DIR));
        return;
    }
    let mut entries: Vec<_> = match fs::read_dir(dir) {
        Ok(e) => e.flatten().collect(),
        Err(e) => {
            log(&format!("读取 {} 失败: {}", CONF_DIR, e));
            return;
        }
    };
    entries.sort_by_key(|e| e.file_name());
    if entries.is_empty() {
        log(&format!("{} 为空，还没有任何单元", CONF_DIR));
        return;
    }
    log(&format!("{} 下的单元:", CONF_DIR));
    for e in entries {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("conf") {
            continue;
        }
        let name = p.file_stem().and_then(|s| s.to_str()).unwrap_or("?").to_string();
        match UnitConf::load(p.to_str().unwrap_or("")) {
            Ok(c) => {
                let active = Command::new("systemctl")
                    .args(["is-active", &format!("afw@{}.service", name)])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                println!("  {:<20} {:<28} systemd: {}", name, c.target.desc(), active);
            }
            Err(err) => println!("  {:<20} 配置错误: {}", name, err),
        }
    }
}
