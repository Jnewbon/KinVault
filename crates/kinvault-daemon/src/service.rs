//! Starting `kinvaultd` automatically at login, per user: a systemd user
//! unit on Linux, a LaunchAgent on macOS, and the per-user `Run` registry
//! key on Windows.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

const NAME: &str = "kinvaultd";

/// Finds `kinvaultd` next to the running executable (CLI or GUI), then on PATH.
///
/// Inside an AppImage the executable lives on a temporary mount that goes
/// away when the app exits, so a copy in the user's data directory is used
/// instead; that copy is what gets started and registered to run at login.
pub fn daemon_binary() -> Result<PathBuf> {
    let found = find_daemon()?;
    let appdir = std::env::var_os("APPDIR").map(PathBuf::from);
    let stable = directories::ProjectDirs::from("", "", "KinVault")
        .context("could not determine the KinVault data directory")?
        .data_dir()
        .join("bin");
    stable_location(found, appdir.as_deref(), &stable)
}

fn find_daemon() -> Result<PathBuf> {
    let file = format!("{NAME}{}", std::env::consts::EXE_SUFFIX);
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
        && dir.join(&file).is_file()
    {
        return Ok(dir.join(&file));
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            if dir.join(&file).is_file() {
                return Ok(dir.join(&file));
            }
        }
    }
    bail!("could not find {file}; install it next to this program or on your PATH")
}

/// Returns `found`, or a fresh copy of it in `stable_dir` when it lives inside
/// a temporary AppImage mount (`appdir`).
fn stable_location(found: PathBuf, appdir: Option<&Path>, stable_dir: &Path) -> Result<PathBuf> {
    let Some(appdir) = appdir.filter(|a| found.starts_with(a)) else {
        return Ok(found);
    };
    std::fs::create_dir_all(stable_dir)?;
    let dest = stable_dir.join(found.file_name().context("daemon path has no file name")?);
    // Copy then rename, which also works while an older copy is running.
    let tmp = stable_dir.join(format!(".{NAME}.tmp"));
    std::fs::copy(&found, &tmp)
        .with_context(|| format!("copying {} out of {}", found.display(), appdir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, &dest)?;
    Ok(dest)
}

/// Starts the daemon in the background without installing it.
pub fn start_detached(daemon: &Path, state_dir: Option<&Path>) -> Result<()> {
    let mut cmd = Command::new(daemon);
    if let Some(dir) = state_dir {
        cmd.arg("--state").arg(dir);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW);
    }
    cmd.spawn()
        .with_context(|| format!("starting {}", daemon.display()))?;
    Ok(())
}

fn run(cmd: &mut Command) -> Result<()> {
    let output = cmd.output().with_context(|| format!("running {cmd:?}"))?;
    if !output.status.success() {
        bail!(
            "{cmd:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn args(daemon: &Path, state_dir: Option<&Path>) -> Vec<String> {
    let mut args = vec![daemon.display().to_string()];
    if let Some(dir) = state_dir {
        args.push("--state".into());
        args.push(dir.display().to_string());
    }
    args
}

/// systemd quoting: wrap every argument in double quotes, escaping `"` and `\`.
pub fn systemd_unit(daemon: &Path, state_dir: Option<&Path>) -> String {
    let exec = args(daemon, state_dir)
        .iter()
        .map(|a| format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Unit]\n\
         Description=KinVault backup service\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={exec}\n\
         Restart=on-failure\n\
         RestartSec=10\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

pub fn launchd_plist(daemon: &Path, state_dir: Option<&Path>) -> String {
    let escape = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let program: String = args(daemon, state_dir)
        .iter()
        .map(|a| format!("        <string>{}</string>\n", escape(a)))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20   <key>Label</key>\n\
         \x20   <string>com.kinvault.kinvaultd</string>\n\
         \x20   <key>ProgramArguments</key>\n\
         \x20   <array>\n\
         {program}\
         \x20   </array>\n\
         \x20   <key>RunAtLoad</key>\n\
         \x20   <true/>\n\
         \x20   <key>KeepAlive</key>\n\
         \x20   <true/>\n\
         </dict>\n\
         </plist>\n"
    )
}

#[cfg(target_os = "linux")]
fn unit_path() -> Result<PathBuf> {
    let dirs = directories::BaseDirs::new().context("no home directory")?;
    Ok(dirs
        .config_dir()
        .join("systemd/user")
        .join(format!("{NAME}.service")))
}

#[cfg(target_os = "macos")]
fn plist_path() -> Result<PathBuf> {
    let dirs = directories::BaseDirs::new().context("no home directory")?;
    Ok(dirs
        .home_dir()
        .join("Library/LaunchAgents/com.kinvault.kinvaultd.plist"))
}

#[cfg(windows)]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

/// Starts the daemon at every login, and right now.
pub fn install(daemon: &Path, state_dir: Option<&Path>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = unit_path()?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, systemd_unit(daemon, state_dir))?;
        run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
        run(Command::new("systemctl").args([
            "--user",
            "enable",
            "--now",
            &format!("{NAME}.service"),
        ]))?;
    }
    #[cfg(target_os = "macos")]
    {
        let path = plist_path()?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, launchd_plist(daemon, state_dir))?;
        run(Command::new("launchctl").arg("load").arg("-w").arg(&path))?;
    }
    #[cfg(windows)]
    {
        let value = args(daemon, state_dir)
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(" ");
        run(Command::new("reg").args([
            "add", RUN_KEY, "/v", "KinVault", "/t", "REG_SZ", "/d", &value, "/f",
        ]))?;
        start_detached(daemon, state_dir)?;
    }
    Ok(())
}

/// Stops starting the daemon at login (and stops the managed instance).
pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = unit_path()?;
        if path.exists() {
            run(Command::new("systemctl").args([
                "--user",
                "disable",
                "--now",
                &format!("{NAME}.service"),
            ]))?;
            std::fs::remove_file(&path)?;
            run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
        }
    }
    #[cfg(target_os = "macos")]
    {
        let path = plist_path()?;
        if path.exists() {
            run(Command::new("launchctl").arg("unload").arg("-w").arg(&path))?;
            std::fs::remove_file(&path)?;
        }
    }
    #[cfg(windows)]
    {
        if is_installed() {
            run(Command::new("reg").args(["delete", RUN_KEY, "/v", "KinVault", "/f"]))?;
        }
    }
    Ok(())
}

pub fn is_installed() -> bool {
    #[cfg(target_os = "linux")]
    return unit_path().is_ok_and(|p| p.exists());
    #[cfg(target_os = "macos")]
    return plist_path().is_ok_and(|p| p.exists());
    #[cfg(windows)]
    return Command::new("reg")
        .args(["query", RUN_KEY, "/v", "KinVault"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    #[allow(unreachable_code)]
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_quotes_paths() {
        let unit = systemd_unit(
            Path::new("/opt/Kin Vault/kinvaultd"),
            Some(Path::new("/home/me/a \"b\"")),
        );
        assert!(
            unit.contains(r#"ExecStart="/opt/Kin Vault/kinvaultd" "--state" "/home/me/a \"b\"""#),
            "{unit}"
        );
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn appimage_daemon_is_copied_somewhere_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let mount = tmp.path().join(".mount_KinVau");
        std::fs::create_dir_all(mount.join("usr/bin")).unwrap();
        let inside = mount.join("usr/bin/kinvaultd");
        std::fs::write(&inside, b"daemon v2").unwrap();
        let stable = tmp.path().join("data/bin");

        // Not in an AppImage, or found outside the mount: used as is.
        assert_eq!(
            stable_location(inside.clone(), None, &stable).unwrap(),
            inside
        );
        let elsewhere = tmp.path().join("kinvaultd");
        assert_eq!(
            stable_location(elsewhere.clone(), Some(&mount), &stable).unwrap(),
            elsewhere
        );
        assert!(!stable.exists());

        // From the mount: copied out (replacing an older copy).
        std::fs::create_dir_all(&stable).unwrap();
        std::fs::write(stable.join("kinvaultd"), b"daemon v1").unwrap();
        let copy = stable_location(inside, Some(&mount), &stable).unwrap();
        assert_eq!(copy, stable.join("kinvaultd"));
        assert_eq!(std::fs::read(&copy).unwrap(), b"daemon v2");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }

    #[test]
    fn plist_lists_arguments() {
        let plist = launchd_plist(Path::new("/Applications/KinVault.app/kinvaultd"), None);
        assert!(plist.contains("<string>/Applications/KinVault.app/kinvaultd</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(!plist.contains("--state"));
    }
}
