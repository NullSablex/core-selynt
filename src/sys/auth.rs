//! Who the caller is, and what they are allowed to act on.
//!
//! This binary is setuid root, so the process is root regardless of who ran it.
//! Authority therefore comes from the **real** uid — which the kernel preserves
//! across the setuid — and from DirectAdmin's own account database. The
//! `USERNAME` environment variable is supplied by the caller and is never
//! trusted on its own.
//!
//! Three levels, matching what each command actually needs:
//!
//! 1. **any account** — acts only on its own apps;
//! 2. **service accounts and DirectAdmin admins/resellers**
//!    ([`caller_is_privileged`]) — may act on behalf of an account, because the
//!    panel's CGI runs as one of them;
//! 3. **real root** ([`caller_is_root`]) — installing and removing the plugin.
//!
//! Matching account *names* against a list was tried and abandoned: the admin
//! account can be renamed and there can be many resellers, so the `usertype=`
//! field in DirectAdmin's database is the authority instead.

use std::ptr;

use anyhow::{Context, Result};

use super::state::{DA_USERS_BASE, PLUGIN_PATH, validate_name};

/// Buffer for `getpwnam_r`/`getpwuid_r`. 4 KiB covers any realistic passwd entry.
const GETPWNAM_BUF_SIZE: usize = 4096;

/// Files under the plugin's `etc/` naming the accounts DirectAdmin and the web
/// server run as. Written at install time by probing the running system, so a
/// renamed account still resolves.
const SERVICE_ACCOUNT_FILES: [&str; 3] =
    ["etc/da_user", "etc/da_cgi_user", "etc/ols_web_user"];

/// Looks up an account by name, returning `(uid, gid, home)`.
/// uid and gid of a system account, when it exists.
/// The account's home directory, from the system account database.
///
/// The root prelude cannot use `$HOME`: it is inherited from whoever invoked
/// the binary, which for the panel is the web server, not the account being
/// acted on.
pub(crate) fn lookup_home(username: &str) -> Option<String> {
    lookup_user(username).ok().map(|(_, _, home)| home)
}

pub(crate) fn lookup_user_ids(username: &str) -> Option<(u32, u32)> {
    lookup_user(username).ok().map(|(uid, gid, _)| (uid, gid))
}

/// Whether a system account by this name exists.
///
/// A state directory can outlive the account it belongs to, and acting on one
/// of those would resolve to nothing useful.
pub(crate) fn user_exists(username: &str) -> bool {
    lookup_user(username).is_ok()
}

fn lookup_user(username: &str) -> Result<(u32, u32, String)> {
    let cname = std::ffi::CString::new(username).context("USERNAME contains a null byte")?;

    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; GETPWNAM_BUF_SIZE];
    let mut result: *mut libc::passwd = ptr::null_mut();

    let ret = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            ptr::from_mut(&mut pwd),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            ptr::from_mut(&mut result),
        )
    };

    if ret != 0 || result.is_null() {
        anyhow::bail!("user {username:?} not found in /etc/passwd");
    }

    let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
        .to_str()
        .context("home dir is not valid UTF-8")?
        .to_string();

    Ok((pwd.pw_uid, pwd.pw_gid, home))
}

/// Resolves a uid back to its account name, if it has one.
pub(crate) fn lookup_uid(uid: u32) -> Option<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; GETPWNAM_BUF_SIZE];
    let mut result: *mut libc::passwd = ptr::null_mut();

    let ret = unsafe {
        libc::getpwuid_r(
            uid,
            ptr::from_mut(&mut pwd),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            ptr::from_mut(&mut result),
        )
    };

    if ret != 0 || result.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
        .to_str()
        .ok()
        .map(ToString::to_string)
}

/// Path to a DirectAdmin account's `user.conf`.
fn da_user_conf(username: &str) -> String {
    format!("{DA_USERS_BASE}/{username}/user.conf")
}

/// Reads `usertype=` for a DirectAdmin account: `admin`, `reseller` or `user`.
/// `None` when there is no such account or the file cannot be read.
///
/// This lives under `data/users/`, which is `diradmin`-owned and `0700`, so it
/// is only readable in the root prelude — exactly where authorisation is
/// decided, and out of reach of the caller.
///
/// The name is interpolated into a path, so it is validated first. It comes
/// from `getpwuid()` rather than the caller, but this decides authorisation and
/// the check is nearly free.
fn da_usertype(username: &str) -> Option<String> {
    if !validate_name(username) {
        return None;
    }
    parse_usertype(&std::fs::read_to_string(da_user_conf(username)).ok()?)
}

/// Extracts `usertype=` from a `user.conf` body.
fn parse_usertype(conf: &str) -> Option<String> {
    conf.lines()
        .find_map(|l| l.trim().strip_prefix("usertype="))
        .map(|v| v.trim().to_string())
}

/// True when a DirectAdmin `usertype` may act on other accounts.
fn usertype_is_privileged(usertype: Option<&str>) -> bool {
    matches!(usertype, Some("admin" | "reseller"))
}

/// True when the caller may act on other accounts and run `admin` commands.
///
/// DirectAdmin executes plugin CGI **as the logged-in account** — `admin` on a
/// default install, but the name is arbitrary and there can be several
/// resellers. Matching account *names* against a list was therefore always
/// going to break on someone's server; authority comes from the account's
/// `usertype=` in DirectAdmin's own database instead:
///
///   * `root` — installer, cron and shell use;
///   * a DA account whose `usertype` is `admin` or `reseller`;
///   * the service accounts in [`SERVICE_ACCOUNT_FILES`], for the paths where
///     DA runs as a worker rather than as the user.
///
/// A plain `user` account is never privileged, so a customer cannot reach
/// another customer's apps even though the CGI runs under their own uid.
/// Whether the caller may install, reconfigure or remove the plugin itself.
///
/// Stricter than [`caller_is_privileged`] on purpose. The web server and
/// DirectAdmin's CGI account are trusted to act *on behalf of* an account —
/// that is what serving the panel requires — but not to take the panel apart.
/// Anything reaching one of those accounts, a compromised CGI endpoint for
/// instance, could otherwise stop every app on the server and strip the
/// configuration.
///
/// Installation is a decision an administrator makes at a shell, so it asks for
/// the identity a shell has.
pub(crate) fn caller_is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

pub(crate) fn caller_is_privileged() -> bool {
    let caller_uid = unsafe { libc::getuid() };
    if caller_uid == 0 {
        return true;
    }
    let Some(caller) = lookup_uid(caller_uid) else {
        return false;
    };

    if usertype_is_privileged(da_usertype(&caller).as_deref()) {
        return true;
    }

    SERVICE_ACCOUNT_FILES
        .iter()
        .filter_map(|f| std::fs::read_to_string(format!("{PLUGIN_PATH}/{f}")).ok())
        .any(|name| {
            let name = name.trim();
            !name.is_empty() && name == caller
        })
}

/// Resolves the user this invocation is allowed to act on, as
/// `(uid, gid, home, username)`.
///
/// This binary is setuid root and world-executable, so `USERNAME` — a value the
/// caller supplies — cannot be trusted by itself. Taking it at face value let
/// any local account run `USERNAME=victim core-selynt ...` and drive the tool
/// over someone else's apps and state with root behind it.
///
/// Authority comes from the real uid instead (see [`caller_is_privileged`]):
/// privileged callers may name any account, everyone else acts only as
/// themselves.
pub(crate) fn resolve_target_user() -> Result<(u32, u32, String, String)> {
    let caller_uid = unsafe { libc::getuid() };
    let caller = lookup_uid(caller_uid);
    let trusted = caller_is_privileged();

    let username = match (std::env::var("USERNAME"), trusted) {
        (Ok(requested), true) => requested,
        (Ok(requested), false) => {
            let own = caller
                .clone()
                .context("caller uid has no account in /etc/passwd")?;
            if requested != own {
                anyhow::bail!(
                    "refusing to act as {requested:?}: caller is {own:?} (uid {caller_uid})"
                );
            }
            own
        }
        // No USERNAME: act as the caller. Root is never a valid target — the
        // privilege drop refuses uid 0 — so say that plainly instead of
        // failing later with a confusing "still root" message.
        (Err(_), _) => {
            let own = caller.context("caller uid has no account in /etc/passwd")?;
            if caller_uid == 0 {
                anyhow::bail!("USERNAME env not set (required when running as root)");
            }
            own
        }
    };

    let (uid, gid, home) = lookup_user(&username)?;
    Ok((uid, gid, home, username))
}

/// Drops privileges to the real user. Must be called AFTER any work that needs
/// root. Uses `initgroups` so the process keeps the user's supplementary
/// groups — required to reach group-restricted runtime binaries (e.g. node in
/// `/usr/local/bin/` on `CloudLinux`).
pub(crate) fn drop_privileges(uid: u32, gid: u32, username: &str) -> Result<()> {
    let cname = std::ffi::CString::new(username).context("invalid username for initgroups")?;
    unsafe {
        if libc::initgroups(cname.as_ptr(), gid) != 0 {
            anyhow::bail!(
                "initgroups({username}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        if libc::setgid(gid) != 0 {
            anyhow::bail!("setgid({gid}) failed: {}", std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            anyhow::bail!("setuid({uid}) failed: {}", std::io::Error::last_os_error());
        }
        if libc::geteuid() == 0 || libc::getuid() == 0 {
            anyhow::bail!("privilege drop failed — still root (uid)");
        }
        if libc::getegid() == 0 || libc::getgid() == 0 {
            anyhow::bail!("privilege drop failed — still root (gid)");
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            anyhow::bail!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_usertype_from_user_conf() {
        let conf = "username=admin\nusertype=admin\ncreator=root\n";
        assert_eq!(parse_usertype(conf).as_deref(), Some("admin"));
    }

    #[test]
    fn parses_usertype_with_surrounding_space() {
        assert_eq!(parse_usertype("  usertype=reseller  \n").as_deref(), Some("reseller"));
    }

    #[test]
    fn missing_usertype_is_none() {
        assert_eq!(parse_usertype("username=bob\ncreator=root\n"), None);
    }

    #[test]
    fn only_admin_and_reseller_are_privileged() {
        assert!(usertype_is_privileged(Some("admin")));
        assert!(usertype_is_privileged(Some("reseller")));
        assert!(!usertype_is_privileged(Some("user")));
        assert!(!usertype_is_privileged(None));
        // Case matters: DA writes these lowercase, anything else is not a match.
        assert!(!usertype_is_privileged(Some("Admin")));
        assert!(!usertype_is_privileged(Some("")));
    }

    #[test]
    fn installing_requires_more_than_being_privileged() {
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        assert!(!caller_is_root(), "non-root must not pass the install gate");
    }

    #[test]
    fn user_conf_path_is_scoped_to_data_users() {
        let p = da_user_conf("bob");
        assert_eq!(p, "/usr/local/directadmin/data/users/bob/user.conf");
    }

    /// The identity files live under the plugin's `etc/`, and the prefix is
    /// part of the constant rather than of the path built from it.
    ///
    /// Splitting this module once dropped the `etc/` prefix while moving the
    /// constant. Everything still compiled and every unit test passed: the
    /// lookup simply found no file, so `apache` and `nobody` stopped being
    /// recognised as service accounts and the panel refused every request a
    /// customer made — "refusing to act as". Nothing but running it caught that.
    #[test]
    fn service_account_files_keep_the_etc_prefix() {
        for f in SERVICE_ACCOUNT_FILES {
            assert!(
                f.starts_with("etc/"),
                "{f} must be relative to the plugin root, not to etc/"
            );
        }
        assert!(SERVICE_ACCOUNT_FILES.contains(&"etc/ols_web_user"));
    }
}
