//! Walking the plugin tree, and the permissions each file should have.
//!
//! Shared by the installer, which *applies* these modes, and the diagnostic,
//! which *verifies* them — two copies would drift, and the drift is invisible.
//! Neither walk follows symlinks: a link could point anywhere, and both callers
//! act on what they find.

use std::path::Path;

/// Reads a file's permission bits as an octal number, e.g. `644`.
/// The permissions a file actually has. Sits beside [`expected_mode`] on
/// purpose: the diagnostic compares the two, and reading one without the other
/// says nothing.
pub(super) fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(std::fs::metadata(path).ok()?.mode() & 0o7777)
}

/// The permissions a file under the plugin tree is expected to have.
pub fn expected_mode(path: &Path) -> u32 {
    let s = path.to_string_lossy();
    if s.ends_with(".service") {
        return 0o644;
    }
    // DirectAdmin executes everything under the access-level directories as a
    // CGI script — "Files should be set to executable mode (755)", says the
    // plugin documentation — so the rule is the directory, not the extension.
    // The pages carry no extension at all: the request path is the file name.
    if s.contains("/user/") || s.contains("/admin/") || s.contains("/reseller/") {
        return 0o755;
    }

    if (s.contains("/scripts/") && s.ends_with(".sh")) || s.contains("/hooks/") {
        return 0o755;
    }
    0o644
}

/// Walks a directory tree, calling `visit` for every directory found.
pub fn walk_dirs(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    visit(dir);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Same reason as `walk`: a symlinked directory would take the caller
        // outside this tree, and changing permissions through it would land on
        // whatever it points at.
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            walk_dirs(&path, visit);
        }
    }
}

/// Walks a directory tree, calling `visit` for every file found.
pub fn walk(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Do not follow symlinks: a link could point anywhere, and the check
        // is about this tree.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            walk(&path, visit);
        } else if meta.is_file() {
            visit(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::expected_mode;
    use std::path::Path;

    #[test]
    fn service_files_are_not_executable() {
        assert_eq!(
            expected_mode(Path::new("/x/scripts/selynt-panel.service")),
            0o644
        );
    }

    #[test]
    fn cgi_endpoints_and_pages_are_executable() {
        assert_eq!(expected_mode(Path::new("/x/user/api/apps.raw")), 0o755);
        assert_eq!(expected_mode(Path::new("/x/user/index.html")), 0o755);
        // The pages carry no extension: the request path is the file name.
        assert_eq!(expected_mode(Path::new("/x/user/apps")), 0o755);
        assert_eq!(expected_mode(Path::new("/x/admin/config")), 0o755);
        assert_eq!(expected_mode(Path::new("/x/scripts/install.sh")), 0o755);
        assert_eq!(expected_mode(Path::new("/x/hooks/anything")), 0o755);
    }

    #[test]
    fn everything_else_is_read_only() {
        assert_eq!(expected_mode(Path::new("/x/images/menu_user.json")), 0o644);
        assert_eq!(expected_mode(Path::new("/x/lib/common.php")), 0o644);
        assert_eq!(expected_mode(Path::new("/x/LICENSE")), 0o644);
    }
}
