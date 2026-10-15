//! Patterns for leaving files and folders out of a backup.
//!
//! - `*` matches any part of one name and `?` one character; neither crosses `/`.
//! - `...` as a whole path element matches any number of folders, even none.
//! - A pattern starting with `/` (or a drive, `C:/`) is an absolute path; any
//!   other pattern matches at any depth, as if it started with `/.../`.
//! - A pattern ending in `/...` (or `/`) leaves out a folder and everything in
//!   it. Any other pattern matches files only, so `/media/*` leaves out the
//!   files in `/media` but not its subfolders.
//!
//! Examples: `*.bat`, `/media/*.bat`, `/media/.../*.bat`, `/media/*`,
//! `/media/...`, `target/...`, `node_modules/`.

use std::path::{Component, Path};

use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    /// `...`: any number of path elements.
    AnyDepth,
    /// One path element, possibly with `*` and `?`.
    Name(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pattern {
    /// Lowercased drive (`c:`) the pattern is limited to, on Windows.
    drive: Option<String>,
    parts: Vec<Part>,
}

/// A set of exclude patterns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Excludes {
    patterns: Vec<Pattern>,
}

impl Excludes {
    pub fn parse<S: AsRef<str>>(patterns: &[S]) -> Result<Self> {
        let patterns = patterns
            .iter()
            .map(|p| parse_pattern(p.as_ref()))
            .collect::<Result<_>>()?;
        Ok(Self { patterns })
    }

    /// Whether a file (or symlink) at this absolute path is left out.
    pub fn excludes_file(&self, path: &Path) -> bool {
        let (drive, names) = split_path(path);
        self.patterns.iter().any(|p| {
            if p.parts.last() == Some(&Part::AnyDepth) {
                // A folder pattern: the file must be inside a matching folder,
                // so a file that merely has the folder's name is kept.
                !names.is_empty() && p.matches(drive.as_deref(), &names[..names.len() - 1])
            } else {
                p.matches(drive.as_deref(), &names)
            }
        })
    }

    /// Whether a folder at this absolute path is left out, with everything in it.
    pub fn excludes_dir(&self, path: &Path) -> bool {
        let (drive, names) = split_path(path);
        self.patterns
            .iter()
            .filter(|p| p.parts.last() == Some(&Part::AnyDepth))
            .any(|p| p.matches(drive.as_deref(), &names))
    }

    /// Whether a path of unknown kind is left out, directly or because a
    /// folder above it is (for filtering file-change notifications).
    pub fn excludes_any(&self, path: &Path) -> bool {
        self.excludes_file(path) || path.ancestors().any(|a| self.excludes_dir(a))
    }
}

impl Pattern {
    fn matches(&self, drive: Option<&str>, names: &[String]) -> bool {
        if let (Some(want), Some(have)) = (&self.drive, drive)
            && want != have
        {
            return false;
        }
        match_parts(&self.parts, names)
    }
}

fn parse_pattern(raw: &str) -> Result<Pattern> {
    let invalid = |why: &str| Error::Invalid(format!("exclude pattern {raw:?} {why}"));
    let text = raw.trim().replace('\\', "/");
    if text.is_empty() {
        return Err(invalid("is empty"));
    }
    let (drive, rest, anchored) = match text.as_bytes() {
        [d, b':', b'/', ..] if d.is_ascii_alphabetic() => {
            (Some(text[..2].to_ascii_lowercase()), &text[3..], true)
        }
        [b'/', ..] => (None, &text[1..], true),
        _ => (None, text.as_str(), false),
    };
    let mut parts: Vec<Part> = Vec::new();
    if !anchored {
        parts.push(Part::AnyDepth);
    }
    for element in rest.split('/') {
        match element {
            // Repeated or trailing slashes.
            "" => {}
            "." => {}
            ".." => return Err(invalid("can't contain \"..\"; use \"...\" for any folders")),
            "..." => {
                // `.../...` means the same as `...`.
                if parts.last() != Some(&Part::AnyDepth) {
                    parts.push(Part::AnyDepth);
                }
            }
            name => parts.push(Part::Name(fold_case(name))),
        }
    }
    // A trailing slash means the folder and everything in it.
    if text.ends_with('/') && parts.last() != Some(&Part::AnyDepth) {
        parts.push(Part::AnyDepth);
    }
    if parts.iter().all(|p| *p == Part::AnyDepth) {
        return Err(invalid("would leave out everything"));
    }
    Ok(Pattern { drive, parts })
}

fn match_parts(parts: &[Part], names: &[String]) -> bool {
    match parts.split_first() {
        None => names.is_empty(),
        Some((Part::AnyDepth, rest)) => {
            (0..=names.len()).any(|skip| match_parts(rest, &names[skip..]))
        }
        Some((Part::Name(glob), rest)) => match names.split_first() {
            Some((name, names)) => match_glob(glob, name) && match_parts(rest, names),
            None => false,
        },
    }
}

/// `*` and `?` wildcards within one name. Compares characters, not bytes,
/// so `?` matches one character even where it takes several bytes (`é`).
fn match_glob(glob: &str, name: &str) -> bool {
    let glob: Vec<char> = glob.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut g, mut n) = (0, 0);
    // Where to resume after the last `*`, and how much of `name` it has taken.
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        match glob.get(g) {
            Some('*') => {
                star = Some((g + 1, n));
                g += 1;
            }
            Some('?') => {
                g += 1;
                n += 1;
            }
            Some(&c) if c == name[n] => {
                g += 1;
                n += 1;
            }
            _ => match star {
                Some((after, taken)) => {
                    g = after;
                    n = taken + 1;
                    star = Some((after, taken + 1));
                }
                None => return false,
            },
        }
    }
    glob[g..].iter().all(|&c| c == '*')
}

/// Splits an absolute path into its drive (Windows) and element names.
fn split_path(path: &Path) -> (Option<String>, Vec<String>) {
    let names = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(fold_case(&n.to_string_lossy())),
            _ => None,
        })
        .collect();
    (drive(path), names)
}

/// The lowercased drive (`c:`) a Windows path starts with.
#[cfg(windows)]
fn drive(path: &Path) -> Option<String> {
    match path.components().next() {
        Some(Component::Prefix(p)) => Some(p.as_os_str().to_string_lossy().to_ascii_lowercase()),
        _ => None,
    }
}

/// Other systems have no drives.
#[cfg(not(windows))]
fn drive(_path: &Path) -> Option<String> {
    None
}

/// Windows paths ignore case.
#[cfg(windows)]
fn fold_case(s: &str) -> String {
    s.to_lowercase()
}

/// Elsewhere case matters.
#[cfg(not(windows))]
fn fold_case(s: &str) -> String {
    s.to_string()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn ex(patterns: &[&str]) -> Excludes {
        Excludes::parse(patterns).unwrap()
    }

    fn file(e: &Excludes, p: &str) -> bool {
        e.excludes_file(Path::new(p))
    }

    fn dir(e: &Excludes, p: &str) -> bool {
        e.excludes_dir(Path::new(p))
    }

    #[test]
    fn name_anywhere() {
        let e = ex(&["*.bat"]);
        assert!(file(&e, "/run.bat"));
        assert!(file(&e, "/media/run.bat"));
        assert!(file(&e, "/home/me/a/b/run.bat"));
        assert!(!file(&e, "/home/me/run.bat.txt"));
        assert!(!dir(&e, "/home/me/scripts.bat"));
    }

    #[test]
    fn files_directly_in_a_folder() {
        let e = ex(&["/media/*.bat"]);
        assert!(file(&e, "/media/run.bat"));
        assert!(!file(&e, "/media/sub/run.bat"));
        assert!(!file(&e, "/other/media/run.bat"));
    }

    #[test]
    fn files_in_a_folder_and_below() {
        let e = ex(&["/media/.../*.bat"]);
        assert!(file(&e, "/media/run.bat"));
        assert!(file(&e, "/media/sub/deeper/run.bat"));
        assert!(!file(&e, "/media/sub/run.txt"));
        assert!(!file(&e, "/elsewhere/run.bat"));
    }

    #[test]
    fn star_matches_files_not_folders() {
        let e = ex(&["/media/*"]);
        assert!(file(&e, "/media/a.txt"));
        assert!(!dir(&e, "/media/sub"));
        assert!(!file(&e, "/media/sub/a.txt"));
    }

    #[test]
    fn everything_in_a_folder() {
        let e = ex(&["/media/..."]);
        assert!(dir(&e, "/media"));
        assert!(dir(&e, "/media/sub"));
        assert!(file(&e, "/media/sub/a.txt"));
        assert!(!dir(&e, "/mediax"));
        assert!(!file(&e, "/other/a.txt"));
    }

    #[test]
    fn folders_by_name_anywhere() {
        for e in [ex(&["target/..."]), ex(&["target/"])] {
            assert!(dir(&e, "/home/me/repo/target"));
            assert!(dir(&e, "/home/me/repo/crates/x/target"));
            assert!(!dir(&e, "/home/me/repo/targets"));
            // A file called "target" stays: the pattern names a folder.
            assert!(!file(&e, "/home/me/repo/target"));
        }
        let e = ex(&["node_modules/", "build/..."]);
        assert!(e.excludes_any(Path::new("/w/app/node_modules/x/index.js")));
        assert!(e.excludes_any(Path::new("/w/app/build/out.o")));
        assert!(!e.excludes_any(Path::new("/w/app/src/main.rs")));
    }

    #[test]
    fn wildcards_within_names() {
        assert!(match_glob("*.bat", ".bat"));
        assert!(match_glob("a*b*c", "aXXbYYc"));
        assert!(!match_glob("a*b*c", "aXXbYY"));
        assert!(match_glob("?.txt", "a.txt"));
        assert!(!match_glob("?.txt", "ab.txt"));
        assert!(match_glob("*", ""));
        assert!(match_glob("**", "anything"));
        // One character, however many bytes it takes.
        assert!(match_glob("?.txt", "é.txt"));
        assert!(match_glob("r?sum?.pdf", "résumé.pdf"));
        assert!(match_glob("??.txt", "日本.txt"));
        assert!(!match_glob("?.txt", "日本.txt"));
    }

    #[test]
    fn question_mark_in_patterns() {
        let e = ex(&["/logs/app-?.log", "photo-??.jpg"]);
        assert!(file(&e, "/logs/app-1.log"));
        assert!(file(&e, "/logs/app-é.log"));
        assert!(!file(&e, "/logs/app-10.log"));
        assert!(!file(&e, "/logs/app-.log"));
        assert!(file(&e, "/home/me/pics/photo-07.jpg"));
        assert!(!file(&e, "/home/me/pics/photo-7.jpg"));
    }

    #[test]
    fn invalid_patterns() {
        for bad in ["", "   ", "/", "...", "/...", "*/../x"] {
            assert!(Excludes::parse(&[bad]).is_err(), "{bad:?}");
        }
        assert!(Excludes::parse(&["*"]).is_ok());
    }

    #[test]
    fn current_folder_elements_are_ignored() {
        let e = ex(&["/media/./photos/"]);
        assert!(dir(&e, "/media/photos"));
    }

    #[test]
    fn drive_letters_limit_a_pattern_to_that_drive() {
        let e = ex(&["D:\\Games\\..."]);
        let p = &e.patterns[0];
        assert_eq!(p.drive.as_deref(), Some("d:"));
        let names = vec!["Games".to_string()];
        assert!(p.matches(Some("d:"), &names));
        assert!(!p.matches(Some("c:"), &names));
        // Paths without a drive (not Windows) aren't limited.
        assert!(p.matches(None, &names));
    }
}
