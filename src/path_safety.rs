use crate::errors::CryoErrors;
use std::path::{Component, Path, PathBuf};

pub(crate) fn is_safe_path(p: &Path) -> bool {
    for component in p.components() {
        match component {
            Component::ParentDir => return false,
            Component::RootDir => return false,
            Component::Prefix(_) => return false,
            Component::Normal(_) => {}
            Component::CurDir => {}
        }
    }
    true
}

pub(crate) fn safe_output_path(root: &Path, relative: &Path) -> Result<PathBuf, CryoErrors> {
    if !is_safe_path(relative) {
        return Err(CryoErrors::UnsafePath(relative.to_path_buf().clone()));
    }

    let joined = root.join(relative);

    let canonical_root = root.canonicalize().map_err(|_| CryoErrors::InvalidPath)?;

    if let Some(parent) = joined.parent() {
        std::fs::create_dir_all(parent).map_err(|_| CryoErrors::WriteError)?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| CryoErrors::UnsafePath(canonical_root.clone()))?;
        if !canonical_parent.starts_with(&canonical_root) {
            return Err(CryoErrors::UnsafePath(relative.to_path_buf().clone()));
        }
    }

    Ok(joined)
}

pub(crate) fn normalize(path: &Path) -> PathBuf {
    let mut stack: Vec<Component> = Vec::new();
    path.components().for_each(|c| match c {
        Component::Normal(_) => stack.push(c),
        Component::ParentDir => match stack.last() {
            Some(Component::Normal(_)) => {
                stack.pop();
            }
            _ => stack.push(c),
        },
        Component::CurDir => {}
        Component::RootDir => stack.push(c),
        Component::Prefix(_) => stack.push(c),
    });
    stack.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_safe_path_normal_relative() {
        assert!(is_safe_path(Path::new("a/b/c")));
    }

    #[test]
    fn is_safe_path_rejects_parent_traversal() {
        assert!(!is_safe_path(Path::new("a/../b")));
    }

    #[test]
    fn is_safe_path_rejects_absolute() {
        assert!(!is_safe_path(Path::new("/etc/passwd")));
    }

    #[test]
    fn is_safe_path_single_component() {
        assert!(is_safe_path(Path::new("file.txt")));
    }
}
