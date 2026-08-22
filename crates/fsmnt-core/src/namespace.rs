//! Composition of independent filesystems into one mounted namespace.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, TargetFilesystem, normalize_path,
};

/// A filesystem namespace assembled from a root filesystem and child mounts.
///
/// Paths are routed to the most specific attached mount point. This models the
/// namespace layer used by operating systems and fstab-style configurations;
/// it is independent of the formats backing each mounted filesystem.
pub struct MountNamespace {
    root: Box<dyn TargetFilesystem>,
    mounts: BTreeMap<String, Box<dyn TargetFilesystem>>,
}

impl MountNamespace {
    /// Create a namespace rooted at `root`.
    #[must_use]
    pub fn new(root: Box<dyn TargetFilesystem>) -> Self {
        Self {
            root,
            mounts: BTreeMap::new(),
        }
    }

    /// Attach `filesystem` at an existing directory in the namespace.
    ///
    /// More-specific mounts may be attached beneath existing child mounts.
    ///
    /// # Errors
    ///
    /// Returns an error if the mount point is empty, malformed, absent, not a
    /// directory, already occupied, or if the attached filesystem does not
    /// expose a directory as its root.
    pub fn attach(
        &mut self,
        mount_point: &str,
        mut filesystem: Box<dyn TargetFilesystem>,
    ) -> FsResult<()> {
        let mount_point = canonical_path(mount_point)?;
        if mount_point.is_empty() {
            return Err(FsError::InvalidPath(
                "the root filesystem cannot be replaced by a child mount".to_string(),
            ));
        }
        if self.mounts.contains_key(&mount_point) {
            return Err(FsError::Filesystem(format!(
                "mount point {mount_point:?} is already occupied"
            )));
        }
        if !self.try_is_dir(&mount_point)? {
            return Err(FsError::NotADirectory(mount_point));
        }
        if !filesystem.metadata("")?.is_dir {
            return Err(FsError::NotADirectory(
                "attached filesystem root".to_string(),
            ));
        }
        self.mounts.insert(mount_point, filesystem);
        Ok(())
    }

    /// Detach and return the filesystem mounted at `mount_point`.
    ///
    /// # Errors
    ///
    /// Returns an error if the mount-point path is malformed.
    pub fn detach(&mut self, mount_point: &str) -> FsResult<Option<Box<dyn TargetFilesystem>>> {
        let mount_point = canonical_path(mount_point)?;
        Ok(self.mounts.remove(&mount_point))
    }

    /// Attached mount points in lexical order, relative to the namespace root.
    pub fn mount_points(&self) -> impl Iterator<Item = &str> {
        self.mounts.keys().map(String::as_str)
    }

    fn route(&self, path: &str) -> Route {
        let mount_point = self
            .mounts
            .keys()
            .rev()
            .filter(|mount_point| is_at_or_below(path, mount_point))
            .max_by_key(|mount_point| mount_point.len())
            .cloned();
        let relative = match &mount_point {
            Some(mount_point) if path == mount_point => String::new(),
            Some(mount_point) => path[mount_point.len() + 1..].to_string(),
            None => path.to_string(),
        };
        Route {
            mount_point,
            relative,
        }
    }

    fn filesystem_mut(&mut self, mount_point: Option<&str>) -> &mut dyn TargetFilesystem {
        match mount_point {
            Some(mount_point) => self
                .mounts
                .get_mut(mount_point)
                .expect("route mount point must remain attached")
                .as_mut(),
            None => self.root.as_mut(),
        }
    }

    fn has_mounted_descendant(&self, path: &str) -> bool {
        self.mounts
            .keys()
            .any(|mount_point| path.is_empty() || is_below(mount_point, path))
    }

    fn direct_mount_children(&self, parent: &str) -> BTreeMap<String, Option<String>> {
        let mut children = BTreeMap::new();
        for mount_point in self.mounts.keys() {
            let remainder = if parent.is_empty() {
                mount_point.as_str()
            } else {
                let Some(remainder) = mount_point.strip_prefix(parent) else {
                    continue;
                };
                let Some(remainder) = remainder.strip_prefix('/') else {
                    continue;
                };
                remainder
            };
            let Some((name, tail)) = remainder.split_once('/').map_or_else(
                || Some((remainder, None)),
                |(name, tail)| Some((name, Some(tail))),
            ) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let exact_mount = tail.is_none().then(|| mount_point.clone());
            let entry = children.entry(name.to_string()).or_insert(None);
            if exact_mount.is_some() {
                *entry = exact_mount;
            }
        }
        children
    }

    fn mounted_child_entry(
        &mut self,
        parent: &str,
        name: String,
        exact_mount: Option<String>,
    ) -> FsResult<FsEntry> {
        let metadata = match exact_mount {
            Some(mount_point) => self
                .mounts
                .get_mut(&mount_point)
                .expect("direct child mount must remain attached")
                .metadata("")?,
            None => directory_metadata(),
        };
        let path = if parent.is_empty() {
            PathBuf::from("/").join(&name)
        } else {
            PathBuf::from(parent).join(&name)
        };
        Ok(FsEntry {
            name,
            path,
            flags: FsEntryFlags::empty(),
            file_id: None,
            metadata,
        })
    }
}

impl TargetFilesystem for MountNamespace {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let path = canonical_path(path)?;
        let route = self.route(&path);
        if self.has_mounted_descendant(&path) && route.mount_point.as_deref() != Some(path.as_str())
        {
            return Err(FsError::NotAFile(path));
        }
        self.filesystem_mut(route.mount_point.as_deref())
            .read(&route.relative)
    }

    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> FsResult<usize> {
        let path = canonical_path(path)?;
        let route = self.route(&path);
        if self.has_mounted_descendant(&path) && route.mount_point.as_deref() != Some(path.as_str())
        {
            return Err(FsError::NotAFile(path));
        }
        self.filesystem_mut(route.mount_point.as_deref())
            .read_at(&route.relative, offset, buffer)
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        let path = canonical_path(path)?;
        let route = self.route(&path);
        if self.has_mounted_descendant(&path) {
            return Ok(true);
        }
        self.filesystem_mut(route.mount_point.as_deref())
            .try_exists(&route.relative)
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        let path = canonical_path(path)?;
        let route = self.route(&path);
        if self.has_mounted_descendant(&path) {
            return Ok(true);
        }
        self.filesystem_mut(route.mount_point.as_deref())
            .try_is_dir(&route.relative)
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        let path = canonical_path(path)?;
        let route = self.route(&path);
        if self.has_mounted_descendant(&path) {
            return Ok(false);
        }
        self.filesystem_mut(route.mount_point.as_deref())
            .try_is_file(&route.relative)
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        let path = canonical_path(path)?;
        let route = self.route(&path);
        if self.has_mounted_descendant(&path) && route.mount_point.as_deref() != Some(path.as_str())
        {
            return Ok(directory_metadata());
        }
        self.filesystem_mut(route.mount_point.as_deref())
            .metadata(&route.relative)
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let path = canonical_path(path)?;
        let route = self.route(&path);
        let children = self.direct_mount_children(&path);
        let entries = match self
            .filesystem_mut(route.mount_point.as_deref())
            .read_dir(&route.relative)
        {
            Ok(entries) => entries,
            Err(FsError::NotFound(_)) if !children.is_empty() => Vec::new(),
            Err(error) => return Err(error),
        };
        let mut by_name: BTreeMap<String, FsEntry> = entries
            .into_iter()
            .map(|mut entry| {
                entry.path = if path.is_empty() {
                    PathBuf::from("/").join(&entry.name)
                } else {
                    PathBuf::from(&path).join(&entry.name)
                };
                (entry.name.clone(), entry)
            })
            .collect();
        for (name, exact_mount) in children {
            let entry = self.mounted_child_entry(&path, name.clone(), exact_mount)?;
            by_name.insert(name, entry);
        }
        Ok(by_name.into_values().collect())
    }

    fn total_size(&self) -> Option<u64> {
        self.root.total_size()
    }

    fn free_space(&mut self) -> Option<u64> {
        self.root.free_space()
    }

    fn volume_uuid(&self) -> Option<String> {
        self.root.volume_uuid()
    }
}

struct Route {
    mount_point: Option<String>,
    relative: String,
}

fn canonical_path(path: &str) -> FsResult<String> {
    let normalized = normalize_path(path);
    if normalized.is_empty() {
        return Ok(String::new());
    }
    if normalized
        .split('/')
        .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
    {
        return Ok(normalized.into_owned());
    }

    let mut components = Vec::new();
    for component in normalized
        .split('/')
        .filter(|component| !component.is_empty())
    {
        match component {
            "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(FsError::InvalidPath(path.to_string()));
                }
            }
            name => components.push(name),
        }
    }
    Ok(components.join("/"))
}

fn is_at_or_below(path: &str, parent: &str) -> bool {
    path == parent || is_below(path, parent)
}

fn is_below(path: &str, parent: &str) -> bool {
    path.strip_prefix(parent)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn directory_metadata() -> FsMetadata {
    FsMetadata {
        is_dir: true,
        ..FsMetadata::default()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::DirFilesystem;

    fn create_directory_fs(files: &[(&str, &str)]) -> (TempDir, Box<dyn TargetFilesystem>) {
        let directory = tempfile::tempdir().expect("temporary filesystem");
        for (path, contents) in files {
            let path = directory.path().join(path);
            fs::create_dir_all(path.parent().expect("fixture file parent"))
                .expect("fixture directories");
            fs::write(path, contents).expect("fixture file");
        }
        let filesystem = Box::new(DirFilesystem::new(directory.path()));
        (directory, filesystem)
    }

    #[test]
    fn routes_to_the_longest_attached_mount_point() {
        let (_root_dir, root) = create_directory_fs(&[
            ("etc/root.txt", "root"),
            ("home/covered.txt", "covered"),
            ("boot/covered.txt", "covered"),
            ("boot/efi/covered.txt", "covered"),
        ]);
        let (_home_dir, home) = create_directory_fs(&[("alice.txt", "home")]);
        let (_boot_dir, boot) =
            create_directory_fs(&[("kernel.txt", "boot"), ("efi/covered.txt", "covered")]);
        let (_efi_dir, efi) = create_directory_fs(&[("bootx64.efi", "efi")]);

        let mut namespace = MountNamespace::new(root);
        namespace.attach("/home", home).expect("attach home");
        namespace.attach("/boot", boot).expect("attach boot");
        namespace.attach("/boot/efi", efi).expect("attach EFI");

        assert_eq!(namespace.read("/etc/root.txt").expect("root file"), b"root");
        assert_eq!(
            namespace.read("/home/alice.txt").expect("home file"),
            b"home"
        );
        assert_eq!(
            namespace.read("/boot/kernel.txt").expect("boot file"),
            b"boot"
        );
        assert_eq!(
            namespace
                .read("/boot/efi/bootx64.efi")
                .expect("nested EFI file"),
            b"efi"
        );
        let mut range = [0_u8; 2];
        assert_eq!(
            namespace
                .read_at("/boot/efi/bootx64.efi", 1, &mut range)
                .expect("nested EFI range"),
            2
        );
        assert_eq!(&range, b"fi");
        assert!(!namespace.exists("/home/covered.txt"));
        assert!(!namespace.exists("/boot/efi/covered.txt"));
    }

    #[test]
    fn directory_listings_overlay_mount_points_and_rebase_paths() {
        let (_root_dir, root) = create_directory_fs(&[
            ("home/covered.txt", "covered"),
            ("boot/root.txt", "root"),
            ("boot/efi/covered.txt", "covered"),
        ]);
        let (_home_dir, home) = create_directory_fs(&[("alice.txt", "home")]);
        let (_efi_dir, efi) = create_directory_fs(&[("bootx64.efi", "efi")]);

        let mut namespace = MountNamespace::new(root);
        namespace.attach("/home", home).expect("attach home");
        namespace
            .attach("/boot/efi", efi)
            .expect("attach nested EFI");

        let root_entries = namespace.read_dir("/").expect("root listing");
        let home_entry = root_entries
            .iter()
            .find(|entry| entry.name == "home")
            .expect("home mount entry");
        assert!(home_entry.metadata.is_dir);
        assert_eq!(home_entry.path, PathBuf::from("/home"));

        let boot_entries = namespace.read_dir("/boot").expect("boot listing");
        let efi_entry = boot_entries
            .iter()
            .find(|entry| entry.name == "efi")
            .expect("EFI mount entry");
        assert!(efi_entry.metadata.is_dir);
        assert_eq!(efi_entry.path, PathBuf::from("boot/efi"));

        let home_entries = namespace.read_dir("/home").expect("home listing");
        assert_eq!(home_entries.len(), 1);
        assert_eq!(home_entries[0].path, PathBuf::from("home/alice.txt"));
    }

    #[test]
    fn rejects_invalid_duplicate_and_non_directory_mount_points() {
        let (_root_dir, root) =
            create_directory_fs(&[("directory/placeholder", ""), ("file", "contents")]);
        let (_child_dir, child) = create_directory_fs(&[("child", "contents")]);
        let (_duplicate_dir, duplicate) = create_directory_fs(&[("child", "contents")]);
        let (_file_root_dir, file_root) = create_directory_fs(&[("child", "contents")]);
        let mut namespace = MountNamespace::new(root);

        assert!(namespace.attach("/", child).is_err());
        assert!(namespace.attach("/file", file_root).is_err());

        let (_mounted_dir, mounted) = create_directory_fs(&[("child", "contents")]);
        namespace
            .attach("/directory", mounted)
            .expect("valid mount point");
        assert!(namespace.attach("/directory", duplicate).is_err());
        assert!(namespace.try_exists("../../escape").is_err());
    }
}
