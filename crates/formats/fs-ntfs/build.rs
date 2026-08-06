fn main() {
    // Embed Windows manifest for the fs-ntfs-shell example to require administrator privileges.
    // This is necessary because the shell opens raw NTFS filesystems which requires elevated access.
    #[cfg(target_os = "windows")]
    embed_resource::compile_for_examples("examples/fs-ntfs-shell.rc", embed_resource::NONE)
        .manifest_required()
        .unwrap();
}
