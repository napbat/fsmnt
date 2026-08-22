# fs-qnx6

`fs-qnx6` is a safe, read-only parser for normal QNX6 Power-Safe
filesystems. It supports little- and big-endian volumes, validates both
checksummed superblocks, selects the newest valid snapshot, walks all five
levels of the uniform pointer tree, resolves inline and long filenames, and
performs ranged sparse-file reads.

The default build is `no_std` with allocation support. Enable `std` for
ordinary `std::io::Read + std::io::Seek` sources. Mount integration lives in
`fsmnt-drivers`; this crate only parses the portable on-disk format.

The QNX MMI variant uses a different superblock layout and is not treated as
a normal Power-Safe volume.

Format references:

- [QNX6 filesystem documentation](https://docs.kernel.org/filesystems/qnx6.html)
- [Linux on-disk structure definitions](https://github.com/torvalds/linux/blob/master/include/linux/qnx6_fs.h)
- [QNX Power-Safe filesystem overview](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.user_guide/topic/fsystems_QNX6_filesystem.html)

```sh
cargo check -p fs-qnx6 --no-default-features
cargo test -p fs-qnx6 --all-features
```
