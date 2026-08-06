# MS-FSCC Reference (v60.0, November 2025)

Split from `[MS-FSCC].pdf` — Microsoft File System Control Codes specification.
Use this index to find the right file for a given topic.

## Top-Level Files

| File | What to find here |
|------|-------------------|
| `00-introduction.md` | **Glossary** and term definitions (reparse point, filter driver, object ID, etc.), normative/informative references, spec overview |
| `01-common-data-types.md` | **Reparse tags** and tag format, **REPARSE_DATA_BUFFER** (symlink, mount point, NFS, LX symlink subtypes), **REPARSE_GUID_DATA_BUFFER**, **FILE_OBJECTID_BUFFER**, alternate data streams, **pathname/filename rules** (8.3, dot dirs, stream names), **FILE_NAME_INFORMATION**, 64/128-bit file IDs |
| `02-status-codes.md` | NTSTATUS codes referenced by FSCTL and info class operations |
| `05-fs-info-classes.md` | **FileFsXxxInformation** — volume metadata: FileFsAttributeInformation (FS name, capabilities), FileFsVolumeInformation (label, serial), FileFsSizeInformation/FileFsFullSizeInformation (cluster counts), FileFsDeviceInformation, FileFsSectorSizeInformation (physical/logical sector sizes) |
| `06-file-attributes.md` | **FILE_ATTRIBUTE_\*** flags — all flag values and definitions (READONLY, HIDDEN, SYSTEM, DIRECTORY, ARCHIVE, REPARSE_POINT, COMPRESSED, ENCRYPTED, SPARSE_FILE, etc.) |
| `07-change-notifications.md` | FILE_NOTIFY_INFORMATION structure, change notification filter flags |
| `08-csv-ioctls.md` | Cluster Shared Volume IOCTLs (STORAGE_QUERY_PROPERTY, VOLUME_GET_GPT_ATTRIBUTES) |
| `09-ntfs-streams.md` | **NTFS attribute types** ($STANDARD_INFORMATION, $FILE_NAME, $DATA, $INDEX_ROOT, $INDEX_ALLOCATION, $BITMAP, $REPARSE_POINT, $EA, $ATTRIBUTE_LIST), **reserved MFT filenames** ($MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, $Bitmap, $Boot, $BadClus, $Secure, $UpCase, $Extend), stream naming rules, known alternate stream names |
| `10-product-behavior.md` | Windows version-specific behavior footnotes. Maps `<N>` references to Windows versions |

## `fsctl/` — FSCTL Request/Reply Structures (Section 2.3)

Grouped by function. Each file contains both request and reply for related FSCTLs.

| File | FSCTLs |
|------|--------|
| `fsctl/volume-data.md` | **GET_NTFS_VOLUME_DATA** (MFT start LCN, MFT zone, clusters, serial), **GET_REFS_VOLUME_DATA** |
| `fsctl/statistics.md` | **FILESYSTEM_GET_STATISTICS** — FILESYSTEM_STATISTICS, NTFS_STATISTICS (MftWrites, BitmapWrites, Allocate), FAT_STATISTICS, EXFAT_STATISTICS |
| `fsctl/usn-journal.md` | **READ_FILE_USN_DATA** (USN_RECORD_COMMON_HEADER, USN_RECORD_V2, USN_RECORD_V3 with reason codes/timestamps), **WRITE_USN_CLOSE_RECORD** |
| `fsctl/retrieval-pointers.md` | **GET_RETRIEVAL_POINTER_COUNT**, **GET_RETRIEVAL_POINTERS**, **GET_RETRIEVAL_POINTERS_AND_REFCOUNT** — extent/cluster mapping |
| `fsctl/reparse-points.md` | **DELETE/GET/SET_REPARSE_POINT** |
| `fsctl/object-ids.md` | **CREATE_OR_GET/DELETE/GET/SET/SET_EXTENDED_OBJECT_ID** |
| `fsctl/compression-integrity.md` | **GET/SET_COMPRESSION** (NONE, DEFAULT, LZNT1), **GET/SET_INTEGRITY_INFORMATION**, **SET_INTEGRITY_INFORMATION_EX** |
| `fsctl/sparse-zero-ranges.md` | **SET_SPARSE**, **SET_ZERO_DATA**, **SET_ZERO_ON_DEALLOCATION**, **QUERY_ALLOCATED_RANGES** |
| `fsctl/extent-duplication.md` | **DUPLICATE_EXTENTS_TO_FILE/EX** — block cloning, DUPLICATE_EXTENTS_DATA |
| `fsctl/pipes.md` | **PIPE_PEEK**, **PIPE_TRANSCEIVE**, **PIPE_WAIT** |
| `fsctl/offload-io.md` | **OFFLOAD_READ**, **OFFLOAD_WRITE** with STORAGE_OFFLOAD_TOKEN |
| `fsctl/encryption.md` | **SET_ENCRYPTION** — ENCRYPTION_BUFFER, DECRYPTION_STATUS_BUFFER |
| `fsctl/misc.md` | FILE_LEVEL_TRIM, FIND_FILES_BY_SID, IS_PATHNAME_VALID, LMR_SET_LINK_TRACKING_INFORMATION, MARK_HANDLE, QUERY_FAT_BPB, QUERY_FILE_REGIONS, QUERY_ON_DISK_VOLUME_INFO, QUERY_SPARING_INFO, RECALL_FILE, REFS_STREAM_SNAPSHOT_MANAGEMENT, SET_DEFECT_MANAGEMENT, SIS_COPYFILE, VIRTUAL_STORAGE_QUERY_PROPERTY |

## `file-info/` — File Information Classes (Section 2.4)

Grouped by function. Each file contains the full struct layout and field descriptions.

| File | Information classes |
|------|--------------------|
| `file-info/basic-metadata.md` | **FileBasicInformation** (timestamps, attributes), **FileStandardInformation** (size, link count, delete pending), FileAccessInformation, FileAllInformation, FileAlignmentInformation, FileAllocationInformation, FileEndOfFileInformation, FileModeInformation, FilePositionInformation, FileStandardLinkInformation, FileValidDataLengthInformation |
| `file-info/directory-enumeration.md` | **FileBothDirectoryInformation**, **FileIdBothDirectoryInformation**, FileDirectoryInformation, FileFullDirectoryInformation, FileIdFullDirectoryInformation, FileIdGlobalTxDirectoryInformation, FileId64Extd*, FileIdAllExtd*, FileIdExtd*, FileNamesInformation, FileNetworkOpenInformation |
| `file-info/names-links-rename.md` | FileAlternateNameInformation, **FileNameInformation**, FileNormalizedNameInformation, FileShortNameInformation, **FileDispositionInformation/Ex**, FileHardLinkInformation, **FileLinkInformation** (SMB/SMB2), **FileRenameInformation/Ex** (SMB/SMB2) |
| `file-info/streams-ea-reparse.md` | FileAttributeTagInformation, FileCompressionInformation, FileEaInformation, **FileFullEaInformation**, **FileObjectIdInformation** (Type 1/2), **FileReparsePointInformation**, **FileStreamInformation**, FileIdInformation, FileInternalInformation |
| `file-info/pipes-mailslots-quota.md` | FileMailslotQuery/SetInformation, FilePipeInformation, FilePipeLocalInformation, FilePipeRemoteInformation, **FileQuotaInformation**, FileSfioReserveInformation |

## Quick Lookup

| Question | File |
|----------|------|
| NTFS attribute types, reserved MFT filenames? | `09-ntfs-streams.md` |
| Reparse points (symlinks, mount points, junctions)? | `01-common-data-types.md` |
| Volume geometry (clusters, sectors, MFT layout)? | `fsctl/volume-data.md` |
| USN journal records and reason codes? | `fsctl/usn-journal.md` |
| Extent-to-cluster mapping? | `fsctl/retrieval-pointers.md` |
| File attribute flags? | `06-file-attributes.md` |
| Directory listing struct fields? | `file-info/directory-enumeration.md` |
| File timestamps and basic metadata? | `file-info/basic-metadata.md` |
| Alternate data streams? | `file-info/streams-ea-reparse.md` |
| Compression format values? | `fsctl/compression-integrity.md` |
| NTSTATUS error codes? | `02-status-codes.md` + FSCTL-specific error tables in each `fsctl/` file |
| Windows version-specific behavior? | `10-product-behavior.md` (search for `<N>` footnote number) |
