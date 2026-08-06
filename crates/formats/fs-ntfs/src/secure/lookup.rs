//! Security descriptor lookup via $SII and $SDH indexes.

use alloc::vec::Vec;

use crate::attribute::{NtfsAttributeItem, NtfsAttributeType};
use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::index::NtfsIndex;
use crate::indexes::{
    NtfsSecurityHashData, NtfsSecurityHashIndex, NtfsSecurityIdIndex, NtfsSecurityIdKey,
};
use crate::io::{Read, Seek, SeekFrom};
use crate::structured_values::NtfsSecurityDescriptor;
use crate::types::NtfsPosition;
use fs_common::io::FsReadSeek;
use fs_common::iter::FsTryIterator;

use super::entry::{SDS_HEADER_SIZE, SDS_MAX_SIZE};

/// Look up a security descriptor by its security ID from the
/// `$Secure` system file.
///
/// On NTFS 3.x+ volumes, security descriptors are stored centrally
/// in the `$Secure` system file (MFT entry 9) rather than inline
/// in each file's attributes. Each file's
/// `$STANDARD_INFORMATION` attribute contains a `security_id` that
/// references a descriptor in `$Secure`.
///
/// The `secure_file` parameter should be the `$Secure` file
/// (MFT entry 9), obtained via `ntfs.file(&mut fs, 9)`.
///
/// The `buf` parameter is a reusable buffer for reading the raw
/// SDS entry. Its contents after the call contain the raw entry
/// data; the returned [`NtfsSecurityDescriptor`] borrows from it.
pub fn ntfs_secure_lookup<'s, T>(
    secure_file: &NtfsFile<'_>,
    fs: &mut T,
    security_id: u32,
    buf: &'s mut Vec<u8>,
) -> Result<NtfsSecurityDescriptor<'s>>
where
    T: Read + Seek,
{
    let sii_index = open_sii_index(secure_file, fs)?;

    let mut finder = sii_index.finder();
    let entry = finder.find(fs, |key: &NtfsSecurityIdKey| {
        security_id.cmp(&key.security_id())
    });

    let entry = match entry {
        Some(Ok(entry)) => entry,
        Some(Err(e)) => return Err(e),
        None => {
            return Err(NtfsError::InvalidSecurityDescriptor {
                position: NtfsPosition::none(),
                reason: "security ID not found in $SII index",
            });
        }
    };

    let sii_data = match entry.data() {
        Some(Ok(d)) => d,
        Some(Err(e)) => return Err(e),
        None => {
            return Err(NtfsError::InvalidSecurityDescriptor {
                position: NtfsPosition::none(),
                reason: "$SII entry has no data",
            });
        }
    };

    read_sds_entry(
        secure_file,
        fs,
        sii_data.sds_offset(),
        sii_data.sds_size(),
        security_id,
        buf,
    )
}

/// Return all `$SDH` data entries whose hash matches the given
/// value.
///
/// Opens the `$SDH` index on `secure_file`, iterates every entry,
/// and collects those with a matching hash. No `$SDS` reads are
/// performed; callers can inspect the returned security IDs and
/// offsets directly.
pub fn ntfs_secure_sdh_entries<T>(
    secure_file: &NtfsFile<'_>,
    fs: &mut T,
    hash: u32,
) -> Result<Vec<NtfsSecurityHashData>>
where
    T: Read + Seek,
{
    let sdh_index = open_sdh_index(secure_file, fs)?;
    let mut entries = sdh_index.entries();
    let mut results = Vec::new();

    while let Some(entry) = entries.try_next(fs)? {
        if let Some(key) = entry.key() {
            let key = key?;
            if key.hash() == hash {
                let data = match entry.data() {
                    Some(Ok(d)) => d,
                    Some(Err(e)) => return Err(e),
                    None => {
                        return Err(NtfsError::InvalidSecurityDescriptor {
                            position: NtfsPosition::none(),
                            reason: "$SDH entry has no data",
                        });
                    }
                };

                if key.hash() != data.hash() || key.security_id() != data.security_id() {
                    return Err(NtfsError::InvalidSecurityDescriptor {
                        position: NtfsPosition::none(),
                        reason: "$SDH key/data mismatch",
                    });
                }

                results.push(data);
            }
        }
    }

    Ok(results)
}

/// Look up a security descriptor by its hash from the `$Secure`
/// system file.
///
/// Searches the `$SDH` index for all entries with the given hash
/// and returns the security descriptor for the entry with the
/// lowest `security_id`. If no entry matches the hash, returns an
/// error.
///
/// For callers that need all matching entries (e.g., to inspect
/// every security ID sharing a hash), use
/// [`ntfs_secure_sdh_entries`] instead.
pub fn ntfs_secure_lookup_by_hash<'s, T>(
    secure_file: &NtfsFile<'_>,
    fs: &mut T,
    hash: u32,
    buf: &'s mut Vec<u8>,
) -> Result<NtfsSecurityDescriptor<'s>>
where
    T: Read + Seek,
{
    let entries = ntfs_secure_sdh_entries(secure_file, fs, hash)?;

    let best = entries.iter().min_by_key(|e| e.security_id()).ok_or(
        NtfsError::InvalidSecurityDescriptor {
            position: NtfsPosition::none(),
            reason: "hash not found in $SDH index",
        },
    )?;

    read_sds_entry(
        secure_file,
        fs,
        best.sds_offset(),
        best.sds_size(),
        best.security_id(),
        buf,
    )
}

/// Read and validate a security descriptor from the `$SDS` stream.
fn read_sds_entry<'s, T>(
    secure_file: &NtfsFile<'_>,
    fs: &mut T,
    sds_offset: u64,
    sds_size: u32,
    expected_security_id: u32,
    buf: &'s mut Vec<u8>,
) -> Result<NtfsSecurityDescriptor<'s>>
where
    T: Read + Seek,
{
    let sds_size_usize = sds_size as usize;
    let sds_position = NtfsPosition::new(sds_offset);

    if sds_size_usize <= SDS_HEADER_SIZE {
        return Err(NtfsError::InvalidSecurityDescriptor {
            position: sds_position,
            reason: "$SDS entry too small for header",
        });
    }

    if sds_size_usize > SDS_MAX_SIZE {
        return Err(NtfsError::InvalidSecurityDescriptor {
            position: sds_position,
            reason: "$SDS entry exceeds maximum allowed size",
        });
    }

    if sds_offset.checked_add(u64::from(sds_size)).is_none() {
        return Err(NtfsError::InvalidSecurityDescriptor {
            position: sds_position,
            reason: "$SDS offset + size overflows u64",
        });
    }

    let sds_item = find_named_data_attribute(secure_file, fs, "$SDS")?;
    let sds_attribute = sds_item.to_attribute()?;
    let mut sds_value = sds_attribute.value(fs)?;

    sds_value.seek(fs, SeekFrom::Start(sds_offset))?;

    buf.resize(sds_size_usize, 0);
    sds_value.read_exact(fs, buf)?;

    let sds_header_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if sds_header_id != expected_security_id {
        return Err(NtfsError::InvalidSecurityDescriptor {
            position: sds_position,
            reason: "$SDS header security ID does not match \
                     lookup key",
        });
    }

    let descriptor_data = &buf[SDS_HEADER_SIZE..];
    let descriptor_position = sds_position + SDS_HEADER_SIZE as u64;
    NtfsSecurityDescriptor::from_bytes(descriptor_data, descriptor_position)
}

/// Opens the $SII (Security ID Index) on the $Secure file.
pub(crate) fn open_sii_index<'n, T>(
    secure_file: &NtfsFile<'n>,
    fs: &mut T,
) -> Result<NtfsIndex<'n, NtfsSecurityIdIndex>>
where
    T: Read + Seek,
{
    open_named_index(secure_file, fs, "$SII")
}

/// Opens the $SDH (Security Descriptor Hash) index on the $Secure
/// file.
pub(crate) fn open_sdh_index<'n, T>(
    secure_file: &NtfsFile<'n>,
    fs: &mut T,
) -> Result<NtfsIndex<'n, NtfsSecurityHashIndex>>
where
    T: Read + Seek,
{
    open_named_index(secure_file, fs, "$SDH")
}

/// Opens a named index (IndexRoot + optional IndexAllocation)
/// on a file.
fn open_named_index<'n, E, T>(
    file: &NtfsFile<'n>,
    fs: &mut T,
    index_name: &str,
) -> Result<NtfsIndex<'n, E>>
where
    E: crate::indexes::NtfsIndexEntryType,
    T: Read + Seek,
{
    let index_root_item = find_named_attribute(file, fs, NtfsAttributeType::IndexRoot, index_name)?;
    let index_root_attribute = index_root_item.to_attribute()?;
    let index_root = index_root_attribute
        .resident_structured_value::<crate::structured_values::NtfsIndexRoot>()?;

    let mut index_allocation_item = None;
    if index_root.is_large_index() {
        index_allocation_item = Some(find_named_attribute(
            file,
            fs,
            NtfsAttributeType::IndexAllocation,
            index_name,
        )?);
    }

    NtfsIndex::<E>::new(file.ntfs(), index_root_item, index_allocation_item, fs)
}

/// Finds a named attribute on a file.
pub(crate) fn find_named_attribute<'n, 'f, T>(
    file: &'f NtfsFile<'n>,
    fs: &mut T,
    ty: NtfsAttributeType,
    name: &str,
) -> Result<NtfsAttributeItem<'n, 'f>>
where
    T: Read + Seek,
{
    let mut iter = file.attributes();

    while let Some(item) = iter.try_next(fs)? {
        let attribute = item.to_attribute()?;

        if attribute.ty()? != ty {
            continue;
        }

        if attribute.name()? != name {
            continue;
        }

        return Ok(item);
    }

    Err(NtfsError::AttributeNotFound {
        position: file.position(),
        ty,
    })
}

/// Finds a named $DATA attribute.
pub(crate) fn find_named_data_attribute<'n, 'f, T>(
    file: &'f NtfsFile<'n>,
    fs: &mut T,
    name: &str,
) -> Result<NtfsAttributeItem<'n, 'f>>
where
    T: Read + Seek,
{
    find_named_attribute(file, fs, NtfsAttributeType::Data, name)
}
