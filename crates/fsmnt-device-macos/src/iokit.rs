//! `IOKit` and `CoreFoundation` FFI bindings for disk property enumeration.
//!
//! Queries the `IORegistry` to retrieve hardware metadata (model, serial
//! number, bus type, removable flag) for a disk identified by its BSD
//! name (e.g. `"disk0"`).
//!
//! The lookup walks from the `IOMedia` node matching the BSD name up
//! through the `IOService` plane to the `IOBlockStorageDevice` ancestor,
//! reading "Device Characteristics" and "Protocol Characteristics".

use std::ffi::{c_char, c_void};
use std::ptr;

use fsmnt_device::{HostDriveBusType, PhysicalExtent};

// ---------------------------------------------------------------------------
// CoreFoundation / IOKit FFI types and constants
// ---------------------------------------------------------------------------
type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFMutableDictionaryRef = *mut c_void;
type CFAllocatorRef = *const c_void;
type CFIndex = isize;
type CFNumberType = i32;

type IOReturn = i32;
type MachPort = u32;

/// `IOKit` iterator handle.
type IOIterator = u32;
/// `IOKit` object handle.
type IOObject = u32;

const KERN_SUCCESS: IOReturn = 0;
const IO_OBJECT_NULL: IOObject = 0;

/// `CFString` encoding: UTF-8.
const K_CFSTRING_ENCODING_UTF8: u32 = 0x0800_0100;
/// Signed 64-bit integer representation accepted by `CFNumberGetValue`.
const K_CFNUMBER_SINT64_TYPE: CFNumberType = 4;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    #[allow(
        non_upper_case_globals,
        reason = "CoreFoundation symbol name is fixed by the framework"
    )]
    static kCFAllocatorDefault: CFAllocatorRef;

    fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFStringGetCString(
        the_string: CFStringRef,
        buffer: *mut u8,
        buffer_size: CFIndex,
        encoding: u32,
    ) -> bool;
    fn CFStringGetLength(the_string: CFStringRef) -> CFIndex;
    fn CFDictionaryGetValue(dict: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
    fn CFGetTypeID(cf: CFTypeRef) -> u64;
    fn CFStringGetTypeID() -> u64;
    fn CFBooleanGetValue(boolean: CFTypeRef) -> bool;
    fn CFBooleanGetTypeID() -> u64;
    fn CFNumberGetValue(number: CFTypeRef, number_type: CFNumberType, value: *mut c_void) -> bool;
    fn CFNumberGetTypeID() -> u64;
    fn CFRelease(cf: CFTypeRef);
}

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceMatching(name: *const c_char) -> CFMutableDictionaryRef;
    fn IOServiceGetMatchingServices(
        main_port: MachPort,
        matching: CFMutableDictionaryRef,
        existing: *mut IOIterator,
    ) -> IOReturn;
    fn IOIteratorNext(iterator: IOIterator) -> IOObject;
    fn IORegistryEntryCreateCFProperties(
        entry: IOObject,
        properties: *mut CFMutableDictionaryRef,
        allocator: CFAllocatorRef,
        options: u32,
    ) -> IOReturn;
    fn IORegistryEntryGetParentEntry(
        entry: IOObject,
        plane: *const c_char,
        parent: *mut IOObject,
    ) -> IOReturn;
    fn IORegistryEntryGetChildIterator(
        entry: IOObject,
        plane: *const c_char,
        iterator: *mut IOIterator,
    ) -> IOReturn;
    fn IOObjectConformsTo(object: IOObject, class_name: *const c_char) -> bool;
    fn IOObjectRelease(object: IOObject) -> IOReturn;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Properties extracted from the `IORegistry` for a disk.
pub(crate) struct DiskProperties {
    /// Device model ("Product Name" from "Device Characteristics").
    pub model: Option<String>,
    /// Device serial number (from "Device Characteristics").
    pub serial_number: Option<String>,
    /// Bus type (from "Protocol Characteristics").
    pub bus_type: Option<HostDriveBusType>,
    /// The `IOMedia` "Removable" property (removable *media*, not device).
    pub removable: Option<bool>,
    /// `true` if this is a whole-disk `IOMedia` node backed by real physical
    /// hardware (`NVMe`, SATA, USB, etc.) rather than a synthesized APFS
    /// volume, disk image, or other virtual device.
    pub is_physical: bool,
}

/// A leaf logical `IOMedia` node above a physical partition.
pub(crate) struct LogicalMedia {
    /// Stable UUID when `IOKit` reports one, otherwise the BSD device name.
    pub id: String,
    /// BSD device name, such as `disk3s1`.
    pub bsd_name: String,
    /// Logical media length in bytes.
    pub length: u64,
    /// Logical block size reported by `IOMedia`.
    pub sector_size: Option<u32>,
}

/// Query `IOKit` for hardware properties of the given BSD disk name.
///
/// Walks the `IORegistry`: finds the `IOMedia` node matching the BSD name,
/// reads its `Removable` property, then traverses up the `IOService` plane
/// to the `IOBlockStorageDevice` ancestor and reads "Device Characteristics"
/// (model, serial) and "Protocol Characteristics" (bus type).
pub(crate) fn disk_properties(bsd_name: &str) -> Option<DiskProperties> {
    let class_name = c"IOMedia".as_ptr();
    // SAFETY: `class_name` is a valid NUL-terminated C string.  The returned
    // matching dictionary is consumed by `IOServiceGetMatchingServices`
    // below (which takes ownership even on failure), so it must not be
    // released here.
    let matching = unsafe { IOServiceMatching(class_name) };
    if matching.is_null() {
        return None;
    }

    let mut iterator: IOIterator = 0;
    // SAFETY: `matching` is a valid matching dictionary and `iterator` is a
    // valid out-pointer.  Main port 0 is `kIOMainPortDefault`.
    let kr = unsafe { IOServiceGetMatchingServices(0, matching, &raw mut iterator) };
    if kr != KERN_SUCCESS {
        return None;
    }

    let result = find_media_entry(iterator, bsd_name);

    // SAFETY: `iterator` is a live iterator handle owned by this function.
    unsafe { IOObjectRelease(iterator) };
    result
}

/// Resolve a physical extent to leaf logical media in the `IOKit` service
/// graph.
///
/// A normal partition resolves to its own slice. Stacked storage such as an
/// APFS container resolves to the synthesized leaf `IOMedia` nodes beneath
/// that slice, preserving ambiguity rather than choosing a volume silently.
pub(crate) fn logical_media_for_extent(extent: &PhysicalExtent) -> Vec<LogicalMedia> {
    let class_name = c"IOMedia".as_ptr();
    // SAFETY: `class_name` is a valid NUL-terminated C string. The matching
    // dictionary is consumed by `IOServiceGetMatchingServices`.
    let matching = unsafe { IOServiceMatching(class_name) };
    if matching.is_null() {
        return Vec::new();
    }

    let mut iterator: IOIterator = 0;
    // SAFETY: `matching` is a valid matching dictionary and `iterator` is a
    // valid out-pointer.
    if unsafe { IOServiceGetMatchingServices(0, matching, &raw mut iterator) } != KERN_SUCCESS {
        return Vec::new();
    }

    let mut media = Vec::new();
    loop {
        // SAFETY: `iterator` is a live iterator handle.
        let entry = unsafe { IOIteratorNext(iterator) };
        if entry == IO_OBJECT_NULL {
            break;
        }

        if media_matches_extent(entry, extent) {
            collect_leaf_media(entry, &mut media);
            // SAFETY: `entry` and `iterator` are live objects owned here.
            unsafe {
                IOObjectRelease(entry);
                IOObjectRelease(iterator);
            }
            media.sort_by(|left, right| left.id.cmp(&right.id));
            media.dedup_by(|left, right| left.id == right.id);
            return media;
        }

        // SAFETY: `entry` is owned by this loop iteration.
        unsafe { IOObjectRelease(entry) };
    }

    // SAFETY: `iterator` is a live iterator owned by this function.
    unsafe { IOObjectRelease(iterator) };
    media
}

/// Map a macOS "Physical Interconnect" string to [`HostDriveBusType`].
pub(crate) fn interconnect_to_bus_type(interconnect: &str) -> HostDriveBusType {
    let lower = interconnect.to_ascii_lowercase();
    if lower.contains("pci-express") || lower.contains("pci express") || lower.contains("nvme") {
        HostDriveBusType::Nvme
    } else if lower.contains("apple fabric") {
        // Apple Silicon internal SSD
        HostDriveBusType::Nvme
    } else if lower.contains("usb") {
        HostDriveBusType::Usb
    } else if lower.contains("sata") {
        HostDriveBusType::Sata
    } else if lower.contains("sas") {
        HostDriveBusType::Sas
    } else if lower.contains("scsi") {
        HostDriveBusType::Scsi
    } else if lower.contains("firewire") || lower.contains("ieee 1394") {
        HostDriveBusType::Ieee1394
    } else if lower.contains("fibre") {
        HostDriveBusType::FibreChannel
    } else if lower.contains("sd card") || lower.contains("secure digital") {
        HostDriveBusType::Sd
    } else if lower.contains("virtual") {
        HostDriveBusType::Virtual
    } else {
        HostDriveBusType::Unknown
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Iterate over `IOMedia` entries to find the one matching `bsd_name`.
fn find_media_entry(iterator: IOIterator, bsd_name: &str) -> Option<DiskProperties> {
    loop {
        // SAFETY: `iterator` is a live iterator handle.
        let entry = unsafe { IOIteratorNext(iterator) };
        if entry == IO_OBJECT_NULL {
            break;
        }

        let props = read_entry_properties(entry, bsd_name);
        // SAFETY: `entry` is a live object handle returned by
        // `IOIteratorNext`, owned by this loop iteration.
        unsafe { IOObjectRelease(entry) };

        if props.is_some() {
            return props;
        }
    }
    None
}

fn media_matches_extent(entry: IOObject, extent: &PhysicalExtent) -> bool {
    let Some(properties) = read_media_properties(entry) else {
        return false;
    };
    let expected_slice_prefix = format!("{}s", extent.drive().as_str());
    let correct_device = properties.bsd_name == extent.drive().as_str()
        || properties.bsd_name.starts_with(&expected_slice_prefix);
    let correct_length = extent.length() == u64::MAX || properties.length <= extent.length();
    correct_device && properties.base == extent.offset() && correct_length
}

fn collect_leaf_media(entry: IOObject, media: &mut Vec<LogicalMedia>) -> bool {
    let current = read_media_properties(entry);
    let plane = c"IOService".as_ptr();
    let mut iterator: IOIterator = IO_OBJECT_NULL;
    // SAFETY: `entry` is a live registry entry, `plane` is a valid C string,
    // and `iterator` is a valid out-pointer.
    let has_iterator =
        unsafe { IORegistryEntryGetChildIterator(entry, plane, &raw mut iterator) } == KERN_SUCCESS;
    let mut descendant_has_media = false;

    if has_iterator {
        loop {
            // SAFETY: `iterator` is a live child iterator.
            let child = unsafe { IOIteratorNext(iterator) };
            if child == IO_OBJECT_NULL {
                break;
            }
            descendant_has_media |= collect_leaf_media(child, media);
            // SAFETY: `child` is owned by this loop iteration.
            unsafe { IOObjectRelease(child) };
        }
        // SAFETY: `iterator` is owned by this function after a successful
        // `IORegistryEntryGetChildIterator` call.
        unsafe { IOObjectRelease(iterator) };
    }

    if let Some(properties) = current {
        if !descendant_has_media {
            media.push(LogicalMedia {
                id: properties.id,
                bsd_name: properties.bsd_name,
                length: properties.length,
                sector_size: properties.sector_size,
            });
        }
        true
    } else {
        descendant_has_media
    }
}

struct MediaProperties {
    id: String,
    bsd_name: String,
    base: u64,
    length: u64,
    sector_size: Option<u32>,
}

fn read_media_properties(entry: IOObject) -> Option<MediaProperties> {
    // SAFETY: `entry` is a live object. This check does not retain it.
    if !unsafe { IOObjectConformsTo(entry, c"IOMedia".as_ptr()) } {
        return None;
    }

    let mut properties: CFMutableDictionaryRef = ptr::null_mut();
    // SAFETY: `entry` is live and `properties` is a valid out-pointer. On
    // success this function owns the returned dictionary.
    let result = unsafe {
        IORegistryEntryCreateCFProperties(entry, &raw mut properties, kCFAllocatorDefault, 0)
    };
    if result != KERN_SUCCESS || properties.is_null() {
        return None;
    }

    let dictionary = properties.cast_const();
    let bsd_name = cf_dict_get_string(dictionary, "BSD Name");
    let base = cf_dict_get_u64(dictionary, "Base");
    let length = cf_dict_get_u64(dictionary, "Size");
    let sector_size = cf_dict_get_u64(dictionary, "Preferred Block Size")
        .and_then(|size| u32::try_from(size).ok());
    let id = cf_dict_get_string(dictionary, "UUID");

    // SAFETY: `properties` is a live dictionary owned by this function.
    unsafe { CFRelease(properties.cast_const()) };

    let bsd_name = bsd_name?;
    Some(MediaProperties {
        id: id.unwrap_or_else(|| bsd_name.clone()),
        bsd_name,
        base: base.unwrap_or(0),
        length: length?,
        sector_size,
    })
}

/// Read properties from a single `IOMedia` entry if its BSD Name matches.
fn read_entry_properties(entry: IOObject, bsd_name: &str) -> Option<DiskProperties> {
    let mut props_dict: CFMutableDictionaryRef = ptr::null_mut();
    // SAFETY: `entry` is a live registry entry and `props_dict` is a valid
    // out-pointer; on success we own the returned dictionary.
    let kr = unsafe {
        IORegistryEntryCreateCFProperties(entry, &raw mut props_dict, kCFAllocatorDefault, 0)
    };
    if kr != KERN_SUCCESS || props_dict.is_null() {
        return None;
    }

    let dict: CFDictionaryRef = props_dict.cast_const();
    let entry_bsd = cf_dict_get_string(dict, "BSD Name");
    let matches = entry_bsd.as_deref() == Some(bsd_name);

    let (removable, whole) = if matches {
        (
            cf_dict_get_bool(dict, "Removable"),
            cf_dict_get_bool(dict, "Whole"),
        )
    } else {
        (None, None)
    };

    // SAFETY: `props_dict` is a live dictionary owned by this function.
    unsafe { CFRelease(props_dict.cast_const()) };

    if !matches {
        return None;
    }

    let (model, serial, bus_type) = walk_to_storage_device(entry);

    // A disk is "physical" if:
    //  1. It is a whole-disk IOMedia node (`Whole = true`), AND
    //  2. Its immediate parent is `IOBlockStorageDriver` (real hardware), AND
    //  3. Its `IOBlockStorageDevice` ancestor is NOT a disk image driver.
    //
    // Synthesized APFS container/volume-group disks have parents like
    // `AppleAPFSContainer`.  Disk images go through `IOBlockStorageDriver`
    // but their storage device is `IODiskImageBlockStorageDeviceOutKernel`.
    let is_whole = whole.unwrap_or(false);
    let has_block_storage_driver = is_whole && parent_conforms_to(entry, c"IOBlockStorageDriver");
    let is_disk_image = has_block_storage_driver
        && (ancestor_conforms_to(entry, c"IODiskImageBlockStorageDeviceOutKernel")
            || ancestor_conforms_to(entry, c"AppleDiskImageDevice"));

    Some(DiskProperties {
        model,
        serial_number: serial,
        bus_type,
        removable,
        is_physical: has_block_storage_driver && !is_disk_image,
    })
}

/// Check whether the immediate parent of `entry` in the `IOService` plane
/// conforms to the given class (e.g. `c"IOBlockStorageDriver"`).
fn parent_conforms_to(entry: IOObject, class_name: &std::ffi::CStr) -> bool {
    let plane = c"IOService".as_ptr();
    let mut parent: IOObject = IO_OBJECT_NULL;
    // SAFETY: `entry` is a live registry entry, `plane` is a valid
    // NUL-terminated C string, and `parent` is a valid out-pointer.
    let kr = unsafe { IORegistryEntryGetParentEntry(entry, plane, &raw mut parent) };
    if kr != KERN_SUCCESS || parent == IO_OBJECT_NULL {
        return false;
    }
    // SAFETY: `parent` is a live object handle and `class_name` is a valid
    // NUL-terminated C string.
    let result = unsafe { IOObjectConformsTo(parent, class_name.as_ptr()) };
    // SAFETY: `parent` was returned with a retain by
    // `IORegistryEntryGetParentEntry`; this function owns it.
    unsafe { IOObjectRelease(parent) };
    result
}

/// Check whether any ancestor of `entry` in the `IOService` plane conforms
/// to the given class.
fn ancestor_conforms_to(entry: IOObject, class_name: &std::ffi::CStr) -> bool {
    let plane = c"IOService".as_ptr();
    let mut current = entry;
    // Don't release `entry` — the caller owns it.
    let mut owned = false;

    loop {
        let mut parent: IOObject = IO_OBJECT_NULL;
        // SAFETY: `current` is a live registry entry, `plane` is a valid
        // NUL-terminated C string, and `parent` is a valid out-pointer.
        let kr = unsafe { IORegistryEntryGetParentEntry(current, plane, &raw mut parent) };
        if owned {
            // SAFETY: `current` was obtained (retained) from a previous
            // `IORegistryEntryGetParentEntry` call, so this loop owns it.
            unsafe { IOObjectRelease(current) };
        }
        if kr != KERN_SUCCESS || parent == IO_OBJECT_NULL {
            return false;
        }
        // SAFETY: `parent` is a live object handle and `class_name` is a
        // valid NUL-terminated C string.
        if unsafe { IOObjectConformsTo(parent, class_name.as_ptr()) } {
            // SAFETY: `parent` is owned by this loop (see above).
            unsafe { IOObjectRelease(parent) };
            return true;
        }
        current = parent;
        owned = true;
    }
}

/// Walk up the `IOService` plane from an `IOMedia` entry to find the
/// `IOBlockStorageDevice` ancestor, then read "Device Characteristics"
/// and "Protocol Characteristics".
fn walk_to_storage_device(
    start: IOObject,
) -> (Option<String>, Option<String>, Option<HostDriveBusType>) {
    let plane = c"IOService".as_ptr();
    let target_class = c"IOBlockStorageDevice".as_ptr();

    let mut current = start;
    // Don't release `start` — the caller owns it.
    let mut owned = false;

    loop {
        // SAFETY: `current` is a live object handle and `target_class` is a
        // valid NUL-terminated C string.
        if unsafe { IOObjectConformsTo(current, target_class) } {
            let result = read_storage_device_props(current);
            if owned {
                // SAFETY: `current` was retained by
                // `IORegistryEntryGetParentEntry`, so this loop owns it.
                unsafe { IOObjectRelease(current) };
            }
            return result;
        }

        let mut parent: IOObject = IO_OBJECT_NULL;
        // SAFETY: `current` is a live registry entry, `plane` is a valid
        // NUL-terminated C string, and `parent` is a valid out-pointer.
        let kr = unsafe { IORegistryEntryGetParentEntry(current, plane, &raw mut parent) };

        if owned {
            // SAFETY: `current` is owned by this loop (see above).
            unsafe { IOObjectRelease(current) };
        }

        if kr != KERN_SUCCESS || parent == IO_OBJECT_NULL {
            break;
        }

        current = parent;
        owned = true;
    }

    (None, None, None)
}

/// Read "Device Characteristics" and "Protocol Characteristics" from an
/// `IOBlockStorageDevice` entry.
fn read_storage_device_props(
    entry: IOObject,
) -> (Option<String>, Option<String>, Option<HostDriveBusType>) {
    let mut props_dict: CFMutableDictionaryRef = ptr::null_mut();
    // SAFETY: `entry` is a live registry entry and `props_dict` is a valid
    // out-pointer; on success we own the returned dictionary.
    let kr = unsafe {
        IORegistryEntryCreateCFProperties(entry, &raw mut props_dict, kCFAllocatorDefault, 0)
    };
    if kr != KERN_SUCCESS || props_dict.is_null() {
        return (None, None, None);
    }

    let dict: CFDictionaryRef = props_dict.cast_const();

    let model = cf_dict_get_nested_string(dict, "Device Characteristics", "Product Name");
    let serial = cf_dict_get_nested_string(dict, "Device Characteristics", "Serial Number");

    let bus_type =
        cf_dict_get_nested_string(dict, "Protocol Characteristics", "Physical Interconnect")
            .map(|s| interconnect_to_bus_type(&s));

    // SAFETY: `props_dict` is a live dictionary owned by this function.
    unsafe { CFRelease(props_dict.cast_const()) };

    (model, serial, bus_type)
}

// ---------------------------------------------------------------------------
// CoreFoundation dictionary helpers
// ---------------------------------------------------------------------------

/// Create a `CFStringRef` from a Rust `&str`.  Returns null on failure.
/// On success the caller owns the string and must `CFRelease` it.
fn cf_string(s: &str) -> CFStringRef {
    let Ok(c) = std::ffi::CString::new(s) else {
        return ptr::null();
    };
    // SAFETY: `c` is a valid NUL-terminated C string that outlives the call,
    // and `kCFAllocatorDefault` is the process-wide default allocator.
    unsafe { CFStringCreateWithCString(kCFAllocatorDefault, c.as_ptr(), K_CFSTRING_ENCODING_UTF8) }
}

/// Convert a `CFStringRef` to a Rust `String`.  Does not release `cf`.
fn cfstring_to_string(cf: CFStringRef) -> Option<String> {
    if cf.is_null() {
        return None;
    }
    // SAFETY: `cf` is a live, non-null CF object.
    if unsafe { CFGetTypeID(cf) != CFStringGetTypeID() } {
        return None;
    }
    // SAFETY: `cf` is a live `CFString` (type checked above).
    let len = unsafe { CFStringGetLength(cf) };
    // A UTF-16 code unit expands to at most 4 UTF-8 bytes; +1 for the NUL.
    let buf_size = usize::try_from(len).ok()? * 4 + 1;
    let mut buf = vec![0u8; buf_size];
    // SAFETY: `cf` is a live `CFString` and `buf` is a writable buffer of
    // exactly `buf_size` bytes.
    let ok = unsafe {
        CFStringGetCString(
            cf,
            buf.as_mut_ptr(),
            CFIndex::try_from(buf_size).ok()?,
            K_CFSTRING_ENCODING_UTF8,
        )
    };
    if !ok {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Look up a string value in a `CFDictionary`.
fn cf_dict_get_string(dict: CFDictionaryRef, key: &str) -> Option<String> {
    let cf_key = cf_string(key);
    if cf_key.is_null() {
        return None;
    }
    // SAFETY: `dict` is a live dictionary and `cf_key` is a live `CFString`.
    // `CFDictionaryGetValue` follows the get rule — the returned value is
    // borrowed, not owned.
    let value = unsafe { CFDictionaryGetValue(dict, cf_key) };
    // SAFETY: `cf_key` was created by `cf_string`, so this function owns it.
    unsafe { CFRelease(cf_key) };
    cfstring_to_string(value)
}

/// Look up a boolean value in a `CFDictionary`.
fn cf_dict_get_bool(dict: CFDictionaryRef, key: &str) -> Option<bool> {
    let cf_key = cf_string(key);
    if cf_key.is_null() {
        return None;
    }
    // SAFETY: `dict` is a live dictionary and `cf_key` is a live `CFString`.
    // The returned value is borrowed (get rule).
    let value = unsafe { CFDictionaryGetValue(dict, cf_key) };
    // SAFETY: `cf_key` was created by `cf_string`, so this function owns it.
    unsafe { CFRelease(cf_key) };
    if value.is_null() {
        return None;
    }
    // SAFETY: `value` is a live, non-null CF object.
    if unsafe { CFGetTypeID(value) != CFBooleanGetTypeID() } {
        return None;
    }
    // SAFETY: `value` is a live `CFBoolean` (type checked above).
    Some(unsafe { CFBooleanGetValue(value) })
}

/// Look up a non-negative integer value in a `CFDictionary`.
fn cf_dict_get_u64(dict: CFDictionaryRef, key: &str) -> Option<u64> {
    let cf_key = cf_string(key);
    if cf_key.is_null() {
        return None;
    }
    // SAFETY: `dict` and `cf_key` are live CoreFoundation objects. The
    // returned value follows the get rule and is borrowed.
    let value = unsafe { CFDictionaryGetValue(dict, cf_key) };
    // SAFETY: this function owns `cf_key`.
    unsafe { CFRelease(cf_key) };
    if value.is_null() {
        return None;
    }
    // SAFETY: `value` is a live non-null CoreFoundation object.
    if unsafe { CFGetTypeID(value) != CFNumberGetTypeID() } {
        return None;
    }

    let mut number = 0_i64;
    // SAFETY: `value` is a type-checked `CFNumber`; `number` is a live
    // correctly sized output location for the requested representation.
    let converted = unsafe {
        CFNumberGetValue(
            value,
            K_CFNUMBER_SINT64_TYPE,
            std::ptr::from_mut(&mut number).cast::<c_void>(),
        )
    };
    converted.then(|| u64::try_from(number).ok()).flatten()
}

/// Look up a string inside a nested `CFDictionary`.
fn cf_dict_get_nested_string(
    dict: CFDictionaryRef,
    outer_key: &str,
    inner_key: &str,
) -> Option<String> {
    let cf_outer = cf_string(outer_key);
    if cf_outer.is_null() {
        return None;
    }
    // SAFETY: `dict` is a live dictionary and `cf_outer` is a live
    // `CFString`.  The returned value is borrowed (get rule).
    let sub = unsafe { CFDictionaryGetValue(dict, cf_outer) };
    // SAFETY: `cf_outer` was created by `cf_string`, so this function owns it.
    unsafe { CFRelease(cf_outer) };
    if sub.is_null() {
        return None;
    }
    cf_dict_get_string(sub, inner_key)
}

#[cfg(test)]
mod tests {
    use super::interconnect_to_bus_type;
    use fsmnt_device::HostDriveBusType;

    #[test]
    fn interconnect_mapping() {
        assert_eq!(
            interconnect_to_bus_type("PCI-Express"),
            HostDriveBusType::Nvme
        );
        assert_eq!(
            interconnect_to_bus_type("Apple Fabric"),
            HostDriveBusType::Nvme
        );
        assert_eq!(interconnect_to_bus_type("USB"), HostDriveBusType::Usb);
        assert_eq!(interconnect_to_bus_type("SATA"), HostDriveBusType::Sata);
        assert_eq!(interconnect_to_bus_type("SAS"), HostDriveBusType::Sas);
        assert_eq!(
            interconnect_to_bus_type("Virtual Interface"),
            HostDriveBusType::Virtual,
        );
        assert_eq!(
            interconnect_to_bus_type("Something New"),
            HostDriveBusType::Unknown,
        );
    }
}
