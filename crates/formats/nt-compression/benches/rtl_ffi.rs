//! Shared FFI bindings for Windows RTL compression APIs (`ntdll.dll`).
//!
//! Used by both `tests/windows_rtl.rs` and `benches/rtl_compare.rs`.
#![cfg(target_os = "windows")]

extern crate alloc;

use alloc::vec;

/// Windows native status code returned by RTL compression routines.
pub type NtStatus = i32;

/// Status indicating that an RTL operation completed successfully.
pub const STATUS_SUCCESS: NtStatus = 0;
#[allow(dead_code)]
/// Status indicating that the caller-provided buffer was too small.
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = -0x3FFF_FFFA; // 0xC0000023
#[allow(dead_code)]
/// Status indicating malformed compressed input.
pub const STATUS_BAD_COMPRESSION_BUFFER: NtStatus = -0x3FFF_FD9C; // 0xC0000242

/// Check whether an NTSTATUS code indicates success (severity = 0).
#[allow(dead_code)]
#[must_use]
pub fn nt_success(status: NtStatus) -> bool {
    status >= 0
}

/// Native LZNT1 compression format identifier.
pub const COMPRESSION_FORMAT_LZNT1: u16 = 2;
/// Native XPRESS compression format identifier.
pub const COMPRESSION_FORMAT_XPRESS: u16 = 3;
/// Native XPRESS Huffman compression format identifier.
pub const COMPRESSION_FORMAT_XPRESS_HUFF: u16 = 4;

#[allow(dead_code)]
/// Native standard-compression engine selector.
pub const COMPRESSION_ENGINE_STANDARD: u16 = 0x0000;
/// Native maximum-compression engine selector.
pub const COMPRESSION_ENGINE_MAXIMUM: u16 = 0x0100;

#[link(name = "ntdll")]
unsafe extern "system" {
    /// Query workspace sizes for an RTL compression format.
    pub fn RtlGetCompressionWorkSpaceSize(
        format: u16,
        workspace_buf_size: *mut u32,
        fragment_workspace_size: *mut u32,
    ) -> NtStatus;

    /// Compress a buffer with an RTL compression format.
    pub fn RtlCompressBuffer(
        format: u16,
        uncompressed: *const u8,
        uncompressed_len: u32,
        compressed: *mut u8,
        compressed_buf_len: u32,
        uncompressed_chunk_size: u32,
        final_compressed_size: *mut u32,
        workspace: *mut u8,
    ) -> NtStatus;

    /// Decompress a buffer with an RTL compression format and workspace.
    pub fn RtlDecompressBufferEx(
        format: u16,
        uncompressed: *mut u8,
        uncompressed_buf_len: u32,
        compressed: *const u8,
        compressed_len: u32,
        final_uncompressed_size: *mut u32,
        workspace: *mut u8,
    ) -> NtStatus;
}

/// Allocate compress and decompress workspaces for the given RTL format.
///
/// # Panics
///
/// Panics if Windows rejects the format or cannot report its workspace sizes.
#[must_use]
pub fn rtl_workspace(format: u16) -> (vec::Vec<u8>, vec::Vec<u8>) {
    let mut compress_size: u32 = 0;
    let mut decompress_size: u32 = 0;
    let status = unsafe {
        RtlGetCompressionWorkSpaceSize(
            format | COMPRESSION_ENGINE_MAXIMUM,
            &raw mut compress_size,
            &raw mut decompress_size,
        )
    };
    assert_eq!(
        status, STATUS_SUCCESS,
        "RtlGetCompressionWorkSpaceSize failed: 0x{status:08X}"
    );
    (
        vec![0u8; compress_size as usize],
        vec![0u8; decompress_size as usize],
    )
}

/// Compress `input` using the RTL API with maximum compression.
///
/// # Panics
///
/// Panics if the native compressor rejects the input or output allocation.
pub fn rtl_compress(format: u16, input: &[u8], workspace: &mut [u8]) -> vec::Vec<u8> {
    let mut compressed = vec![0u8; input.len() * 2 + 4096];
    let mut final_size: u32 = 0;
    let status = unsafe {
        RtlCompressBuffer(
            format | COMPRESSION_ENGINE_MAXIMUM,
            input.as_ptr(),
            u32::try_from(input.len()).expect("the RTL API accepts buffers smaller than 4 GiB"),
            compressed.as_mut_ptr(),
            u32::try_from(compressed.len())
                .expect("the RTL API accepts buffers smaller than 4 GiB"),
            4096,
            &raw mut final_size,
            workspace.as_mut_ptr(),
        )
    };
    assert!(
        nt_success(status),
        "RtlCompressBuffer failed: 0x{status:08X}"
    );
    compressed.truncate(final_size as usize);
    compressed
}

/// Decompress RTL-compressed data.
///
/// # Panics
///
/// Panics if the native decompressor rejects the stream or expected size.
#[allow(
    dead_code,
    reason = "the shared FFI module is compiled as targets that do not all decompress data"
)]
pub fn rtl_decompress(
    format: u16,
    compressed: &[u8],
    expected_size: usize,
    workspace: &mut [u8],
) -> vec::Vec<u8> {
    let mut output = vec![0u8; expected_size];
    let mut final_size: u32 = 0;
    let status = unsafe {
        RtlDecompressBufferEx(
            format,
            output.as_mut_ptr(),
            u32::try_from(output.len()).expect("the RTL API accepts buffers smaller than 4 GiB"),
            compressed.as_ptr(),
            u32::try_from(compressed.len())
                .expect("the RTL API accepts buffers smaller than 4 GiB"),
            &raw mut final_size,
            workspace.as_mut_ptr(),
        )
    };
    assert!(
        nt_success(status),
        "RtlDecompressBufferEx failed: 0x{status:08X}"
    );
    output.truncate(final_size as usize);
    output
}
