//! Shared FFI bindings for Windows RTL compression APIs (`ntdll.dll`).
//!
//! Used by both `tests/windows_rtl.rs` and `benches/rtl_compare.rs`.
#![cfg(target_os = "windows")]

extern crate alloc;

use alloc::vec;

pub type NtStatus = i32;

pub const STATUS_SUCCESS: NtStatus = 0;
#[allow(dead_code)]
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = -0x3FFF_FFFA; // 0xC0000023
#[allow(dead_code)]
pub const STATUS_BAD_COMPRESSION_BUFFER: NtStatus = -0x3FFF_FD9C; // 0xC0000242

/// Check whether an NTSTATUS code indicates success (severity = 0).
#[allow(dead_code)]
pub fn nt_success(status: NtStatus) -> bool {
    status >= 0
}

pub const COMPRESSION_FORMAT_LZNT1: u16 = 2;
pub const COMPRESSION_FORMAT_XPRESS: u16 = 3;
pub const COMPRESSION_FORMAT_XPRESS_HUFF: u16 = 4;

#[allow(dead_code)]
pub const COMPRESSION_ENGINE_STANDARD: u16 = 0x0000;
pub const COMPRESSION_ENGINE_MAXIMUM: u16 = 0x0100;

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn RtlGetCompressionWorkSpaceSize(
        format: u16,
        workspace_buf_size: *mut u32,
        fragment_workspace_size: *mut u32,
    ) -> NtStatus;

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
pub fn rtl_workspace(format: u16) -> (vec::Vec<u8>, vec::Vec<u8>) {
    let mut compress_size: u32 = 0;
    let mut decompress_size: u32 = 0;
    let status = unsafe {
        RtlGetCompressionWorkSpaceSize(
            format | COMPRESSION_ENGINE_MAXIMUM,
            &mut compress_size,
            &mut decompress_size,
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
pub fn rtl_compress(format: u16, input: &[u8], workspace: &mut [u8]) -> vec::Vec<u8> {
    let mut compressed = vec![0u8; input.len() * 2 + 4096];
    let mut final_size: u32 = 0;
    let status = unsafe {
        RtlCompressBuffer(
            format | COMPRESSION_ENGINE_MAXIMUM,
            input.as_ptr(),
            input.len() as u32,
            compressed.as_mut_ptr(),
            compressed.len() as u32,
            4096,
            &mut final_size,
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
            output.len() as u32,
            compressed.as_ptr(),
            compressed.len() as u32,
            &mut final_size,
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
