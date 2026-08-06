//! Shared FFI bindings for wimlib compression APIs via dynamic loading.
//!
//! Used by both `tests/wimlib_cross.rs` and `benches/wimlib_compare.rs`.
//! Loads wimlib at runtime; tests/benches skip gracefully when unavailable.

use std::ffi::c_void;
use std::fmt;
use std::sync::Arc;

#[repr(i32)]
#[derive(Clone, Copy, Debug)]
pub enum WimlibCompressionType {
    Xpress = 1,
    Lzx = 2,
    #[allow(dead_code, reason = "will be used by LZMS cross-validation (#66)")]
    Lzms = 3,
}

#[derive(Debug)]
pub struct WimlibError {
    pub code: i32,
}

impl fmt::Display for WimlibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wimlib error code {}", self.code)
    }
}

type CreateCompressorFn = unsafe extern "C" fn(
    ctype: i32,
    max_block_size: usize,
    compression_level: u32,
    compressor_ret: *mut *mut c_void,
) -> i32;

type CompressFn = unsafe extern "C" fn(
    uncompressed_data: *const u8,
    uncompressed_size: usize,
    compressed_data: *mut u8,
    compressed_size_avail: usize,
    compressor: *mut c_void,
) -> usize;

type FreeCompressorFn = unsafe extern "C" fn(compressor: *mut c_void);

type CreateDecompressorFn = unsafe extern "C" fn(
    ctype: i32,
    max_block_size: usize,
    decompressor_ret: *mut *mut c_void,
) -> i32;

type DecompressFn = unsafe extern "C" fn(
    compressed_data: *const u8,
    compressed_size: usize,
    uncompressed_data: *mut u8,
    uncompressed_size: usize,
    decompressor: *mut c_void,
) -> i32;

type FreeDecompressorFn = unsafe extern "C" fn(decompressor: *mut c_void);

pub struct Wimlib {
    _library: libloading::Library,
    create_compressor: CreateCompressorFn,
    compress: CompressFn,
    free_compressor: FreeCompressorFn,
    create_decompressor: CreateDecompressorFn,
    decompress: DecompressFn,
    free_decompressor: FreeDecompressorFn,
}

// SAFETY: `Wimlib` holds a loaded shared library and resolved function
// pointers. The wimlib C library is stateless at the library level
// (all mutable state lives in per-compressor/decompressor handles),
// so sharing the `Wimlib` struct across threads is safe.
unsafe impl Send for Wimlib {}
unsafe impl Sync for Wimlib {}

fn library_candidates() -> &'static [&'static str] {
    if cfg!(target_os = "linux") {
        &[
            "libwim.so",
            "libwim.so.15",
            "libwimlib.so",
            "libwimlib.so.15",
        ]
    } else if cfg!(target_os = "macos") {
        &["libwim.dylib", "libwim.15.dylib", "libwimlib.dylib"]
    } else if cfg!(target_os = "windows") {
        &["libwim-15.dll", "libwim.dll", "wimlib.dll"]
    } else {
        &[]
    }
}

impl Wimlib {
    pub fn load() -> Option<Arc<Self>> {
        let library = library_candidates()
            .iter()
            .find_map(|name| unsafe { libloading::Library::new(*name).ok() })?;

        unsafe {
            let create_compressor = *library
                .get::<CreateCompressorFn>(b"wimlib_create_compressor")
                .ok()?;
            let compress = *library.get::<CompressFn>(b"wimlib_compress").ok()?;
            let free_compressor = *library
                .get::<FreeCompressorFn>(b"wimlib_free_compressor")
                .ok()?;
            let create_decompressor = *library
                .get::<CreateDecompressorFn>(b"wimlib_create_decompressor")
                .ok()?;
            let decompress = *library.get::<DecompressFn>(b"wimlib_decompress").ok()?;
            let free_decompressor = *library
                .get::<FreeDecompressorFn>(b"wimlib_free_decompressor")
                .ok()?;

            Some(Arc::new(Self {
                _library: library,
                create_compressor,
                compress,
                free_compressor,
                create_decompressor,
                decompress,
                free_decompressor,
            }))
        }
    }
}

pub struct WimlibCompressor {
    wimlib: Arc<Wimlib>,
    handle: *mut c_void,
}

// SAFETY: The wimlib compressor handle is an opaque, self-contained
// allocation with no thread-local state. It is safe to move between
// threads as long as it is not used concurrently (enforced by `&self`
// requiring exclusive logical access in single-threaded bench loops).
unsafe impl Send for WimlibCompressor {}

impl WimlibCompressor {
    pub fn new(
        wimlib: &Arc<Wimlib>,
        ctype: WimlibCompressionType,
        max_block_size: usize,
    ) -> Result<Self, WimlibError> {
        let mut handle: *mut c_void = std::ptr::null_mut();
        let ret =
            unsafe { (wimlib.create_compressor)(ctype as i32, max_block_size, 0, &mut handle) };
        if ret != 0 {
            return Err(WimlibError { code: ret });
        }
        Ok(Self {
            wimlib: Arc::clone(wimlib),
            handle,
        })
    }

    pub fn compress(&self, src: &[u8], dst: &mut [u8]) -> usize {
        unsafe {
            (self.wimlib.compress)(
                src.as_ptr(),
                src.len(),
                dst.as_mut_ptr(),
                dst.len(),
                self.handle,
            )
        }
    }
}

impl Drop for WimlibCompressor {
    fn drop(&mut self) {
        unsafe {
            (self.wimlib.free_compressor)(self.handle);
        }
    }
}

pub struct WimlibDecompressor {
    wimlib: Arc<Wimlib>,
    handle: *mut c_void,
}

// SAFETY: Same rationale as WimlibCompressor — the decompressor handle
// is a self-contained allocation with no thread-local state.
unsafe impl Send for WimlibDecompressor {}

impl WimlibDecompressor {
    pub fn new(
        wimlib: &Arc<Wimlib>,
        ctype: WimlibCompressionType,
        max_block_size: usize,
    ) -> Result<Self, WimlibError> {
        let mut handle: *mut c_void = std::ptr::null_mut();
        let ret =
            unsafe { (wimlib.create_decompressor)(ctype as i32, max_block_size, &mut handle) };
        if ret != 0 {
            return Err(WimlibError { code: ret });
        }
        Ok(Self {
            wimlib: Arc::clone(wimlib),
            handle,
        })
    }

    pub fn decompress(&self, src: &[u8], dst: &mut [u8]) -> Result<usize, WimlibError> {
        let ret = unsafe {
            (self.wimlib.decompress)(
                src.as_ptr(),
                src.len(),
                dst.as_mut_ptr(),
                dst.len(),
                self.handle,
            )
        };
        if ret != 0 {
            return Err(WimlibError { code: ret });
        }
        Ok(dst.len())
    }
}

impl Drop for WimlibDecompressor {
    fn drop(&mut self) {
        unsafe {
            (self.wimlib.free_decompressor)(self.handle);
        }
    }
}
