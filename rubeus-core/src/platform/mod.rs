//! Platform-specific code
//! Windows LSA/SSPI behind cfg(windows)

#[cfg(windows)]
pub mod windows;

#[cfg(not(windows))]
pub mod stub;
