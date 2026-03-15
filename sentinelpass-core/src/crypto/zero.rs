//! Zeroization utilities for secure memory handling.
//!
//! Provides utilities to securely clear sensitive data from memory.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A secure buffer that automatically zeroizes on drop
///
/// Use this to store sensitive data in memory. The buffer will
/// be automatically zeroized when it goes out of scope.
#[derive(ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer from data
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new secure buffer from a string
    pub fn from_string(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a reference to the inner data (use carefully!)
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consume the buffer and return the data wrapped in `Zeroizing`
    /// so it is automatically zeroized when dropped.
    pub fn into_inner(mut self) -> Zeroizing<Vec<u8>> {
        let data = std::mem::take(&mut self.data);
        std::mem::forget(self); // prevent double-zeroize in Drop
        Zeroizing::new(data)
    }
}

impl From<Vec<u8>> for SecureBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<String> for SecureBuffer {
    fn from(s: String) -> Self {
        Self::from_string(s)
    }
}

impl AsRef<[u8]> for SecureBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Zeroize a byte slice
///
/// This function will overwrite the provided bytes with zeros
/// using a best-effort approach. Note that compiler optimizations
/// may remove this code in some cases.
pub fn zeroize_bytes(data: &mut [u8]) {
    data.zeroize();
}

/// Zeroize a string
///
/// This function will overwrite the string's contents with zeros.
pub fn zeroize_string(s: &mut String) {
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer = SecureBuffer::new(data.clone());

        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.as_bytes(), &data[..]);
    }

    #[test]
    fn test_secure_buffer_from_string() {
        let s = "secret data".to_string();
        let buffer = SecureBuffer::from_string(s.clone());

        assert_eq!(buffer.len(), s.len());
        assert_eq!(buffer.as_bytes(), s.as_bytes());
    }

    #[test]
    fn test_secure_buffer_is_empty() {
        let buffer = SecureBuffer::new(vec![]);
        assert!(buffer.is_empty());

        let buffer = SecureBuffer::new(vec![1, 2, 3]);
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_zeroize_bytes() {
        let mut data = vec![1, 2, 3, 4, 5];
        zeroize_bytes(&mut data);

        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_zeroize_string() {
        let mut s = String::from("secret");
        zeroize_string(&mut s);

        // String should be cleared (though length may remain)
        assert!(s.is_empty() || s.chars().all(|c| c == '\0'));
    }

    #[test]
    fn test_into_inner() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer = SecureBuffer::new(data.clone());
        let inner = buffer.into_inner();

        // inner is Zeroizing<Vec<u8>>, dereferences to the original data
        assert_eq!(&*inner, &data);
        // buffer is consumed — no longer accessible
    }
}
