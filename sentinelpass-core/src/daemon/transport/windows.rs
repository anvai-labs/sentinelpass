//! Windows named pipe transport (server-side).
//!
//! The connection type ([`WindowsNamedPipeConnection`], symmetric
//! client/server) and client connect logic live in `sentinelpass_protocol`.
//!
//! WBS-508 (TD-ROB-15): the server instance is created with raw
//! `CreateNamedPipeW` rather than tokio's `ServerOptions`, because the pipe
//! must carry an EXPLICIT security descriptor:
//!
//! - an explicit DACL granting the CURRENT USER generic read/write — no
//!   inherited ACL that a share- or profile-level loosening could widen;
//! - `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance — pipe-name
//!   squatting protection: a squatter that created the name first makes the
//!   daemon fail loudly (`ERROR_ACCESS_DENIED`) instead of the daemon
//!   silently serving a pipe a third process pre-created; while the daemon
//!   lives, squatters cannot take the name either;
//! - `PIPE_REJECT_REMOTE_CLIENTS` — remote (SMB) clients are rejected at
//!   the pipe level.
//!
//! The FFI sequence below is type-checked against the `windows` crate for
//! the `x86_64-pc-windows-msvc` target.

pub use sentinelpass_protocol::transport::windows::connect_named_pipe;
pub use sentinelpass_protocol::WindowsNamedPipeConnection;

use super::{TransportConfig, TransportError, TransportResult};
use std::sync::atomic::{AtomicBool, Ordering};

/// Windows named pipe transport
pub struct WindowsNamedPipeTransport {
    pipe_name: String,
    /// WBS-508: the FIRST CreateNamedPipeW for this name passes
    /// FILE_FLAG_FIRST_PIPE_INSTANCE; later instances (same server, more
    /// concurrent clients) must not, or they would fail by definition.
    first_instance_created: AtomicBool,
}

impl WindowsNamedPipeTransport {
    /// Create a new named pipe transport
    pub fn new(config: TransportConfig) -> TransportResult<Self> {
        let pipe_name = config
            .windows_pipe_path
            .or_else(|| {
                // Default to named pipe
                Some(r"\\.\pipe\SentinelPass".to_string())
            })
            .ok_or_else(|| TransportError::Other("Windows pipe path not configured".to_string()))?;

        Ok(Self {
            pipe_name,
            first_instance_created: AtomicBool::new(false),
        })
    }

    /// Get the pipe name
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Create a new named pipe server instance.
    ///
    /// Fails with `ERROR_ACCESS_DENIED` if the name already exists but was
    /// NOT created by this transport (squatting), which the daemon surfaces
    /// as a startup failure — fail-closed.
    pub fn create_server(
        &self,
    ) -> TransportResult<tokio::net::windows::named_pipe::NamedPipeServer> {
        let first = !self.first_instance_created.swap(true, Ordering::SeqCst);
        let handle = create_pipe_with_user_dacl(&self.pipe_name, first)?;

        unsafe {
            tokio::net::windows::named_pipe::NamedPipeServer::from_raw_handle(handle)
                .map_err(|e| TransportError::ConnectionFailed(format!("from_raw_handle: {e}")))
        }
    }

    /// Connect as a client (with timeout)
    pub async fn connect(&self, timeout_ms: u64) -> TransportResult<WindowsNamedPipeConnection> {
        connect_named_pipe(&self.pipe_name, timeout_ms).await
    }
}

/// Create one named-pipe server instance with the explicit current-user
/// DACL (WBS-508). Returns the raw handle (ownership transfers to the
/// caller, which must wrap it in `NamedPipeServer`).
fn create_pipe_with_user_dacl(
    pipe_name: &str,
    first_instance: bool,
) -> TransportResult<*mut std::ffi::c_void> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_SUCCESS, GENERIC_READ,
        GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Security::Authorization::{
        BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, SetEntriesInAclW, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        GetTokenInformation, InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
        SetSecurityDescriptorOwner, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SECURITY_DESCRIPTOR_REVISION is the value 1; the windows crate does
    // not re-export the constant.
    const SD_REVISION: u32 = 1;

    let mut wide_name: Vec<u16> = pipe_name.encode_utf16().collect();
    wide_name.push(0);

    unsafe {
        // --- 1. Current-user SID from our process token -------------------
        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).map_err(|e| {
            TransportError::ConnectionFailed(format!(
                "WBS-508: OpenProcessToken failed ({e}); refusing to create the pipe \
                 without an explicit DACL"
            ))
        })?;

        let mut info_len: u32 = 0;
        // Probe pass: fails with ERROR_INSUFFICIENT_BUFFER and fills the length.
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut info_len);
        let mut token_buffer = vec![0u8; info_len as usize];
        if let Err(e) = GetTokenInformation(
            token_handle,
            TokenUser,
            Some(token_buffer.as_mut_ptr().cast()),
            info_len,
            &mut info_len,
        ) {
            let _ = CloseHandle(token_handle);
            return Err(TransportError::ConnectionFailed(format!(
                "WBS-508: GetTokenInformation(TokenUser) failed ({e}); refusing to create \
                 the pipe without an explicit DACL"
            )));
        }
        let token_user = &*(token_buffer.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;

        // --- 2. Explicit DACL: current user, generic read/write only ------
        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, Some(sid));
        let explicit_access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_READ.0 | GENERIC_WRITE.0,
            grfAccessMode: windows::Win32::Security::Authorization::GRANT_ACCESS,
            grfInheritance: windows::Win32::Security::ACE_FLAGS(0), // NO_INHERITANCE
            Trustee: trustee,
        };
        let mut new_acl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
        if SetEntriesInAclW(Some(&[explicit_access]), None, &mut new_acl) != ERROR_SUCCESS {
            let _ = CloseHandle(token_handle);
            return Err(TransportError::ConnectionFailed(
                "WBS-508: SetEntriesInAclW failed; refusing to create the pipe without \
                 an explicit DACL"
                    .to_string(),
            ));
        }

        // --- 3. Security descriptor carrying that DACL + owner -------------
        let mut security_descriptor: windows::Win32::Security::SECURITY_DESCRIPTOR =
            std::mem::zeroed();
        let sd_ptr = windows::Win32::Security::PSECURITY_DESCRIPTOR(
            (&mut security_descriptor as *mut windows::Win32::Security::SECURITY_DESCRIPTOR)
                .cast(),
        );
        if InitializeSecurityDescriptor(sd_ptr, SD_REVISION).is_err() {
            let _ = CloseHandle(token_handle);
            return Err(TransportError::ConnectionFailed(
                "WBS-508: InitializeSecurityDescriptor failed".to_string(),
            ));
        }
        if SetSecurityDescriptorDacl(sd_ptr, true, Some(new_acl), false).is_err() {
            let _ = CloseHandle(token_handle);
            return Err(TransportError::ConnectionFailed(
                "WBS-508: SetSecurityDescriptorDacl failed".to_string(),
            ));
        }
        let _ = SetSecurityDescriptorOwner(sd_ptr, Some(sid), false);

        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&mut security_descriptor
                as *mut windows::Win32::Security::SECURITY_DESCRIPTOR)
                .cast(),
            bInheritHandle: false.into(),
        };

        // --- 4. CreateNamedPipeW with first-instance + remote rejection ----
        let open_mode = PIPE_ACCESS_DUPLEX
            | if first_instance {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0)
            };
        let created = CreateNamedPipeW(
            PCWSTR(wide_name.as_mut_ptr()),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            65536, // out buffer
            65536, // in buffer
            0,
            Some(&security_attributes),
        );

        // Kernel copied the SD/ACL during the call; release our copies.
        let _ = CloseHandle(token_handle);

        if created == INVALID_HANDLE_VALUE {
            let err = GetLastError();
            let hint = if err == ERROR_ACCESS_DENIED {
                " — the pipe name already exists (name squatting or another daemon); \
                 refusing to serve on a pipe we did not create"
            } else {
                ""
            };
            return Err(TransportError::ConnectionFailed(format!(
                "CreateNamedPipeW failed for {pipe_name} (error {err:?}){hint}"
            )));
        }

        // Free the ACL the helper API allocated for us.
        let _ = windows::Win32::Foundation::LocalFree(Some(
            windows::Win32::Foundation::HLOCAL(new_acl.cast()),
        ));

        Ok(created.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_named_pipe_transport_creation() {
        let transport = WindowsNamedPipeTransport::new(TransportConfig {
            windows_pipe_path: Some(r"\\.\pipe\SentinelPass-Test".to_string()),
            ..Default::default()
        });

        assert!(transport.is_ok());
        let transport = transport.unwrap();
        assert_eq!(transport.pipe_name(), r"\\.\pipe\SentinelPass-Test");
    }

    #[test]
    fn test_windows_named_pipe_transport_default() {
        let transport = WindowsNamedPipeTransport::new(TransportConfig::default()).unwrap();
        assert_eq!(transport.pipe_name(), r"\\.\pipe\SentinelPass");
    }

    #[test]
    fn test_transport_config_for_windows() {
        let _config = TransportConfig::for_current_platform();
        // On Windows, this should have a pipe path
        // But this test runs on all platforms, so we just verify it doesn't panic
    }
}
