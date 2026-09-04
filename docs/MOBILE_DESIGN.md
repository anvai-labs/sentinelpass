# Mobile Apps & Thick Client Auto-fill - Technical Design

**Version:** 0.1.0-design
**Date:** 2026-02-24
**Status:** Design Phase

## Table of Contents
1. [Overview](#overview)
2. [Mobile Architecture](#mobile-architecture)
3. [iOS App Design](#ios-app-design)
4. [Android App Design](#android-app-design)
5. [Thick Client Auto-fill Design](#thick-client-auto-fill-design)
6. [Shared Rust Core Bridge](#shared-rust-core-bridge)
7. [Sync Architecture](#sync-architecture)
8. [Security Considerations](#security-considerations)

---

## Overview

This document outlines the technical design for extending SentinelPass to support:
1. **iOS apps** (iPhone/iPad)
2. **Android apps** (Phone/Tablet)
3. **Thick client auto-fill** for native Windows/macOS applications

### Design Principles

1. **Platform-Native UIs** - Use Swift/SwiftUI for iOS, Kotlin/Compose for Android (not React Native/Flutter)
2. **Shared Rust Core** - Leverage existing `sentinelpass-core` via FFI/JNI bridges
3. **Platform Security** - Integrate with platform secure enclaves (iOS Secure Enclave, Android Keystore)
4. **Offline-First** - Full functionality without cloud dependency
5. **Optional Cloud Sync** - iCloud, Google Drive, or self-hosted relay

---

## Mobile Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Mobile Device                           │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐        ┌──────────────┐                   │
│  │   Native UI  │        │  Platform    │                   │
│  │ (SwiftUI/    │◄───────►│  Services   │                   │
│  │  Compose)    │        │ (Keystore,   │                   │
│  │              │        │  Biometric)  │                   │
│  └──────┬───────┘        └──────────────┘                   │
│         │                                                        │
│         │                                                        │
│  ┌──────▼───────┐                                               │
│  │   FFI/JNI    │                                               │
│  │   Bridge     │                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
│         │                                                        │
│  ┌──────▼──────────────────────────────────────────┐          │
│  │     sentinelpass-core (Rust)                    │          │
│  │  - VaultManager                                 │          │
│  │  - Crypto (Argon2id, AES-256-GCM)               │          │
│  │  - Database (SQLite)                            │          │
│  │  - Sync (optional)                              │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                 │
│  ┌─────────────────────────────────────────────────┐          │
│  │     Encrypted Vault Database (SQLite)           │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ Sync (Optional)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Sync Services                           │
├─────────────────┬───────────────┬───────────────────────────┤
│  iCloud (iOS)   │ Google Drive  │  Self-hosted Relay        │
│  (CloudKit)     │ (Drive API)   │  (sentinelpass-relay)     │
└─────────────────┴───────────────┴───────────────────────────┘
```

### Cross-Platform Considerations

| Concern | iOS | Android | Resolution |
|---------|-----|---------|------------|
| **UI Framework** | SwiftUI | Jetpack Compose | Platform-native |
| **Secure Storage** | Keychain | Keystore | Platform APIs |
| **Biometric** | LocalAuthentication | BiometricPrompt | Platform APIs |
| **Background Sync** | BackgroundTasks | WorkManager | Platform APIs |
| **Database** | SQLite via Rust | SQLite via Rust | Shared Rust core |
| **Cloud Sync** | CloudKit | Drive REST API | Platform-specific |

---

## iOS App Design

### App Structure

```
SentinelPass/
├── SentinelPass/
│   ├── App/
│   │   ├── SentinelPassApp.swift          # App entry point
│   │   └── AppDelegate.swift              # Lifecycle management
│   ├── Core/
│   │   ├── VaultManager.swift             # FFI bridge to sentinelpass-core
│   │   ├── CryptoBridge.swift             # Crypto operations via Rust
│   │   ├── DatabaseBridge.swift           # Database operations via Rust
│   │   └── BiometricManager.swift         # Face ID / Touch ID
│   ├── Views/
│   │   ├── UnlockView.swift               # Master password unlock
│   │   ├── EntryListView.swift            # Vault entry list
│   │   ├── EntryDetailView.swift          # Entry details
│   │   ├── PasswordGeneratorView.swift    # Password generator
│   │   ├── SettingsView.swift             # App settings
│   │   └── HealthDashboardView.swift      # Password health
│   ├── Services/
│   │   ├── CloudKitSync.swift             # iCloud sync
│   │   ├── AutoFillService.swift          # Password AutoFill
│   │   └── NotificationService.swift      # Push notifications
│   ├── Models/
│   │   ├── Entry.swift                    # Entry models
│   │   └── VaultState.swift               # App state
│   └── Resources/
│       ├── Assets.xcassets                # Images, icons
│       └── Localizable.strings            # Localization
├── SentinelPassTests/
└── SentinelPassUITests/
```

### Swift-Rust FFI Bridge

```swift
// VaultManager.swift

import Foundation

class VaultManager {
    private var rustVault: OpaquePointer?

    // Initialize vault (calls Rust via FFI)
    func initialize(vaultPath: String, masterPassword: String) throws {
        // Convert Swift strings to C strings
        let vaultPathC = vaultPath.cString(using: .utf8)
        let passwordC = masterPassword.cString(using: .utf8)

        // Call Rust function
        let result = vault_init(vaultPathC, passwordC)

        if result != 0 {
            throw VaultError.initializationFailed
        }

        self.rustVault = vault_get_handle()
    }

    // Get entry by ID
    func getEntry(id: UUID) throws -> Entry {
        var entry: Entry?
        let idString = id.uuidString.cString(using: .utf8)

        let result = vault_get_entry(rustVault, idString) { rawEntry in
            entry = Entry.fromRaw(rawEntry)
        }

        guard let entry = entry else {
            throw VaultError.entryNotFound
        }
        return entry
    }

    // Add new entry
    func addEntry(_ entry: Entry) throws {
        let rawEntry = entry.toRaw()
        let result = vault_add_entry(rustVault, rawEntry)

        if result != 0 {
            throw VaultError.addFailed
        }
    }
}

// FFI Declarations (would be in a separate header file)
// These correspond to Rust functions exported via C ABI

@_cdecl("vault_init")
private func vault_init(_ path: UnsafePointer<CChar>, _ password: UnsafePointer<CChar>) -> Int32

@_cdecl("vault_get_handle")
private func vault_get_handle() -> OpaquePointer?

@_cdecl("vault_get_entry")
private func vault_get_entry(_ vault: OpaquePointer?, _ id: UnsafePointer<CChar>, _ callback: @escaping @convention(c) (OpaquePointer?) -> Void) -> Int32

@_cdecl("vault_add_entry")
private func vault_add_entry(_ vault: OpaquePointer?, _ entry: OpaquePointer?) -> Int32
```

### Rust FFI Exports

```rust
// sentinelpass-core/src/ffi/ios.rs

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::Mutex;
use crate::vault::VaultManager;

// Global vault instance (simplified - would use proper handle management in production)
static VAULT: Mutex<Option<VaultManager>> = Mutex::new(None);

#[no_mangle]
pub extern "C" fn vault_init(
    vault_path: *const c_char,
    master_password: *const c_char,
) -> c_int {
    // Convert C strings to Rust strings
    let path = unsafe { CStr::from_ptr(vault_path).to_str().unwrap() };
    let password = unsafe { CStr::from_ptr(master_password).to_str().unwrap() };

    // Initialize vault
    match VaultManager::initialize(path, password) {
        Ok(vault) => {
            *VAULT.lock().unwrap() = Some(vault);
            0 // Success
        }
        Err(_) => -1, // Error
    }
}

#[no_mangle]
pub extern "C" fn vault_get_entry(
    id: *const c_char,
    callback: extern "C" fn(*mut EntryRaw),
) -> c_int {
    let id_str = unsafe { CStr::from_ptr(id).to_str().unwrap() };

    if let Some(vault) = VAULT.lock().unwrap().as_ref() {
        if let Ok(entry) = vault.get_entry(id_str) {
            let raw_entry = entry_to_raw(entry);
            callback(raw_entry);
            return 0;
        }
    }
    -1
}

// Helper: Convert Rust Entry to C-compatible struct
#[repr(C)]
pub struct EntryRaw {
    id: *const c_char,
    title: *const c_char,
    username: *const c_char,
    password: *const c_char,
    // ... other fields
}

fn entry_to_raw(entry: Entry) -> *mut EntryRaw {
    Box::into_raw(Box::new(EntryRaw {
        id: CString::new(entry.id).unwrap().into_raw(),
        title: CString::new(entry.title).unwrap().into_raw(),
        // ... other fields
    }))
}
```

### iOS-Security Integration

```swift
// BiometricManager.swift

import LocalAuthentication

class BiometricManager {
    private let context = LAContext()

    enum BiometricError: Error {
        case notAvailable
        case notEnrolled
        case authenticationFailed
        case userCancel
    }

    func canUseBiometrics() -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    func authenticate(reason: String) async throws -> Bool {
        try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        )
    }

    // Store biometric-wrapped master key in Keychain
    func storeBiometricKey(_ key: Data, forAccount account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrAccount as String: account,
            kSecValueData as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw BiometricError.authenticationFailed
        }
    }

    func retrieveBiometricKey(forAccount account: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let data = result as? Data else {
            throw BiometricError.authenticationFailed
        }

        return data
    }
}
```

### AutoFill Integration

```swift
// AutoFillService.swift

import AuthenticationServices

class AutoFillCredentialProvider: ASCredentialProviderExtension {

    func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        // Called when user activates password auto-fill
        // Search vault for matching credentials
    }

    func provideCredential(for credentialIdentity: ASCredentialIdentity) {
        // Provide username/password to the requesting app
    }
}

// In main app:
extension ASCredentialIdentity {
    static func create(from entry: Entry) -> ASCredentialIdentity {
        return ASCredentialIdentity(
            serviceIdentifier: ASCredentialServiceIdentifier(
                identifier: entry.domain,
                type: .domain
            ),
            user: entry.username,
            recordIdentifier: entry.id.uuidString
        )
    }
}
```

### iCloud Sync (CloudKit)

```swift
// CloudKitSync.swift

import CloudKit

class CloudKitSync {
    private let container = CKContainer.default()
    private let privateDatabase: CKDatabase

    init() {
        self.privateDatabase = container.privateCloudDatabase
    }

    func pushVaultEntry(_ entry: Entry) async throws {
        // Create encrypted sync blob (use sentinelpass-core sync module)
        let syncBlob = try await createSyncBlob(from: entry)

        // Create CloudKit record
        let record = CKRecord(recordType: "VaultEntry")
        record["id"] = entry.id.uuidString
        record["encryptedPayload"] = syncBlob.data
        record["version"] = entry.syncVersion
        record["modifiedAt"] = entry.modifiedAt

        try await privateDatabase.save(record)
    }

    func pullVaultEntries(sinceVersion: Int) async throws -> [SyncBlob] {
        let query = CKQuery(recordType: "VaultEntry", predicate: NSPredicate(format: "version > %d", sinceVersion))

        let result = try await privateDatabase.records(matching: query)

        // Convert CKRecords to SyncBlobs for decryption in Rust
        return result.matchResults.compactMap { try? $0.1.get() }
            .map { record in
                SyncBlob(
                    id: record["id"] as! String,
                    encryptedPayload: record["encryptedPayload"] as! Data,
                    version: record["version"] as! Int
                )
            }
    }
}
```

---

## Android App Design

### App Structure

```
sentinelpass-android/
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/com/sentinelpass/
│   │   │   │   ├── SentinelPassApp.kt       # Application class
│   │   │   │   ├── core/
│   │   │   │   │   ├── VaultManager.kt      # JNI bridge to Rust
│   │   │   │   │   ├── CryptoBridge.kt      # Crypto via Rust
│   │   │   │   │   ├── DatabaseBridge.kt    # Database via Rust
│   │   │   │   │   └── BiometricManager.kt  # Fingerprint/Face
│   │   │   │   ├── ui/
│   │   │   │   │   ├── screens/
│   │   │   │   │   │   ├── UnlockScreen.kt
│   │   │   │   │   │   ├── EntryListScreen.kt
│   │   │   │   │   │   ├── EntryDetailScreen.kt
│   │   │   │   │   │   ├── PasswordGeneratorScreen.kt
│   │   │   │   │   │   └── SettingsScreen.kt
│   │   │   │   │   ├── components/
│   │   │   │   │   └── theme/
│   │   │   │   ├── services/
│   │   │   │   │   ├── GoogleDriveSync.kt   # Google Drive sync
│   │   │   │   │   ├── AutoFillService.kt   # Autofill service
│   │   │   │   │   └── TileService.kt       # Quick settings tile
│   │   │   │   └── data/
│   │   │   │       ├── Entry.kt
│   │   │   │       └── VaultState.kt
│   │   │   ├── cpp/
│   │   │   │   └── sentinelpass_jni.cpp    # JNI bridge code
│   │   │   ├── res/                         # Android resources
│   │   │   └── AndroidManifest.xml
│   │   └── test/                            # Unit tests
│   └── build.gradle                        # Build configuration
└── rust/
    └── Cargo.toml                           # Rust FFI library
```

### Kotlin-JNI Bridge

```kotlin
// VaultManager.kt

class VaultManager(private val context: Context) {

    private var nativeHandle: Long = 0

    // Load native library
    companion object {
        init {
            System.loadLibrary("sentinelpass_jni")
        }
    }

    // Initialize vault (calls Rust via JNI)
    fun initialize(vaultPath: String, masterPassword: String): Result<Unit> {
        return try {
            nativeHandle = nativeInit(vaultPath, masterPassword)
            if (nativeHandle == 0L) {
                Result.failure(VaultError.InitializationFailed)
            } else {
                Result.success(Unit)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // Get entry by ID
    fun getEntry(id: String): Result<Entry> {
        return try {
            val jsonEntry = nativeGetEntry(nativeHandle, id)
            val entry = parseEntryJson(jsonEntry)
            Result.success(entry)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // Add new entry
    fun addEntry(entry: Entry): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val jsonEntry = serializeEntryToJson(entry)
            val result = nativeAddEntry(nativeHandle, jsonEntry)
            if (result == 0) Result.success(Unit)
            else Result.failure(VaultError.AddFailed)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // Native method declarations
    private external fun nativeInit(vaultPath: String, masterPassword: String): Long
    private external fun nativeGetEntry(handle: Long, id: String): String
    private external fun nativeAddEntry(handle: Long, entryJson: String): Int
    private external fun nativeDestroy(handle: Long)

    protected fun finalize() {
        if (nativeHandle != 0L) {
            nativeDestroy(nativeHandle)
        }
    }
}
```

### Rust JNI Exports

```rust
// sentinelpass-core/src/ffi/android.rs

use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject};
use jni::sys::{jlong, jint, jstring};
use crate::vault::VaultManager;

// Store vault handles (simplified - would use proper handle management)
use std::sync::Mutex;
lazy_static! {
    static ref VAULTS: Mutex<Vec<VaultManager>> = Mutex::new(Vec::new());
}

#[no_mangle]
pub extern "system" fn Java_com_sentinelpass_core_VaultManager_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    vault_path: JString,
    master_password: JString,
) -> jlong {
    // Convert Java strings to Rust strings
    let path: String = env.get_string(&vault_path).unwrap().into();
    let password: String = env.get_string(&master_password).unwrap().into();

    // Initialize vault
    match VaultManager::initialize(&path, &password) {
        Ok(vault) => {
            let mut vaults = VAULTS.lock().unwrap();
            vaults.push(vault);
            // Return handle as index (simplified)
            (vaults.len() - 1) as jlong
        }
        Err(_) => 0, // Error
    }
}

#[no_mangle]
pub extern "system" fn Java_com_sentinelpass_core_VaultManager_nativeGetEntry(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    id: JString,
) -> jstring {
    let id_str: String = env.get_string(&id).unwrap().into();

    if let Some(vault) = VAULTS.lock().unwrap().get(handle as usize) {
        if let Ok(entry) = vault.get_entry(&id_str) {
            let json = serde_json::to_string(&entry).unwrap();
            return env.new_string(json).unwrap().into_raw();
        }
    }

    // Return null on error
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "system" fn Java_com_sentinelpass_core_VaultManager_nativeAddEntry(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    entry_json: JString,
) -> jint {
    let json: String = env.get_string(&entry_json).unwrap().into();

    if let Some(vault) = VAULTS.lock().unwrap().get(handle as usize) {
        if let Ok(entry) = serde_json::from_str::<Entry>(&json) {
            return match vault.add_entry(&entry) {
                Ok(_) => 0,  // Success
                Err(_) => -1, // Error
            };
        }
    }

    -1
}
```

### Android Security Integration

```kotlin
// BiometricManager.kt

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity

class BiometricManager(private val activity: FragmentActivity) {

    private val biometricManager = BiometricManager.from(activity)

    enum class BiometricError {
        NOT_AVAILABLE, NOT_ENROLLED, AUTHENTICATION_FAILED
    }

    fun canUseBiometrics(): Boolean {
        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun authenticate(
        reason: String,
        onSuccess: () -> Unit,
        onFailure: (BiometricError) -> Unit
    ) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(reason)
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()

        val biometricPrompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFailure(BiometricError.AUTHENTICATION_FAILED)
                }
            }
        )

        biometricPrompt.authenticate(promptInfo)
    }

    // Store biometric-wrapped key in Android Keystore
    fun storeBiometricKey(key: ByteArray, alias: String): Result<Unit> {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

            // Store encrypted secret
            val secretEntry = KeyStore.SecretKeyEntry(
                SecretKeySpec(key, "AES")
            )

            val protectionParameter = KeyProtection.Builder(
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(30)
                .build()

            keyStore.setEntry(
                alias,
                secretEntry,
                protectionParameter
            )

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
```

### AutoFill Service

```kotlin
// AutoFillService.kt

import android.service.autofill.AutofillService
import android.service.autofill.FillResponse
import android.service.autofill.Dataset

class SentinelPassAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        // Extract domain from request
        val structure = request.fillContexts.last().structure
        val domain = extractDomain(structure)

        // Search vault for matching credentials
        val vaultManager = (application as SentinelPassApp).vaultManager
        val entries = vaultManager.searchByDomain(domain)

        // Build fill response with datasets
        val response = FillResponse.Builder()

        entries.forEach { entry ->
            val dataset = Dataset.Builder()
                .setValue(
                    structure.findNodeById("username")?.id,
                    AutofillValue.forText(entry.username)
                )
                .setValue(
                    structure.findNodeById("password")?.id,
                    AutofillValue.forText(entry.password)
                )
                .build()

            response.addDataset(dataset)
        }

        callback.onSuccess(response.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Extract new credentials from form
        // Save to vault
    }
}
```

### Google Drive Sync

```kotlin
// GoogleDriveSyncService.kt

import com.google.api.services.drive.Drive

class GoogleDriveSyncService(private val drive: Drive) {

    suspend fun pushVaultEntry(entry: Entry): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            // Create encrypted sync blob (use sentinelpass-core sync module)
            val syncBlob = createSyncBlob(entry)

            // Upload to Google Drive
            val fileMetadata = com.google.api.services.drive.model.File()
                .setName("sentinelpass-${entry.id}.json")
                .setParents(listOf("appDataFolder")) // Application data folder

            val mediaContent = FileContent(
                "application/json",
                syncBlob.toInputStream()
            )

            drive.files().create(fileMetadata, mediaContent)
                .setFields("id")
                .execute()

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun pullVaultEntries(): Result<List<SyncBlob>> = withContext(Dispatchers.IO) {
        try {
            // List all files in appDataFolder
            val files = drive.files().list()
                .setSpaces("appDataFolder")
                .setQ("name contains 'sentinelpass-'")
                .execute()

            // Download and decrypt each file
            val blobs = files.files.mapNotNull { file ->
                drive.files().get(file.id).executeMediaAsInputStream().use { input ->
                    parseSyncBlob(input)
                }
            }

            Result.success(blobs)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
```

---

## Thick Client Auto-fill Design

### Overview

Thick client auto-fill enables SentinelPass to inject credentials directly into native (non-browser) applications on Windows and macOS.

### Windows Credential Provider Integration

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Windows Application                      │
│                  (e.g., PuTTY, Outlook)                      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ CREDUI_PASSWORD CREDENTIAL
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              SentinelPass Credential Provider                │
│            (Credential Provider DLL)                         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ IPC (named pipe / TCP)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                  sentinelpass-daemon                         │
│                  (running as service)                        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ SQLite read
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              Encrypted Vault Database                        │
└─────────────────────────────────────────────────────────────┘
```

#### Implementation

```rust
// sentinelpass-windows-cp/
// Credential Provider DLL (C++/WinRT)

#include <windows.h>
#include <credentialprovider.h>
#include <string>

class SentinelPassCredential : public ICredentialProviderCredential {
public:
    HRESULT STDMETHODCALLTYPE GetStringValue(
        DWORD fieldID,
        PWSTR* ppszStringValue) override {

        if (fieldID == CPFT_USERNAME) {
            // Fetch username from daemon via IPC
            std::wstring username = fetchUsernameFromDaemon();
            *ppszStringValue = _wcsdup(username.c_str());
            return S_OK;
        }

        if (fieldID == CPFT_PASSWORD) {
            // Fetch password from daemon via IPC
            std::wstring password = fetchPasswordFromDaemon();
            *ppszStringValue = _wcsdup(password.c_str());
            return S_OK;
        }

        return E_NOTIMPL;
    }

private:
    std::wstring fetchUsernameFromDaemon() {
        // Connect to sentinelpass-daemon via named pipe
        HANDLE hPipe = CreateFile(
            L"\\\\.\\pipe\\sentinelpass_cp",
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            return L"";
        }

        // Send IPC request for credential
        const char* request = R"({"type": "get_credential_for_cp", "target": "<app_name>"})";
        DWORD written;
        WriteFile(hPipe, request, strlen(request), &written, NULL);

        // Read response
        char response[4096];
        DWORD read;
        ReadFile(hPipe, response, sizeof(response), &read, NULL);

        CloseHandle(hPipe);

        // Parse JSON and extract username
        // ... JSON parsing code

        return L"<username>";
    }
};

class SentinelPassProvider : public ICredentialProvider {
public:
    HRESULT STDMETHODCALLTYPE SetUsageScenario(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags) override {

        // Determine which application is requesting credentials
        // This allows us to provide context-aware autofill
        m_scenario = cpus;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetCredentialCount(
        DWORD* pdwCount,
        DWORD* pdwDefault,
        BOOL* pbAutoLoggedIn) override {

        // Return number of available credentials for this target
        *pdwCount = 1; // For now, just one credential
        *pdwDefault = 0;
        *pbAutoLoggedIn = FALSE;
        return S_OK;
    }

private:
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_scenario;
};
```

#### Daemon IPC Extension

```rust
// sentinelpass-core/src/daemon/credential_provider.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CpCredentialRequest {
    pub target: String,      // e.g., "putty", "outlook", "github.com"
    pub request_type: String, // "get_credential_for_cp"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CpCredentialResponse {
    pub username: String,
    pub password: String,
    pub title: String,
}

impl IpcServer {
    pub fn handle_credential_provider_request(
        &self,
        request: CpCredentialRequest,
    ) -> Result<CpCredentialResponse> {
        // Look up credential by target application/domain
        let entry = self.vault
            .search_by_domain(&request.target)?
            .into_iter()
            .next()
            .ok_or_else(|| Error::EntryNotFound)?;

        Ok(CpCredentialResponse {
            username: entry.username,
            password: entry.password, // Note: decrypt first!
            title: entry.title,
        })
    }
}
```

### macOS Accessibility Integration

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     macOS Application                        │
│                  (e.g., iTerm2, Mail)                        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ User presses hotkey (Cmd+Opt+P)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              SentinelPass Helper App                         │
│              (Accessibility API)                             │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ IPC (Unix socket)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                  sentinelpass-daemon                         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ Unix socket
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              Encrypted Vault Database                        │
└─────────────────────────────────────────────────────────────┘
```

#### Implementation (Swift)

```swift
// sentinelpass-macos-helper/
// Helper app for accessibility-based autofill

import Cocoa
import ApplicationServices
import AXKit

class PasswordInjector {

    func injectCredentials(username: String, password: String) {
        guard let focusedElement = AXUIElement.createSystemWide().focusedElement else {
            return
        }

        // Find password field (heuristic: secure text field)
        if let passwordField = findPasswordField(in: focusedElement) {
            // Type password
            typeText(password, into: passwordField)
        }

        // Find username field (heuristic: before password field)
        if let usernameField = findUsernameField(before: passwordField) {
            typeText(username, into: usernameField)
        }
    }

    private func findPasswordField(in element: AXUIElement) -> AXUIElement? {
        // Use Accessibility API to find secure text fields
        var children: AnyObject?
        let result = AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &children)

        guard result == .success,
              let childArray = children as? [AXUIElement] else {
            return nil
        }

        for child in childArray {
            var role: AnyObject?
            AXUIElementCopyAttributeValue(child, kAXRoleAttribute as CFString, &role)

            if let roleString = role as? String,
               roleString == kAXSecureTextFieldRole {
                return child
            }
        }

        return nil
    }

    private func typeText(_ text: String, into element: AXUIElement) {
        // Use Accessibility API to set value
        let textValue = text as AXValue
        AXUIElementSetAttributeValue(element, kAXValueAttribute as CFString, textValue)
    }
}

// Global hotkey handler
class HotkeyManager {
    private var eventTap: CFMachPort?

    func registerHotkey() {
        let eventMask = (1 << CGEventType.keyDown.rawValue)

        let callback: CGEventTapCallBack = { (proxy, type, event, refcon) in
            // Check for Cmd+Opt+P
            if event.flags.contains(.maskCommand) &&
               event.flags.contains(.maskOption) &&
               event.keyCode == 35 { // P key
                // Show password picker
                self.showPasswordPicker()
            }
            return Unmanaged.passUnretained(event).toOpaque()
        }

        eventTap = CGEvent.tapCreate(
            tap: .cgSessionEventTap,
            place: .headInsertEventTap,
            options: .defaultTap,
            eventsOfInterest: CGEventMask(eventMask),
            callback: callback,
            userInfo: nil
        )

        let runLoopSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, eventTap, 0)
        CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, .commonModes)
    }

    private func showPasswordPicker() {
        // Show quick search UI
        // User types to search vault
        // On selection, inject credentials
    }
}
```

#### Daemon IPC Extension (macOS)

```rust
// sentinelpass-core/src/daemon/accessibility.rs

use crate::daemon::ipc::IpcMessage;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessibilityRequest {
    pub request_type: String, // "search_credential_for_accessibility"
    pub query: String,        // User's search query
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessibilityResponse {
    pub results: Vec<CredentialSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub domain: String,
}

impl IpcServer {
    pub fn handle_accessibility_request(
        &self,
        request: AccessibilityRequest,
    ) -> Result<AccessibilityResponse> {
        // Search vault by query (matches title, domain, username)
        let results = self.vault.search(&request.query)?;

        Ok(AccessibilityResponse {
            results: results.into_iter().map(|entry| CredentialSummary {
                id: entry.id,
                title: entry.title,
                username: entry.username,
                domain: entry.domain,
            }).collect(),
        })
    }

    pub fn get_full_credential_for_accessibility(
        &self,
        id: String,
    ) -> Result<CredentialDetail> {
        let entry = self.vault.get_entry(&id)?;

        Ok(CredentialDetail {
            username: entry.username,
            password: entry.password.to_plain_string(), // Decrypt
            totp_code: self.get_totp_code(&entry)?,
        })
    }
}
```

### System Tray / Quick Access

#### Windows (System Tray)

```rust
// sentinelpass-ui/src-tauri/src/system_tray.rs

use tauri::{AppHandle, Manager, CustomMenuItem, SystemTray, SystemTrayEvent, SystemTrayMenu};

pub fn create_system_tray() -> SystemTray {
    let tray_menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("search", "Search Vault"))
        .add_item(CustomMenuItem::new("lock", "Lock Vault"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("quit", "Quit"));

    SystemTray::new().with_menu(tray_menu)
}

pub fn handle_system_tray_event(app: &AppHandle, event: SystemTrayEvent) {
    match event {
        SystemTrayEvent::LeftClick { .. } => {
            // Show quick search window
            tauri::WindowBuilder::new(
                app,
                "quick-search",
                tauri::WindowUrl::App("quick-search.html".into())
            )
                .title("Quick Search")
                .inner_size(400.0, 300.0)
                .always_on_top(true)
                .skip_taskbar(true)
                .build()
                .unwrap();
        }
        SystemTrayEvent::MenuItemClick { id, .. } => {
            match id.as_str() {
                "search" => {
                    // Same as left click
                }
                "lock" => {
                    // Lock vault
                    app.emit_all("lock-vault", ()).unwrap();
                }
                "quit" => {
                    app.exit(0);
                }
                _ => {}
            }
        }
        _ => {}
    }
}
```

#### macOS (Menu Bar)

```swift
// sentinelpass-macos-helper/MenuBarController.swift

import Cocoa

class MenuBarController: NSObject, NSMenuDelegate {
    private var statusItem: NSStatusItem?
    private var quickSearchWindow: NSWindow?

    func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "lock.fill", accessibilityDescription: "SentinelPass")
            button.action = #selector(statusBarButtonClicked)
            button.target = self
        }

        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Search Vault", action: #selector(showQuickSearch), keyEquivalent: "p"))
        menu.addItem(NSMenuItem(title: "Lock Vault", action: #selector(lockVault), keyEquivalent: "l"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit SentinelPass", action: #selector(quit), keyEquivalent: "q"))

        statusItem?.menu = menu
    }

    @objc func statusBarButtonClicked() {
        showQuickSearch()
    }

    @objc func showQuickSearch() {
        // Show quick search window
        if quickSearchWindow == nil {
            quickSearchWindow = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 400, height: 300),
                styleMask: [.titled, .closable],
                backing: .buffered,
                defer: false
            )

            quickSearchWindow?.center()
            quickSearchWindow?.makeKeyAndOrderFront(nil)
        } else {
            quickSearchWindow?.makeKeyAndOrderFront(nil)
        }
    }

    @objc func lockVault() {
        // Send IPC message to daemon to lock vault
        NotificationCenter.default.post(name: .lockVault, object: nil)
    }

    @objc func quit() {
        NSApplication.shared.terminate(nil)
    }
}

extension Notification.Name {
    static let lockVault = Notification.Name("lockVault")
}
```

---

## Shared Rust Core Bridge

### Mobile Bridge Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              sentinelpass-mobile-bridge                     │
│                 (Rust library)                              │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   iOS FFI    │  │  Android JNI │  │  Test Utils  │     │
│  │  (C ABI)     │  │  (JNI ABI)   │  │  (mocking)   │     │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘     │
│         │                  │                                 │
│         └──────────┬───────┘                                 │
│                    ▼                                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │          sentinelpass-core (reused)                  │  │
│  │  - VaultManager                                      │  │
│  │  - Crypto (Argon2id, AES-256-GCM)                    │  │
│  │  - Database (SQLite)                                 │  │
│  │  - Sync (relay, iCloud, Google Drive)               │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Bridge Implementation

```rust
// sentinelpass-mobile-bridge/src/lib.rs

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use sentinelpass_core::vault::VaultManager;
use sentinelpass_core::crypto::SecureBuffer;

// Mobile-specific configuration
const MOBILE_DB_PATH: &str = "sentinelpass_vault.db";

// Error codes
pub const SP_SUCCESS: c_int = 0;
pub const SP_ERROR_INVALID_PARAM: c_int = -1;
pub const SP_ERROR_VAULT_LOCKED: c_int = -2;
pub const SP_ERROR_NOT_FOUND: c_int = -3;
pub const SP_ERROR_CRYPTO: c_int = -4;

/// Initialize vault on mobile
#[no_mangle]
pub extern "C" fn sp_vault_init(
    db_path: *const c_char,
    master_password: *const c_char,
) -> c_int {
    if db_path.is_null() || master_password.is_null() {
        return SP_ERROR_INVALID_PARAM;
    }

    let path = unsafe { CStr::from_ptr(db_path).to_str() };
    let password = unsafe { CStr::from_ptr(master_password).to_str() };

    let (db_path, password) = match (path, password) {
        (Ok(p), Ok(pwd)) => (p, pwd),
        _ => return SP_ERROR_INVALID_PARAM,
    };

    match VaultManager::initialize(db_path, password) {
        Ok(_) => SP_SUCCESS,
        Err(_) => SP_ERROR_CRYPTO,
    }
}

/// Add entry to vault
#[no_mangle]
pub extern "C" fn sp_entry_add(
    title: *const c_char,
    username: *const c_char,
    password: *const c_char,
    domain: *const c_char,
) -> c_int {
    // Implementation
    SP_SUCCESS
}

/// Search entries by query
#[no_mangle]
pub extern "C" fn sp_entry_search(
    query: *const c_char,
    callback: extern "C" fn(*const c_char),
) -> c_int {
    // Implementation
    SP_SUCCESS
}

/// Get TOTP code for entry
#[no_mangle]
pub extern "C" fn sp_totp_get_code(
    entry_id: *const c_char,
    out_code: *mut c_char,
    out_code_len: *mut usize,
) -> c_int {
    // Implementation
    SP_SUCCESS
}

/// Biometric unlock (verify biometric-wrapped key)
#[no_mangle]
pub extern "C" fn sp_biometric_unlock(
    wrapped_key: *const u8,
    wrapped_key_len: usize,
) -> c_int {
    // Decrypt biometric-wrapped key and use it to unlock vault
    SP_SUCCESS
}

// JNI-specific exports (Android)
#[cfg(feature = "jni")]
pub mod jni {
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::{jlong, jstring};

    #[no_mangle]
    pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeInit(
        mut env: JNIEnv,
        _class: JClass,
        db_path: JString,
        master_password: JString,
    ) -> jlong {
        let path: String = env.get_string(&db_path).unwrap().into();
        let password: String = env.get_string(&master_password).unwrap().into();

        match VaultManager::init(&path, &password) {
            Ok(vault) => Box::into_raw(Box::new(vault)) as jlong,
            Err(_) => 0,
        }
    }

    // ... more JNI functions
}

// iOS-specific exports
#[cfg(feature = "ios")]
pub mod ios {
    use std::os::raw::{c_char, c_int};

    #[no_mangle]
    pub extern "C" fn sp_ios_vault_init(
        db_path: *const c_char,
        master_password: *const c_char,
    ) -> c_int {
        // iOS-specific initialization
        super::sp_vault_init(db_path, master_password)
    }
}
```

---

## Sync Architecture

### Multi-Platform Sync Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Mobile Device                             │
│                   (iOS or Android)                           │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ Sync Preference
                               │ (user selects)
                               ▼
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│     iCloud      │   │  Google Drive   │   │  Self-hosted    │
│  (CloudKit)     │   │  (Drive API)    │   │     Relay       │
│                 │   │                 │   │                 │
│  Platform-only  │   │  Platform-only  │   │  Cross-platform │
└─────────────────┘   └─────────────────┘   └─────────────────┘
```

### Sync Implementation Strategy

#### iCloud (iOS)

```swift
// Use CloudKit for seamless sync
// Vault entries stored as encrypted blobs in private database
// Leverage CloudKit's automatic conflict resolution

class CloudKitSyncEngine {
    private let container = CKContainer.default()
    private let database: CKDatabase

    init() {
        self.database = container.privateCloudDatabase
    }

    func push(entry: EncryptedEntry) async throws {
        let record = CKRecord(recordType: "VaultEntry")
        record["id"] = entry.id.uuidString
        record["encryptedPayload"] = entry.encryptedData
        record["version"] = entry.version
        record["modifiedAt"] = entry.modifiedAt

        try await database.save(record)
    }

    func pull(sinceVersion: Int) async throws -> [EncryptedEntry] {
        let predicate = NSPredicate(format: "version > %d", sinceVersion)
        let query = CKQuery(recordType: "VaultEntry", predicate: predicate)

        let result = try await database.records(matching: query)

        return result.matchResults.compactMap { try? $0.1.get() }
            .map { record in
                EncryptedEntry(
                    id: UUID(uuidString: record["id"] as! String)!,
                    encryptedData: record["encryptedPayload"] as! Data,
                    version: record["version"] as! Int,
                    modifiedAt: record["modifiedAt"] as! Date
                )
            }
    }
}
```

#### Google Drive (Android)

```kotlin
// Use Google Drive API v3
// Store encrypted blobs in appDataFolder (hidden from user)

class GoogleDriveSyncEngine(private val drive: Drive) {

    suspend fun push(entry: EncryptedEntry): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val fileMetadata = com.google.api.services.drive.model.File()
                .setName("sentinelpass-${entry.id}.json")
                .setParents(listOf("appDataFolder"))
                .setAppProperties(mapOf(
                    "version" to entry.version.toString(),
                    "modifiedAt" to entry.modifiedAt.toEpochMilli().toString()
                ))

            val mediaContent = FileContent(
                "application/json",
                entry.encryptedData.inputStream()
            )

            drive.files().create(fileMetadata, mediaContent)
                .setFields("id")
                .execute()

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun pull(): Result<List<EncryptedEntry>> = withContext(Dispatchers.IO) {
        try {
            val files = drive.files().list()
                .setSpaces("appDataFolder")
                .setQ("name contains 'sentinelpass-'")
                .execute()

            val entries = files.files.mapNotNull { file ->
                drive.files().get(file.id).executeMediaAsInputStream().use { input ->
                    parseEncryptedEntry(input)
                }
            }

            Result.success(entries)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
```

#### Self-Hosted Relay (Cross-Platform)

```rust
// Reuse existing sentinelpass-relay for cross-platform sync
// Mobile apps can use HTTPS endpoints via platform HTTP clients

// iOS (Swift):
class RelaySyncEngine {
    private let baseURL: URL
    private let deviceIdentity: DeviceIdentity

    func push(entries: [EncryptedEntry]) async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent("api/v1/sync/push"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        // Add Ed25519 auth header
        let auth = try await signAuthHeader(method: "POST", path: "/api/v1/sync/push", body: payload)
        request.setValue(auth, forHTTPHeaderField: "Authorization")

        let (data, _) = try await URLSession.shared.data(for: request)
        // Handle response
    }
}
```

---

## Security Considerations

### Mobile Security

#### iOS
- **Keychain Services**: Store master key wrapper with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`
- **Secure Enclave**: Consider using Secure Enclave for master key derivation (iOS 9+)
- **Data Protection**: Use iOS file encryption (`NSFileProtectionComplete`)
- **Screen Capture**: Prevent screen recording/capture in sensitive views
- **Background App Refresh**: Lock vault when app goes to background

#### Android
- **Android Keystore**: Store master key with hardware-backed keystore when available
- **Biometric Prompt**: Require biometric auth every 30 seconds max
- **Screen Lock**: Lock vault when screen turns off
- **Root Detection**: Warn or refuse operation on rooted devices
- **Screenshot Prevention**: Set `FLAG_SECURE` on sensitive windows

### Thick Client Security

#### Windows
- **Named Pipe Security**: Use proper ACLs on named pipes (only allow same user)
- **Credential Provider isolation**: Run in separate security context
- **Memory protection**: Use SecureMemoryPattern for sensitive data in memory

#### macOS
- **Accessibility Permissions**: Require explicit user grant
- **Code Signing**: Sign helper app to prevent tampering
- **Sandboxing**: App Store distribution requires sandbox compliance
- **Hardened Runtime**: Enable hardened runtime for production

### Cross-Platform Concerns

1. **Screen Recording/Mirroring**: Detect and prevent
2. **Clipboard Timeout**: Auto-clear clipboard after 30 seconds
3. **Screenshot Prevention**: Block screenshots on sensitive screens
4. **Debugging Detection**: Refuse operation if debugger attached (mobile)
5. **Jailbreak/Root Detection**: Warn on compromised devices

---

## Implementation Phases

### Phase 1: Foundation (2-3 months)
- [ ] Set up mobile bridge crate
- [ ] Implement FFI/JNI bridge layer
- [ ] Create basic iOS app shell
- [ ] Create basic Android app shell
- [ ] Implement core vault operations via bridge

### Phase 2: Core Features (2-3 months)
- [ ] Master password unlock flow
- [ ] Entry list/detail views
- [ ] Add/edit/delete entries
- [ ] Search functionality
- [ ] Password generator
- [ ] Biometric unlock

### Phase 3: Platform Integration (2-3 months)
- [ ] iOS AutoFill integration
- [ ] Android Autofill service
- [ ] iCloud sync (iOS)
- [ ] Google Drive sync (Android)
- [ ] Push notifications

### Phase 4: Thick Client (2-3 months)
- [ ] Windows Credential Provider
- [ ] macOS Accessibility integration
- [ ] System tray/menu bar quick access
- [ ] Global hotkey for quick search

### Phase 5: Polish (1-2 months)
- [ ] UI/UX refinements
- [ ] Performance optimization
- [ ] Security audit
- [ ] App store submissions
- [ ] Documentation

---

## References

- [iOS Password AutoFill Guidelines](https://developer.apple.com/documentation/authenticationservices)
- [Android Autofill Framework](https://developer.android.com/guide/topics/text/autofill)
- [Windows Credential Provider API](https://docs.microsoft.com/en-us/windows/win32/api/credentialprovider/)
- [macOS Accessibility API](https://developer.apple.com/documentation/appkit/accessibility)
- [CloudKit Framework](https://developer.apple.com/icloud/cloudkit/)
- [Google Drive API v3](https://developers.google.com/drive/api/v3/reference)
