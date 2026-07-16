# SentinelPass - Installation Guide

## Important: Native Host Required

**SentinelPass requires a native application to be installed for full functionality.**

### What This Means

The SentinelPass browser extension connects to a local password manager application (daemon) that must be installed on your computer. This is required for:
- Storing and retrieving passwords
- Autofill functionality
- Secure encryption operations

### Installation Steps

#### 1. Download and Install the Desktop Application

Choose your platform:

**Windows:**
```bash
# Download from https://github.com/anvai-labs/sentinelpass/releases
# Run sentinelpass-installer-VERSION-windows.zip
# Extract and run install-user.cmd
```

**macOS:**
```bash
# Download from https://github.com/anvai-labs/sentinelpass/releases
# Extract sentinelpass-installer-VERSION-macos.tar.gz
# Run: ./install-user.command
```

**Linux:**
```bash
# Download from https://github.com/anvai-labs/sentinelpass/releases
# Extract sentinelpass-installer-VERSION-linux.tar.gz
# Run: ./install.sh
```

#### 2. Initialize Your Vault

After installing:
```bash
sentinelpass init
```

#### 3. Start the Daemon

The daemon should start automatically. If not:
```bash
sentinelpass-daemon
```

#### 4. Reload the Extension

After installation, reload the extension:
1. Go to `chrome://extensions/`
2. Find SentinelPass
3. Click the reload button

### Troubleshooting

**Extension shows "Vault Locked" but won't unlock:**
- Make sure the daemon is running
- Check: `ps aux | grep sentinelpass-daemon`

**"Native messaging host not found":**
- Reinstall the desktop application
- Check that native messaging host is properly registered

**Autofill not working:**
- Make sure the daemon is running
- Unlock the vault first
- Use Ctrl+Shift+U (or Cmd+Shift+U on Mac) to trigger autofill

### Without the Desktop Application

The browser extension will show:
- "Vault Locked" status
- Limited functionality
- Prompts to install the desktop application

### Security

- All passwords are encrypted locally using AES-256-GCM
- Your master password never leaves your computer
- The native application runs entirely locally - no cloud services

### Support

For issues or questions:
- GitHub: https://github.com/anvai-labs/sentinelpass/issues
- Documentation: https://github.com/anvai-labs/sentinelpass
