# ObFUSE

An obfuscating FUSE (Filesystem in Userspace) filesystem that transparently encrypts and obfuscates file contents on disk while presenting them in plaintext to the user.

## Overview

ObFUSE mounts an encrypted view of a directory. Files written through the ObFUSE mount point are automatically encrypted before being stored on the underlying filesystem. When read back through the mount point, they are transparently decrypted.

## Features

- Transparent encryption/decryption of file contents
- FUSE-based — runs entirely in userspace, no kernel modules required
- Passphrase-based key derivation
- Preserves directory structure and file metadata

## Requirements

- Linux with FUSE support (`libfuse3-dev`)
- GCC or Clang
- OpenSSL (`libssl-dev`)
- pkg-config

### Install dependencies (Debian/Ubuntu)

```bash
sudo apt install libfuse3-dev libssl-dev pkg-config build-essential
```

## Building

```bash
make
```

## Usage

```bash
# Mount an obfuscated filesystem
./obfuse -s <source_dir> <mount_point>

# Unmount
fusermount -u <mount_point>
```

## How It Works

1. **Mount**: ObFUSE takes a source directory (where encrypted data is stored) and a mount point (where plaintext is accessible).
2. **Write**: Data written to the mount point is encrypted using AES-256-CTR with a key derived from the user's passphrase, then stored in the source directory.
3. **Read**: Data read from the mount point is fetched from the source directory and decrypted on the fly.
4. **Key Derivation**: The encryption key is derived from the user's passphrase using PBKDF2-HMAC-SHA256.

## Project Structure

```
ObFUSE/
├── src/
│   ├── obfuse.c        # Main FUSE operations and entry point
│   ├── crypto.c         # Encryption/decryption routines
│   ├── crypto.h         # Crypto function declarations
│   └── utils.h          # Utility macros and helpers
├── Makefile
├── LICENSE
└── README.md
```

## License

MIT License. See [LICENSE](LICENSE) for details.
