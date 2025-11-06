# CryptoVault - Design Document + Security Analysis

## Table of Contents
1. Introduction
2. Threat Model & Security Assumptions
3. Cryptographic Mechanisms
4. Design Decisions & Rationale
5. System Flow
6. Security Features

## 1. Introduction

### 1.1 Purpose

This password manager is a **secure, local-first credential storage application** built to protect user passwords using modern cryptographic techniques. It provides both a graphical user interface (GUI) and command-line interface (CLI) for managing encrypted password entries.

### 1.2 Our guarantees

The system provides:
- **Secure Encryption**: All entries are encrypted using AES-256-GCM.
- **Master Password Protection**: Single master password protects all entries.
- **Master Password Security**: Master password is never stored/never used. Only the user knows and has access to it.
- **Integrity Protection**: HMAC-SHA256 prevents tampering.
- **Secure Password Generation**: Cryptographically randomly generated passwords, for users who prefer this option.
- **Memory Protection**: Sensitive data is zeroed after use. Memory compromise is no risk to the users sensitive data.
- **Auto-Lock**: Inactivity timeout protection.
- **Clipboard Clearing**: Cleans buffer of sensitive data.
- **Cross-Platform**: Runs on Windows, macOS, and Linux (+ maybe mobile in the future!!)

### 1.3 Overview

The password manager uses a **2-Tier Key Hierarchy**:
1. **KEK (Key Encryption Key)**: Derived from the master password using Argon2id.
2. **DEK (Data Encryption Key)**: Random 256-bit key, derived from the KEK, that is used to encrypt all entries.

This separation allows users to change their master password without re-encrypting all stored credentials.

```
Master Password → !salt! + [Argon2id] → KEK → [AES-GCM Wrapping] → !Wrapped DEK!
                                                                ↓
                                            [AES-GCM Encryption] ← Unwrapped DEK
                                                                ↓
                                                        !Encrypted Entries!
!x! : x is stored on vault.json
```


## 2. Threat Model & Security Assumptions

### 2.1 Attackers & Capabilities

#### Attacker 1: Offline Attacker with Vault File
Capabilities:
- Has access to the encrypted vault file (`vault.json`)
- Can perform offline brute-force attacks
- Has significant computational resources

Protections:
- Argon2id with high memory cost (64 MB) slows brute-force attacks
- AES-256-GCM provides strong encryption
- Strong master password requirements (12+ characters, complexity)

#### Attacker 2: Malicious Software on User's System
Capabilities:
- Can read memory while vault is unlocked
- Can capture keystrokes (keylogger)
- Can read clipboard contents

Protections:
- Secure memory zeroing after use (`SecureZero`)
- Auto-lock timeout (1-5 minutes configurable)
- Clipboard auto-clear (30 seconds to 3 minutes)
- **Note:** If attacker has code execution on the user's system, no password manager can provide complete protection.

#### Attacker Profile 3: Vault Tampering
Capabilities:
- Can modify the vault file
- Can inject malicious entries
- Can modify metadata (timestamps, salt, etc.)

Protections:
- HMAC-SHA256 integrity checking on all vault operations
- Authenticated encryption (AES-GCM) provides per-entry integrity
- Constant-time HMAC comparison prevents timing attacks

### 2.2 Security Assumptions

#### Trusted Components:
1. **User's OS**: We assume the OS kernel is not compromised
2. **Go Runtime**: We trust the Go standard library and crypto implementations
3. **User's Master Password**: We assume the user chooses a strong master password
4. **Physical Security**: We assume the user's device has basic physical security

#### Out of Scope:
1. **Network Security**: Since this is a local-only application 
2. **Social Engineering**: We cannot protect against user-targeted phishing
3. **Hardware Attacks**: We do not protect against hardware keyloggers or DMA attacks
4. **Backup Security**: Users are responsible for securing vault backups

### 2.3 Attack Scenarios & Mitigations

Brute-force master password | Argon2id (3 iterations, 64MB memory, 4 threads) 
Rainbow table attack | Unique per-vault salt (128 bits) 
Vault file tampering | HMAC-SHA256 integrity check 
Memory dump while unlocked | SecureZero on sensitive keys 
Clipboard sniffing | Auto-clear after 30s-3min 
Timing attack on HMAC | Constant-time comparison 
Entry tampering | AES-GCM authenticated encryption 

## 3. Cryptographic Mechanisms

### 3.1 Argon2id - Key Derivation

**Purpose:** Derive the KEK from the user's master password.

**Algorithm:** Argon2id (hybrid mode combining Argon2i (side-channel resistance) and Argon2d (hardware resistance))

**Parameters:**
```go
const (
    argonTime    = 3         // Iterations (time cost)
    argonMemory  = 64 * 1024 // Memory in KB (64 MB)
    argonThreads = 4         // Parallelism (4 threads)
    argonKeyLen  = 32        // Output length (256 bits)
)
```

**Why Argon2id?**
- **Memory-hard**: Makes brute-force attacks expensive (requires 64 MB RAM per attempt!)
- **Timing attack resistant**: Argon2i component resists side-channel attacks (timing analysis...)
- **GPU-resistant**: Argon2d component resists GPU parallelization (hardware attacks)
- **Modern standard**: Winner of Password Hashing Competition (2015)
- **Flexible**: Parameters can be tuned for future use

**Alternatives Considered:**
**PBKDF2** |  Rejected | Not memory-hard; vulnerable to GPU/ASIC attacks 
**Bcrypt** |  Rejected | Limited to 72-byte passwords; low memory cost 
**Scrypt** | ⚠️ Considered | Good, but Argon2id is more modern and flexible 
**Argon2id** | **CHOSEN** | Winner of PHC; memory-hard; timing-attack resistant 

**HOW:**
Master Password (variable length)
         ↓
    [Argon2id]
         ↓
    Parameters:
    • Salt: 128-bit random
    • Time: 3 iterations
    • Memory: 64 MB
    • Threads: 4
    • Output: 256 bits
         ↓
    KEK (32 bytes fixed)


**Security Properties:**
- **Preimage resistance**: Cannot reverse KEK to get password
- **Collision resistance**: Different passwords → different KEKs
- **Salt uniqueness**: Each vault has unique stored salt (prevents rainbow tables)

### 3.2 AES-256-GCM - Encryption

**Purpose:** Encrypt DEK (wrapped using KEK) + vault entries encryption.

**Algorithm:** AES-256-GCM

**Why?**
- **AE**: Provides confidentiality, integrity and authentication
- **NIST-approved**: Modern standard (FIPS 197 + SP 800-38D)
- **Hardware acceleration**: Up to 15x faster than competitors!!
- **Parallel encryption**: GCM mode allows efficient parallelization (1 pass over the data)
- **Tamper detection**: Built-in auth tag (128 bits)

**Properties:**
• Key size: 256 bits (32 bytes)
• Nonce size: 96 bits (12 bytes) - randomly generated per encryption
• Authentication tag: 128 bits (16 bytes) - automatically appended
• Block size: 128 bits (16 bytes)

**Alternatives Considered:**

**AES-CBC** |  Rejected | No authentication; padding oracle attacks 
**ChaCha20-Poly1305** | ⚠️ Considered | Good, but AES has hardware acceleration 
**AES-GCM** | **CHOSEN** | Authenticated encryption; hardware support 

**Dual-Usage:**

#### Usage 1: Key Wrapping (DEK secure)
KEK (32 bytes) + DEK (32 bytes) → AES-GCM → Wrapped DEK (44 bytes)
                                              └─ Nonce (12) + Ciphertext (32) + Tag

#### Usage 2: Entry Encryption (Data Protection)
DEK (32 bytes) + Plaintext (data) → AES-GCM → Ciphertext (variable length + 28 bytes)
                                                    └─ Nonce (12) + Ciphertext + Tag 

**Additional Properties:**
- **Non-determinism**: Same plaintext encrypts differently each time (random nonce)
- **Authentication**: Detects any tampering (bitflip, truncation, reordering)
- **CCA resistance**: Attacker cannot forge valid ciphertext

### 3.3 KEK/DEK Wrapping Pattern

**Problem:** If we encrypt all entries with KEK (derived from Master Password), changing the master password requires re-encrypting all entries.

**Solution:** 2-tier key hierarchy (Explained in 1.3).

**HOW:**
┌─────────────────────────────────────────────────────────────────┐
│  Master Password (User Input) (ex. IloveDODO123)                │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │   Argon2id + Salt (stored)    
                 │   (Slow derivation)   │
                 └───────────┬───────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  KEK (32 bytes) │ ◄─── Derived (not stored)
                    └────────┬────────┘
                             │
                             │ AES-GCM
                             ▼
                    ┌─────────────────┐
                    │  Wrapped DEK    │ ◄─── (Stored in vault.json)
                    │  (44 bytes)     │
                    └────────┬────────┘
                             │
                             │ AES-GCM Decrypt
                             ▼
                    ┌─────────────────┐
                    │  DEK (32 bytes) │ ◄─── Random (never changes)
                    └────────┬────────┘
                             │ AES-GCM
                ┌────────────┼────────────┐
                │            │            │
                ▼            ▼            ▼
         ┌─────────┐  ┌─────────┐  ┌─────────┐
         │ Entry   │  │ Entry   │  │ Entry   │
         │Encrypted│  │Encrypted│  │Encrypted│
         └─────────┘  └─────────┘  └─────────┘

**Benefits:**
1. **Fast Password Change**: Only re-wrap DEK (single), not all entries
2. **Key Separation**: KEK never directly encrypts user data
3. **Forward Secrecy**: If KEK is compromised after password change, old wrapped DEK is useless

**Key Lifetime:**
- **KEK**: Ephemeral - derived when vault unlocks, zeroed when vault locks
- **DEK**: Persistent - generated once, stays in memory while vault is unlocked
- **Master Password**: Only in memory during authentication, immediately zeroed

### 3.4 HMAC-SHA256 - Integrity Protection

**Purpose:** Detect any unauthorized modifications to the vault structure.

**Algorithm:** HMAC-SHA-256

**What is Protected:**
```json
{
  "salt": "base64-encoded-salt",
  "wrappedDEK": "base64-encoded-wrapped-dek",
  "entries": [
    {
      "service": "encrypted-service",
      "username": "encrypted-username",
      "password": "encrypted-password",
      "notes": "encrypted-notes",
      "created_at": 1699920000,
      "modified_at": 1699920000
    }
  ],
  "hmac": "base64-encoded-hmac-sha256"
}
```

**HMAC Computation:**
```
HMAC = SHA256(KEK, JSON(salt + wrappedDEK + entries))
```

**Verification Process:**
1. Load vault file
2. Derive KEK from master password
3. Extract stored HMAC from vault
4. Compute expected HMAC from vault data (excluding HMAC field)
5. Constant-time comparison: stored HMAC == computed HMAC
6. If mismatch: REJECT (vault tampered)
7. If match: PROCEED (vault authenticated)


**What it Protects Against:**
- **Metadata tampering**: Salt or wrappedDEK modification
- **Entry reordering**: Changing order of entries
- **Entry injection**: Adding malicious entries
- **Timestamp manipulation**: Modifying created_at/modified_at
- **Partial deletion**: Removing entries

**Why Use KEK as HMAC Key?**
- **Key Reuse**: We already have KEK in memory (no additional key management)
- **Authentication Binding**: Only valid user (who knows the master password) can generate valid HMACs
- **No Key Derivation**: No additional KDF needed (KEK is already high-entropy)

**Security Properties:**
- **Collision resistance**: Cannot find two vault states with same HMAC
- **Preimage resistance**: Cannot craft vault data to match target HMAC
- **Timing attack resistance**: Constant-time comparison prevents timing side-channels

### 3.5 Cryptographic Diagrams

#### Full Flow
```
┌──────────────────┐
│ Master Password  │
└────────┬─────────┘
         │
         ▼
┌─────────────────────────────┐
│  Generate Random Salt       │
│  (128 bits, once per vault) │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Argon2id Key Derivation    │
│  • Time: 3                  │
│  • Memory: 64 MB            │
│  • Threads: 4               │
│  • Output: 256 bits         │
└────────┬────────────────────┘
         │
         ▼
    ┌────────┐
    │  KEK   │ (Ephemeral - only in memory)
    └────┬───┘
         │
         ├──────────────────────────────────────┐
         │                                      │
         ▼                                      ▼
┌──────────────────┐                  ┌────────────────────┐
│ Wrap DEK         │                  │ Compute HMAC       │
│ (AES-GCM)        │                  │ (SHA-256)          │
└────────┬─────────┘                  └────────┬───────────┘
         │                                      │
         ▼                                      ▼
┌──────────────────┐                  ┌────────────────────┐
│  Wrapped DEK     │ ──────────┐      │  HMAC Tag          │
│  (stored)        │           │      │  (stored)          │
└──────────────────┘           │      └────────────────────┘
                               │
                               │      ┌────────────────────┐
                               └─────►│  Save vault.json   │
                               ┌─────►│  (salt, wrapped    │
                               │      │   DEK, entries,    │
                               │      │   HMAC)            │
                               │      └────────────────────┘
                               │
┌──────────────────┐           │
│ Unwrap DEK       │           │
│ (AES-GCM)        │           │
└────────┬─────────┘           │
         │                     │
         ▼                     │
    ┌────────┐                 │
    │  DEK   │ (In memory while vault unlocked)
    └────┬───┘                 │
         │                     │
         ▼                     │
┌──────────────────┐           │
│ Encrypt Entry    │           │
│ • Service        │           │
│ • Username       │           │
│ • Password       │──────────┘
│ • Notes          │
│ (AES-GCM each)   │
└──────────────────┘
```

#### Vault Unlock Sequence
```
User enters master password
         │
         ▼
┌─────────────────────────────┐
│  Load vault.json            │
│  • Extract salt             │
│  • Extract wrapped DEK      │
│  • Extract HMAC             │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Derive KEK                 │
│  Argon2id(password, salt)   │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Verify HMAC                │
│  Compare stored vs computed │
└────────┬────────────────────┘
         │
         ├─ Mismatch ──► REJECT (tampered vault)
         │
         ▼ Match
┌─────────────────────────────┐
│  Unwrap DEK                 │
│  AES-GCM decrypt with KEK   │
└────────┬────────────────────┘
         │
         ├─ Fail ──► REJECT (wrong password)
         │
         ▼ Success
┌─────────────────────────────┐
│  Vault Unlocked             │
│  • KEK in memory (for HMAC) │
│  • DEK in memory (for data) │
│  • Start auto-lock timer    │
└─────────────────────────────┘
```

---

## 4. Design Decisions & Rationale

### 4.1 Technology Choices

#### Why Go (Dr. Nadim said so)?

**Advantages:**
1. **Strong Standard Library**: `crypto/*` packages are well-reviewed and regulation-compliant
2. **Memory Safety**: No buffer overflows or use-after-free vulnerabilities
3. **Cross-Platform**: Single codebase compiles to Windows, macOS, Linux
4. **Static Binaries**: No dependency hell (single `.exe` or binary)
5. **Performance**: Fast execution, efficient memory usage
6. **Secure Defaults**: Crypto APIs are hard to misuse

**Trade-offs:**
- **Garbage Collection**: Can leave sensitive data in memory longer
  - *Mitigation*: `SecureZero` and `runtime.KeepAlive` to force immediate zeroing
- **No Secure Enclaves**: Cannot use OS-level key storage (e.g., Keychain, TPM)
  - *Decision*: Simplicity and portability over platform-specific features

#### Why use Fyne for GUI?

**Advantages:**
1. **Pure Go**: No Go dependencies (easier cross-compilation)
2. **Modern UI**: Material Design-inspired, native look
3. **Active Development**: Regular updates and bug fixes
4. **Lightweight**: Small binary size for GUI app
5. **Easy Theming**: Custom theme support for dark/light mode

**Alternatives Considered:**
- **Electron**: Rejected (huge binary size, security concerns, Chromium overhead)
- **Qt/GTK Bindings**: Rejected (CGo complexity, cross-compilation issues)
- **Web UI**: Rejected (no need for network features)


### 4.2 Key Design Patterns

#### Pattern: Secure Memory Handling

**Problem:** Go's garbage collector can leave copies of sensitive data in memory.

**Solution:** Explicit zeroing with compiler optimization prevention.

**Implementation:**
```go
// SecureZero overwrites a byte slice with zeros.
func SecureZero(b []byte) {
    for i := range b {
        b[i] = 0
    }
    runtime.KeepAlive(b) // Prevent compiler optimization
}

// Usage: Always defer zeroing
func DeriveKey(password string) {
    passwordBytes := []byte(password)
    defer SecureZero(passwordBytes) // Zero on function exit
    
    // Use passwordBytes...
}
```

**Defense-in-Depth:**
- Cannot prevent all memory copies (GC, swap, hibernation)
- Reduces window of opportunity for memory dumps
- Best practice for credential handling

#### Pattern: HMAC Integrity Checking
**Problem:** AES-GCM protects individual entries, but not vault structure.

**Attack Scenario:**
1. Attacker copies vault file
2. User adds new entry
3. Attacker replaces vault with old copy (rollback attack)
4. AES-GCM doesn't detect this (all entries are still valid)

**Solution:** HMAC over entire vault structure.

**Protected Elements:**
- Salt (prevents salt substitution)
- Wrapped DEK (prevents key replacement)
- All entries (prevents entry reordering/injection)
- Timestamps (prevents rollback attacks)

**Verification:**
```go
// Before trusting any vault data
vault, err := LoadVault(filename)
hmacValid := vault.verifyHMAC(kek)
if !hmacValid {
    return errors.New("SECURITY ALERT: Vault tampered!")
}
```

### 4.3 Security Trade-offs

#### Trade-off 1: Argon2id Parameters

**Higher Settings:**
- Stronger resistance to brute-force
- Slower vault unlock (poor UX)
- Higher battery drain on mobile

**Current Settings (64 MB, 3 iterations):**
- Unlock time for legitimate user: ~100-300ms (acceptable)
- Brute-force cost: ~$10,000 to crack weak password (8 characters, lowercase only)
- **Decision:** Balanced for user use; can increase in future versions

#### Trade-off 2: Auto-Lock Timeout

**Shorter Timeout (1 minute):**
- Less time for memory dump attacks
-  Frequent re-authentication (annoying)

**Longer Timeout (30 minutes):**
- Better user experience
-  Longer exposure if device stolen

**Current Default (1 minute, configurable 1-5 min):**
- **Decision:** Short default for security-conscious users, but configurable for convenience


## 5. System Flow

### 5.1 Sequence Diagrams

#### 5.1.1 First-Time Setup

```
User              GUI/CLI           Vault Layer         Crypto Layer
 │                  │                    │                    │
 │─Enter Password──►│                    │                    │
 │                  │                    │                    │
 │                  │─Check Strength────►│                    │
 │                  │◄─Score 0.85────────│                    │
 │                  │                    │                    │
 │                  │                    │─GenerateBytes(16)─►│
 │                  │                    │◄─Salt──────────────│
 │                  │                    │                    │
 │                  │                    │─DeriveKEK(pw,salt)►│
 │                  │                    │◄─KEK───────────────│
 │                  │                    │                    │
 │                  │                    │─GenerateBytes(32)─►│
 │                  │                    │◄─DEK───────────────│
 │                  │                    │                    │
 │                  │                    │─WrapKey(KEK,DEK)──►│
 │                  │                    │◄─Wrapped DEK───────│
 │                  │                    │                    │
 │                  │                    │─ComputeHMAC(KEK)──►│
 │                  │                    │◄─HMAC Tag──────────│
 │                  │                    │                    │
 │                  │◄─Save vault.json──┤                    │
 │                  │                    │                    │
 │◄─Vault Created───│                    │                    │
 │                  │                    │                    │
```

#### 5.1.2 Vault Unlock

```
User              GUI/CLI           Vault Layer         Crypto Layer         File System
 │                  │                    │                    │                    │
 │─Enter Password──►│                    │                    │                    │
 │                  │                    │                    │                    │
 │                  │─Load Vault────────►│────Read File──────►│                    │
 │                  │                    │◄───vault.json──────┤                    │
 │                  │                    │                    │                    │
 │                  │                    │─DeriveKEK(pw,salt)►│                    │
 │                  │                    │◄─KEK───────────────│                    │
 │                  │                    │                    │                    │
 │                  │                    │─VerifyHMAC(KEK)───►│                    │
 │                  │                    │◄─Valid/Invalid─────│                    │
 │                  │                    │                    │                    │
 │                  │                    │ (If Invalid: STOP - Tampered!)          │
 │                  │                    │                    │                    │
 │                  │                    │─UnwrapKey(KEK)────►│                    │
 │                  │                    │◄─DEK (or Error)────│                    │
 │                  │                    │                    │                    │
 │                  │◄─Vault Unlocked────│                    │                    │
 │                  │  (KEK+DEK in mem)  │                    │                    │
 │                  │                    │                    │                    │
 │◄─Show Entries────│                    │                    │                    │
 │                  │                    │                    │                    │
```

#### 5.1.3 Add Entry

```
User              GUI/CLI           Vault Layer         Crypto Layer
 │                  │                    │                    │
 │─Enter Details───►│                    │                    │
 │  (srv,user,pass) │                    │                    │
 │                  │                    │                    │
 │                  │─AddEntry(details)─►│                    │
 │                  │                    │                    │
 │                  │                    │─Encrypt(service)──►│
 │                  │                    │◄─Ciphertext────────│
 │                  │                    │                    │
 │                  │                    │─Encrypt(username)─►│
 │                  │                    │◄─Ciphertext────────│
 │                  │                    │                    │
 │                  │                    │─Encrypt(password)─►│
 │                  │                    │◄─Ciphertext────────│
 │                  │                    │                    │
 │                  │                    │─Encrypt(notes)────►│
 │                  │                    │◄─Ciphertext────────│
 │                  │                    │                    │
 │                  │                    │─Add to entries[]    │
 │                  │                    │                    │
 │                  │                    │─ComputeHMAC(KEK)──►│
 │                  │                    │◄─New HMAC Tag──────│
 │                  │                    │                    │
 │                  │◄─Save vault.json───┤                    │
 │                  │                    │                    │
 │◄─Entry Added─────│                    │                    │
 │                  │                    │                    │
```

#### 5.4.4 Change Master Password

```
User              GUI/CLI           Vault Layer         Crypto Layer
 │                  │                    │                    │
 │─Old Password────►│                    │                    │
 │─New Password────►│                    │                    │
 │                  │                    │                    │
 │                  │─Verify Old────────►│─DeriveKEK(old)────►│
 │                  │                    │─UnwrapDEK─────────►│
 │                  │                    │◄─DEK (verified)────│
 │                  │                    │                    │
 │                  │                    │─GenerateBytes(16)─►│
 │                  │                    │◄─New Salt──────────│
 │                  │                    │                    │
 │                  │                    │─DeriveKEK(new)────►│
 │                  │                    │◄─New KEK───────────│
 │                  │                    │                    │
 │                  │                    │─WrapKey(newKEK,DEK)►
 │                  │                    │◄─New Wrapped DEK───│
 │                  │                    │                    │
 │                  │                    │─ComputeHMAC(newKEK)►
 │                  │                    │◄─New HMAC Tag──────│
 │                  │                    │                    │
 │                  │◄─Save vault.json───┤                    │
 │                  │  (newSalt, newWDEK)│                    │
 │                  │                    │                    │
 │◄─Password Changed│                    │                    │
 │                  │                    │                    │
 │  Note: DEK unchanged → all entries still encrypted!        │
```

---

## 6. Implementation Details



### 6.2 Key Data Structures

#### Vault Structure
```go
// Vault is the encrypted vault file.
type Vault struct {
    Salt       string  `json:"salt"`         // Base64-encoded 128-bit salt
    WrappedDEK string  `json:"wrappedDEK"`   // Base64-encoded AES-GCM wrapped DEK
    Entries    []Entry `json:"entries"`      // Array of encrypted entries
    HMAC       string  `json:"hmac"`         // Base64-encoded HMAC-SHA256
}
```

#### Entry Structure
```go
// Entry is a single vault entry.
// All fields are encrypted (base64-encoded ciphertext)
type Entry struct {
    Service    string `json:"service"`      // Encrypted service name
    Username   string `json:"username"`     // Encrypted username
    Password   string `json:"password"`     // Encrypted password
    Notes      string `json:"notes"`        // Encrypted notes
    CreatedAt  int64  `json:"created_at"`   // Unix timestamp
    ModifiedAt int64  `json:"modified_at"`  // Unix timestamp
}
```

---

## 6. Security Features

### 6.1 Defense-in-Depth Layers

#### Layer 1: **Cryptographic Protection**
- Argon2id key derivation (memory-hard, GPU-resistant)
- AES-256-GCM encryption (authenticated encryption)
- HMAC-SHA256 integrity (tamper detection)
- Random nonces (no deterministic encryption)

#### Layer 2: **Key Management**
- KEK/DEK separation (fast password changes)
- Secure key wrapping (never store plaintext keys)
- Ephemeral KEK (only in memory during session)
- Memory zeroing (SecureZero after use)

#### Layer 3: **Runtime Protection**
- Auto-lock timeout (1-5 minutes configurable)
- Clipboard auto-clear (30 seconds to 3 minutes)
- Password strength scoring (warn weak passwords)
- No logging of sensitive data

#### Layer 4: **File System Protection**
- Restrictive file permissions (0600 - owner read/write only)
- HMAC prevents tampering
- AES-GCM prevents corruption

### 6.2 Security Checklist

- Password hashing | Argon2id (3, 64MB, 4)
- Data encryption | AES-256-GCM
- Integrity protection | HMAC-SHA256 
- Random number generation | crypto/rand (OS-based) 
- Secure memory handling | SecureZero + runtime.KeepAlive 
- Master password requirements | 12+ chars, complexity check 
- Auto-lock | 1-5 min configurable 
- Clipboard auto-clear | 30s-3min configurable 
- Constant-time comparison | HMAC verification 
- Key wrapping | AES-GCM with KEK 
- Unique salts | 128-bit random per vault 
- Unique nonces | 96-bit random per encryption 
- Password strength meter | Scoring algorithm 
- No plaintext storage | All entries encrypted 
- No network communication | Local-only 

### 6.3 Known Limitations

#### 1. **Memory Dump Attacks**
- **Risk**: If attacker dumps RAM while vault is unlocked, KEK/DEK visible
- **Mitigation**: SecureZero, auto-lock timeout
- **Limitation**: Cannot prevent OS-level memory access

#### 2. **Keyloggers**
- **Risk**: Malware can capture master password as user types
- **Mitigation**: None (application-level)
- **Recommendation**: Use OS-level protections (antivirus, secure boot)

#### 3. **Backup Security**
- **Risk**: User manually copies vault.json to insecure locations
- **Mitigation**: None (user responsibility)
- **Recommendation**: Encrypt backup storage (BitLocker, FileVault)

#### 4. **Physical Access**
- **Risk**: Attacker with physical access can install keylogger, rootkit
- **Mitigation**: None ;(
- **Recommendation**: Enable FDE, lock device when unattended

#### 5. **Clipboard Sniffing**
- **Risk**: Malware reads clipboard before auto-clear
- **Mitigation**: Configurable short timeout (30s)
- **Limitation**: Cannot prevent privileged malware

### 6.4 Potential Future Improvements

**Potential Enhancements:**
1. **Biometric Support**: Fingerprint/face unlock (platform-specific)
2. **Hardware Security**: Use TPM/Secure Enclave for key storage
3. **Password History**: Track compromised passwords (Have I Been Pwned API)
4. **Two-Factor Unlock**: TOTP or YubiKey as second factor
5. **Encrypted Cloud Sync**: Optional E2EE sync (user-controlled)
6. **Audit Log**: Track all vault operations (read/write)

**Trade-offs:**
- Each feature adds complexity and attack surface
- Current design prioritizes simplicity and security over features

**Version:** 1.0  
**Last Updated:** November 4, 2025 (Submission Day)  
**Author:** Crypto-Project Team S 