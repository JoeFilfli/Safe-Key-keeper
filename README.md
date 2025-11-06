# 🔐 CryptoVault 🔐

A simple and reliable password manager built in **Go**.  
It helps you safely store, organize, and retrieve your passwords in one encrypted vault — all offline.

[![Go Version](https://img.shields.io/badge/Go-1.25.3-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Our Features

- **Easy to Use GUI and CLI**
- **Create and manage all your passwords**
- **Password generator for cryptographically strong random passwords**
- **Works fully offline (local)**
- **Auto-lock after inactivity**
- **Clipboard clears automatically**
- **Cross-platform support (Windows, macOS, Linux, mobile (in the future maybe))**


## First-Time Setup

1. Run the app  
2. Set up your master password 
3. Login to CryptoVault 
4. Start adding/viewing/editing passwords for your favorite services  
5. Enjoy the absolute security of your passwords (even we can't see em!)

⚠️ *Your master password is required to access the vault. Don’t forget it!*
  *We reccomend that you store it out-of-band (i.e. on paper, on your phone...)*


## Example Screens

### GUI View
┌────────────────────────────────────────────────────────┐
│  [Search: Type to filter entries...]                   │
│  ┌─────┬──────┬────────┬──────────┬──────────┬────────┐│
│  │ Add │ View │ Delete │ Settings │Change PW │ Logout ││
│  └─────┴──────┴────────┴──────────┴──────────┴────────┘│
│                                                        │
│  📌 Your Password Entries:                             │
│  • Amazon                                              │
│  • Facebook                                            │
│  • Gmail                                               │
│  • GitHub                                              │
│  • Netflix                                             │
│                                                        │
│  ✅ Status: Vault unlocked. Auto-lock in 1 minute.     │
└────────────────────────────────────────────────────────┘
**We even left our CLI version (used mostly for testing and whatnot)**

### CLI View

========================================
           MAIN MENU
========================================
1. List all entries
2. Add new entry
3. View entry
4. Edit entry
5. Delete entry
6. Change master password
7. Exit
========================================
Choose an option: _

## Prerequisites

**Requirements**
- Go Version 1.17 or newer
- Fyne Version 2 or newer
- Git

**Steps**
```bash
git clone https://github.com/yourusername/Crypto-Project.git
cd Crypto-Project

go mod download
go build -o password-manager ./cmd/gui
go run ./cmd/gui
```

## Project Structure
```
Crypto-Project/
├── cmd/
│   ├── gui/           # GUI version
│   └── cli/           # CLI version
├── internal/
│   ├── crypto/        # Cryptography functions
│   └── vault/         # Vault management
├── go.mod
├── go.sum
├── README.md
└── vault.json         # Created automatically once your Master Password is set
```

##  Documentation

- [User Manual](USER_MANUAL.md) — How to use the app  
- [Design Document](DESIGN_DOCUMENT.md) — System design overview  

**Made with LOVE in Go**