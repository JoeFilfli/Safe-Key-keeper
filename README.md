# 🔐 **CryptoVault**

A lightweight and reliable **password manager built in Go**.  
Keep all your passwords safe in one encrypted vault — completely **offline** and **under your control**.

[![Go Version](https://img.shields.io/badge/Go-1.25.3-blue.svg)](https://golang.org)  
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## ✨ Features

- 🖥️ **Simple GUI & CLI** — Use whichever fits your workflow  
- 🔑 **Add, edit, and manage all your passwords easily**  
- 🔒 **Built-in password generator** for strong, random passwords  
- 🌐 **Works 100% offline** — no servers, no telemetry  
- ⏱️ **Auto-locks after inactivity** for better safety  
- 📋 **Clipboard clears automatically** after a short delay  
- 💻 **Cross-platform** — works on Windows, macOS, and Linux  
- 📱 *Mobile support planned for the future*

---

## 🚀 First-Time Setup

1. Launch the application  
2. Set your **master password**  
3. Log in to your new vault  
4. Add, view, or edit your password entries  
5. Relax — your data is fully encrypted and offline  

⚠️ **Important:** Your master password is the *only* way to access your vault.  
Store it safely (for example, on paper or in a secure note).

---

## 🖼️ Example Screens

### **GUI Example**
```
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
```

### **CLI Example**
```
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
```

---

## ⚙️ Prerequisites

**Requirements**
- Go 1.17+  
- Fyne v2+ (for GUI)  
- Git

**Setup**
```bash
git clone https://github.com/yourusername/CryptoVault.git
cd CryptoVault

go mod download
go build -o password-manager ./cmd/gui
go run ./cmd/gui
```

---

## 🧩 Project Structure
```
CryptoVault/
├── cmd/
│   ├── gui/           # GUI application (Fyne)
│   └── cli/           # CLI version
├── internal/
│   ├── crypto/        # Cryptography functions
│   └── vault/         # Vault management logic
├── go.mod
├── go.sum
├── README.md
└── vault.json         # Created automatically after setup
```

---

## 📚 Documentation

- 📖 [User Manual](USER_MANUAL.md) — How to use CryptoVault  
- 🧠 [Design Document](DESIGN_DOCUMENT.md) — Technical overview and design  

---

**Made with ❤️ in Go**  
Simple. Secure. Offline.
