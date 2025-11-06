# CryptoVault - User Manual

## Welcome

CryptoVault helps you store and manage all your passwords securely in one place.  
You only need to remember one master password to unlock your vault.

---

## Installation + Running

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

## First-Time Setup

1. Run the app  
2. Set up your master password 
3. Login to CryptoVault 
4. Start adding/viewing/editing passwords for your favorite services  
5. Enjoy the absolute security of your passwords (even we can't see em!)

⚠️ *Your master password is required to access the vault. Don’t forget it!*
  *We reccomend that you store it out-of-band (i.e. on paper, on your phone...)*

## Using the UI

- **Add Entry:** Click “Add” fill in service, username, and password (+ optional notes).
- **View Entry:** Select an entry, then click “View” to view that entry's details.
- **Edit Entry:** Select an entry, then click “Edit”, to edit that entry's details (then Save!).
- **Delete Entry:** Select an entry, “Delete” to delete that entry.
- **System Settings** Set your preffered system settings, fully customizing your secure experience.
- **Change Master Password:** Click “Change Password” to Change master Password.
- **Search:** Type in the search box to filter entries.
- **Logout:** Click “Logout” when done.
- **Exit:** Click "Exit" to quit app.

## Common Tasks

### Add a Password
- Enter service name, username, password and (optional) notes.
- (Optional) Use “Generate” to create a strong password.
- Click “Save.”

### View or Copy a Password
- Open the entry → “View.”
- Click “Copy Password” to copy it temporarily.

### Change Master Password
- “Change PW” → Enter old and new passwords → Save.

### Delete an Entry
- Select the entry → “Delete.”


## Settings

You can adjust:
- Auto-lock timeout (1–5 minutes)
- Clipboard clear time (30s–3min)
- Default password length (12–32 chars)

## Best Practices

- Use a long, unique master password, following our password strength assessor.  
- Back up your `vault.json` file securely.  
- Never share your Master Password
- Keep your app (future versions) and OS updated.
- Never edit `vault.json` manually.

---

## Troubleshooting

- IF Forgot master password | THEN Data can’t be recovered! Create a new vault.
- IF Vault won’t open | THEN Check if `vault.json` is in the same folder.
- IF Clipboard not clearing/Auto-Logout not working | THEN Check your settings or restart app.
- IF App won’t start | THEN Rebuild using Go or re-download it entirely.


## FAQ

**Q:** Where are my passwords stored?  
**A:** In `vault.json`, locally on your device.

**Q:** Can I use it on another computer?  
**A:** Yes — copy your `vault.json` and use the same master password.

**Q:** Can I back up my vault?  
**A:** Yes — copy `vault.json` securely to a USB or encrypted drive.

Our first version.
*Version 1.0 — November 2025*
Wait for our future updates!