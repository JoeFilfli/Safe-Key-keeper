package main

import (
	"Crypto-Project/internal/crypto"
	"Crypto-Project/internal/vault"
	"encoding/base64"
	"fmt"
	"image/color"
	"sort"
	"strings"
	"time"
	"unicode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Global settings variables (can be changed in the Settings window)
var (
	vaultFile        = "vault.json"
	clipboardTimeout = 30 * time.Second
	autoLockTimeout  = 1 * time.Minute
	passwordLength   = 16 // Default generated password length
)

var (
	currentApp         fyne.App
	vaultTimer         *time.Timer
	currentVaultWindow fyne.Window
	openVaultWindows   []fyne.Window
	loginMessage       string
	loggingOut         bool = false
)

// TappableText is a custom widget using canvas.Text for size control and tap behavior.
type TappableText struct {
	widget.BaseWidget
	text     *canvas.Text
	OnTapped func() // Function to execute when the text is tapped
}

// Extend the base widget to create a new custom TappableText
func NewTappableText(text string, tapped func(), size float32) *TappableText {
	t := &TappableText{
		text:     canvas.NewText(text, theme.ForegroundColor()),
		OnTapped: tapped,
	}
	t.text.TextSize = size // Set the size here!
	t.text.Alignment = fyne.TextAlignLeading
	t.ExtendBaseWidget(t)
	return t
}

func (t *TappableText) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(t.text)
}

func (t *TappableText) MinSize() fyne.Size {
	return t.text.MinSize()
}

func (t *TappableText) SetText(text string) {
	t.text.Text = text
	t.text.Refresh()
	t.Refresh()
}

func (t *TappableText) SetBold(b bool) {
	if b {
		t.text.TextStyle.Bold = true
	} else {
		t.text.TextStyle.Bold = false
	}
	t.text.Refresh()
}

// Tapped implements the fyne.Tappable interface
func (t *TappableText) Tapped(*fyne.PointEvent) {
	if t.OnTapped != nil {
		t.OnTapped()
	}
}

// TappedSecondary implements the fyne.Tappable interface
func (t *TappableText) TappedSecondary(*fyne.PointEvent) {}

// ------------------- CUSTOM THEME FIX (FYNE ERROR) -------------------

// MyTheme defines a custom Fyne theme to fix the input background color.
type MyTheme struct {
	fyne.Theme
}

func (m *MyTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// CRITICAL FIX: Intercept the color requested for the Entry field background (fixes grey box).
	if name == theme.ColorNameInputBackground {
		return theme.DefaultTheme().Color(theme.ColorNameBackground, variant)
	}
	return theme.DefaultTheme().Color(name, variant)
}

func (m *MyTheme) Font(name fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(name)
}

func (m *MyTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (m *MyTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

func NewMyTheme() fyne.Theme {
	return &MyTheme{theme.DefaultTheme()}
}

// ------------------- MAIN -------------------

func main() {
	a := app.New()
	currentApp = a
	a.Settings().SetTheme(NewMyTheme())

	// Start with the intro window
	showIntroWindow(a)
	a.Run()
}

// ------------------- INTRO WINDOW -------------------

func showIntroWindow(a fyne.App) {
	w := a.NewWindow("Loading...")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(400, 300))
	w.CenterOnScreen() // <-- Centers the window
	w.SetPadded(false) // No padding for a centered feel

	welcome := widget.NewLabel("Welcome to CryptoVault")
	welcome.TextStyle.Bold = true
	welcome.TextStyle.TabWidth = 50 // Ensures it appears centered better
	welcome.Alignment = fyne.TextAlignCenter

	// Percentage progress bar
	progress := widget.NewProgressBar()
	progress.SetValue(0.0)

	content := container.NewCenter(container.NewVBox(
		welcome,
		widget.NewSeparator(),
		widget.NewLabel("Loading CryptoVault..."),
		progress,
	))

	w.SetContent(content)
	w.Show()

	// Simulate the loading time and update the progress bar
	go func() {
		// Simulating a 1.5 second loading period
		totalSteps := 15
		for i := 1; i <= totalSteps; i++ {
			time.Sleep(100 * time.Millisecond) // 100ms per step
			fyne.Do(func() {
				value := float64(i) / float64(totalSteps)
				progress.SetValue(value)
			})
		}

		// When loading is complete, close the intro window and show the next
		fyne.Do(func() {
			w.Close()
			if vault.Exists(vaultFile) {
				showLoginWindow(a)
			} else {
				showSetupMasterPasswordWindow(a)
			}
		})
	}()
}

// ------------------- UTILS -------------------

func resetLockTimer() {
	if vaultTimer != nil {
		vaultTimer.Stop()
	}
	vaultTimer = time.AfterFunc(autoLockTimeout, func() {
		fyne.Do(func() {
			for _, w := range openVaultWindows {
				w.Close()
			}
			openVaultWindows = nil
			currentVaultWindow = nil
			loginMessage = "You were logged out due to inactivity."
			showLoginWindow(currentApp)
		})
	})
}

// decryptEntry decrypts a vault entry field (service, username, password, or notes).
// Returns the decrypted plaintext string and an error if decryption fails.
// Errors can occur from: base64 decoding failure, GCM authentication failure (tampering),
// or corrupted ciphertext. All errors should be handled by the caller.
func decryptEntry(dek []byte, entry string) (string, error) {
	// Decode from Base64 - can fail if entry is corrupted
	enc, err := base64.StdEncoding.DecodeString(entry)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}

	// Decrypt using DEK - can fail if:
	// - Wrong DEK (shouldn't happen after successful vault unlock)
	// - Tampered ciphertext (GCM authentication fails)
	// - Corrupted data
	dec, err := crypto.DecryptEntry(dek, enc)
	if err != nil {
		return "", fmt.Errorf("decryption failed (possible tampering): %w", err)
	}

	return string(dec), nil
}

func copyToClipboard(clipboard fyne.Clipboard, text string, status *widget.Label) {
	clipboard.SetContent(text)
	status.SetText(fmt.Sprintf("Password copied! Clearing in %s.", clipboardTimeout))
	status.Refresh()

	time.AfterFunc(clipboardTimeout, func() {
		fyne.Do(func() {
			if clipboard.Content() == text {
				clipboard.SetContent("")
				status.SetText("Clipboard cleared.")
			} else {
				status.SetText("Clipboard changed.")
			}
			status.Refresh()
		})
	})
}

func removeWindowFromSlice(win fyne.Window) {
	for i, w := range openVaultWindows {
		if w == win {
			openVaultWindows = append(openVaultWindows[:i], openVaultWindows[i+1:]...)
			break
		}
	}
}

func initVaultSetup(password string) error {
	vaultSalt, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return err
	}
	vaultDEK, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return err
	}
	kek := crypto.DeriveKEK([]byte(password), vaultSalt)
	wrappedDEK, err := crypto.WrapKey(kek, vaultDEK)
	if err != nil {
		return err
	}
	return vault.SaveVault(vaultFile, []vault.Entry{}, vaultSalt, wrappedDEK)
}

func scorePassword(password string) (string, float64) {
	length := len(password)
	score := 0.0

	if length >= 12 {
		score += 1.0
	} else if length >= 8 {
		score += 0.5
	}

	hasUpper, hasLower, hasDigit, hasSymbol := false, false, false, false
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if hasUpper {
		score += 0.5
	}
	if hasLower {
		score += 0.5
	}
	if hasDigit {
		score += 1.0
	}
	if hasSymbol {
		score += 1.5
	}

	normalized := score / 4.5
	if normalized > 1.0 {
		normalized = 1.0
	}

	switch {
	case normalized >= 0.8 && length >= 12:
		return "Strong 💪", normalized
	case normalized >= 0.5:
		return "Decent 👍", normalized
	default:
		return "Very Weak 😞", normalized
	}
}

// ------------------- LOGIN WINDOW -------------------

func showLoginWindow(a fyne.App) {
	w := a.NewWindow("Crypto Vault Login")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 500))
	w.CenterOnScreen() // <-- Centers the window

	w.SetOnClosed(func() { a.Quit() })

	title := widget.NewLabel("Login to Your Vault")
	title.TextStyle.Bold = true

	passEntry := widget.NewEntry()
	passEntry.Password = true
	passEntry.SetPlaceHolder("Enter Your Master Password")

	msg := widget.NewLabel(loginMessage)
	msg.Wrapping = fyne.TextWrapWord
	loginMessage = ""

	loginBtn := widget.NewButton("Unlock Vault", func() {
		resetLockTimer()
		passwordStr := strings.TrimSpace(passEntry.Text)
		password := []byte(passwordStr)
		defer crypto.SecureZero(password) // Zero password after use

		if len(password) == 0 {
			msg.SetText("Password required")
			return
		}

		if !vault.Exists(vaultFile) {
			_, score := scorePassword(passwordStr)
			if score < 0.5 {
				msg.SetText("Password too weak.")
				return
			}

			// Generate salt with error handling
			salt, err := crypto.GenerateRandomBytes(16)
			if err != nil {
				msg.SetText("❌ Failed to generate salt: " + err.Error())
				return
			}
			defer crypto.SecureZero(salt) // Zero salt after use

			kek := crypto.DeriveKEK(password, salt)
			// Note: KEK is passed to showVaultWindow, so don't zero it here

			// Generate DEK with error handling
			dek, err := crypto.GenerateRandomBytes(32)
			if err != nil {
				msg.SetText("❌ Failed to generate encryption key: " + err.Error())
				crypto.SecureZero(kek) // Zero KEK if we fail
				return
			}
			// Note: DEK is passed to showVaultWindow, so don't zero it here

			// Wrap DEK with error handling
			wrapped, err := crypto.WrapKey(kek, dek)
			if err != nil {
				msg.SetText("❌ Failed to wrap encryption key: " + err.Error())
				crypto.SecureZero(kek) // Zero KEK if we fail
				crypto.SecureZero(dek) // Zero DEK if we fail
				return
			}

			v := &vault.Vault{
				Salt:       base64.StdEncoding.EncodeToString(salt),
				WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
				Entries:    []vault.Entry{},
			}

			// Save with HMAC protection
			err = v.SaveWithHMAC(vaultFile, kek)
			if err != nil {
				msg.SetText("❌ Failed to save vault: " + err.Error())
				crypto.SecureZero(kek) // Zero KEK if we fail
				crypto.SecureZero(dek) // Zero DEK if we fail
				return
			}

			w.Hide()
			showVaultWindow(a, v, dek, kek)
			// DEK and KEK are now owned by vault window, don't zero them
			return
		}

		// Load existing vault first to get salt
		vTemp, err := vault.Load(vaultFile)
		if err != nil {
			msg.SetText("Failed loading vault.")
			return
		}

		salt, err := base64.StdEncoding.DecodeString(vTemp.Salt)
		if err != nil {
			msg.SetText("Failed loading vault - invalid salt.")
			return
		}
		defer crypto.SecureZero(salt) // Zero salt after use

		kek := crypto.DeriveKEK(password, salt)
		// Note: KEK is passed to showVaultWindow, so don't zero it here

		// First, try to unwrap DEK to verify password is correct
		wrappedDEK, _ := base64.StdEncoding.DecodeString(vTemp.WrappedDEK)
		dek, err := crypto.UnwrapKey(kek, wrappedDEK)
		if err != nil {
			// Password is wrong
			msg.SetText("Wrong password.")
			crypto.SecureZero(kek)
			return
		}
		// Note: DEK and KEK are passed to showVaultWindow, so don't zero them

		// Password is correct! Now verify HMAC integrity
		v, err := vault.LoadAndVerifyHMAC(vaultFile, kek)
		if err != nil {
			// If HMAC verification fails, try loading without HMAC (backwards compatibility)
			if err.Error() == "HMAC field is missing (vault may be from older version)" {
				v, err = vault.Load(vaultFile)
				if err != nil {
					msg.SetText("Failed loading vault.")
					crypto.SecureZero(kek)
					crypto.SecureZero(dek)
					return
				}
				msg.SetText("⚠️ Vault loaded without HMAC verification (older format). It will be upgraded on next save.")
			} else {
				// HMAC mismatch - vault was tampered with!
				msg.SetText("❌ SECURITY ALERT: " + err.Error())
				crypto.SecureZero(kek)
				crypto.SecureZero(dek)
				return
			}
		}

		msg.SetText("Vault unlocked ✅")
		w.Hide()
		showVaultWindow(a, v, dek, kek)
		// DEK and KEK are now owned by vault window, don't zero them
	})

	form := container.NewVBox(title, passEntry, loginBtn, msg)
	w.SetContent(container.NewPadded(form))
	w.Show()
}

func showSetupMasterPasswordWindow(a fyne.App) {
	w := a.NewWindow("Set Your Master Password")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 500))
	w.CenterOnScreen() // <-- Centers the window

	title := widget.NewLabel("Create Master Password")
	title.TextStyle.Bold = true

	pw := widget.NewEntry()
	pw.Password = true
	pw.SetPlaceHolder("Enter Your Master Password")

	confirm := widget.NewEntry()
	confirm.Password = true
	confirm.SetPlaceHolder("Confirm Master Password")

	msg := widget.NewLabel("")
	reqLabel := widget.NewLabel("Password requirements:\n• At least 8 characters\n• Uppercase and lowercase\n• Numbers\n• Symbols")
	reqLabel.Wrapping = fyne.TextWrapWord
	reqLabel.Alignment = fyne.TextAlignCenter

	strengthLabel := widget.NewLabel("Strength:")
	indicatorText := widget.NewLabel("")
	indicatorBar := widget.NewProgressBar()

	updateStrength := func(p string) {
		text, score := scorePassword(p)
		indicatorText.SetText(text)
		indicatorBar.SetValue(score)
	}
	pw.OnChanged = func(s string) { updateStrength(s) }

	saveBtn := widget.NewButton("Set Password", func() {
		password := strings.TrimSpace(pw.Text)
		passwordBytes := []byte(password)
		defer crypto.SecureZero(passwordBytes) // Zero password after use

		if password == "" || confirm.Text == "" {
			msg.SetText("Fill all fields.")
			return
		}
		if password != confirm.Text {
			msg.SetText("Passwords do not match.")
			return
		}

		_, score := scorePassword(password)
		if score < 0.8 {
			msg.SetText("Password too weak.")
			return
		}

		// Generate salt with error handling
		salt, err := crypto.GenerateRandomBytes(16)
		if err != nil {
			msg.SetText("❌ Failed to generate salt: " + err.Error())
			return
		}
		defer crypto.SecureZero(salt) // Zero salt after use

		kek := crypto.DeriveKEK(passwordBytes, salt)
		defer crypto.SecureZero(kek) // Zero KEK after use

		// Generate DEK with error handling
		dek, err := crypto.GenerateRandomBytes(32)
		if err != nil {
			msg.SetText("❌ Failed to generate encryption key: " + err.Error())
			return
		}
		defer crypto.SecureZero(dek) // Zero DEK after use (no longer needed after save)

		// Wrap DEK with error handling
		wrapped, err := crypto.WrapKey(kek, dek)
		if err != nil {
			msg.SetText("❌ Failed to wrap encryption key: " + err.Error())
			return
		}

		v := &vault.Vault{
			Salt:       base64.StdEncoding.EncodeToString(salt),
			WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
			Entries:    []vault.Entry{},
		}

		// Save with HMAC protection
		err = v.SaveWithHMAC(vaultFile, kek)
		if err != nil {
			msg.SetText("❌ Failed to save vault: " + err.Error())
			return
		}

		w.Close()
		showLoginWindow(a)
	})

	w.SetContent(container.NewVBox(
		title, pw, confirm, reqLabel,
		container.NewHBox(strengthLabel, container.NewVBox(indicatorBar, indicatorText)),
		saveBtn, msg,
	))
	w.Show()
}

// ------------------- UTILS: SETTINGS WINDOW -------------------

func showSettingsWindow(a fyne.App, refreshTimer func()) {
	resetLockTimer()
	w := a.NewWindow("Settings")
	openVaultWindows = append(openVaultWindows, w)
	w.SetOnClosed(func() { removeWindowFromSlice(w) })
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 400))
	w.CenterOnScreen() // <-- Centers the window

	// --- 1. Clipboard Timeout Setting ---
	clipboardOptions := []string{"30 Seconds", "1 Minute", "3 Minutes"}
	clipboardSelect := widget.NewSelect(clipboardOptions, func(s string) {
		switch s {
		case "30 Seconds":
			clipboardTimeout = 30 * time.Second
		case "1 Minute":
			clipboardTimeout = 1 * time.Minute
		case "3 Minutes":
			clipboardTimeout = 3 * time.Minute
		}
	})

	// Set initial value based on the current global variable
	switch clipboardTimeout {
	case 30 * time.Second:
		clipboardSelect.SetSelected("30 Seconds")
	case 1 * time.Minute:
		clipboardSelect.SetSelected("1 Minute")
	case 3 * time.Minute:
		clipboardSelect.SetSelected("3 Minutes")
	default:
		clipboardSelect.SetSelected("30 Seconds") // Fallback
	}

	// --- 2. Auto-Logout Timeout Setting ---
	logoutOptions := []string{"1 Minute", "3 Minutes", "5 Minutes"}
	logoutSelect := widget.NewSelect(logoutOptions, func(s string) {
		switch s {
		case "1 Minute":
			autoLockTimeout = 1 * time.Minute
		case "3 Minutes":
			autoLockTimeout = 3 * time.Minute
		case "5 Minutes":
			autoLockTimeout = 5 * time.Minute
		}
		refreshTimer() // immediately update the running lock timer
	})

	// Set initial value
	switch autoLockTimeout {
	case 1 * time.Minute:
		logoutSelect.SetSelected("1 Minute")
	case 3 * time.Minute:
		logoutSelect.SetSelected("3 Minutes")
	case 5 * time.Minute:
		logoutSelect.SetSelected("5 Minutes")
	default:
		logoutSelect.SetSelected("1 Minute") // Fallback
	}

	// --- 3. Password Generation Length ---
	lengthOptions := []string{"12 Characters", "16 Characters", "24 Characters", "32 Characters"}

	lengthSelect := widget.NewSelect(lengthOptions, func(s string) {
		switch s {
		case "12 Characters":
			passwordLength = 12
		case "16 Characters":
			passwordLength = 16
		case "24 Characters":
			passwordLength = 24
		case "32 Characters":
			passwordLength = 32
		}
	})

	// Set initial value
	lengthSelect.SetSelected(fmt.Sprintf("%d Characters", passwordLength))
	if lengthSelect.Selected == "" {
		lengthSelect.SetSelected("16 Characters") // Fallback
	}

	content := container.NewVBox(
		widget.NewLabel("🔐 Security Settings"),
		widget.NewSeparator(),

		widget.NewLabel("Auto-Clear Clipboard Timeout:"),
		clipboardSelect,
		widget.NewSeparator(),

		widget.NewLabel("Auto-Logout Inactivity Timeout:"),
		logoutSelect,
		widget.NewSeparator(),

		widget.NewLabel("Default Password Generation Length:"),
		lengthSelect,

		widget.NewSeparator(),
		widget.NewButton("Close", func() { w.Close() }),
	)

	w.SetContent(container.NewPadded(content))
	w.Show()
}

// ------------------- UTILS: ADD ENTRY WINDOW -------------------

func showAddEntryWindow(a fyne.App, v *vault.Vault, dek []byte, kek []byte, list *widget.List, status *widget.Label, filterEntries func(string)) {
	resetLockTimer()

	w := a.NewWindow("Add Entry")
	openVaultWindows = append(openVaultWindows, w)
	w.SetOnClosed(func() { removeWindowFromSlice(w) })
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(450, 500))
	w.CenterOnScreen() // <-- Centers the window

	service := widget.NewEntry()
	service.SetPlaceHolder("Service (e.g. Gmail)")
	service.OnChanged = func(s string) { resetLockTimer() }

	username := widget.NewEntry()
	username.SetPlaceHolder("Username/email")
	username.OnChanged = func(s string) { resetLockTimer() }

	pw := widget.NewEntry()
	pw.Password = true
	pw.SetPlaceHolder("Account password")

	generatorBtn := widget.NewButton("Generate", func() {
		resetLockTimer()
		// Uses global passwordLength variable
		pass, err := crypto.GenerateSecurePassword(passwordLength)
		if err != nil {
			status.SetText("Failed to generate")
			return
		}
		pw.SetText(pass)
	})
	generatorBtn.Importance = widget.LowImportance

	passwordInputRow := container.NewBorder(nil, nil, nil, generatorBtn, pw)

	strengthLabel := widget.NewLabel("Strength:")
	strengthLabel.TextStyle.Bold = true
	indicatorText := widget.NewLabel("")
	indicatorText.TextStyle.Bold = true
	indicatorBar := widget.NewProgressBar()

	updateIndicator := func(pwStr string) {
		text, score := scorePassword(pwStr)
		indicatorText.SetText(text)
		indicatorBar.SetValue(score)
	}
	updateIndicator(pw.Text)
	pw.OnChanged = func(s string) {
		resetLockTimer()
		updateIndicator(s)
	}

	notes := widget.NewMultiLineEntry()
	notes.SetPlaceHolder("Notes (optional)")
	notes.Wrapping = fyne.TextWrapWord
	notes.OnChanged = func(s string) { resetLockTimer() }

	save := widget.NewButton("Save", func() {
		resetLockTimer()
		if service.Text == "" || username.Text == "" || pw.Text == "" {
			status.SetText("Fill all fields")
			return
		}

		if err := v.AddEntry(service.Text, username.Text, pw.Text, notes.Text, dek); err != nil {
			status.SetText("Error adding entry")
			return
		}

		// Save with HMAC protection
		err := v.SaveWithHMAC(vaultFile, kek)
		if err != nil {
			status.SetText("❌ Failed to save: " + err.Error())
			return
		}

		filterEntries("")
		list.Refresh()
		status.SetText("Entry added ✅")
		w.Close()
	})

	content := container.NewVBox(
		widget.NewLabel("Add New Entry"),
		container.NewPadded(service),
		container.NewPadded(username),
		passwordInputRow,
		container.NewHBox(strengthLabel, container.NewVBox(indicatorBar, indicatorText)),
		widget.NewLabel("Notes:"),
		notes,
		save,
	)

	w.SetContent(container.NewPadded(content))
	w.Show()
}

// ------------------- UTILS: EDIT ENTRY WINDOW -------------------

func showEditEntryWindow(a fyne.App, v *vault.Vault, dek []byte, kek []byte, index int, refreshList func(), status *widget.Label) {
	resetLockTimer()

	entry := v.Entries[index]

	w := a.NewWindow("Edit Entry")
	openVaultWindows = append(openVaultWindows, w)
	w.SetOnClosed(func() { removeWindowFromSlice(w) })
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(450, 550))
	w.CenterOnScreen()

	w.SetCloseIntercept(func() { removeWindowFromSlice(w); w.Close() })

	// Decrypt entry fields - handle errors
	serviceText, err := decryptEntry(dek, entry.Service)
	if err != nil {
		status.SetText("❌ Failed to decrypt entry: " + err.Error())
		w.Close()
		return
	}

	usernameText, err := decryptEntry(dek, entry.Username)
	if err != nil {
		status.SetText("❌ Failed to decrypt entry: " + err.Error())
		w.Close()
		return
	}

	passwordText, err := decryptEntry(dek, entry.Password)
	if err != nil {
		status.SetText("❌ Failed to decrypt entry: " + err.Error())
		w.Close()
		return
	}

	// Service
	service := widget.NewEntry()
	service.SetText(serviceText)
	service.SetPlaceHolder("Service (e.g., Gmail)")
	service.OnChanged = func(s string) { resetLockTimer() }

	// Username
	username := widget.NewEntry()
	username.SetText(usernameText)
	username.SetPlaceHolder("Username/email")
	username.OnChanged = func(s string) { resetLockTimer() }

	// Password with eye toggle and generate button
	pw := widget.NewEntry()
	pw.SetText(passwordText)
	pw.Password = true
	pw.OnChanged = func(s string) { resetLockTimer() }

	var toggleButton *widget.Button
	toggleFunc := func() {
		resetLockTimer()
		pw.Password = !pw.Password
		if pw.Password {
			toggleButton.SetIcon(theme.VisibilityIcon())
		} else {
			toggleButton.SetIcon(theme.VisibilityOffIcon())
		}
		pw.Refresh()
	}
	toggleButton = widget.NewButtonWithIcon("", theme.VisibilityIcon(), toggleFunc)

	generateBtn := widget.NewButton("Generate", func() {
		resetLockTimer()
		// Uses global passwordLength variable
		pass, err := crypto.GenerateSecurePassword(passwordLength)
		if err != nil {
			status.SetText("Failed to generate password")
			return
		}
		pw.SetText(pass)
	})
	generateBtn.Importance = widget.LowImportance

	passwordRow := container.NewBorder(nil, nil, toggleButton, generateBtn, pw)

	// Notes (editable in edit window)
	notesText, err := decryptEntry(dek, entry.Notes)
	if err != nil {
		status.SetText("❌ Failed to decrypt notes: " + err.Error())
		w.Close()
		return
	}

	notesBox := widget.NewMultiLineEntry()
	notesBox.SetText(notesText)
	notesBox.Wrapping = fyne.TextWrapWord
	notesBox.OnChanged = func(s string) { resetLockTimer() }

	// Save button
	saveBtn := widget.NewButton("Save Changes", func() {
		resetLockTimer()
		if service.Text == "" || username.Text == "" || pw.Text == "" {
			status.SetText("Fill all fields")
			return
		}

		// Encrypt updated fields - handle errors
		newService, err := crypto.EncryptEntry(dek, []byte(service.Text))
		if err != nil {
			status.SetText("❌ Failed to encrypt service: " + err.Error())
			return
		}

		newUsername, err := crypto.EncryptEntry(dek, []byte(username.Text))
		if err != nil {
			status.SetText("❌ Failed to encrypt username: " + err.Error())
			return
		}

		newPassword, err := crypto.EncryptEntry(dek, []byte(pw.Text))
		if err != nil {
			status.SetText("❌ Failed to encrypt password: " + err.Error())
			return
		}

		newNotes, err := crypto.EncryptEntry(dek, []byte(notesBox.Text))
		if err != nil {
			status.SetText("❌ Failed to encrypt notes: " + err.Error())
			return
		}

		v.Entries[index].Service = base64.StdEncoding.EncodeToString(newService)
		v.Entries[index].Username = base64.StdEncoding.EncodeToString(newUsername)
		v.Entries[index].Password = base64.StdEncoding.EncodeToString(newPassword)
		v.Entries[index].Notes = base64.StdEncoding.EncodeToString(newNotes)

		// Save with HMAC protection
		err = v.SaveWithHMAC(vaultFile, kek)
		if err != nil {
			status.SetText("❌ Failed to save vault: " + err.Error())
			return
		}

		refreshList()
		status.SetText("Entry updated ✅")
		w.Close()
	})

	content := container.NewVBox(
		widget.NewLabel("Service:"),
		service,
		widget.NewLabel("Username:"),
		username,
		widget.NewLabel("Password:"),
		passwordRow,
		widget.NewLabel("Notes:"),
		notesBox,
		saveBtn,
	)

	w.SetContent(container.NewPadded(content))
	w.Show()
}

// ------------------- UTILS: CHANGE MASTER PASSWORD WINDOW (Fixed Inputs) -------------------
// ------------------- UTILS: CHANGE MASTER PASSWORD WINDOW (Fixed Input Focus) -------------------

func showChangeMasterPasswordWindow(a fyne.App, v *vault.Vault, dek []byte, kek []byte, vaultStatus *widget.Label) {
	resetLockTimer()

	w := a.NewWindow("Change Master Password")
	openVaultWindows = append(openVaultWindows, w)
	w.SetOnClosed(func() { removeWindowFromSlice(w) })
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 550))
	w.CenterOnScreen()

	title := widget.NewLabel("Change Your Master Password")
	title.TextStyle.Bold = true
	title.Alignment = fyne.TextAlignCenter

	instructions := widget.NewLabel("Enter your current password, then choose a strong new password.")
	instructions.Wrapping = fyne.TextWrapWord
	instructions.Alignment = fyne.TextAlignCenter

	currentPasswordEntry := widget.NewEntry()
	currentPasswordEntry.Password = true
	currentPasswordEntry.SetPlaceHolder("Enter Current Master Password")
	currentPasswordEntry.OnChanged = func(s string) { resetLockTimer() }

	newPasswordEntry := widget.NewEntry()
	newPasswordEntry.Password = true
	newPasswordEntry.SetPlaceHolder("Enter New Master Password")
	newPasswordEntry.OnChanged = func(s string) { resetLockTimer() }

	confirmPasswordEntry := widget.NewEntry()
	confirmPasswordEntry.Password = true
	confirmPasswordEntry.SetPlaceHolder("Confirm New Master Password")
	confirmPasswordEntry.OnChanged = func(s string) { resetLockTimer() }

	strengthLabel := widget.NewLabel("New Password Strength:")
	strengthLabel.TextStyle.Bold = true
	strengthIndicatorText := widget.NewLabel("")
	strengthIndicatorText.TextStyle.Bold = true
	strengthIndicatorBar := widget.NewProgressBar()

	updateStrength := func(password string) {
		if password == "" {
			strengthIndicatorText.SetText("")
			strengthIndicatorBar.SetValue(0)
			return
		}
		text, score := scorePassword(password)
		strengthIndicatorText.SetText(text)
		strengthIndicatorBar.SetValue(score)
	}

	newPasswordEntry.OnChanged = func(s string) {
		resetLockTimer()
		updateStrength(s)
	}

	statusMsg := widget.NewLabel("")
	statusMsg.Wrapping = fyne.TextWrapWord
	statusMsg.Alignment = fyne.TextAlignCenter

	reqLabel := widget.NewLabel("New password requirements:\n• At least 12 characters\n• Uppercase and lowercase letters\n• Numbers and symbols\n• Strong strength score (0.8+)")
	reqLabel.Wrapping = fyne.TextWrapWord
	reqLabel.Alignment = fyne.TextAlignLeading

	changeBtn := widget.NewButton("Change Master Password", func() {
		resetLockTimer()

		currentPassword := strings.TrimSpace(currentPasswordEntry.Text)
		currentPasswordBytes := []byte(currentPassword)
		defer crypto.SecureZero(currentPasswordBytes)

		newPassword := strings.TrimSpace(newPasswordEntry.Text)
		newPasswordBytes := []byte(newPassword)
		defer crypto.SecureZero(newPasswordBytes)

		confirmPassword := strings.TrimSpace(confirmPasswordEntry.Text)

		if currentPassword == "" || newPassword == "" || confirmPassword == "" {
			statusMsg.SetText("❌ Please fill in all fields.")
			return
		}

		if newPassword != confirmPassword {
			statusMsg.SetText("❌ New passwords do not match.")
			return
		}

		if currentPassword == newPassword {
			statusMsg.SetText("❌ New password must be different from current password.")
			return
		}

		_, score := scorePassword(newPassword)
		if score < 0.8 {
			statusMsg.SetText("❌ New password is too weak. Please use a stronger password.")
			return
		}

		statusMsg.SetText("⏳ Verifying current password...")
		statusMsg.Refresh()

		currentVault, err := vault.Load(vaultFile)
		if err != nil {
			statusMsg.SetText("❌ Failed to load vault.")
			return
		}

		currentSalt, err := base64.StdEncoding.DecodeString(currentVault.Salt)
		if err != nil {
			statusMsg.SetText("❌ Vault data corrupted (invalid salt).")
			return
		}
		defer crypto.SecureZero(currentSalt)

		currentKEK := crypto.DeriveKEK(currentPasswordBytes, currentSalt)
		defer crypto.SecureZero(currentKEK)

		wrappedDEK, err := base64.StdEncoding.DecodeString(currentVault.WrappedDEK)
		if err != nil {
			statusMsg.SetText("❌ Vault data corrupted (invalid wrapped DEK).")
			return
		}

		verifiedDEK, err := crypto.UnwrapKey(currentKEK, wrappedDEK)
		if err != nil {
			statusMsg.SetText("❌ Current password is incorrect.")
			return
		}
		defer crypto.SecureZero(verifiedDEK)

		statusMsg.SetText("⏳ Changing master password...")
		statusMsg.Refresh()

		err = v.ChangeMasterPassword(newPasswordBytes, verifiedDEK, vaultFile)
		if err != nil {
			statusMsg.SetText("❌ Failed to change password: " + err.Error())
			return
		}

		statusMsg.SetText("✅ Master password changed successfully!")
		vaultStatus.SetText("Master password changed successfully! ✅")

		currentPasswordEntry.SetText("")
		newPasswordEntry.SetText("")
		confirmPasswordEntry.SetText("")
		strengthIndicatorText.SetText("")
		strengthIndicatorBar.SetValue(0)

		time.AfterFunc(2*time.Second, func() {
			fyne.Do(func() {
				w.Close()
			})
		})
	})
	changeBtn.Importance = widget.HighImportance

	cancelBtn := widget.NewButton("Cancel", func() {
		w.Close()
	})

	// ⭐️ FIX: Use widget.NewForm for guaranteed input focus area ⭐️
	passwordForm := widget.NewForm(
		widget.NewFormItem("Current Password:", currentPasswordEntry),
		widget.NewFormItem("New Password:", newPasswordEntry),
		widget.NewFormItem("Confirm New Password:", confirmPasswordEntry),
	)

	strengthLayout := container.NewHBox(strengthLabel, container.NewVBox(strengthIndicatorBar, strengthIndicatorText))

	content := container.NewVBox(
		title,
		instructions,
		widget.NewSeparator(),

		passwordForm, // Insert the form

		widget.NewSeparator(),
		strengthLayout,
		widget.NewSeparator(),
		reqLabel,
		statusMsg,
		container.NewHBox(changeBtn, cancelBtn),
	)

	w.SetContent(container.NewPadded(content))
	w.Show()
}

// ------------------- VAULT WINDOW -------------------

// DisplayItem is used to hold mixed data types (header or actual entry) for the list widget.
type DisplayItem struct {
	IsHeader   bool
	HeaderChar string
	Entry      vault.Entry // Only valid if IsHeader is false
}

// ------------------- VAULT WINDOW (Fixed: No Headers, Simple List) -------------------

func showVaultWindow(a fyne.App, v *vault.Vault, dek []byte, kek []byte) {
	w := a.NewWindow("Crypto Vault")
	// Increased Width to fit all buttons
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(700, 500))
	w.CenterOnScreen()

	currentVaultWindow = w
	openVaultWindows = append(openVaultWindows, w)

	w.SetOnClosed(func() {
		if vaultTimer != nil {
			vaultTimer.Stop()
		}
		crypto.SecureZero(dek)
		crypto.SecureZero(kek)
		currentVaultWindow = nil
		for _, win := range openVaultWindows {
			if win != w {
				win.Close()
			}
		}
		openVaultWindows = nil
	})

	resetLockTimer()

	// ⭐️ FIX: Reverting to a simple slice of entries (no DisplayItem struct) ⭐️
	var filteredEntries []vault.Entry
	selectedIndex := -1
	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search...")
	status := widget.NewLabel("Vault unlocked.")

	var entriesList *widget.List

	// ⭐️ FIX: Simple filter and sort function (no header generation) ⭐️
	filterEntries := func(query string) {
		query = strings.ToLower(query)
		filteredEntries = nil

		for i := range v.Entries {
			serviceStr, err := decryptEntry(dek, v.Entries[i].Service)
			if err != nil {
				status.SetText("❌ Failed to decrypt entry: " + err.Error())
				continue
			}

			notesStr, err := decryptEntry(dek, v.Entries[i].Notes)
			if err != nil {
				status.SetText("❌ Failed to decrypt entry notes: " + err.Error())
				continue
			}

			serviceStr = strings.ToLower(serviceStr)
			notesStr = strings.ToLower(notesStr)

			if query == "" || strings.Contains(serviceStr, query) || strings.Contains(notesStr, query) {
				filteredEntries = append(filteredEntries, v.Entries[i])
			}
		}

		// Alphabetical sorting is kept for clean organization
		sort.Slice(filteredEntries, func(i, j int) bool {
			serviceA, errA := decryptEntry(dek, filteredEntries[i].Service)
			serviceB, errB := decryptEntry(dek, filteredEntries[j].Service)

			if errA != nil {
				return false
			}
			if errB != nil {
				return true
			}

			return strings.ToLower(serviceA) < strings.ToLower(serviceB)
		})

		if entriesList != nil {
			entriesList.Refresh()
			selectedIndex = -1
		}
	}
	filterEntries("")

	// The List Definition (simplified)
	entriesList = widget.NewList(
		func() int { return len(filteredEntries) },
		func() fyne.CanvasObject {
			tappableText := NewTappableText("", func() {}, theme.TextSize())
			// Wrapped in padding for consistent row height
			return container.NewPadded(tappableText)
		},
		func(i int, o fyne.CanvasObject) {
			paddedContainer := o.(*fyne.Container)
			tappableText := paddedContainer.Objects[0].(*TappableText)

			serviceName, err := decryptEntry(dek, filteredEntries[i].Service)
			if err != nil {
				tappableText.SetText("❌ [Decryption Error]")
			} else {
				tappableText.SetText(serviceName)
			}

			tappableText.OnTapped = func() {
				resetLockTimer()
				if selectedIndex == i {
					entriesList.Unselect(i)
					status.SetText("Entry deselected.")
				} else {
					entriesList.Select(i)
				}
			}

			if selectedIndex == i {
				tappableText.SetBold(true)
			} else {
				tappableText.SetBold(false)
			}
			tappableText.Refresh()
		},
	)

	// List Selection Handlers (Updated to use simple index)
	entriesList.OnSelected = func(id widget.ListItemID) {
		resetLockTimer()
		selectedIndex = int(id)
		status.SetText("Entry selected.")
		entriesList.Refresh()
	}

	entriesList.OnUnselected = func(id widget.ListItemID) {
		resetLockTimer()
		if selectedIndex == int(id) {
			selectedIndex = -1
		}
		status.SetText("Entry deselected.")
		entriesList.Refresh()
	}

	searchEntry.OnChanged = func(s string) { resetLockTimer(); filterEntries(s) }

	// ---------------- TOP BUTTONS ----------------
	addBtn := widget.NewButton("➕ Add", func() {
		resetLockTimer()
		showAddEntryWindow(a, v, dek, kek, entriesList, status, filterEntries)
		filterEntries(searchEntry.Text)
	})

	viewBtn := widget.NewButton("🔍 View", func() {
		resetLockTimer()
		if selectedIndex < 0 {
			status.SetText("Select an entry first")
			return
		}

		e := filteredEntries[selectedIndex] // Access the entry directly

		service, errService := decryptEntry(dek, e.Service)
		user, errUser := decryptEntry(dek, e.Username)
		pass, errPass := decryptEntry(dek, e.Password)
		notes, errNotes := decryptEntry(dek, e.Notes)

		if errUser != nil || errPass != nil || errService != nil || errNotes != nil {
			status.SetText("❌ Decryption error for selected entry!")
			return
		}

		win := a.NewWindow("Entry Details: " + service)
		openVaultWindows = append(openVaultWindows, win)
		win.SetOnClosed(func() { removeWindowFromSlice(win) })
		win.SetFixedSize(true)
		win.Resize(fyne.NewSize(500, 350))
		win.CenterOnScreen()

		passwordEntry := widget.NewEntry()
		passwordEntry.SetText(pass)
		passwordEntry.Password = true
		passwordEntry.Disable()

		var toggleButton *widget.Button
		toggleButton = widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
			resetLockTimer()
			passwordEntry.Password = !passwordEntry.Password
			if passwordEntry.Password {
				toggleButton.SetIcon(theme.VisibilityIcon())
			} else {
				toggleButton.SetIcon(theme.VisibilityOffIcon())
			}
			passwordEntry.Refresh()
		})

		passwordRow := container.NewBorder(
			nil, nil,
			widget.NewLabel("Password:"),
			toggleButton,
			passwordEntry,
		)

		notesBox := widget.NewMultiLineEntry()
		notesBox.SetText(notes)
		notesBox.Disable()

		copyButton := widget.NewButton("📋 Copy Password (Auto-Clear)", func() {
			resetLockTimer()
			copyToClipboard(win.Clipboard(), pass, status)
		})

		editButton := widget.NewButtonWithIcon(" Edit", theme.DocumentCreateIcon(), func() {
			resetLockTimer()
			win.Close()

			targetEntry := filteredEntries[selectedIndex]

			// Find actual index in v.Entries (original, unsorted list)
			masterIndex := -1
			for i, entry := range v.Entries {
				if entry.Service == targetEntry.Service &&
					entry.Username == targetEntry.Username {
					masterIndex = i
					break
				}
			}
			if masterIndex == -1 {
				status.SetText("Failed to locate entry")
				return
			}

			showEditEntryWindow(a, v, dek, kek, masterIndex, func() {
				filterEntries(searchEntry.Text)
				entriesList.Refresh()
			}, status)
		})

		closeButton := widget.NewButton("Close", func() { win.Close() })

		win.SetContent(container.NewVBox(
			widget.NewLabel("Service: "+service),
			widget.NewLabel("Username: "+user),
			widget.NewSeparator(),
			passwordRow,
			container.NewHBox(editButton),
			widget.NewLabel("Notes:"),
			notesBox,
			copyButton,
			closeButton,
		))
		win.Show()
	})

	deleteBtn := widget.NewButton("🗑 Delete", func() {
		resetLockTimer()
		if selectedIndex < 0 {
			status.SetText("Select entry")
			return
		}

		entry := filteredEntries[selectedIndex]

		masterIndex := -1
		for i, e := range v.Entries {
			if e.Service == entry.Service && e.Username == entry.Username {
				masterIndex = i
				break
			}
		}
		if masterIndex != -1 {
			v.Entries = append(v.Entries[:masterIndex], v.Entries[masterIndex+1:]...)

			err := v.SaveWithHMAC(vaultFile, kek)
			if err != nil {
				status.SetText("❌ Failed to save after deletion: " + err.Error())
				return
			}

			filterEntries(searchEntry.Text)
			status.SetText("Entry deleted ✅")
		} else {
			status.SetText("Entry not found.")
		}
	})

	settingsBtn := widget.NewButtonWithIcon("Settings", theme.SettingsIcon(), func() {
		showSettingsWindow(a, resetLockTimer)
	})

	changePasswordBtn := widget.NewButton("🔑 Change Password", func() {
		resetLockTimer()
		showChangeMasterPasswordWindow(a, v, dek, kek, status)
	})

	logoutBtn := widget.NewButton("🚪 Logout", func() {
		if vaultTimer != nil {
			vaultTimer.Stop()
		}
		currentVaultWindow = nil
		for _, w := range openVaultWindows {
			w.Close()
		}
		openVaultWindows = nil

		crypto.SecureZero(dek)
		crypto.SecureZero(kek)

		loginMessage = "You logged out."
		showLoginWindow(a)
	})

	exitBtn := widget.NewButtonWithIcon("Exit", theme.ContentClearIcon(), func() {
		crypto.SecureZero(dek)
		crypto.SecureZero(kek)
		a.Quit()
	})

	topButtons := container.NewHBox(addBtn, viewBtn, deleteBtn, settingsBtn, changePasswordBtn, logoutBtn, exitBtn)

	content := container.NewBorder(
		container.NewVBox(searchEntry, container.NewPadded(topButtons)),
		status, nil, nil, entriesList,
	)
	w.SetContent(content)
	w.Show()
}
