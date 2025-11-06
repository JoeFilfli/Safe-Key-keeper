package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"

	"Crypto-Project/internal/crypto"
	"Crypto-Project/internal/vault"
)

// Global constants and variables
const vaultFile = "vault.json"

var (
	passwordLength = 16 // Default generated password length
)

// Global reader for console input
var reader = bufio.NewReader(os.Stdin)

// ------------------- MAIN -------------------

func main() {
	fmt.Println("========================================")
	fmt.Println("   Welcome to Password Manager CLI")
	fmt.Println("========================================")
	fmt.Println()

	// Check if vault exists
	if !vault.Exists(vaultFile) {
		// Create new vault
		fmt.Println("No vault found. Let's create one!")
		setupMasterPassword()
	} else {
		// Login to existing vault
		login()
	}
}

// ------------------- AUTHENTICATION -------------------

// setupMasterPassword creates a new vault with a strong master password
func setupMasterPassword() {
	fmt.Println("\n--- Set Your Master Password ---")
	fmt.Println("Password requirements:")
	fmt.Println("• At least 12 characters")
	fmt.Println("• Uppercase and lowercase letters")
	fmt.Println("• Numbers and symbols")
	fmt.Println()

	var password string
	var confirmPassword string

	for {
		fmt.Print("Enter your master password: ")
		password = readPassword()
		password = strings.TrimSpace(password)
		passwordBytes := []byte(password)
		defer crypto.SecureZero(passwordBytes) // Zero password after use

		if password == "" {
			fmt.Println("❌ Password cannot be empty!")
			continue
		}

		// Check password strength
		strength, score := scorePassword(password)
		fmt.Printf("Password strength: %s (%.0f%%)\n", strength, score*100)

		if score < 0.8 {
			fmt.Println("❌ Password too weak. Please use a stronger password.")
			continue
		}

		fmt.Print("Confirm your master password: ")
		confirmPassword = readPassword()
		confirmPassword = strings.TrimSpace(confirmPassword)

		if password != confirmPassword {
			fmt.Println("❌ Passwords do not match!")
			continue
		}

		break
	}

	// Generate salt with error handling
	salt, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		fmt.Println("❌ Failed to generate salt:", err)
		os.Exit(1)
	}
	defer crypto.SecureZero(salt) // Zero salt after use

	// Derive KEK
	kek := crypto.DeriveKEK([]byte(password), salt)
	defer crypto.SecureZero(kek) // Zero KEK after use

	// Generate DEK with error handling
	dek, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		fmt.Println("❌ Failed to generate encryption key:", err)
		os.Exit(1)
	}
	// Note: DEK will be used in vault operations, don't zero it here

	// Wrap DEK with error handling
	wrappedDEK, err := crypto.WrapKey(kek, dek)
	if err != nil {
		fmt.Println("❌ Failed to wrap encryption key:", err)
		crypto.SecureZero(dek)
		os.Exit(1)
	}

	// Create and save vault
	v := &vault.Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Entries:    []vault.Entry{},
	}

	// Save with HMAC protection
	err = v.SaveWithHMAC(vaultFile, kek)
	if err != nil {
		fmt.Println("❌ Failed to save vault:", err)
		crypto.SecureZero(dek)
		crypto.SecureZero(kek)
		os.Exit(1)
	}

	fmt.Println("✅ Vault created successfully!")
	fmt.Println()

	// Start main menu (KEK is kept for HMAC operations)
	mainMenu(v, dek, kek)
}

// login authenticates the user and unlocks the vault
func login() {
	fmt.Println("\n--- Login to Your Vault ---")

	// Load vault first to get salt
	vTemp, err := vault.Load(vaultFile)
	if err != nil {
		fmt.Println("❌ Failed to load vault:", err)
		os.Exit(1)
	}

	// Prompt for master password
	fmt.Print("Enter your master password: ")
	password := readPassword()
	password = strings.TrimSpace(password)
	passwordBytes := []byte(password)
	defer crypto.SecureZero(passwordBytes) // Zero password after use

	if password == "" {
		fmt.Println("❌ Password cannot be empty!")
		os.Exit(1)
	}

	// Decode salt and wrappedDEK
	salt, err := base64.StdEncoding.DecodeString(vTemp.Salt)
	if err != nil {
		fmt.Println("❌ Vault data corrupted (invalid salt).")
		os.Exit(1)
	}
	defer crypto.SecureZero(salt) // Zero salt after use

	// Derive KEK
	kek := crypto.DeriveKEK(passwordBytes, salt)
	// Note: KEK is kept for HMAC operations, don't zero it here

	// First, try to unwrap DEK to verify password is correct
	wrappedDEK, err := base64.StdEncoding.DecodeString(vTemp.WrappedDEK)
	if err != nil {
		fmt.Println("❌ Vault data corrupted (invalid wrapped DEK).")
		crypto.SecureZero(kek)
		os.Exit(1)
	}

	// Unwrap DEK - this verifies the password is correct
	dek, err := crypto.UnwrapKey(kek, wrappedDEK)
	if err != nil {
		// Password is wrong
		fmt.Println("❌ Wrong password!")
		crypto.SecureZero(kek)
		os.Exit(1)
	}
	// Note: DEK and KEK will be used in vault operations, don't zero them here

	// Password is correct! Now verify HMAC integrity
	v, err := vault.LoadAndVerifyHMAC(vaultFile, kek)
	if err != nil {
		// If HMAC verification fails, try loading without HMAC (backwards compatibility)
		if err.Error() == "HMAC field is missing (vault may be from older version)" {
			v, err = vault.Load(vaultFile)
			if err != nil {
				fmt.Println("❌ Failed to load vault:", err)
				crypto.SecureZero(kek)
				crypto.SecureZero(dek)
				os.Exit(1)
			}
			fmt.Println("⚠️ Vault loaded without HMAC verification (older format). It will be upgraded on next save.")
		} else {
			// HMAC mismatch - vault was tampered with!
			fmt.Println("❌ SECURITY ALERT:", err.Error())
			crypto.SecureZero(kek)
			crypto.SecureZero(dek)
			os.Exit(1)
		}
	}

	fmt.Println("✅ Vault unlocked!")
	fmt.Println()

	// Start main menu (KEK is kept for HMAC operations)
	mainMenu(v, dek, kek)
}

// ------------------- MAIN MENU -------------------

// mainMenu displays the main menu and handles user choices
func mainMenu(v *vault.Vault, dek []byte, kek []byte) {
	// Ensure sensitive keys are zeroed on exit
	defer crypto.SecureZero(dek)
	defer crypto.SecureZero(kek)
	
	for {
		fmt.Println("\n========================================")
		fmt.Println("           MAIN MENU")
		fmt.Println("========================================")
		fmt.Println("1. List all entries")
		fmt.Println("2. Search entries")
		fmt.Println("3. Add new entry")
		fmt.Println("4. View entry")
		fmt.Println("5. Edit entry")
		fmt.Println("6. Delete entry")
		fmt.Println("7. Change master password")
		fmt.Println("8. Settings")
		fmt.Println("9. Exit")
		fmt.Println("========================================")
		fmt.Print("Choose an option: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			listEntries(v, dek, "")
		case "2":
			searchEntries(v, dek)
		case "3":
			addEntry(v, dek, kek)
		case "4":
			viewEntry(v, dek)
		case "5":
			editEntry(v, dek, kek)
		case "6":
			deleteEntry(v, dek, kek)
		case "7":
			changeMasterPassword(v, dek)
		case "8":
			settingsMenu()
		case "9":
			fmt.Println("\nExiting... Goodbye!")
			// Keys will be zeroed by defer statements
			os.Exit(0)
		default:
			fmt.Println("❌ Invalid option. Please try again.")
		}
	}
}

// ------------------- ENTRY MANAGEMENT -------------------

// listEntries displays all entries (or filtered entries) in alphabetical order
func listEntries(v *vault.Vault, dek []byte, query string) []vault.Entry {
	query = strings.ToLower(query)
	var filteredEntries []vault.Entry

	// Filter entries based on search query
	for i := range v.Entries {
		// Decrypt service and notes for searching
		serviceStr, err := decryptEntry(dek, v.Entries[i].Service)
		if err != nil {
			fmt.Printf("❌ Failed to decrypt entry %d: %s\n", i+1, err.Error())
			continue // Skip corrupted entries
		}

		notesStr, err := decryptEntry(dek, v.Entries[i].Notes)
		if err != nil {
			// If notes fail, still include the entry
			notesStr = ""
		}

		serviceStr = strings.ToLower(serviceStr)
		notesStr = strings.ToLower(notesStr)

		// Check if query matches
		if query == "" || strings.Contains(serviceStr, query) || strings.Contains(notesStr, query) {
			filteredEntries = append(filteredEntries, v.Entries[i])
		}
	}

	// Sort alphabetically by service name
	sort.Slice(filteredEntries, func(i, j int) bool {
		serviceA, errA := decryptEntry(dek, filteredEntries[i].Service)
		serviceB, errB := decryptEntry(dek, filteredEntries[j].Service)

		// If decryption fails, put corrupted entries at the end
		if errA != nil {
			return false
		}
		if errB != nil {
			return true
		}

		return strings.ToLower(serviceA) < strings.ToLower(serviceB)
	})

	// Display entries
	if len(filteredEntries) == 0 {
		fmt.Println("\nNo entries found.")
		return filteredEntries
	}

	fmt.Println("\n========================================")
	fmt.Println("           VAULT ENTRIES")
	fmt.Println("========================================")
	for i, entry := range filteredEntries {
		serviceName, err := decryptEntry(dek, entry.Service)
		if err != nil {
			fmt.Printf("%d. ❌ [Decryption Error]\n", i+1)
		} else {
			fmt.Printf("%d. %s\n", i+1, serviceName)
		}
	}
	fmt.Println("========================================")

	return filteredEntries
}

// searchEntries prompts for a search query and displays matching entries
func searchEntries(v *vault.Vault, dek []byte) {
	fmt.Print("\nEnter search query: ")
	query, _ := reader.ReadString('\n')
	query = strings.TrimSpace(query)

	listEntries(v, dek, query)
}

// addEntry prompts the user to add a new entry to the vault
func addEntry(v *vault.Vault, dek []byte, kek []byte) {
	fmt.Println("\n--- Add New Entry ---")

	// Service name
	fmt.Print("Service (e.g., Gmail): ")
	service, _ := reader.ReadString('\n')
	service = strings.TrimSpace(service)
	if service == "" {
		fmt.Println("❌ Service name cannot be empty!")
		return
	}

	// Username
	fmt.Print("Username/email: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println("❌ Username cannot be empty!")
		return
	}

	// Password (with generator option)
	fmt.Println("\nPassword options:")
	fmt.Println("1. Enter password manually")
	fmt.Println("2. Generate secure password")
	fmt.Print("Choose option: ")
	pwChoice, _ := reader.ReadString('\n')
	pwChoice = strings.TrimSpace(pwChoice)

	var password string
	if pwChoice == "2" {
		// Generate password
		generated, err := crypto.GenerateSecurePassword(passwordLength)
		if err != nil {
			fmt.Println("❌ Failed to generate password:", err)
			return
		}
		password = generated
		fmt.Printf("✅ Generated password: %s\n", password)
	} else {
		// Manual entry
		fmt.Print("Password: ")
		password = readPassword()
		password = strings.TrimSpace(password)
		if password == "" {
			fmt.Println("❌ Password cannot be empty!")
			return
		}

		// Show password strength
		strength, score := scorePassword(password)
		fmt.Printf("Password strength: %s (%.0f%%)\n", strength, score*100)
	}

	// Notes (optional)
	fmt.Print("Notes (optional, press Enter to skip): ")
	notes, _ := reader.ReadString('\n')
	notes = strings.TrimSpace(notes)

	// Add entry with error handling
	err := v.AddEntry(service, username, password, notes, dek)
	if err != nil {
		fmt.Println("❌ Failed to add entry:", err)
		return
	}

	// Save vault with HMAC protection
	err = v.SaveWithHMAC(vaultFile, kek)
	if err != nil {
		fmt.Println("❌ Failed to save vault:", err)
		return
	}

	fmt.Println("✅ Entry added successfully!")
}

// viewEntry displays detailed information about a specific entry
func viewEntry(v *vault.Vault, dek []byte) {
	filteredEntries := listEntries(v, dek, "")
	if len(filteredEntries) == 0 {
		return
	}

	fmt.Print("\nEnter entry number to view: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var index int
	_, err := fmt.Sscanf(choice, "%d", &index)
	if err != nil || index < 1 || index > len(filteredEntries) {
		fmt.Println("❌ Invalid entry number!")
		return
	}

	entry := filteredEntries[index-1]

	// Decrypt all fields with error handling
	service, err := decryptEntry(dek, entry.Service)
	if err != nil {
		fmt.Println("❌ Failed to decrypt service:", err)
		return
	}

	username, err := decryptEntry(dek, entry.Username)
	if err != nil {
		fmt.Println("❌ Failed to decrypt username:", err)
		return
	}

	password, err := decryptEntry(dek, entry.Password)
	if err != nil {
		fmt.Println("❌ Failed to decrypt password:", err)
		return
	}

	notes, err := decryptEntry(dek, entry.Notes)
	if err != nil {
		fmt.Println("❌ Failed to decrypt notes:", err)
		return
	}

	// Display entry details
	fmt.Println("\n========================================")
	fmt.Println("         ENTRY DETAILS")
	fmt.Println("========================================")
	fmt.Printf("Service:  %s\n", service)
	fmt.Printf("Username: %s\n", username)
	fmt.Printf("Password: %s\n", strings.Repeat("*", len(password)))
	if notes != "" {
		fmt.Printf("Notes:    %s\n", notes)
	}
	fmt.Println("========================================")

	// Option to show password
	fmt.Print("\nShow password? (y/n): ")
	show, _ := reader.ReadString('\n')
	show = strings.TrimSpace(strings.ToLower(show))

	if show == "y" || show == "yes" {
		fmt.Printf("\n🔑 Password: %s\n", password)
	}
}

// editEntry allows the user to modify an existing entry
func editEntry(v *vault.Vault, dek []byte, kek []byte) {
	filteredEntries := listEntries(v, dek, "")
	if len(filteredEntries) == 0 {
		return
	}

	fmt.Print("\nEnter entry number to edit: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var index int
	_, err := fmt.Sscanf(choice, "%d", &index)
	if err != nil || index < 1 || index > len(filteredEntries) {
		fmt.Println("❌ Invalid entry number!")
		return
	}

	entry := filteredEntries[index-1]

	// Find the actual index in v.Entries
	masterIndex := -1
	for i, e := range v.Entries {
		if e.Service == entry.Service && e.Username == entry.Username {
			masterIndex = i
			break
		}
	}
	if masterIndex == -1 {
		fmt.Println("❌ Failed to locate entry!")
		return
	}

	// Decrypt current values
	currentService, _ := decryptEntry(dek, entry.Service)
	currentUsername, _ := decryptEntry(dek, entry.Username)
	currentPassword, _ := decryptEntry(dek, entry.Password)
	currentNotes, _ := decryptEntry(dek, entry.Notes)

	fmt.Println("\n--- Edit Entry ---")
	fmt.Println("(Press Enter to keep current value)")

	// Service
	fmt.Printf("Service [%s]: ", currentService)
	newService, _ := reader.ReadString('\n')
	newService = strings.TrimSpace(newService)
	if newService == "" {
		newService = currentService
	}

	// Username
	fmt.Printf("Username [%s]: ", currentUsername)
	newUsername, _ := reader.ReadString('\n')
	newUsername = strings.TrimSpace(newUsername)
	if newUsername == "" {
		newUsername = currentUsername
	}

	// Password
	fmt.Println("\nPassword options:")
	fmt.Println("1. Keep current password")
	fmt.Println("2. Enter new password")
	fmt.Println("3. Generate new password")
	fmt.Print("Choose option: ")
	pwChoice, _ := reader.ReadString('\n')
	pwChoice = strings.TrimSpace(pwChoice)

	newPassword := currentPassword
	if pwChoice == "2" {
		fmt.Print("New password: ")
		newPassword = readPassword()
		newPassword = strings.TrimSpace(newPassword)
		if newPassword == "" {
			newPassword = currentPassword
		} else {
			strength, score := scorePassword(newPassword)
			fmt.Printf("Password strength: %s (%.0f%%)\n", strength, score*100)
		}
	} else if pwChoice == "3" {
		generated, err := crypto.GenerateSecurePassword(passwordLength)
		if err != nil {
			fmt.Println("❌ Failed to generate password:", err)
		} else {
			newPassword = generated
			fmt.Printf("✅ Generated password: %s\n", newPassword)
		}
	}

	// Notes
	fmt.Printf("Notes [%s]: ", currentNotes)
	newNotes, _ := reader.ReadString('\n')
	newNotes = strings.TrimSpace(newNotes)
	if newNotes == "" {
		newNotes = currentNotes
	}

	// Encrypt and save
	encService, err := crypto.EncryptEntry(dek, []byte(newService))
	if err != nil {
		fmt.Println("❌ Failed to encrypt service:", err)
		return
	}

	encUsername, err := crypto.EncryptEntry(dek, []byte(newUsername))
	if err != nil {
		fmt.Println("❌ Failed to encrypt username:", err)
		return
	}

	encPassword, err := crypto.EncryptEntry(dek, []byte(newPassword))
	if err != nil {
		fmt.Println("❌ Failed to encrypt password:", err)
		return
	}

	encNotes, err := crypto.EncryptEntry(dek, []byte(newNotes))
	if err != nil {
		fmt.Println("❌ Failed to encrypt notes:", err)
		return
	}

	v.Entries[masterIndex].Service = base64.StdEncoding.EncodeToString(encService)
	v.Entries[masterIndex].Username = base64.StdEncoding.EncodeToString(encUsername)
	v.Entries[masterIndex].Password = base64.StdEncoding.EncodeToString(encPassword)
	v.Entries[masterIndex].Notes = base64.StdEncoding.EncodeToString(encNotes)

	// Save vault with HMAC protection
	err = v.SaveWithHMAC(vaultFile, kek)
	if err != nil {
		fmt.Println("❌ Failed to save vault:", err)
		return
	}

	fmt.Println("✅ Entry updated successfully!")
}

// deleteEntry removes an entry from the vault with confirmation
func deleteEntry(v *vault.Vault, dek []byte, kek []byte) {
	filteredEntries := listEntries(v, dek, "")
	if len(filteredEntries) == 0 {
		return
	}

	fmt.Print("\nEnter entry number to delete: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var index int
	_, err := fmt.Sscanf(choice, "%d", &index)
	if err != nil || index < 1 || index > len(filteredEntries) {
		fmt.Println("❌ Invalid entry number!")
		return
	}

	entry := filteredEntries[index-1]

	// Show entry details for confirmation
	serviceName, _ := decryptEntry(dek, entry.Service)
	fmt.Printf("\n⚠️  Are you sure you want to delete '%s'? (y/n): ", serviceName)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "y" && confirm != "yes" {
		fmt.Println("❌ Deletion cancelled.")
		return
	}

	// Find the actual index in v.Entries
	masterIndex := -1
	for i, e := range v.Entries {
		if e.Service == entry.Service && e.Username == entry.Username {
			masterIndex = i
			break
		}
	}

	if masterIndex == -1 {
		fmt.Println("❌ Failed to locate entry!")
		return
	}

	// Delete the entry
	v.Entries = append(v.Entries[:masterIndex], v.Entries[masterIndex+1:]...)

	// Save vault with HMAC protection
	err = v.SaveWithHMAC(vaultFile, kek)
	if err != nil {
		fmt.Println("❌ Failed to save vault:", err)
		return
	}

	fmt.Println("✅ Entry deleted successfully!")
}

// ------------------- PASSWORD MANAGEMENT -------------------

// changeMasterPassword allows the user to change the master password
func changeMasterPassword(v *vault.Vault, dek []byte) {
	fmt.Println("\n--- Change Master Password ---")

	// Verify current password
	fmt.Print("Enter current master password: ")
	currentPassword := readPassword()
	currentPassword = strings.TrimSpace(currentPassword)
	currentPasswordBytes := []byte(currentPassword)
	defer crypto.SecureZero(currentPasswordBytes)

	if currentPassword == "" {
		fmt.Println("❌ Password cannot be empty!")
		return
	}

	// Verify current password is correct
	currentVault, err := vault.Load(vaultFile)
	if err != nil {
		fmt.Println("❌ Failed to load vault:", err)
		return
	}

	currentSalt, err := base64.StdEncoding.DecodeString(currentVault.Salt)
	if err != nil {
		fmt.Println("❌ Vault data corrupted (invalid salt).")
		return
	}
	defer crypto.SecureZero(currentSalt)

	currentKEK := crypto.DeriveKEK(currentPasswordBytes, currentSalt)
	defer crypto.SecureZero(currentKEK)

	wrappedDEK, err := base64.StdEncoding.DecodeString(currentVault.WrappedDEK)
	if err != nil {
		fmt.Println("❌ Vault data corrupted (invalid wrapped DEK).")
		return
	}

	verifiedDEK, err := crypto.UnwrapKey(currentKEK, wrappedDEK)
	if err != nil {
		fmt.Println("❌ Current password is incorrect!")
		return
	}
	defer crypto.SecureZero(verifiedDEK)

	// Prompt for new password
	fmt.Println("\nNew password requirements:")
	fmt.Println("• At least 12 characters")
	fmt.Println("• Uppercase and lowercase letters")
	fmt.Println("• Numbers and symbols")
	fmt.Println()

	var newPassword string
	for {
		fmt.Print("Enter new master password: ")
		newPassword = readPassword()
		newPassword = strings.TrimSpace(newPassword)
		newPasswordBytes := []byte(newPassword)
		defer crypto.SecureZero(newPasswordBytes)

		if newPassword == "" {
			fmt.Println("❌ Password cannot be empty!")
			continue
		}

		if newPassword == currentPassword {
			fmt.Println("❌ New password must be different from current password!")
			continue
		}

		// Check password strength
		strength, score := scorePassword(newPassword)
		fmt.Printf("Password strength: %s (%.0f%%)\n", strength, score*100)

		if score < 0.8 {
			fmt.Println("❌ Password too weak. Please use a stronger password.")
			continue
		}

		fmt.Print("Confirm new master password: ")
		confirmPassword := readPassword()
		confirmPassword = strings.TrimSpace(confirmPassword)

		if newPassword != confirmPassword {
			fmt.Println("❌ Passwords do not match!")
			continue
		}

		break
	}

	// Change master password
	err = v.ChangeMasterPassword([]byte(newPassword), verifiedDEK, vaultFile)
	if err != nil {
		fmt.Println("❌ Failed to change password:", err)
		return
	}

	fmt.Println("✅ Master password changed successfully!")
}

// ------------------- SETTINGS -------------------

// settingsMenu displays and manages application settings
func settingsMenu() {
	fmt.Println("\n========================================")
	fmt.Println("           SETTINGS")
	fmt.Println("========================================")
	fmt.Printf("Current password generation length: %d characters\n", passwordLength)
	fmt.Println("========================================")
	fmt.Println("1. Change password generation length")
	fmt.Println("2. Back to main menu")
	fmt.Print("Choose an option: ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		fmt.Println("\nPassword length options:")
		fmt.Println("1. 12 characters")
		fmt.Println("2. 16 characters (default)")
		fmt.Println("3. 24 characters")
		fmt.Println("4. 32 characters")
		fmt.Print("Choose option: ")

		lengthChoice, _ := reader.ReadString('\n')
		lengthChoice = strings.TrimSpace(lengthChoice)

		switch lengthChoice {
		case "1":
			passwordLength = 12
		case "2":
			passwordLength = 16
		case "3":
			passwordLength = 24
		case "4":
			passwordLength = 32
		default:
			fmt.Println("❌ Invalid option!")
			return
		}

		fmt.Printf("✅ Password generation length set to %d characters\n", passwordLength)
	case "2":
		return
	default:
		fmt.Println("❌ Invalid option!")
	}
}

// ------------------- UTILITY FUNCTIONS -------------------

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

// scorePassword evaluates password strength and returns a description and score (0.0-1.0)
// Score is based on: length, uppercase, lowercase, digits, and symbols
func scorePassword(password string) (string, float64) {
	length := len(password)
	score := 0.0

	// Length scoring
	if length >= 12 {
		score += 1.0
	} else if length >= 8 {
		score += 0.5
	}

	// Character variety scoring
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

	// Normalize score to 0.0-1.0 range
	normalized := score / 4.5
	if normalized > 1.0 {
		normalized = 1.0
	}

	// Determine strength description
	switch {
	case normalized >= 0.8 && length >= 12:
		return "Strong", normalized
	case normalized >= 0.5:
		return "Decent", normalized
	default:
		return "Very Weak", normalized
	}
}

// readPassword reads a password from stdin without echoing it to the console
// This provides better security when entering passwords
func readPassword() string {
	// For now, we'll just read normally
	// In a production CLI, you'd use a library like golang.org/x/term for proper password input
	password, _ := reader.ReadString('\n')
	return strings.TrimSpace(password)
}
