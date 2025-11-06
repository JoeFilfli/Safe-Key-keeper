package vault

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"Crypto-Project/internal/crypto"
)

// TestVaultHMAC_SaveAndLoad verifies HMAC is computed and verified correctly.
func TestVaultHMAC_SaveAndLoad(t *testing.T) {
	// Setup
	password := []byte("test-password-123")
	salt, _ := crypto.GenerateRandomBytes(16)
	kek := crypto.DeriveKEK(password, salt)
	defer crypto.SecureZero(kek)
	
	dek, _ := crypto.GenerateRandomBytes(32)
	wrappedDEK, _ := crypto.WrapKey(kek, dek)
	
	// Create test vault
	vault := &Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Entries: []Entry{
			{
				Service:    "test-service",
				Username:   "test-user",
				Password:   "test-pass",
				Notes:      "test-notes",
				CreatedAt:  1234567890,
				ModifiedAt: 1234567890,
			},
		},
	}
	
	filename := "test_vault_hmac.json"
	defer os.Remove(filename)
	
	// Test: Save with HMAC
	err := vault.SaveWithHMAC(filename, kek)
	if err != nil {
		t.Fatalf("SaveWithHMAC failed: %v", err)
	}
	
	// Verify HMAC field was added
	if vault.HMAC == "" {
		t.Fatal("HMAC field is empty after SaveWithHMAC")
	}
	
	// Test: Load and verify HMAC
	loadedVault, err := LoadAndVerifyHMAC(filename, kek)
	if err != nil {
		t.Fatalf("LoadAndVerifyHMAC failed: %v", err)
	}
	
	// Verify vault data matches
	if loadedVault.Salt != vault.Salt {
		t.Error("Salt mismatch after load")
	}
	if loadedVault.WrappedDEK != vault.WrappedDEK {
		t.Error("WrappedDEK mismatch after load")
	}
	if len(loadedVault.Entries) != len(vault.Entries) {
		t.Error("Entry count mismatch after load")
	}
}

// TestVaultHMAC_TamperDetection verifies tampering is detected.
func TestVaultHMAC_TamperDetection(t *testing.T) {
	// Setup
	password := []byte("test-password-123")
	salt, _ := crypto.GenerateRandomBytes(16)
	kek := crypto.DeriveKEK(password, salt)
	defer crypto.SecureZero(kek)
	
	dek, _ := crypto.GenerateRandomBytes(32)
	wrappedDEK, _ := crypto.WrapKey(kek, dek)
	
	vault := &Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Entries: []Entry{
			{
				Service:    "original-service",
				Username:   "original-user",
				Password:   "original-pass",
				Notes:      "original-notes",
				CreatedAt:  1234567890,
				ModifiedAt: 1234567890,
			},
		},
	}
	
	filename := "test_vault_tamper.json"
	defer os.Remove(filename)
	
	// Save with HMAC
	err := vault.SaveWithHMAC(filename, kek)
	if err != nil {
		t.Fatalf("SaveWithHMAC failed: %v", err)
	}
	
	// Test 1: Tamper with service field
	t.Run("Tamper with service field", func(t *testing.T) {
		// Load vault file
		data, _ := os.ReadFile(filename)
		var tamperedVault Vault
		json.Unmarshal(data, &tamperedVault)
		
		// Modify service field
		tamperedVault.Entries[0].Service = "tampered-service"
		
		// Save tampered vault (keeping original HMAC)
		tamperedData, _ := json.MarshalIndent(tamperedVault, "", "  ")
		os.WriteFile(filename, tamperedData, 0600)
		
		// Try to load - should fail
		_, err := LoadAndVerifyHMAC(filename, kek)
		if err == nil {
			t.Fatal("Expected HMAC verification to fail for tampered service, but it passed")
		}
		if err.Error() != "HMAC mismatch: vault has been tampered with" {
			t.Errorf("Expected 'HMAC mismatch' error, got: %v", err)
		}
		
		// Restore original vault for next test
		vault.SaveWithHMAC(filename, kek)
	})
	
	// Test 2: Tamper with timestamp
	t.Run("Tamper with timestamp", func(t *testing.T) {
		// Load vault file
		data, _ := os.ReadFile(filename)
		var tamperedVault Vault
		json.Unmarshal(data, &tamperedVault)
		
		// Modify timestamp
		tamperedVault.Entries[0].CreatedAt = 9999999999
		
		// Save tampered vault (keeping original HMAC)
		tamperedData, _ := json.MarshalIndent(tamperedVault, "", "  ")
		os.WriteFile(filename, tamperedData, 0600)
		
		// Try to load - should fail
		_, err := LoadAndVerifyHMAC(filename, kek)
		if err == nil {
			t.Fatal("Expected HMAC verification to fail for tampered timestamp, but it passed")
		}
		
		// Restore original vault
		vault.SaveWithHMAC(filename, kek)
	})
	
	// Test 3: Tamper with Salt
	t.Run("Tamper with salt", func(t *testing.T) {
		// Load vault file
		data, _ := os.ReadFile(filename)
		var tamperedVault Vault
		json.Unmarshal(data, &tamperedVault)
		
		// Modify salt
		tamperedVault.Salt = "AAAABBBBCCCCDDDD"
		
		// Save tampered vault (keeping original HMAC)
		tamperedData, _ := json.MarshalIndent(tamperedVault, "", "  ")
		os.WriteFile(filename, tamperedData, 0600)
		
		// Try to load - should fail
		_, err := LoadAndVerifyHMAC(filename, kek)
		if err == nil {
			t.Fatal("Expected HMAC verification to fail for tampered salt, but it passed")
		}
		
		// Restore original vault
		vault.SaveWithHMAC(filename, kek)
	})
	
	// Test 4: Tamper with WrappedDEK
	t.Run("Tamper with wrappedDEK", func(t *testing.T) {
		// Load vault file
		data, _ := os.ReadFile(filename)
		var tamperedVault Vault
		json.Unmarshal(data, &tamperedVault)
		
		// Modify wrappedDEK
		tamperedVault.WrappedDEK = "AAAA" + tamperedVault.WrappedDEK[4:]
		
		// Save tampered vault (keeping original HMAC)
		tamperedData, _ := json.MarshalIndent(tamperedVault, "", "  ")
		os.WriteFile(filename, tamperedData, 0600)
		
		// Try to load - should fail
		_, err := LoadAndVerifyHMAC(filename, kek)
		if err == nil {
			t.Fatal("Expected HMAC verification to fail for tampered wrappedDEK, but it passed")
		}
		
		// Restore original vault
		vault.SaveWithHMAC(filename, kek)
	})
	
	// Test 5: Remove HMAC field
	t.Run("Remove HMAC field", func(t *testing.T) {
		// Load vault file
		data, _ := os.ReadFile(filename)
		var tamperedVault Vault
		json.Unmarshal(data, &tamperedVault)
		
		// Remove HMAC
		tamperedVault.HMAC = ""
		
		// Save tampered vault
		tamperedData, _ := json.MarshalIndent(tamperedVault, "", "  ")
		os.WriteFile(filename, tamperedData, 0600)
		
		// Try to load - should fail
		_, err := LoadAndVerifyHMAC(filename, kek)
		if err == nil {
			t.Fatal("Expected HMAC verification to fail for missing HMAC, but it passed")
		}
		if err.Error() != "HMAC field is missing (vault may be from older version)" {
			t.Errorf("Expected 'HMAC field is missing' error, got: %v", err)
		}
		
		// Restore original vault
		vault.SaveWithHMAC(filename, kek)
	})
	
	// Test 6: Corrupt HMAC value
	t.Run("Corrupt HMAC value", func(t *testing.T) {
		// Load vault file
		data, _ := os.ReadFile(filename)
		var tamperedVault Vault
		json.Unmarshal(data, &tamperedVault)
		
		// Corrupt HMAC
		tamperedVault.HMAC = "invalid-base64-!@#$"
		
		// Save tampered vault
		tamperedData, _ := json.MarshalIndent(tamperedVault, "", "  ")
		os.WriteFile(filename, tamperedData, 0600)
		
		// Try to load - should fail
		_, err := LoadAndVerifyHMAC(filename, kek)
		if err == nil {
			t.Fatal("Expected HMAC verification to fail for corrupted HMAC, but it passed")
		}
	})
}

// TestVaultHMAC_WrongPassword verifies that wrong password is detected.
func TestVaultHMAC_WrongPassword(t *testing.T) {
	// Setup with correct password
	correctPassword := []byte("correct-password")
	salt, _ := crypto.GenerateRandomBytes(16)
	correctKEK := crypto.DeriveKEK(correctPassword, salt)
	defer crypto.SecureZero(correctKEK)
	
	dek, _ := crypto.GenerateRandomBytes(32)
	wrappedDEK, _ := crypto.WrapKey(correctKEK, dek)
	
	vault := &Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Entries:    []Entry{},
	}
	
	filename := "test_vault_wrong_password.json"
	defer os.Remove(filename)
	
	// Save with correct password
	err := vault.SaveWithHMAC(filename, correctKEK)
	if err != nil {
		t.Fatalf("SaveWithHMAC failed: %v", err)
	}
	
	// Try to load with wrong password
	wrongPassword := []byte("wrong-password")
	wrongKEK := crypto.DeriveKEK(wrongPassword, salt)
	defer crypto.SecureZero(wrongKEK)
	
	_, err = LoadAndVerifyHMAC(filename, wrongKEK)
	if err == nil {
		t.Fatal("Expected HMAC verification to fail with wrong password, but it passed")
	}
	if err.Error() != "HMAC mismatch: vault has been tampered with" {
		t.Errorf("Expected 'HMAC mismatch' error, got: %v", err)
	}
}

// TestVaultHMAC_MultipleEntries tests HMAC with multiple vault entries.
func TestVaultHMAC_MultipleEntries(t *testing.T) {
	password := []byte("test-password")
	salt, _ := crypto.GenerateRandomBytes(16)
	kek := crypto.DeriveKEK(password, salt)
	defer crypto.SecureZero(kek)
	
	dek, _ := crypto.GenerateRandomBytes(32)
	wrappedDEK, _ := crypto.WrapKey(kek, dek)
	
	// Create vault with multiple entries
	vault := &Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Entries: []Entry{
			{Service: "Gmail", Username: "user1", Password: "pass1", Notes: "note1", CreatedAt: 1000, ModifiedAt: 1000},
			{Service: "Facebook", Username: "user2", Password: "pass2", Notes: "note2", CreatedAt: 2000, ModifiedAt: 2000},
			{Service: "Twitter", Username: "user3", Password: "pass3", Notes: "note3", CreatedAt: 3000, ModifiedAt: 3000},
		},
	}
	
	filename := "test_vault_multiple.json"
	defer os.Remove(filename)
	
	// Save with HMAC
	err := vault.SaveWithHMAC(filename, kek)
	if err != nil {
		t.Fatalf("SaveWithHMAC failed: %v", err)
	}
	
	// Load and verify
	loadedVault, err := LoadAndVerifyHMAC(filename, kek)
	if err != nil {
		t.Fatalf("LoadAndVerifyHMAC failed: %v", err)
	}
	
	// Verify all entries
	if len(loadedVault.Entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(loadedVault.Entries))
	}
	
	// Test: Reorder entries (should fail HMAC)
	t.Run("Reorder entries", func(t *testing.T) {
		data, _ := os.ReadFile(filename)
		var tamperedVault Vault
		json.Unmarshal(data, &tamperedVault)
		
		// Swap first two entries
		tamperedVault.Entries[0], tamperedVault.Entries[1] = tamperedVault.Entries[1], tamperedVault.Entries[0]
		
		// Save with original HMAC
		tamperedData, _ := json.MarshalIndent(tamperedVault, "", "  ")
		os.WriteFile(filename, tamperedData, 0600)
		
		// Try to load - should fail
		_, err := LoadAndVerifyHMAC(filename, kek)
		if err == nil {
			t.Fatal("Expected HMAC verification to fail for reordered entries, but it passed")
		}
	})
}

// TestVaultHMAC_EmptyVault tests HMAC with empty vault.
func TestVaultHMAC_EmptyVault(t *testing.T) {
	password := []byte("test-password")
	salt, _ := crypto.GenerateRandomBytes(16)
	kek := crypto.DeriveKEK(password, salt)
	defer crypto.SecureZero(kek)
	
	dek, _ := crypto.GenerateRandomBytes(32)
	wrappedDEK, _ := crypto.WrapKey(kek, dek)
	
	// Create empty vault
	vault := &Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Entries:    []Entry{}, // Empty
	}
	
	filename := "test_vault_empty.json"
	defer os.Remove(filename)
	
	// Save with HMAC
	err := vault.SaveWithHMAC(filename, kek)
	if err != nil {
		t.Fatalf("SaveWithHMAC failed: %v", err)
	}
	
	// Load and verify
	loadedVault, err := LoadAndVerifyHMAC(filename, kek)
	if err != nil {
		t.Fatalf("LoadAndVerifyHMAC failed: %v", err)
	}
	
	if len(loadedVault.Entries) != 0 {
		t.Errorf("Expected 0 entries, got %d", len(loadedVault.Entries))
	}
}

// TestVaultHMAC_BackwardsCompatibility verifies old vaults without HMAC still load.
func TestVaultHMAC_BackwardsCompatibility(t *testing.T) {
	password := []byte("test-password")
	salt, _ := crypto.GenerateRandomBytes(16)
	kek := crypto.DeriveKEK(password, salt)
	defer crypto.SecureZero(kek)
	
	dek, _ := crypto.GenerateRandomBytes(32)
	wrappedDEK, _ := crypto.WrapKey(kek, dek)
	
	// Create vault without HMAC (old format)
	vault := &Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Entries:    []Entry{},
		// HMAC field intentionally omitted
	}
	
	filename := "test_vault_old_format.json"
	defer os.Remove(filename)
	
	// Save using old Save() method (no HMAC)
	err := vault.Save(filename)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	
	// Verify old Load() still works
	_, err = LoadVault(filename)
	if err != nil {
		t.Fatalf("LoadVault failed: %v", err)
	}
	
	// Verify LoadAndVerifyHMAC fails gracefully for old format
	_, err = LoadAndVerifyHMAC(filename, kek)
	if err == nil {
		t.Fatal("Expected error for vault without HMAC, but got success")
	}
	if err.Error() != "HMAC field is missing (vault may be from older version)" {
		t.Errorf("Expected 'HMAC field is missing' error, got: %v", err)
	}
}

