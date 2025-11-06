package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

// TestDecryptEntryTampering verifies that decryption fails when ciphertext is tampered with.
// This ensures that GCM authentication is working properly and detects any modifications.
func TestDecryptEntryTampering(t *testing.T) {
	// Generate a DEK for testing
	dek, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatal("failed to generate DEK:", err)
	}

	// Original plaintext
	plaintext := []byte("sensitive password data")

	// Encrypt the plaintext
	ciphertext, err := EncryptEntry(dek, plaintext)
	if err != nil {
		t.Fatal("encryption failed:", err)
	}

	// Test 1: Normal decryption should succeed
	t.Run("Normal decryption succeeds", func(t *testing.T) {
		decrypted, err := DecryptEntry(dek, ciphertext)
		if err != nil {
			t.Fatalf("expected successful decryption, got error: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("decrypted data doesn't match original.\nWant: %s\nGot: %s", plaintext, decrypted)
		}
	})

	// Test 2: Tamper with last byte (authentication tag)
	t.Run("Tampering with auth tag fails", func(t *testing.T) {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		// Flip last byte (part of authentication tag)
		tampered[len(tampered)-1] ^= 0xFF

		_, err := DecryptEntry(dek, tampered)
		if err == nil {
			t.Fatal("expected decryption error for tampered auth tag, but got success")
		}
		t.Logf("✓ Correctly detected tampering: %v", err)
	})

	// Test 3: Tamper with middle byte (ciphertext)
	t.Run("Tampering with ciphertext fails", func(t *testing.T) {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		// Flip a byte in the middle (in the ciphertext portion)
		middleIndex := len(tampered) / 2
		tampered[middleIndex] ^= 0xFF

		_, err := DecryptEntry(dek, tampered)
		if err == nil {
			t.Fatal("expected decryption error for tampered ciphertext, but got success")
		}
		t.Logf("✓ Correctly detected tampering: %v", err)
	})

	// Test 4: Truncate ciphertext
	t.Run("Truncated ciphertext fails", func(t *testing.T) {
		truncated := ciphertext[:len(ciphertext)-5]

		_, err := DecryptEntry(dek, truncated)
		if err == nil {
			t.Fatal("expected decryption error for truncated ciphertext, but got success")
		}
		t.Logf("✓ Correctly detected truncation: %v", err)
	})

	// Test 5: Empty ciphertext
	t.Run("Empty ciphertext fails", func(t *testing.T) {
		_, err := DecryptEntry(dek, []byte{})
		if err == nil {
			t.Fatal("expected decryption error for empty ciphertext, but got success")
		}
		t.Logf("✓ Correctly rejected empty ciphertext: %v", err)
	})

	// Test 6: Wrong DEK
	t.Run("Wrong DEK fails", func(t *testing.T) {
		wrongDEK, _ := GenerateRandomBytes(32)
		_, err := DecryptEntry(wrongDEK, ciphertext)
		if err == nil {
			t.Fatal("expected decryption error for wrong DEK, but got success")
		}
		t.Logf("✓ Correctly rejected wrong DEK: %v", err)
	})
}

// TestUnwrapKeyTampering verifies that unwrapping fails when wrapped DEK is tampered with.
func TestUnwrapKeyTampering(t *testing.T) {
	// Generate KEK and DEK
	salt, _ := GenerateRandomBytes(16)
	password := []byte("test-master-password-123!")
	kek := DeriveKEK(password, salt)
	
	dek, _ := GenerateRandomBytes(32)

	// Wrap the DEK
	wrappedDEK, err := WrapKey(kek, dek)
	if err != nil {
		t.Fatal("failed to wrap DEK:", err)
	}

	// Test 1: Normal unwrapping should succeed
	t.Run("Normal unwrapping succeeds", func(t *testing.T) {
		unwrapped, err := UnwrapKey(kek, wrappedDEK)
		if err != nil {
			t.Fatalf("expected successful unwrapping, got error: %v", err)
		}
		if !bytes.Equal(unwrapped, dek) {
			t.Fatal("unwrapped DEK doesn't match original")
		}
	})

	// Test 2: Tamper with wrapped DEK
	t.Run("Tampering with wrapped DEK fails", func(t *testing.T) {
		tampered := make([]byte, len(wrappedDEK))
		copy(tampered, wrappedDEK)
		tampered[len(tampered)-1] ^= 0xFF

		_, err := UnwrapKey(kek, tampered)
		if err == nil {
			t.Fatal("expected unwrap error for tampered wrapped DEK, but got success")
		}
		t.Logf("✓ Correctly detected tampering: %v", err)
	})

	// Test 3: Wrong KEK (wrong password)
	t.Run("Wrong KEK fails", func(t *testing.T) {
		wrongPassword := []byte("wrong-password")
		wrongKEK := DeriveKEK(wrongPassword, salt)

		_, err := UnwrapKey(wrongKEK, wrappedDEK)
		if err == nil {
			t.Fatal("expected unwrap error for wrong KEK, but got success")
		}
		t.Logf("✓ Correctly rejected wrong password: %v", err)
	})
}

// TestEncryptDecryptEntry verifies basic encrypt/decrypt functionality.
func TestEncryptDecryptEntry(t *testing.T) {
	dek, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatal("failed to generate DEK:", err)
	}

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"Empty string", ""},
		{"Short password", "test123"},
		{"Long password", "this-is-a-very-long-password-with-lots-of-characters-1234567890!@#$%^&*()"},
		{"Special characters", "P@ssw0rd!#$%^&*()_+-=[]{}|;:',.<>?/~`"},
		{"Unicode", "パスワード密码🔐"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := EncryptEntry(dek, []byte(tc.plaintext))
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			// Verify ciphertext is different from plaintext (unless empty)
			if len(tc.plaintext) > 0 && bytes.Equal(ciphertext, []byte(tc.plaintext)) {
				t.Fatal("ciphertext should not match plaintext")
			}

			// Decrypt
			decrypted, err := DecryptEntry(dek, ciphertext)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			// Verify plaintext matches
			if string(decrypted) != tc.plaintext {
				t.Fatalf("decrypted text doesn't match.\nWant: %s\nGot: %s", tc.plaintext, decrypted)
			}
		})
	}
}

// TestWrapUnwrapKey verifies basic key wrapping functionality.
func TestWrapUnwrapKey(t *testing.T) {
	// Generate password and salt
	password := []byte("my-secure-master-password-2024!")
	salt, err := GenerateRandomBytes(16)
	if err != nil {
		t.Fatal("failed to generate salt:", err)
	}

	// Derive KEK
	kek := DeriveKEK(password, salt)

	// Generate DEK
	dek, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatal("failed to generate DEK:", err)
	}

	// Wrap DEK
	wrapped, err := WrapKey(kek, dek)
	if err != nil {
		t.Fatalf("failed to wrap key: %v", err)
	}

	// Verify wrapped is different from original DEK
	if bytes.Equal(wrapped, dek) {
		t.Fatal("wrapped DEK should not match original DEK")
	}

	// Unwrap DEK
	unwrapped, err := UnwrapKey(kek, wrapped)
	if err != nil {
		t.Fatalf("failed to unwrap key: %v", err)
	}

	// Verify unwrapped matches original
	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("unwrapped DEK doesn't match original")
	}
}

// TestGenerateRandomBytes verifies random byte generation.
func TestGenerateRandomBytes(t *testing.T) {
	// Test various sizes
	sizes := []int{16, 32, 64, 128}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			bytes1, err := GenerateRandomBytes(size)
			if err != nil {
				t.Fatalf("failed to generate random bytes: %v", err)
			}

			if len(bytes1) != size {
				t.Fatalf("expected %d bytes, got %d", size, len(bytes1))
			}

			// Generate second set and verify they're different (extremely unlikely to be same)
			bytes2, err := GenerateRandomBytes(size)
			if err != nil {
				t.Fatalf("failed to generate second set of random bytes: %v", err)
			}

			if bytes.Equal(bytes1, bytes2) {
				t.Fatal("two random byte slices should not be equal (entropy issue?)")
			}
		})
	}
}

// TestGenerateSecurePassword verifies password generation.
func TestGenerateSecurePassword(t *testing.T) {
	testCases := []struct {
		name      string
		length    int
		shouldErr bool
	}{
		{"Valid 12 chars", 12, false},
		{"Valid 16 chars", 16, false},
		{"Valid 24 chars", 24, false},
		{"Valid 32 chars", 32, false},
		{"Invalid too short", 8, true},
		{"Invalid too short", 11, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			password, err := GenerateSecurePassword(tc.length)

			if tc.shouldErr {
				if err == nil {
					t.Fatal("expected error for invalid length, but got success")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(password) != tc.length {
				t.Fatalf("expected password length %d, got %d", tc.length, len(password))
			}

			// Verify password has required character types
			hasUpper, hasLower, hasDigit, hasSymbol := false, false, false, false
			for _, c := range password {
				switch {
				case c >= 'A' && c <= 'Z':
					hasUpper = true
				case c >= 'a' && c <= 'z':
					hasLower = true
				case c >= '0' && c <= '9':
					hasDigit = true
				default:
					hasSymbol = true
				}
			}

			if !hasUpper {
				t.Fatal("password missing uppercase letter")
			}
			if !hasLower {
				t.Fatal("password missing lowercase letter")
			}
			if !hasDigit {
				t.Fatal("password missing digit")
			}
			if !hasSymbol {
				t.Fatal("password missing symbol")
			}
		})
	}
}

