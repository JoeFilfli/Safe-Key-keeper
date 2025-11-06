package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

// TestSecureZero verifies that SecureZero properly overwrites memory.
func TestSecureZero(t *testing.T) {
	t.Run("Zero empty slice", func(t *testing.T) {
		data := []byte{}
		SecureZero(data)
		// Should not panic
	})

	t.Run("Zero single byte", func(t *testing.T) {
		data := []byte{0xFF}
		SecureZero(data)
		if data[0] != 0 {
			t.Errorf("expected byte to be zeroed, got 0x%02X", data[0])
		}
	})

	t.Run("Zero multiple bytes", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0xFF, 0xFE, 0xFD}
		SecureZero(data)
		
		for i, b := range data {
			if b != 0 {
				t.Errorf("byte %d not zeroed: got 0x%02X", i, b)
			}
		}
	})

	t.Run("Zero sensitive data", func(t *testing.T) {
		password := []byte("super-secret-password-12345")
		original := make([]byte, len(password))
		copy(original, password)
		
		// Verify password has data before zeroing
		if bytes.Equal(password, make([]byte, len(password))) {
			t.Fatal("password should not be zeros before SecureZero")
		}
		
		SecureZero(password)
		
		// Verify all bytes are zero
		for i, b := range password {
			if b != 0 {
				t.Errorf("password byte %d not zeroed: got 0x%02X (was 0x%02X)", 
					i, b, original[i])
			}
		}
	})

	t.Run("Zero DEK-sized slice", func(t *testing.T) {
		dek := make([]byte, 32)
		// Fill with non-zero data
		for i := range dek {
			dek[i] = byte(i + 1)
		}
		
		SecureZero(dek)
		
		expected := make([]byte, 32) // All zeros
		if !bytes.Equal(dek, expected) {
			t.Error("DEK not fully zeroed")
		}
	})
}

// TestSecureZeroMultiple verifies zeroing multiple slices at once.
func TestSecureZeroMultiple(t *testing.T) {
	t.Run("Zero multiple slices", func(t *testing.T) {
		slice1 := []byte{0x01, 0x02, 0x03}
		slice2 := []byte{0xFF, 0xFE, 0xFD}
		slice3 := []byte("sensitive data")
		
		SecureZeroMultiple(slice1, slice2, slice3)
		
		// Verify all slices are zeroed
		for i, b := range slice1 {
			if b != 0 {
				t.Errorf("slice1[%d] not zeroed", i)
			}
		}
		for i, b := range slice2 {
			if b != 0 {
				t.Errorf("slice2[%d] not zeroed", i)
			}
		}
		for i, b := range slice3 {
			if b != 0 {
				t.Errorf("slice3[%d] not zeroed", i)
			}
		}
	})

	t.Run("Zero no slices", func(t *testing.T) {
		// Should not panic
		SecureZeroMultiple()
	})

	t.Run("Zero mixed size slices", func(t *testing.T) {
		small := []byte{0xFF}
		medium := make([]byte, 32)
		large := make([]byte, 1024)
		
		for i := range medium {
			medium[i] = 0xAA
		}
		for i := range large {
			large[i] = 0xBB
		}
		
		SecureZeroMultiple(small, medium, large)
		
		// Verify all are zero
		if small[0] != 0 {
			t.Error("small slice not zeroed")
		}
		for _, b := range medium {
			if b != 0 {
				t.Error("medium slice not fully zeroed")
				break
			}
		}
		for _, b := range large {
			if b != 0 {
				t.Error("large slice not fully zeroed")
				break
			}
		}
	})
}

// TestSecureCompare verifies constant-time comparison.
func TestSecureCompare(t *testing.T) {
	testCases := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{
			name:     "Equal empty slices",
			a:        []byte{},
			b:        []byte{},
			expected: true,
		},
		{
			name:     "Equal single byte",
			a:        []byte{0x42},
			b:        []byte{0x42},
			expected: true,
		},
		{
			name:     "Equal multiple bytes",
			a:        []byte{0x01, 0x02, 0x03, 0x04},
			b:        []byte{0x01, 0x02, 0x03, 0x04},
			expected: true,
		},
		{
			name:     "Different lengths",
			a:        []byte{0x01, 0x02},
			b:        []byte{0x01, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "Different at start",
			a:        []byte{0x01, 0x02, 0x03},
			b:        []byte{0xFF, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "Different at end",
			a:        []byte{0x01, 0x02, 0x03},
			b:        []byte{0x01, 0x02, 0xFF},
			expected: false,
		},
		{
			name:     "Different in middle",
			a:        []byte{0x01, 0x02, 0x03},
			b:        []byte{0x01, 0xFF, 0x03},
			expected: false,
		},
		{
			name:     "Completely different",
			a:        []byte{0x00, 0x00, 0x00},
			b:        []byte{0xFF, 0xFF, 0xFF},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := SecureCompare(tc.a, tc.b)
			if result != tc.expected {
				t.Errorf("SecureCompare(%v, %v) = %v, want %v",
					tc.a, tc.b, result, tc.expected)
			}
		})
	}
}

// TestSecureZeroDefer verifies that defer works correctly with SecureZero.
func TestSecureZeroDefer(t *testing.T) {
	t.Run("Defer zeroing in function", func(t *testing.T) {
		var capturedPassword []byte
		
		// Function that uses defer
		usePassword := func() {
			password := []byte("secret-password")
			defer SecureZero(password)
			
			// Capture reference to verify zeroing after return
			capturedPassword = password
			
			// Simulate using password
			_ = len(password)
		}
		
		// Call function
		usePassword()
		
		// Verify password was zeroed after function returned
		for i, b := range capturedPassword {
			if b != 0 {
				t.Errorf("password byte %d not zeroed after defer: 0x%02X", i, b)
			}
		}
	})
}

// BenchmarkSecureZero measures performance of zeroing operation.
func BenchmarkSecureZero(b *testing.B) {
	sizes := []int{16, 32, 64, 256, 1024, 4096}
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			// Fill with non-zero data
			for i := range data {
				data[i] = byte(i)
			}
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				SecureZero(data)
			}
		})
	}
}

// BenchmarkSecureCompare measures performance of constant-time comparison.
func BenchmarkSecureCompare(b *testing.B) {
	sizes := []int{16, 32, 64, 256}
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			a := make([]byte, size)
			b_slice := make([]byte, size)
			
			// Make them equal
			for i := range a {
				a[i] = byte(i)
				b_slice[i] = byte(i)
			}
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = SecureCompare(a, b_slice)
			}
		})
	}
}

