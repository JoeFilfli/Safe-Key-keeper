package crypto

import (
	"runtime"
)

// SecureZero overwrites a byte slice with zeros to clear sensitive data from memory.
// Uses runtime.KeepAlive() to prevent compiler optimization. Defense-in-depth only.
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b) // Prevent optimization
}

// SecureZeroMultiple zeros multiple byte slices.
func SecureZeroMultiple(slices ...[]byte) {
	for _, slice := range slices {
		SecureZero(slice)
	}
}

// SecureCompare performs constant-time comparison to prevent timing attacks.
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	
	return diff == 0
}

