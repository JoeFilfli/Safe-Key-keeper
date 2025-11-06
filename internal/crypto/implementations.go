package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2idKDF implements memory-hard key derivation.
// Resistant to GPU/ASIC/side-channel attacks. Quantum-safe.
type Argon2idKDF struct {
	Time    uint32 // Iterations (CPU cost)
	Memory  uint32 // Memory usage in KiB
	Threads uint8  // Parallelism
}

// NewArgon2idKDF creates KDF with default params (t=3, m=64MiB, p=4).
func NewArgon2idKDF() *Argon2idKDF {
	return &Argon2idKDF{
		Time:    3,
		Memory:  64 * 1024, // 64 MiB
		Threads: 4,
	}
}

func (a *Argon2idKDF) DeriveKey(password []byte, salt []byte, keyLen int) []byte {
	return argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, uint32(keyLen))
}

func (a *Argon2idKDF) GetName() string {
	return "Argon2id"
}

func (a *Argon2idKDF) GetVersion() string {
	return fmt.Sprintf("t=%d,m=%d,p=%d", a.Time, a.Memory, a.Threads)
}

// AES256GCM implements authenticated encryption (AES-256-GCM).
// Provides confidentiality + authenticity + integrity. 128-bit post-quantum security.
type AES256GCM struct{}

func NewAES256GCM() *AES256GCM {
	return &AES256GCM{}
}

// Encrypt returns [nonce || ciphertext || auth_tag].
func (a *AES256GCM) Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt verifies authentication then decrypts.
func (a *AES256GCM) Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return plaintext, nil
}

func (a *AES256GCM) GetName() string {
	return "AES-256-GCM"
}

func (a *AES256GCM) NonceSize() int {
	return 12
}

func (a *AES256GCM) KeySize() int {
	return 32
}

// SystemRNG uses OS CSPRNG (crypto/rand). Quantum-safe.
type SystemRNG struct{}

func NewSystemRNG() *SystemRNG {
	return &SystemRNG{}
}

func (s *SystemRNG) GenerateBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid byte count: %d", n)
	}

	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return b, nil
}

func (s *SystemRNG) GetName() string {
	return "crypto/rand"
}

// DefaultCryptoProvider bundles Argon2id + AES-256-GCM + crypto/rand.
type DefaultCryptoProvider struct {
	kdf    KeyDerivationFunction
	cipher SymmetricCipher
	rng    RandomGenerator
}

func NewDefaultCryptoProvider() *DefaultCryptoProvider {
	return &DefaultCryptoProvider{
		kdf:    NewArgon2idKDF(),
		cipher: NewAES256GCM(),
		rng:    NewSystemRNG(),
	}
}

func (d *DefaultCryptoProvider) GetKDF() KeyDerivationFunction {
	return d.kdf
}

func (d *DefaultCryptoProvider) GetCipher() SymmetricCipher {
	return d.cipher
}

func (d *DefaultCryptoProvider) GetRNG() RandomGenerator {
	return d.rng
}

func (d *DefaultCryptoProvider) GetName() string {
	return "Classical Cryptography"
}

func (d *DefaultCryptoProvider) GetVersion() string {
	return "v1.0"
}

// defaultProvider is the global crypto provider. Swap with SetCryptoProvider().
var defaultProvider CryptoProvider = NewDefaultCryptoProvider()

func GetCryptoProvider() CryptoProvider {
	return defaultProvider
}

// SetCryptoProvider swaps the global crypto suite (e.g., for post-quantum migration).
func SetCryptoProvider(provider CryptoProvider) {
	defaultProvider = provider
}

// Backward compatibility functions. Delegate to current provider.

func DeriveKEKWithProvider(password []byte, salt []byte) []byte {
	return GetCryptoProvider().GetKDF().DeriveKey(password, salt, 32)
}

func EncryptWithProvider(key []byte, plaintext []byte) ([]byte, error) {
	return GetCryptoProvider().GetCipher().Encrypt(key, plaintext)
}

func DecryptWithProvider(key []byte, ciphertext []byte) ([]byte, error) {
	return GetCryptoProvider().GetCipher().Decrypt(key, ciphertext)
}

func GenerateRandomBytesWithProvider(n int) ([]byte, error) {
	return GetCryptoProvider().GetRNG().GenerateBytes(n)
}

