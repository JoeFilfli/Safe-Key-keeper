package crypto

// Package crypto provides cryptographic interfaces for algorithm abstraction.
// Enables future migration to post-quantum algorithms without code changes.

// KeyDerivationFunction derives keys from passwords. (Current: Argon2id)
type KeyDerivationFunction interface {
	DeriveKey(password []byte, salt []byte, keyLen int) []byte
	GetName() string
	GetVersion() string
}

// SymmetricCipher provides authenticated encryption. (Current: AES-256-GCM)
// Returns: [nonce || ciphertext || auth_tag]
type SymmetricCipher interface {
	Encrypt(key []byte, plaintext []byte) ([]byte, error)
	Decrypt(key []byte, ciphertext []byte) ([]byte, error)
	GetName() string
	NonceSize() int
	KeySize() int
}

// RandomGenerator generates cryptographically secure random bytes. (Current: crypto/rand)
type RandomGenerator interface {
	GenerateBytes(n int) ([]byte, error)
	GetName() string
}

// CryptoProvider factory for swapping entire crypto suites.
type CryptoProvider interface {
	GetKDF() KeyDerivationFunction
	GetCipher() SymmetricCipher
	GetRNG() RandomGenerator
	GetName() string
	GetVersion() string
}

// AlgorithmMetadata tracks which algorithms encrypted the vault.
// Enables algorithm migration and version tracking.
type AlgorithmMetadata struct {
	KDFAlgorithm    string `json:"kdf_algorithm"`
	KDFVersion      string `json:"kdf_version"`
	CipherAlgorithm string `json:"cipher_algorithm"`
	CipherVersion   string `json:"cipher_version"`
	Created         int64  `json:"created"`
}

