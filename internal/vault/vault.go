package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	"Crypto-Project/internal/crypto"
)

// Entry is a single vault entry. All fields encrypted except timestamps.
type Entry struct {
	Service    string `json:"service"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Notes      string `json:"notes"`
	CreatedAt  int64  `json:"created_at"`
	ModifiedAt int64  `json:"modified_at"`
}

// Vault is the encrypted vault file.
type Vault struct {
	Salt       string  `json:"salt"`              // Base64 salt
	WrappedDEK string  `json:"wrappedDEK"`        // Base64 encrypted DEK
	Entries    []Entry `json:"entries"`
	HMAC       string  `json:"hmac,omitempty"`    // Base64 HMAC-SHA256 (optional for backwards compatibility)
}

func (v *Vault) Save(filename string) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}

func LoadVault(filename string) (*Vault, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// AddEntry encrypts and stores a new entry.
func (v *Vault) AddEntry(service, username, password, notes string, dek []byte) error {
	encService, err := crypto.EncryptEntry(dek, []byte(service))
	if err != nil {
		return err
	}
	encUsername, err := crypto.EncryptEntry(dek, []byte(username))
	if err != nil {
		return err
	}
	encPassword, err := crypto.EncryptEntry(dek, []byte(password))
	if err != nil {
		return err
	}
	encNotes, err := crypto.EncryptEntry(dek, []byte(notes))
	if err != nil {
		return err
	}

	entry := Entry{
		Service:    base64.StdEncoding.EncodeToString(encService),
		Username:   base64.StdEncoding.EncodeToString(encUsername),
		Password:   base64.StdEncoding.EncodeToString(encPassword),
		Notes:      base64.StdEncoding.EncodeToString(encNotes),
		CreatedAt:  time.Now().Unix(),
		ModifiedAt: time.Now().Unix(),
	}

	v.Entries = append(v.Entries, entry)
	return nil
}

// GetEntry decrypts one entry.
func (v *Vault) GetEntry(index int, dek []byte) (service, username, password, notes string, err error) {
	if index < 0 || index >= len(v.Entries) {
		return "", "", "", "", errors.New("invalid entry index")
	}
	e := v.Entries[index]

	decService, _ := base64.StdEncoding.DecodeString(e.Service)
	decUsername, _ := base64.StdEncoding.DecodeString(e.Username)
	decPassword, _ := base64.StdEncoding.DecodeString(e.Password)
	decNotes, _ := base64.StdEncoding.DecodeString(e.Notes)

	serviceBytes, err := crypto.DecryptEntry(dek, decService)
	if err != nil {
		return "", "", "", "", err
	}

	usernameBytes, err := crypto.DecryptEntry(dek, decUsername)
	if err != nil {
		return "", "", "", "", err
	}

	passwordBytes, err := crypto.DecryptEntry(dek, decPassword)
	if err != nil {
		return "", "", "", "", err
	}

	notesBytes, err := crypto.DecryptEntry(dek, decNotes)
	if err != nil {
		return "", "", "", "", err
	}

	return string(serviceBytes), string(usernameBytes), string(passwordBytes), string(notesBytes), nil
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func Load(filename string) (*Vault, error) {
	return LoadVault(filename)
}

// SaveVault creates a new vault file (first-time setup).
func SaveVault(filename string, entries []Entry, salt []byte, wrappedDEK []byte) error {
	v := Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Entries:    entries,
	}
	return v.Save(filename)
}

// ChangeMasterPassword re-wraps the DEK with a new KEK and saves with HMAC.
func (v *Vault) ChangeMasterPassword(newPassword []byte, dek []byte, filename string) error {
	newSalt, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return errors.New("failed to generate new salt")
	}

	newKEK := crypto.DeriveKEK(newPassword, newSalt)
	defer crypto.SecureZero(newKEK)

	newWrappedDEK, err := crypto.WrapKey(newKEK, dek)
	if err != nil {
		return errors.New("failed to wrap DEK with new password")
	}

	v.Salt = base64.StdEncoding.EncodeToString(newSalt)
	v.WrappedDEK = base64.StdEncoding.EncodeToString(newWrappedDEK)

	// Save with HMAC using the new KEK
	return v.SaveWithHMAC(filename, newKEK)
}

// computeHMAC calculates HMAC-SHA256 of vault structure (excluding HMAC field).
// Uses KEK as HMAC key. Detects tampering with metadata, entry order, timestamps.
func (v *Vault) computeHMAC(kek []byte) (string, error) {
	vaultCopy := Vault{
		Salt:       v.Salt,
		WrappedDEK: v.WrappedDEK,
		Entries:    v.Entries,
	}

	data, err := json.Marshal(vaultCopy)
	if err != nil {
		return "", err
	}

	h := hmac.New(sha256.New, kek)
	h.Write(data)
	hmacBytes := h.Sum(nil)

	return base64.StdEncoding.EncodeToString(hmacBytes), nil
}

// verifyHMAC checks stored HMAC matches computed HMAC. Uses constant-time comparison.
func (v *Vault) verifyHMAC(kek []byte) error {
	if v.HMAC == "" {
		return errors.New("HMAC field is missing (vault may be from older version)")
	}

	storedHMAC, err := base64.StdEncoding.DecodeString(v.HMAC)
	if err != nil {
		return errors.New("stored HMAC is invalid (not valid base64)")
	}

	expectedHMACStr, err := v.computeHMAC(kek)
	if err != nil {
		return err
	}

	expectedHMAC, err := base64.StdEncoding.DecodeString(expectedHMACStr)
	if err != nil {
		return err
	}

	if !hmac.Equal(storedHMAC, expectedHMAC) {
		return errors.New("HMAC mismatch: vault has been tampered with")
	}

	return nil
}

// SaveWithHMAC saves vault with HMAC authentication for integrity protection.
func (v *Vault) SaveWithHMAC(filename string, kek []byte) error {
	hmacStr, err := v.computeHMAC(kek)
	if err != nil {
		return err
	}

	v.HMAC = hmacStr
	return v.Save(filename)
}

// LoadAndVerifyHMAC loads vault and verifies HMAC. Rejects tampered vaults.
func LoadAndVerifyHMAC(filename string, kek []byte) (*Vault, error) {
	v, err := LoadVault(filename)
	if err != nil {
		return nil, err
	}

	if err := v.verifyHMAC(kek); err != nil {
		return nil, err
	}

	return v, nil
}
