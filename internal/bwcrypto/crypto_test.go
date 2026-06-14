package bwcrypto

import (
	"encoding/hex"
	"testing"
)

// Bitwarden-compatible reference values generated with node(crypto) (see /tmp/bw_ref.mjs).
const (
	refPassword   = "correct horse battery staple"
	refEmail      = "User@Example.com"
	refIter       = 100000
	refMasterKey  = "a69d536a06ad85726e4173a146710f671fcc245c23226099326470a8eda63eb0"
	refEncKey     = "c10ad79ad020c7d5b1d20265fe6d29d6b12f0af254ad805500802f1fecb8553f"
	refMacKey     = "7455d0cc8fdb1162fb4603d93637e9b56a901fcf6ecd0b89149b76f446849e9d"
	refUserKey    = "7f384a83cabd0fd0b08120a6dbe88be4e0009b991ad0a2eec287f78d72fd94cb46a79df112815a15a42ac9072f614ff9f0296c6f1ea2eeab53d1a32d47caeae5"
	refEncUserKey = "2.DBdWiLu3dxhvyQx/ts1muQ==|797bDUbt4/oi6mzN+Xjq0G7Olzd5aOVI/t+0TBnfGaHS11HegHWVdmT/U27LrmRi/SMVOQ005UmngfAgX+QYUZ75/KVcZiDDbInKoxTodaU=|C6cXaDy8tVfJxSsKmTVWX8GnXwjKauqkBPv1JQfMfZU="
)

func TestDeriveMasterKey(t *testing.T) {
	mk, err := DeriveMasterKey(refPassword, refEmail, KdfConfig{KdfType: KdfPBKDF2, Iterations: refIter})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mk.Enc); got != refMasterKey {
		t.Fatalf("masterKey mismatch:\n got=%s\nwant=%s", got, refMasterKey)
	}
}

func TestStretchKey(t *testing.T) {
	mkBytes, _ := hex.DecodeString(refMasterKey)
	stretched, err := StretchKey(&SymmetricKey{Enc: mkBytes})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(stretched.Enc); got != refEncKey {
		t.Fatalf("encKey mismatch:\n got=%s\nwant=%s", got, refEncKey)
	}
	if got := hex.EncodeToString(stretched.Mac); got != refMacKey {
		t.Fatalf("macKey mismatch:\n got=%s\nwant=%s", got, refMacKey)
	}
}

func TestDecryptUserKey(t *testing.T) {
	// decrypt masterKeyEncryptedUserKey with the stretched key derived from the password; should equal userKey
	mk, _ := DeriveMasterKey(refPassword, refEmail, KdfConfig{KdfType: KdfPBKDF2, Iterations: refIter})
	stretched, _ := StretchKey(mk)
	plain, err := DecryptString(refEncUserKey, stretched)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString([]byte(plain)); got != refUserKey {
		t.Fatalf("userKey mismatch:\n got=%s\nwant=%s", got, refUserKey)
	}
}
