package keymgr

import (
	"os"
	"testing"
)

func TestDeriveKeyAndSalt_RandomWhenUnset(t *testing.T) {
	os.Unsetenv("GOPHANTOM_SALT")
	key1, salt1, err := DeriveKeyAndSalt()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	key2, salt2, err := DeriveKeyAndSalt()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(salt1) == string(salt2) {
		t.Error("two calls without GOPHANTOM_SALT should produce different salts")
	}
	if string(key1) == string(key2) {
		t.Error("two calls without GOPHANTOM_SALT should produce different keys")
	}
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
}

func TestDeriveKeyAndSalt_DeterministicWithEnv(t *testing.T) {
	// 16 bytes base64 = "AAAAAAAAAAAAAAAAAAAAAA=="
	os.Setenv("GOPHANTOM_SALT", "AAAAAAAAAAAAAAAAAAAAAA==")
	defer os.Unsetenv("GOPHANTOM_SALT")

	key1, salt1, err := DeriveKeyAndSalt()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	key2, salt2, err := DeriveKeyAndSalt()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(salt1) != string(salt2) {
		t.Error("same GOPHANTOM_SALT should produce same salt")
	}
	if string(key1) != string(key2) {
		t.Error("same GOPHANTOM_SALT should produce same key")
	}
}

func TestDeriveKeyAndSalt_InvalidBase64(t *testing.T) {
	os.Setenv("GOPHANTOM_SALT", "not-valid-base64!!!")
	defer os.Unsetenv("GOPHANTOM_SALT")

	_, _, err := DeriveKeyAndSalt()
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestDeriveKeyAndSalt_WrongLength(t *testing.T) {
	// 8 bytes instead of 16
	os.Setenv("GOPHANTOM_SALT", "AAAAAAAAAAA=")
	defer os.Unsetenv("GOPHANTOM_SALT")

	_, _, err := DeriveKeyAndSalt()
	if err == nil {
		t.Fatal("expected error for wrong salt length, got nil")
	}
}

func TestDeriveKeyFromEnvValues_Deterministic(t *testing.T) {
	pairs := []string{"hostname=DC01", "domain=CORP.LOCAL"}
	key1, _, err := DeriveKeyFromEnvValues(pairs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
}

func TestDeriveKeyFromEnvValues_OrderIndependent(t *testing.T) {
	// ComputeEnvHash sorts internally, so different input order → same hash
	hash1 := ComputeEnvHash([]string{"hostname=DC01", "domain=CORP.LOCAL"})
	hash2 := ComputeEnvHash([]string{"domain=CORP.LOCAL", "hostname=DC01"})
	if hash1 != hash2 {
		t.Errorf("hash should be order-independent:\n  %s\n  %s", hash1, hash2)
	}
}

func TestDeriveKeyFromEnvValues_Empty(t *testing.T) {
	_, _, err := DeriveKeyFromEnvValues(nil)
	if err == nil {
		t.Fatal("expected error for empty pairs, got nil")
	}
}

func TestComputeEnvHash_DifferentInputs(t *testing.T) {
	h1 := ComputeEnvHash([]string{"hostname=DC01"})
	h2 := ComputeEnvHash([]string{"hostname=DC02"})
	if h1 == h2 {
		t.Error("different inputs should produce different hashes")
	}
}
