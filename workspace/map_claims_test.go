package jwt

import (
	"encoding/json"
	"testing"
)

func TestMapClaimsJSONRoundTrip(t *testing.T) {
	claims := MapClaims{
		"exp": int64(100),
		"iat": int64(50),
		"nbf": int64(50),
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	var newClaims MapClaims
	err = json.Unmarshal(data, &newClaims)
	if err != nil {
		t.Fatalf("failed to unmarshal claims: %v", err)
	}

	if !newClaims.VerifyExpiresAt(90, true) {
		t.Errorf("VerifyExpiresAt(90, true) failed, expected true")
	}
	if newClaims.VerifyExpiresAt(110, true) {
		t.Errorf("VerifyExpiresAt(110, true) failed, expected false")
	}

	if !newClaims.VerifyIssuedAt(60, true) {
		t.Errorf("VerifyIssuedAt(60, true) failed, expected true")
	}
	if newClaims.VerifyIssuedAt(40, true) {
		t.Errorf("VerifyIssuedAt(40, true) failed, expected false")
	}

	if !newClaims.VerifyNotBefore(60, true) {
		t.Errorf("VerifyNotBefore(60, true) failed, expected true")
	}
	if newClaims.VerifyNotBefore(40, true) {
		t.Errorf("VerifyNotBefore(40, true) failed, expected false")
	}
}

func TestMapClaimsFloatAndLargeInt(t *testing.T) {
	claims := MapClaims{
		"exp": 1234567890.123,
		"iat": int64(9223372036854775807),
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	var newClaims MapClaims
	err = json.Unmarshal(data, &newClaims)
	if err != nil {
		t.Fatalf("failed to unmarshal claims: %v", err)
	}

	if !newClaims.VerifyExpiresAt(1234567890, true) {
		t.Errorf("VerifyExpiresAt failed for float value")
	}

	if !newClaims.VerifyIssuedAt(9223372036854775807, true) {
		t.Errorf("VerifyIssuedAt failed for MaxInt64")
	}
}
