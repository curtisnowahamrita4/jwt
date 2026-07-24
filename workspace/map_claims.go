package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// TimeFunc provides the current time.
var TimeFunc = time.Now

// MapClaims is a claims type that uses the map[string]interface{} type.
type MapClaims map[string]interface{}

// VerifyExpiresAt compares the exp claim against cmp.
// If req is true, it will return false if the claim is missing.
func (m MapClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	v, ok := m["exp"]
	if !ok {
		return !req
	}
	val, ok := parseNumericClaim(v)
	if !ok {
		return false
	}
	return verifyExp(val, cmp, req)
}

// VerifyIssuedAt compares the iat claim against cmp.
// If req is true, it will return false if the claim is missing.
func (m MapClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	v, ok := m["iat"]
	if !ok {
		return !req
	}
	val, ok := parseNumericClaim(v)
	if !ok {
		return false
	}
	return verifyIat(val, cmp, req)
}

// VerifyNotBefore compares the nbf claim against cmp.
// If req is true, it will return false if the claim is missing.
func (m MapClaims) VerifyNotBefore(cmp int64, req bool) bool {
	v, ok := m["nbf"]
	if !ok {
		return !req
	}
	val, ok := parseNumericClaim(v)
	if !ok {
		return false
	}
	return verifyNbf(val, cmp, req)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (m *MapClaims) UnmarshalJSON(data []byte) error {
	var mapData map[string]interface{}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&mapData); err != nil {
		return err
	}
	if *m == nil {
		*m = make(MapClaims)
	}
	for k, v := range mapData {
		(*m)[k] = cleanupNumber(v)
	}
	return nil
}

// Valid validates time based claims "exp", "iat", "nbf".
func (m MapClaims) Valid() error {
	now := TimeFunc().Unix()
	if !m.VerifyExpiresAt(now, false) {
		return errors.New("token is expired")
	}
	if !m.VerifyNotBefore(now, false) {
		return errors.New("token is not valid yet")
	}
	return nil
}

func parseJSONNumber(n json.Number) interface{} {
	if i, err := n.Int64(); err == nil {
		const maxSafeInt = 9007199254740991
		const minSafeInt = -9007199254740991
		if i >= minSafeInt && i <= maxSafeInt {
			return float64(i)
		}
		return i
	}
	if f, err := n.Float64(); err == nil {
		return f
	}
	return n
}

func cleanupNumber(v interface{}) interface{} {
	switch val := v.(type) {
	case json.Number:
		return parseJSONNumber(val)
	case map[string]interface{}:
		for k, mv := range val {
			val[k] = cleanupNumber(mv)
		}
		return val
	case []interface{}:
		for i, sv := range val {
			val[i] = cleanupNumber(sv)
		}
		return val
	}
	return v
}
