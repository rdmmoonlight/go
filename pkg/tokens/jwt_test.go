package tokens

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndValidate(t *testing.T) {
	m := NewJWTManager("kunci-uji-minimal-32-karakter-aman!!", time.Hour)
	tok, err := m.GenerateToken("u-1", "a@b.co")
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.ValidateToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.UserID != "u-1" || c.Email != "a@b.co" || c.Subject != "u-1" {
		t.Fatalf("klaim tidak sesuai: %+v", c)
	}
}

func TestRejectsWrongSecretExpiredAndNone(t *testing.T) {
	a := NewJWTManager("kunci-a-kunci-a-kunci-a-kunci-a-kunci", time.Hour)
	b := NewJWTManager("kunci-b-kunci-b-kunci-b-kunci-b-kunci", time.Hour)
	tok, _ := a.GenerateToken("u", "e@x.io")
	if _, err := b.ValidateToken(tok); err == nil {
		t.Fatal("kunci berbeda harus ditolak")
	}

	expired := NewJWTManager("kunci-a-kunci-a-kunci-a-kunci-a-kunci", -time.Minute)
	old, _ := expired.GenerateToken("u", "e@x.io")
	if _, err := a.ValidateToken(old); err == nil {
		t.Fatal("token kedaluwarsa harus ditolak")
	}

	none := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{UserID: "u"})
	s, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := a.ValidateToken(s); err == nil {
		t.Fatal("algoritma none harus ditolak")
	}
}
