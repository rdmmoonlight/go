package password

import "testing"

func TestHashAndVerify(t *testing.T) {
	h, err := Hash("rahasia-123")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify("rahasia-123", h); err != nil || !ok {
		t.Fatalf("kata sandi benar harus lolos: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify("salah", h); ok {
		t.Fatal("kata sandi salah tidak boleh lolos")
	}
	if _, err := Verify("x", "bukan-hash"); err == nil {
		t.Fatal("format tidak valid harus menghasilkan error")
	}
}

// Vektor uji RFC 6070 disesuaikan untuk HMAC-SHA256 (password/salt/1 iterasi).
func TestPBKDF2Vector(t *testing.T) {
	got := pbkdf2([]byte("password"), []byte("salt"), 1, 32)
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if hex := toHex(got); hex != want {
		t.Fatalf("pbkdf2 = %s, want %s", hex, want)
	}
}

func toHex(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, d[v>>4], d[v&0x0f])
	}
	return string(out)
}
