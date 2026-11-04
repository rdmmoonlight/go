package store

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

// Tes ini memakai Postgres sungguhan: set TEST_DATABASE_URL untuk menjalankannya.
func openTest(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL tidak diset; tes Postgres dilewati")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pg, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pg.db.Exec(`TRUNCATE auth.users`)
		_ = pg.Close()
	})
	if _, err := pg.db.Exec(`TRUNCATE auth.users`); err != nil {
		t.Fatal(err)
	}
	return pg
}

func TestPostgresCreateFindAndNormalize(t *testing.T) {
	pg := openTest(t)
	ctx := context.Background()
	u, err := pg.Create(ctx, "Ghofur", "  Ghofur@Example.COM ", "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "ghofur@example.com" {
		t.Fatalf("email harus dinormalisasi, dapat %q", u.Email)
	}
	got, err := pg.FindByEmail(ctx, "GHOFUR@example.com")
	if err != nil || got.ID != u.ID || got.PasswordHash != "hash-1" {
		t.Fatalf("FindByEmail: %+v err=%v", got, err)
	}
	if _, err := pg.FindByEmail(ctx, "tidak@ada.io"); err != ErrNotFound {
		t.Fatalf("harus ErrNotFound, dapat %v", err)
	}
}

func TestPostgresDuplicateEmail(t *testing.T) {
	pg := openTest(t)
	ctx := context.Background()
	if _, err := pg.Create(ctx, "A", "dup@example.com", "h"); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Create(ctx, "B", "DUP@example.com", "h"); err != ErrEmailTaken {
		t.Fatalf("harus ErrEmailTaken, dapat %v", err)
	}
}

func TestPostgresConcurrentDuplicateOnlyOneWins(t *testing.T) {
	pg := openTest(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, taken := 0, 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pg.Create(ctx, "X", "race@example.com", "h")
			mu.Lock()
			defer mu.Unlock()
			switch err {
			case nil:
				ok++
			case ErrEmailTaken:
				taken++
			default:
				t.Errorf("galat tak terduga: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || taken != 7 {
		t.Fatalf("ok=%d taken=%d, harapan 1 dan 7", ok, taken)
	}
}

func TestPostgresUpsertExternalIdempotent(t *testing.T) {
	pg := openTest(t)
	ctx := context.Background()
	a, err := pg.UpsertExternal(ctx, "Gee", "g@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := pg.UpsertExternal(ctx, "Nama Lain", "G@Example.com")
	if err != nil || b.ID != a.ID || b.Name != "Gee" {
		t.Fatalf("upsert kedua harus mengembalikan pengguna yang sama: %+v err=%v", b, err)
	}
	if a.PasswordHash != "" {
		t.Fatal("pengguna Google tidak memiliki kata sandi")
	}
}

func TestMigrationIsRepeatable(t *testing.T) {
	pg := openTest(t)
	ctx := context.Background()
	if _, err := pg.db.ExecContext(ctx, migrateSQL); err != nil {
		t.Fatalf("migrasi kedua harus aman: %v", err)
	}
}

func TestOpenPostgresRejectsEmptyDSN(t *testing.T) {
	if _, err := OpenPostgres(context.Background(), ""); err == nil {
		t.Fatal("DSN kosong harus ditolak")
	}
}

func TestPostgresProfileLifecycle(t *testing.T) {
	pg := openTest(t)
	ctx := context.Background()
	u, err := pg.Create(ctx, "Ghofur", "p@example.com", "h1")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := pg.Create(ctx, "Budi", "b@example.com", "h")

	name, userName, avatar := "Tri Wahyu", "Ghofur_01", "https://a.test/a.png"
	got, err := pg.UpdateProfile(ctx, u.ID, ProfileUpdate{Name: &name, UserName: &userName, AvatarURL: &avatar, PhoneNumber: "+62812", Bio: "Akuntan"})
	if err != nil || got.Name != name || got.UserName != userName || got.AvatarURL != avatar || got.PhoneNumber != "+62812" || got.Bio != "Akuntan" {
		t.Fatalf("UpdateProfile: %+v err=%v", got, err)
	}
	// Pointer nil tidak mengubah kolom; telepon dan bio kosong menjadi NULL.
	got, err = pg.UpdateProfile(ctx, u.ID, ProfileUpdate{})
	if err != nil || got.Name != name || got.UserName != userName || got.AvatarURL != avatar || got.PhoneNumber != "" || got.Bio != "" {
		t.Fatalf("UpdateProfile kosong: %+v err=%v", got, err)
	}
	// Username unik tanpa membedakan huruf besar-kecil.
	dup := "ghofur_01"
	if _, err := pg.UpdateProfile(ctx, other.ID, ProfileUpdate{UserName: &dup}); err != ErrUserNameTaken {
		t.Fatalf("harus ErrUserNameTaken, dapat %v", err)
	}
	byID, err := pg.FindByID(ctx, u.ID)
	if err != nil || byID.Email != "p@example.com" || byID.PasswordHash != "h1" {
		t.Fatalf("FindByID: %+v err=%v", byID, err)
	}
	if _, err := pg.FindByID(ctx, "bukan-uuid"); err != ErrNotFound {
		t.Fatalf("id bukan UUID harus ErrNotFound, dapat %v", err)
	}
	if _, err := pg.FindByID(ctx, "00000000-0000-4000-8000-000000000000"); err != ErrNotFound {
		t.Fatalf("id tidak ada harus ErrNotFound, dapat %v", err)
	}
	if _, err := pg.UpdateProfile(ctx, "bukan-uuid", ProfileUpdate{}); err != ErrNotFound {
		t.Fatalf("UpdateProfile id tidak valid harus ErrNotFound, dapat %v", err)
	}
}

func TestPostgresUpdatePasswordAndDelete(t *testing.T) {
	pg := openTest(t)
	ctx := context.Background()
	u, _ := pg.Create(ctx, "Ghofur", "d@example.com", "lama")
	if err := pg.UpdatePasswordHash(ctx, u.ID, "baru"); err != nil {
		t.Fatal(err)
	}
	if got, _ := pg.FindByEmail(ctx, "d@example.com"); got.PasswordHash != "baru" {
		t.Fatalf("hash tidak berubah: %+v", got)
	}
	if err := pg.Delete(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.FindByEmail(ctx, "d@example.com"); err != ErrNotFound {
		t.Fatalf("setelah hapus harus ErrNotFound, dapat %v", err)
	}
	if err := pg.Delete(ctx, u.ID); err != ErrNotFound {
		t.Fatalf("hapus ulang harus ErrNotFound, dapat %v", err)
	}
	if err := pg.UpdatePasswordHash(ctx, "bukan-uuid", "x"); err != ErrNotFound {
		t.Fatalf("id tidak valid harus ErrNotFound, dapat %v", err)
	}
}
