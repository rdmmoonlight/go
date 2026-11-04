package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "github.com/glebarez/go-sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore membuka/membuat database SQLite dan secara otomatis membuat tabel users jika belum ada.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Auto-migrate tabel users sederhana
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT,
		user_name TEXT UNIQUE,
		avatar_url TEXT,
		phone_number TEXT,
		bio TEXT
	);`
	if _, err := db.Exec(query); err != nil {
		return nil, fmt.Errorf("gagal inisialisasi tabel users: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) Create(ctx context.Context, name, email, passwordHash string) (*User, error) {
	key := normalize(email)
	id := newID()

	query := `INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, id, name, key, passwordHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, ErrEmailTaken
		}
		return nil, err
	}

	return &User{
		ID:           id,
		Name:         name,
		Email:        key,
		PasswordHash: passwordHash,
	}, nil
}

func (s *SQLiteStore) FindByEmail(ctx context.Context, email string) (*User, error) {
	key := normalize(email)
	query := `SELECT id, name, email, password_hash, user_name, avatar_url, phone_number, bio FROM users WHERE email = ?`

	var u User
	var userName, avatarURL, phoneNumber, bio sql.NullString

	err := s.db.QueryRowContext(ctx, query, key).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash,
		&userName, &avatarURL, &phoneNumber, &bio,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	u.UserName = userName.String
	u.AvatarURL = avatarURL.String
	u.PhoneNumber = phoneNumber.String
	u.Bio = bio.String

	return &u, nil
}

func (s *SQLiteStore) FindByID(ctx context.Context, id string) (*User, error) {
	query := `SELECT id, name, email, password_hash, user_name, avatar_url, phone_number, bio FROM users WHERE id = ?`

	var u User
	var userName, avatarURL, phoneNumber, bio sql.NullString

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash,
		&userName, &avatarURL, &phoneNumber, &bio,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	u.UserName = userName.String
	u.AvatarURL = avatarURL.String
	u.PhoneNumber = phoneNumber.String
	u.Bio = bio.String

	return &u, nil
}

func (s *SQLiteStore) UpsertExternal(ctx context.Context, name, email string) (*User, error) {
	u, err := s.FindByEmail(ctx, email)
	if err == nil {
		return u, nil
	}
	if errors.Is(err, ErrNotFound) {
		return s.Create(ctx, name, email, "")
	}
	return nil, err
}

func (s *SQLiteStore) UpdateProfile(ctx context.Context, id string, upd ProfileUpdate) (*User, error) {
	u, err := s.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if upd.UserName != nil {
		u.UserName = *upd.UserName
	}
	if upd.Name != nil {
		u.Name = *upd.Name
	}
	if upd.AvatarURL != nil {
		u.AvatarURL = *upd.AvatarURL
	}
	u.PhoneNumber = upd.PhoneNumber
	u.Bio = upd.Bio

	query := `UPDATE users SET name = ?, user_name = ?, avatar_url = ?, phone_number = ?, bio = ? WHERE id = ?`
	_, err = s.db.ExecContext(ctx, query, u.Name, u.UserName, u.AvatarURL, u.PhoneNumber, u.Bio, id)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, ErrUserNameTaken
		}
		return nil, err
	}

	return u, nil
}

func (s *SQLiteStore) UpdatePasswordHash(ctx context.Context, id, passwordHash string) error {
	query := `UPDATE users SET password_hash = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, passwordHash, id)
	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}
