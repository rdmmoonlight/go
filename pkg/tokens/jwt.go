package tokens

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const Issuer = "aumo-auth"

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	secretKey     []byte
	tokenDuration time.Duration
}

func NewJWTManager(secretKey string, duration time.Duration) *JWTManager {
	return &JWTManager{
		secretKey:     []byte(secretKey),
		tokenDuration: duration,
	}
}

func (m *JWTManager) GenerateToken(userID, email string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(now.Add(m.tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

func (m *JWTManager) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return m.secretKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid || claims.UserID == "" {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}
