package jwt

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	if Reference {
		return jwt.ParseRSAPrivateKeyFromPEM(key)
	}
	panic("unimplemented")
}
