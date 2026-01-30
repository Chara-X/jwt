package jwt

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	if Reference {
		return jwt.ParseRSAPublicKeyFromPEM(key)
	}
	panic("unimplemented")
}
