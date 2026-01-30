package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type Token struct {
	t         *jwt.Token
	Header    map[string]interface{}
	Claims    jwt.Claims
	Signature []byte
}

func New(method SigningMethod) *Token {
	if Reference {
		return &Token{t: jwt.New(method)}
	}
	return &Token{Header: map[string]interface{}{"typ": "JWT", "alg": method.Alg()}, Claims: jwt.MapClaims{}}
}
func Parse(tokenString string, key interface{}, options ...jwt.ParserOption) (*Token, error) {
	if Reference {
		var t, err = jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) { return key, nil }, options...)
		return &Token{t: t}, err
	}
	var token = &Token{Claims: &MapClaims{}}
	var parts = strings.Split(tokenString, ".")
	json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(parts[0]))).Decode(&token.Header)
	json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(parts[1]))).Decode(token.Claims.(*MapClaims))
	token.Signature, _ = base64.RawURLEncoding.DecodeString(parts[2])
	return token, SigningMethods[token.Header["alg"].(string)]().Verify(parts[0]+"."+parts[1], token.Signature, key)
}
func (t *Token) SignedString(key interface{}) (string, error) {
	if Reference {
		return t.t.SignedString(key)
	}
	var header, _ = json.Marshal(t.Header)
	var claims, _ = json.Marshal(t.Claims)
	var signingString = base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	var sig, _ = SigningMethods[t.Header["alg"].(string)]().Sign(signingString, key)
	return signingString + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
