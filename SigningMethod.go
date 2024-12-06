package jwt

type SigningMethod interface {
	Verify(signingString string, sig []byte, key interface{}) error
	Sign(signingString string, key interface{}) ([]byte, error)
	Alg() string
}
