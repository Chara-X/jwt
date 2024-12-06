package jwt

import "github.com/golang-jwt/jwt/v5"

func init() {
	for _, alg := range jwt.GetAlgorithms() {
		SigningMethods[alg] = func() SigningMethod {
			return jwt.GetSigningMethod(alg)
		}
	}
}
