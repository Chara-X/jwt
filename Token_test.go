package jwt

import (
	"fmt"

	_ "github.com/golang-jwt/jwt/v5"
)

func ExampleToken() {
	var token = New(SigningMethods["HS256"]())
	token.Claims = MapClaims{"iss": "google", "sub": "bob"}
	var key = []byte("123")
	var tokenString, _ = token.SignedString(key)
	token, _ = Parse(tokenString, key)
	fmt.Println(token.Claims.GetIssuer())
	fmt.Println(token.Claims.GetSubject())
	// Output:
	// google <nil>
	// bob <nil>
}
