package jwt

var Reference = false
var SigningMethods = map[string]func() SigningMethod{}
