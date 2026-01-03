package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

func GenerateDERPrivateKey() []byte {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return x509.MarshalPKCS1PrivateKey(key)
}

func ParseDERPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(der)
}
