package saml2

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
)

type TLSCertKeyStore tls.Certificate

func (d TLSCertKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	pk, ok := d.PrivateKey.(*rsa.PrivateKey)

	if !ok {
		return nil, nil, fmt.Errorf("Private key was not RSA")
	}

	if len(d.Certificate) < 1 {
		return nil, nil, fmt.Errorf("No public certificates provided")
	}

	crt := d.Certificate[0]

	return pk, crt, nil
}
