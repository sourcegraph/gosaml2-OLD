package saml2

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func (sp *SAMLServiceProvider) validationContext() *dsig.ValidationContext {
	return dsig.NewDefaultValidationContext(sp.IDPCertificateStore)
}

//ValidateEncodedResponse both decodes and validates, based on SP
//configuration, an encoded, signed response. It will also appropriately
//decrypt a response if the assertion was encrypted
func (sp *SAMLServiceProvider) ValidateEncodedResponse(encodedResponse string) (*etree.Element, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	err = doc.ReadFromBytes(raw)
	if err != nil {
		return nil, err
	}

	response, err := sp.validationContext().Validate(doc.Root())
	if err != nil && !sp.SkipSignatureValidation {
		return nil, err
	}

	err = sp.Validate(response)
	if err == nil {
		//If there was no error, then return the response
		return response, nil
	}

	//If an error aside from missing assertion, return it.
	if err != ErrMissingAssertion {
		return nil, err
	}

	//If the error indicated a missing assertion, proceed to attempt decryption
	//of encrypted assertion.
	res, err := NewResponseFromReader(bytes.NewReader(raw))

	if err != nil {
		return nil, fmt.Errorf("Error getting response: %v", err)
	}

	var decryptCert tls.Certificate

	if crt, ok := sp.SPKeyStore.(dsig.TLSCertKeyStore); ok {
		decryptCert = tls.Certificate(crt)
	} else {
		pk, cert, err := sp.SPKeyStore.GetKeyPair()
		if err != nil {
			return nil, fmt.Errorf("error getting keypair: %v", err)
		}

		decryptCert = tls.Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  pk,
		}

		return nil, fmt.Errorf("Cannot get tls.Certificate from keystore")
	}

	docBytes, err := res.Decrypt(tls.Certificate(decryptCert))

	if err != nil {
		return nil, fmt.Errorf("Error decrypting assertion: %v", err)
	}

	resDoc := etree.NewDocument()
	err = resDoc.ReadFromBytes(docBytes)

	if err != nil {
		return nil, fmt.Errorf("Error reading decrypted assertion: %v", err)
	}

	el := etree.NewElement("DecryptedAssertion")
	el.AddChild(resDoc.Root())

	return el, nil
}
