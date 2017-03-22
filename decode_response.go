package saml2

import (
	"bytes"
	"compress/flate"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

func (sp *SAMLServiceProvider) validationContext() *dsig.ValidationContext {
	ctx := dsig.NewDefaultValidationContext(sp.IDPCertificateStore)
	ctx.Clock = sp.Clock
	return ctx
}

// validateResponseAttributes validates a SAML Response's tag and attributes. It does
// not inspect child elements of the Response at all.
func (sp *SAMLServiceProvider) validateResponseAttributes(response *etree.Element) error {
	if response.Tag != ResponseTag {
		return ErrMissingElement{
			Tag: ResponseTag,
		}
	}

	destinationAttr := response.SelectAttr(DestinationAttr)
	if destinationAttr == nil {
		return ErrMissingElement{Tag: DestinationAttr}
	}

	if destinationAttr.Value != sp.AssertionConsumerServiceURL {
		return ErrInvalidValue{
			Key:      DestinationAttr,
			Expected: sp.AssertionConsumerServiceURL,
			Actual:   destinationAttr.Value,
		}
	}

	versionAttr := response.SelectAttr(VersionAttr)
	if versionAttr == nil {
		return ErrMissingElement{
			Tag:       response.Tag,
			Attribute: VersionAttr,
		}
	}

	if versionAttr.Value != "2.0" {
		return ErrInvalidValue{
			Reason:   ReasonUnsupported,
			Key:      "SAML version",
			Expected: "2.0",
			Actual:   versionAttr.Value,
		}
	}

	return nil
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
		// Attempt to inflate the response in case it happens to be compressed (as with one case at saml.oktadev.com)
		buf, flateErr := ioutil.ReadAll(flate.NewReader(bytes.NewReader(raw)))
		if flateErr == nil {
			err = doc.ReadFromBytes(buf)
		}
	}
	if err != nil {
		return nil, err
	}

	response := doc.Root()
	err = sp.validateResponseAttributes(response)
	if err != nil {
		return nil, err
	}

	if !sp.SkipSignatureValidation {
		response, err = sp.validationContext().Validate(response)
		if err == dsig.ErrMissingSignature {
			// The Response wasn't signed. It is possible that the Assertion inside of
			// the Response was signed.

			// Unfortunately we just blew away our Response
			response = doc.Root()

			unverifiedAssertion, err := etreeutils.NSSelectOne(response, SAMLAssertionNamespace, AssertionTag)
			if err != nil {
				return nil, err
			}

			if unverifiedAssertion == nil {
				return nil, ErrMissingAssertion
			}

			assertion, err := sp.validationContext().Validate(unverifiedAssertion)
			if err != nil {
				return nil, err
			}

			// Because the top level response wasn't signed, we don't trust it
			// or any of its children - except the signed assertions as returned
			// by the signature validation. Make a copy of the response (to avoid mutating
			// the original document) and strip all of its children, then re-add only
			// the validated assertion.
			//
			// Note that we're leaving attributes of the Response in place. Since we're
			// processing an unsigned Response they can't be trusted, but we'll validate
			// them anyway.
			response = response.Copy()
			for _, el := range response.ChildElements() {
				response.RemoveChild(el)
			}

			response.AddChild(assertion)
		} else if err != nil || response == nil {
			return nil, err
		}
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

	//This is the tls.Certificate we'll use to decrypt
	var decryptCert tls.Certificate

	switch crt := sp.SPKeyStore.(type) {
	case dsig.TLSCertKeyStore:
		//Get the tls.Certificate directly if possible
		decryptCert = tls.Certificate(crt)
	default:
		//Otherwise, construct one from the results of GetKeyPair
		pk, cert, err := sp.SPKeyStore.GetKeyPair()
		if err != nil {
			return nil, fmt.Errorf("error getting keypair: %v", err)
		}

		decryptCert = tls.Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  pk,
		}
	}

	//Decrypt the xml contents of the assertion
	docBytes, err := res.Decrypt(decryptCert)

	if err != nil {
		return nil, fmt.Errorf("Error decrypting assertion: %v", err)
	}

	//Read the assertion and return it
	resDoc := etree.NewDocument()
	err = resDoc.ReadFromBytes(docBytes)

	if err != nil {
		return nil, fmt.Errorf("Error reading decrypted assertion: %v", err)
	}

	el := etree.NewElement("DecryptedAssertion")
	el.AddChild(resDoc.Root())

	return el, nil
}
