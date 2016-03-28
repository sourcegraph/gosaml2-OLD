package saml2

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
	"github.com/satori/go.uuid"
)

const issueInstantFormat = "2006-01-02T15:04:05"

type SAMLServiceProvider struct {
	IdentityProviderSSOURL      string
	IdentityProviderIssuer      string
	AssertionConsumerServiceURL string
	SignAuthnRequests           bool
	IDPCertificateStore         dsig.X509CertificateStore
	SPKeyStore                  dsig.X509KeyStore
}

func (sp *SAMLServiceProvider) signingContext() *dsig.SigningContext {
	return dsig.NewDefaultSigningContext(sp.SPKeyStore)
}

func (sp *SAMLServiceProvider) validationContext() *dsig.ValidationContext {
	return dsig.NewDefaultValidationContext(sp.IDPCertificateStore)
}

func (sp *SAMLServiceProvider) BuildAuthRequest() (string, error) {
	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	authnRequest.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	authnRequest.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")

	authnRequest.CreateAttr("ID", "_"+uuid.NewV4().String())
	authnRequest.CreateAttr("Version", "2.0")
	authnRequest.CreateAttr("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
	authnRequest.CreateAttr("AssertionConsumerServiceURL", sp.AssertionConsumerServiceURL)
	authnRequest.CreateAttr("AssertionConsumerServiceIndex", "0")
	authnRequest.CreateAttr("AttributeConsumingServiceIndex", "0")
	authnRequest.CreateAttr("IssueInstant", time.Now().UTC().Format(issueInstantFormat))

	authnRequest.CreateElement("saml:Issuer").SetText(sp.IdentityProviderIssuer)

	nameIdPolicy := authnRequest.CreateElement("samlp:NameIDPolicy")
	nameIdPolicy.CreateAttr("AllowCreate", "true")
	nameIdPolicy.CreateAttr("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")

	requestedAuthnContext := authnRequest.CreateElement("samlp:RequestedAuthnContext")
	requestedAuthnContext.CreateAttr("Comparison", "exact")

	authnContextClassRef := requestedAuthnContext.CreateElement("saml:AuthnContextClassRef")
	authnContextClassRef.SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	var doc *etree.Document

	if sp.SignAuthnRequests {
		signed, err := sp.signingContext().SignEnveloped(authnRequest)
		if err != nil {
			return "", err
		}

		doc = etree.CreateDocument(signed)
	} else {
		doc = etree.CreateDocument(authnRequest)
	}

	buf := &bytes.Buffer{}

	_, err := doc.WriteTo(buf)
	if err != nil {
		return "", err
	}

	return doc.WriteToString()
}

func (sp *SAMLServiceProvider) BuildAuthURL(relayState string) (string, error) {
	parsedUrl, err := url.Parse(sp.IdentityProviderSSOURL)
	if err != nil {
		return "", err
	}

	authnRequest, err := sp.BuildAuthRequest()
	if err != nil {
		return "", err
	}

	qs := parsedUrl.Query()

	qs.Add("SAMLRequest", base64.StdEncoding.EncodeToString([]byte(authnRequest)))

	if relayState != "" {
		qs.Add("RelayState", relayState)
	}

	parsedUrl.RawQuery = qs.Encode()
	return parsedUrl.String(), nil
}

func (sp *SAMLServiceProvider) ValidateEncodedResponse(encodedResponse string) error {
	raw, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return err
	}

	doc := etree.NewDocument()
	err = doc.ReadFromBytes(raw)
	if err != nil {
		return err
	}

	_, err = sp.validationContext().Validate(doc.Root())
	if err != nil {
		return err
	}

	return nil
}

type AssertionInfo struct {
	FirstName    string
	LastName     string
	EmailAddress string
	Login        string
}

func (sp *SAMLServiceProvider) RetrieveAssertionInfo(encodedResponse string) (*AssertionInfo, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	err = doc.ReadFromBytes(raw)
	if err != nil {
		return nil, err
	}

	assertionInfo, err := sp.validationContext().RetrieveAssertionInfo(doc.Root())
	if err != nil {
		return nil, err
	}

	ai := &AssertionInfo{
		FirstName:    assertionInfo["FirstName"],
		LastName:     assertionInfo["LastName"],
		EmailAddress: assertionInfo["Email"],
		Login:        assertionInfo["Login"],
	}

	return ai, nil
}
