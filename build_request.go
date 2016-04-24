package saml2

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/satori/go.uuid"
)

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

	authnRequest.CreateAttr("Destination", "http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO")
	// authnRequest.CreateAttr("Destination", sp.IdentityProviderSSOURL)

	authnRequest.CreateElement("saml:Issuer").SetText(sp.IdentityProviderIssuer)

	nameIdPolicy := authnRequest.CreateElement("samlp:NameIDPolicy")
	nameIdPolicy.CreateAttr("AllowCreate", "true")
	nameIdPolicy.CreateAttr("Format", sp.NameIdFormat)

	requestedAuthnContext := authnRequest.CreateElement("samlp:RequestedAuthnContext")
	requestedAuthnContext.CreateAttr("Comparison", "exact")

	authnContextClassRef := requestedAuthnContext.CreateElement("saml:AuthnContextClassRef")
	authnContextClassRef.SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	doc := etree.NewDocument()

	if sp.SignAuthnRequests {
		signed, err := sp.SigningContext().SignEnveloped(authnRequest)
		if err != nil {
			return "", err
		}

		doc.SetRoot(signed)
	} else {
		doc.SetRoot(authnRequest)
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

	buf := &bytes.Buffer{}

	fw, err := flate.NewWriter(buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("flate NewWriter error: %v", err)
	}

	_, err = fw.Write([]byte(authnRequest))
	if err != nil {
		return "", fmt.Errorf("flate.Writer Write error: %v", err)
	}

	err = fw.Close()
	if err != nil {
		return "", fmt.Errorf("flate.Writer Close error: %v", err)
	}

	qs := parsedUrl.Query()

	qs.Add("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))

	if relayState != "" {
		qs.Add("RelayState", relayState)
	}

	parsedUrl.RawQuery = qs.Encode()
	return parsedUrl.String(), nil
}
