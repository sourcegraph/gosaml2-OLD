package saml2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
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
	AudienceURI                 string
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

type proxyRestriction struct {
	Count    int
	Audience []string
}

type warningInfo struct {
	OneTimeUse       bool
	ProxyRestriction *proxyRestriction
	NotInAudience    bool
}

type AssertionInfo struct {
	Values      map[string]string
	WarningInfo *warningInfo
}

func childPath(space, tag string) string {
	if space == "" {
		return "./" + tag
	} else {
		return "./" + space + ":" + tag
	}
}

func (sp *SAMLServiceProvider) VerifyAssertionConditions(assertionElement, conditionsStatement *etree.Element) (*warningInfo, error) {
	warningInfo := &warningInfo{}

	audienceRestrictionStatement := conditionsStatement.FindElement(childPath(assertionElement.Space, AudienceRestrictionTag))
	if audienceRestrictionStatement != nil {
		audienceStatements := audienceRestrictionStatement.FindElements(childPath(assertionElement.Space, AudienceTag))
		if len(audienceStatements) == 0 {
			return nil, errors.New("Missing AudienceStatement")
		}

		matched := false
		for _, audienceStatement := range audienceStatements {
			if audienceStatement.Text() == sp.AudienceURI {
				matched = true
			}
		}

		if !matched {
			warningInfo.NotInAudience = true
		}
	}

	oneTimeUseStatement := conditionsStatement.FindElement(childPath(assertionElement.Space, OneTimeUseTag))
	if oneTimeUseStatement != nil {
		warningInfo.OneTimeUse = true
	}

	proxyRestrictionStatement := conditionsStatement.FindElement(childPath(assertionElement.Space, ProxyRestrictionTag))
	if proxyRestrictionStatement != nil {
		proxyRestrictionInfo := &proxyRestriction{}
		countAttr := proxyRestrictionStatement.SelectAttr(CountAttr)
		if countAttr != nil {
			count, err := strconv.Atoi(countAttr.Value)
			if err != nil {
				return nil, errors.New("Could not parse Count attribute")
			}

			proxyRestrictionInfo.Count = count
		}

		proxyAudienceStatements := proxyRestrictionStatement.FindElements(childPath(assertionElement.Space, AudienceTag))
		pas := make([]string, len(proxyAudienceStatements))
		for i, proxyAudienceStatement := range proxyAudienceStatements {
			pas[i] = proxyAudienceStatement.Text()
		}

		proxyRestrictionInfo.Audience = pas
		warningInfo.ProxyRestriction = proxyRestrictionInfo
	}

	return warningInfo, nil
}

func (sp *SAMLServiceProvider) RetrieveAssertionInfo(encodedResponse string) (*AssertionInfo, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}

	assertionInfo := &AssertionInfo{}

	doc := etree.NewDocument()
	err = doc.ReadFromBytes(raw)
	if err != nil {
		return nil, err
	}

	el := doc.Root()

	assertionElement := el.FindElement("//" + AssertionTag)
	if assertionElement == nil {
		return nil, errors.New("Missing Assertion")
	}

	//Verify all conditions for the assertion
	conditionsStatement := assertionElement.FindElement(childPath(assertionElement.Space, ConditionsTag))
	if conditionsStatement == nil {
		return nil, errors.New("Missing ConditionsStatement")
	}
	now := time.Now()

	notBeforeAttr := conditionsStatement.SelectAttr(NotBeforeAttr)
	if notBeforeAttr != nil {
		before, err := time.Parse(time.RFC3339, notBeforeAttr.Value)
		if err != nil {
			return nil, errors.New("Could not parse 'NotBefore' attribute")
		}

		if now.Before(before) {
			return nil, errors.New("Assertion statement is not valid yet")
		}
	}
	notOnOrAfterAttr := conditionsStatement.SelectAttr(NotOnOrAfterAttr)
	if notBeforeAttr != nil {
		after, err := time.Parse(time.RFC3339, notOnOrAfterAttr.Value)
		if err != nil {
			return nil, errors.New("Could not parse 'NotOnOrAfter' attribute")
		}
		if now.After(after) {
			return nil, errors.New("Assertion statement is no longer valid")
		}
	}

	warningInfo, err := sp.VerifyAssertionConditions(assertionElement, conditionsStatement)
	if err != nil {
		return nil, err
	}

	//Get the actual assertion attributes
	attributeStatement := assertionElement.FindElement(childPath(assertionElement.Space, AttributeStatementTag))
	if attributeStatement == nil {
		return nil, errors.New("Missing AttributeStatement")
	}

	info := make(map[string]string)
	for _, child := range attributeStatement.ChildElements() {
		nameAttr := child.SelectAttr(NameAttr)
		attributeValue := child.FindElement(childPath(child.Space, AttributeValueTag))
		if attributeValue == nil {
			return nil, errors.New("Missing AttributeValue")
		}
		info[nameAttr.Value] = attributeValue.Text()
	}

	assertionInfo.Values = info
	assertionInfo.WarningInfo = warningInfo
	return assertionInfo, nil
}
