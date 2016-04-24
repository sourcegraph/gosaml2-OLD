package saml2

import (
	"fmt"
	"strconv"
	"time"

	"github.com/beevik/etree"
)

//ErrParsing indicates that the value present in an assertion could not be
//parsed. It can be inspected for the specific tag name, the contents, and the
//intended type.
type ErrParsing struct {
	Tag, Value, Type string
}

func (ep ErrParsing) Error() string {
	return fmt.Sprintf("Error parsing %s tag value as type %s", ep.Tag, ep.Value)
}

//Oft-used messages
const (
	ReasonUnsupported = "Unsupported"
	ReasonExpired     = "Expired"
)

//ErrInvalidValue indicates that the expected value did not match the received
//value.
type ErrInvalidValue struct {
	Key, Expected, Actual string
	Reason                string
}

func (e ErrInvalidValue) Error() string {
	if e.Reason == "" {
		e.Reason = "Unrecognized"
	}
	return fmt.Sprintf("%s %s value, Expected: %s, Actual: %s", e.Reason, e.Key, e.Expected, e.Actual)
}

//Well-known methods of subject confirmation
const (
	SubjMethodBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

//VerifyAssertionConditions inspects an assertion element and makes sure that
//all SAML2 contracts are upheld.
func (sp *SAMLServiceProvider) VerifyAssertionConditions(assertionElement, conditionsStatement *etree.Element) (*WarningInfo, error) {
	warningInfo := &WarningInfo{}
	now := time.Now()

	notBeforeAttr := conditionsStatement.SelectAttr(NotBeforeAttr)
	if notBeforeAttr != nil {
		before, err := time.Parse(time.RFC3339, notBeforeAttr.Value)
		if err != nil {
			return nil, ErrParsing{Tag: NotBeforeAttr, Value: notBeforeAttr.Value, Type: "time.RFC3339"}
		}

		if now.Before(before) {
			warningInfo.InvalidTime = true
		}
	}
	notOnOrAfterAttr := conditionsStatement.SelectAttr(NotOnOrAfterAttr)
	if notOnOrAfterAttr != nil {
		after, err := time.Parse(time.RFC3339, notOnOrAfterAttr.Value)
		if err != nil {
			return nil, ErrParsing{Tag: NotOnOrAfterAttr, Value: notOnOrAfterAttr.Value, Type: "time.RFC3339"}
		}
		if now.After(after) {
			warningInfo.InvalidTime = true
		}
	}

	audienceRestrictionStatement := conditionsStatement.FindElement(childPath(assertionElement.Space, AudienceRestrictionTag))
	if audienceRestrictionStatement != nil {
		audienceStatements := audienceRestrictionStatement.FindElements(childPath(assertionElement.Space, AudienceTag))
		if len(audienceStatements) == 0 {
			return nil, ErrMissingElement{Tag: AudienceTag}
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
		proxyRestrictionInfo := &ProxyRestriction{}
		countAttr := proxyRestrictionStatement.SelectAttr(CountAttr)
		if countAttr != nil {
			count, err := strconv.Atoi(countAttr.Value)
			if err != nil {
				return nil, ErrParsing{Tag: ProxyRestrictionTag, Value: countAttr.Value, Type: "int"}
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

//Validate ensures that the assertion passed is valid for the current Service
//Provider.
func (sp *SAMLServiceProvider) Validate(el *etree.Element) error {
	el = el.Copy()

	destinationAttr := el.SelectAttr(DestinationAttr)
	if destinationAttr == nil {
		return ErrMissingElement{Tag: DestinationAttr}
	}
	if destinationAttr.Value != sp.AssertionConsumerServiceURL {
		return ErrInvalidValue{Key: DestinationAttr, Expected: sp.AssertionConsumerServiceURL, Actual: destinationAttr.Value}
	}

	idAttr := el.SelectAttr(IdAttr)
	if idAttr == nil || idAttr.Value == "" {
		return ErrMissingElement{Tag: el.Tag, Attribute: IdAttr}
	}

	versionAttr := el.SelectAttr(VersionAttr)
	if versionAttr == nil {
		return ErrMissingElement{Tag: el.Tag, Attribute: VersionAttr}
	}
	if versionAttr.Value != "2.0" {
		return ErrInvalidValue{
			Reason:   ReasonUnsupported,
			Key:      "SAML version",
			Expected: "2.0",
			Actual:   versionAttr.Value,
		}
	}

	assertionElement := el.FindElement(AssertionTag)
	if assertionElement == nil {
		return ErrMissingAssertion
	}

	subjectStatement := assertionElement.FindElement(childPath(assertionElement.Space, SubjectTag))
	if subjectStatement == nil {
		return ErrMissingElement{Tag: SubjectTag}
	}

	subjectConfirmationStatement := subjectStatement.FindElement(childPath(assertionElement.Space, SubjectConfirmationTag))
	if subjectConfirmationStatement == nil {
		return ErrMissingElement{Tag: SubjectConfirmationTag}
	}

	methodAttr := subjectConfirmationStatement.SelectAttr(MethodAttr)
	if methodAttr.Value != SubjMethodBearer {
		return ErrInvalidValue{
			Reason:   ReasonUnsupported,
			Key:      SubjectConfirmationTag,
			Expected: SubjMethodBearer,
			Actual:   methodAttr.Value,
		}
	}

	subjectConfirmationDataStatement := subjectConfirmationStatement.FindElement(childPath(assertionElement.Space, SubjectConfirmationDataTag))
	if subjectConfirmationDataStatement == nil {
		return ErrMissingElement{Tag: SubjectConfirmationDataTag}
	}

	recipientAttr := subjectConfirmationDataStatement.SelectAttr(RecipientAttr)
	if recipientAttr == nil {
		return ErrMissingElement{Tag: SubjectConfirmationTag, Attribute: RecipientAttr}
	}
	if recipientAttr.Value != sp.AssertionConsumerServiceURL {
		return ErrInvalidValue{
			Key:      RecipientAttr,
			Expected: sp.AssertionConsumerServiceURL,
			Actual:   recipientAttr.Value,
		}
	}

	notOnOrAfterAttr := subjectConfirmationDataStatement.SelectAttr(NotOnOrAfterAttr)
	if notOnOrAfterAttr != nil {
		after, err := time.Parse(time.RFC3339, notOnOrAfterAttr.Value)
		if err != nil {
			return ErrParsing{Tag: NotOnOrAfterAttr, Value: notOnOrAfterAttr.Value, Type: "time.RFC3339"}
		}
		t := time.Now()

		if time.Now().After(after) {
			return ErrInvalidValue{
				Reason:   ReasonExpired,
				Key:      NotOnOrAfterAttr,
				Expected: t.Format(time.RFC3339),
				Actual:   notOnOrAfterAttr.Value,
			}
		}
	}

	return nil
}
