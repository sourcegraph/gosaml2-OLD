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
