package saml2

import (
	"encoding/xml"
	"fmt"

	"github.com/beevik/etree"
)

//ErrMissingElement is the error type that indicates an element and/or attribute is
//missing. It provides a structured error that can be more appropriately acted
//upon.
type ErrMissingElement struct {
	Tag, Attribute string
}

type ErrVerification struct {
	Cause error
}

func (e ErrVerification) Error() string {
	return fmt.Sprintf("error validating response: %s", e.Cause.Error())
}

//ErrMissingAssertion indicates that an appropriate assertion element could not
//be found in the SAML Response
var (
	ErrMissingAssertion = ErrMissingElement{Tag: AssertionTag}
)

func (e ErrMissingElement) Error() string {
	if e.Attribute != "" {
		return fmt.Sprintf("missing %s attribute on %s element", e.Attribute, e.Tag)
	}
	return fmt.Sprintf("missing %s element", e.Tag)
}

//RetrieveAssertionInfo takes an encoded response and returns the AssertionInfo
//contained, or an error message if an error has been encountered.
func (sp *SAMLServiceProvider) RetrieveAssertionInfo(encodedResponse string) (*AssertionInfo, error) {
	assertionInfo := &AssertionInfo{}

	el, err := sp.ValidateEncodedResponse(encodedResponse)
	if err != nil {
		return nil, ErrVerification{Cause: err}
	}

	assertionElement := el.FindElement(AssertionTag)
	if assertionElement == nil {
		return nil, ErrMissingAssertion
	}

	//Verify all conditions for the assertion
	conditionsStatement := assertionElement.FindElement(childPath(assertionElement.Space, ConditionsTag))
	if conditionsStatement == nil {
		return nil, ErrMissingElement{Tag: ConditionsTag}
	}

	warningInfo, err := sp.VerifyAssertionConditions(assertionElement, conditionsStatement)
	if err != nil {
		return nil, err
	}

	//Get the NameID
	subjectStatement := assertionElement.FindElement(childPath(assertionElement.Space, SubjectTag))
	if subjectStatement == nil {
		return nil, ErrMissingElement{Tag: SubjectTag}
	}

	nameIDStatement := subjectStatement.FindElement(childPath(assertionElement.Space, NameIdTag))
	if nameIDStatement == nil {
		return nil, ErrMissingElement{Tag: NameIdTag}
	}
	assertionInfo.NameID = nameIDStatement.Text()

	//Get the actual assertion attributes
	attributeStatement := assertionElement.FindElement(childPath(assertionElement.Space, AttributeStatementTag))
	if attributeStatement == nil && !sp.AllowMissingAttributes {
		return nil, ErrMissingElement{Tag: AttributeStatementTag}
	}

	if attributeStatement != nil {
		doc := etree.NewDocument()
		doc.SetRoot(attributeStatement)
		bs, err := doc.WriteToBytes()

		if err != nil {
			return nil, err
		}

		err = xml.Unmarshal(bs, &assertionInfo.Values)
		if err != nil {
			return nil, err
		}
	}
	assertionInfo.WarningInfo = warningInfo
	return assertionInfo, nil
}
