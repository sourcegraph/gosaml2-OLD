package saml2

import "fmt"

//ErrMissingElement is the error type that indicates an element and/or attribute is
//missing. It provides a structured error that can be more appropriately acted
//upon.
type ErrMissingElement struct {
	Tag, Attribute string
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
		return nil, err
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
	if attributeStatement == nil {
		return nil, ErrMissingElement{Tag: AttributeStatementTag}
	}

	info := make(map[string]string)
	for _, child := range attributeStatement.ChildElements() {
		nameAttr := child.SelectAttr(NameAttr)
		attributeValue := child.FindElement(childPath(child.Space, AttributeValueTag))
		if attributeValue == nil {
			return nil, ErrMissingElement{Tag: AttributeValueTag}
		}
		info[nameAttr.Value] = attributeValue.Text()
	}

	assertionInfo.Values = info
	assertionInfo.WarningInfo = warningInfo
	return assertionInfo, nil
}
