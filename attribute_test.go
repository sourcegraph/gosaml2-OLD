package saml2

import (
	"encoding/xml"
	"log"
	"strings"
	"testing"
)

const testAttrs = `<saml2:Attribute
    FriendlyName="eduPersonEntitlement"
    Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
  <saml2:AttributeValue
      xmlns:xsd="http://www.w3.org/2001/XMLSchema"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:type="xsd:string">
    urn:mace:dir:entitlement:common-lib-terms
  </saml2:AttributeValue>
  <saml2:AttributeValue
      xmlns:xsd="http://www.w3.org/2001/XMLSchema"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:type="xsd:string">
    https://university.edu/path/to/thingy
  </saml2:AttributeValue>
  <saml2:AttributeValue
      xmlns:xsd="http://www.w3.org/2001/XMLSchema"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:type="xsd:string">
    urn:mace:incommon:entitlement:common:1
  </saml2:AttributeValue>
</saml2:Attribute>`

const (
	attrName = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
	attr1val = "urn:mace:dir:entitlement:common-lib-terms"
	vLen     = 3
)

func TestAttributeDecode(t *testing.T) {
	r := strings.NewReader(testAttrs)

	var attr Attribute

	err := xml.NewDecoder(r).Decode(&attr)
	if err != nil {
		t.Fatalf("Error decoding: %v", err)
	}

	if len(attr.Values) != vLen {
		t.Errorf("Wrong number of values returned: %d, should be %d.", len(attr.Values), vLen)
	}

	if attr.Values[0] != attr1val {
		t.Errorf("Wrong attribute value: %s, should be %s", attr.Values[0], attr1val)
	}

	if attr.Name != attrName {
		t.Errorf("Wrong attribute name: %s, should be %s", attr.Name, attrName)
	}

	log.Printf("%#v", attr)
}
