package saml2

import (
	"encoding/xml"
	"strings"
)

// Attribute holds the assertion name/values returned by the remote hosts
type Attribute struct {
	FriendlyName string    `xml:"FriendlyName,attr"`
	Name         string    `xml:"Name,attr"`
	NameFormat   string    `xml:"NameFormat,attr"`
	Values       []AttrVal `xml:"AttributeValue"`
}

// Value is an abstraction for the
type AttrVal string

// UnmarshalXML implements xml.Unmarshaler
func (v *AttrVal) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	err := d.DecodeElement(&s, &start)
	if err != nil {
		return err
	}
	*v = AttrVal(strings.TrimSpace(s))
	return nil
}
