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

// Values is a type for holding Assertion Values which may be multi-valued
type Values map[string]Attribute

// Get is a safe method (nil maps will not panic) for returning the first value
// for an assertion key.
func (vals Values) Get(k string) string {
	if vals == nil {
		return ""
	}
	if v, ok := vals[k]; ok && len(v.Values) > 0 {
		return string(v.Values[0])
	}
	return ""
}

// Set replaces any pre-existing key's values (if any existed) with only the
// given value.
func (vals Values) Set(k, v string) {
	vals[k] = Attribute{Values: []AttrVal{AttrVal(v)}}
}

// Add appends to any set of values, whether or not the key existed already.
// That is, it will create a slice if none existed.
func (vals Values) Add(k, v string) {
	if _, ok := vals[k]; !ok {
		vals.Set(k, v)
		return
	}
	val := vals[k]
	val.Values = append(val.Values, AttrVal(v))
	vals[k] = val
}
