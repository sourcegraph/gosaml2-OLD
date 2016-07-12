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

// AttrVal is an abstraction for the string value of an XML document, which will
// ensure that all surrounding space is trimmed during Unmarshaling
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

// Values is a convenience wrapper for a map of strings to Attributes, which
// can be used for easy access to the string values of Attribute lists.
type Values map[string]Attribute

// Get is a safe method (nil maps will not panic) for returning the first value
// for an attribute at a key, or the empty string if none exists.
func (vals Values) Get(k string) string {
	if vals == nil {
		return ""
	}
	if v, ok := vals[k]; ok && len(v.Values) > 0 {
		return string(v.Values[0])
	}
	return ""
}

// Set replaces any pre-existing key's values (if any existed) with an
// attribute containing only the given value.
func (vals Values) Set(k, v string) {
	vals[k] = Attribute{Values: []AttrVal{AttrVal(v)}}
}

// Add appends to any Attribute's set of values, whether or not the key existed
// already. That is, it will create an attribute with a one-length slice if none
// existed.
func (vals Values) Add(k, v string) {
	if _, ok := vals[k]; !ok {
		vals.Set(k, v)
		return
	}
	val := vals[k]
	val.Values = append(val.Values, AttrVal(v))
	vals[k] = val
}

// Delete implements a quick key delete
func (vals Values) Del(k string) {
	delete(vals, k)
}

// UnmarshalXML implements encoding/xml.Unmarshaler
func (vals *Values) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*vals = Values{}

	var list struct{ Attribute []Attribute }

	err := d.DecodeElement(&list, &start)
	if err != nil {
		return err
	}

	for _, a := range list.Attribute {
		(*vals)[a.Name] = a
	}

	return nil
}
