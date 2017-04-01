package types

import (
	"encoding/xml"
)

type Response struct {
	XMLName             xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Destination         string               `xml:"Destination,attr"`
	Version             string               `xml:"Version,attr"`
	Status              *Status              `xml:"Status"`
	Issuer              *Issuer              `xml:"Issuer"`
	Assertions          []Assertion          `xml:"Assertion"`
	EncryptedAssertions []EncryptedAssertion `xml:"EncryptedAssertion"`
}

type Status struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}

type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:"Value,attr"`
}

type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

type Assertion struct {
	XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	Issuer     *Issuer     `xml:"Issuer"`
	Subject    *Subject    `xml:"Subject"`
	Conditions *Conditions `xml:"Conditions"`
}

type Subject struct {
	XMLName             xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              *NameID              `xml:"NameID"`
	SubjectConfirmation *SubjectConfirmation `xml:"SubjectConfirmation"`
}

type NameID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Value   string   `xml:",chardata"`
}

type SubjectConfirmation struct {
	XMLName                 xml.Name                 `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
	Method                  string                   `xml:"Method,attr"`
	SubjectConfirmationData *SubjectConfirmationData `xml:"SubjectConfirmationData"`
}

type SubjectConfirmationData struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
	Recipient    string   `xml:"Recipient,attr"`
	InResponseTo string   `xml:"InResponseTo,attr"`
}

type Conditions struct {
	XMLName             xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AudienceRestriction *AudienceRestriction `xml:"AudienceRestriction"`
}

type AudienceRestriction struct {
	XMLName  xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	Audience *Audience `xml:"Audience"`
}

type Audience struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
	Value   string   `xml:",chardata"`
}
