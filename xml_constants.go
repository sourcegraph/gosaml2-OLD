package saml2

const (
	ResponseTag                = "Response"
	AssertionTag               = "Assertion"
	SubjectTag                 = "Subject"
	NameIdTag                  = "NameID"
	SubjectConfirmationTag     = "SubjectConfirmation"
	SubjectConfirmationDataTag = "SubjectConfirmationData"
	AttributeStatementTag      = "AttributeStatement"
	AttributeValueTag          = "AttributeValue"
	ConditionsTag              = "Conditions"
	AudienceRestrictionTag     = "AudienceRestriction"
	AudienceTag                = "Audience"
	OneTimeUseTag              = "OneTimeUse"
	ProxyRestrictionTag        = "ProxyRestriction"
)

const (
	DestinationAttr  = "Destination"
	VersionAttr      = "Version"
	IdAttr           = "ID"
	MethodAttr       = "Method"
	RecipientAttr    = "Recipient"
	NameAttr         = "Name"
	NotBeforeAttr    = "NotBefore"
	NotOnOrAfterAttr = "NotOnOrAfter"
	CountAttr        = "Count"
)

const (
	Persistent      = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	Transient       = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	EmailAddress    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	Unspecified     = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	X509SubjectName = "urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName"
)
