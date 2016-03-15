package saml2

import (
	"encoding/base64"
	"testing"

	"github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

var idpCertificate = `
-----BEGIN CERTIFICATE-----
MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a
-----END CERTIFICATE-----
`

const exampleResponse = `
<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8080/v1/_saml_callback" ID="id9464273530269711243550013" InResponseTo="_8a64888e-0a14-4fb9-905d-65629b84786a" IssueInstant="2016-03-15T00:21:40.409Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id9464273530269711243550013"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>gvXF2ygtu4WbVYdepEtHFbgCZLfKW893eFF+x6gjX80=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>FfjEHuBk+a/zEi6a1s9dt/apotEVdR/SprEwZwpnZGG1vd1HVOZP4z+7rh2OMzqWT2tjXWT0AEtIocxkOBzaRqQvGHIID8RGTApKRde3a9ykY41Y5+hmSxYzQLQeTJ/boFqEV1nQdVmf6qwsH/M221IL0+pGbNxBNmDEZaepr6kSMuhiz/Wl4zZ3JVgdOqCCkZcSPLER4XLQ1OTTMvDDTmK1kkgMpejTtatlUHxcn27bUKK4uGvUuZXv3ydNKmS2FzogooLVggzKXN3mmyMDfLENTHYfjJi8h1l89nKZI4pVmFmuIdiGNV9EDycNaO3CNYIyI5w7A1JLBSVQVRCgNw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id9464273531132552093682430" IssueInstant="2016-03-15T00:21:40.409Z" Version="2.0"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id9464273531132552093682430"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>DRYTp4xjc4Ec2+fJkQQ2KxFp/4raYPQYGrLtXTp2IhQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>UquJAMHALMZGSab+9XCc6L010djnsDx1wOP7b3LEQpEmGsKUEbblAuI1mdCaKi28VSP7h04S8M4x4xmgG6+RgYERKrMrc6DsW5Mto3nl6TaYQYUMVchp7vX1kDmuGqiEuYusrqIwQnFJNgt+SDAXODolfaJqKH02EMrzEeSFyfEiwaP8+R2jTQ9vqrMTX+t9b9nNo7F1N2sPWFGfk2TC3F5r4H+MF7n33cSny/qzPEEisldLF3LoTdnrPJdKpio/9kPr7ODhks+hwij82gYlvLCXkagmn76lSsAbUgsYoq1C3zvhYUHjTH2c0jmqHNwKT/8FA/oJtxx3N9agDpXEHw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">russell.haering@scaleft.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_8a64888e-0a14-4fb9-905d-65629b84786a" NotOnOrAfter="2016-03-15T00:26:40.409Z" Recipient="http://localhost:8080/v1/_saml_callback"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2016-03-15T00:16:40.409Z" NotOnOrAfter="2016-03-15T00:26:40.409Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AudienceRestriction><saml2:Audience>123</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2016-03-15T00:21:40.409Z" SessionIndex="_8a64888e-0a14-4fb9-905d-65629b84786a" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>
`

func TestSAML(t *testing.T) {
	sp := &SAMLServiceProvider{
		IdentityProviderSSOURL:      "https://dev-116807.oktapreview.com/app/scaleftdev116807_scaleft_1/exk5zt0r12Edi4rD20h7/sso/saml",
		IdentityProviderIssuer:      "http://www.okta.com/exk5zt0r12Edi4rD20h7",
		AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
		SignAuthnRequests:           true,
		IDPCertificateStore:         nil,
		SPKeyStore:                  dsig.RandomKeyStoreForTest(),
	}

	err := sp.ValidateEncodedResponse(base64.StdEncoding.EncodeToString([]byte(exampleResponse)))
	require.NoError(t, err)
}
