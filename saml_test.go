package saml2

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestSAML(t *testing.T) {
	// NOTE: These tests will probably start failing after 2026-02-09 21:53:06 +0000 UTC, hopefully this code lives long enough to see that happen
	// You'll have to regenerate a base64 encoded response then
	block, _ := pem.Decode([]byte(idpCertificate))
	require.NotEmpty(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.NotEmpty(t, cert)

	randomKeyStore := dsig.RandomKeyStoreForTest()
	_, _cert, err := randomKeyStore.GetKeyPair()

	cert0, err := x509.ParseCertificate(_cert)
	require.NoError(t, err)
	require.NotEmpty(t, cert0)

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert, cert0},
	}

	sp := &SAMLServiceProvider{
		IdentityProviderSSOURL:      "https://dev-116807.oktapreview.com/app/scaleftdev116807_scaleft_1/exk5zt0r12Edi4rD20h7/sso/saml",
		IdentityProviderIssuer:      "http://www.okta.com/exk5zt0r12Edi4rD20h7",
		AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
		SignAuthnRequests:           true,
		AudienceURI:                 "123",
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  randomKeyStore,
	}

	authRequestURL, err := sp.BuildAuthURL("/some/link/here")
	require.NoError(t, err)
	require.NotEmpty(t, authRequestURL)

	authRequestString, err := sp.BuildAuthRequest()
	require.NoError(t, err)

	encodedAuthRequest := base64.StdEncoding.EncodeToString([]byte(authRequestString))
	// Verify that our signed auth request can be validated
	err = sp.ValidateEncodedResponse(encodedAuthRequest)
	require.NoError(t, err)

	// Validate actual responses from Okta
	err = sp.ValidateEncodedResponse(exampleBase64)
	require.NoError(t, err)

	err = sp.ValidateEncodedResponse(exampleBase64_2)
	require.NoError(t, err)

	_, err = sp.RetrieveAssertionInfo(exampleBase64_2)
	require.Error(t, err)

	assertionInfo, err := sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString([]byte(assertionInfoModifiedAudienceResponse)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.True(t, assertionInfo.WarningInfo.NotInAudience)

	assertionInfo, err = sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString([]byte(assertionInfoOneTimeUseResponse)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.True(t, assertionInfo.WarningInfo.OneTimeUse)

	assertionInfo, err = sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString([]byte(assertionInfoProxyRestrictionResponse)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.NotEmpty(t, assertionInfo.WarningInfo.ProxyRestriction)
	require.Equal(t, 3, assertionInfo.WarningInfo.ProxyRestriction.Count)
	require.Equal(t, []string{"123"}, assertionInfo.WarningInfo.ProxyRestriction.Audience)

	assertionInfo, err = sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString([]byte(assertionInfoProxyRestrictionNoCountResponse)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.NotEmpty(t, assertionInfo.WarningInfo.ProxyRestriction)
	require.Equal(t, 0, assertionInfo.WarningInfo.ProxyRestriction.Count)
	require.Equal(t, []string{"123"}, assertionInfo.WarningInfo.ProxyRestriction.Audience)

	assertionInfo, err = sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString([]byte(assertionInfoProxyRestrictionNoAudienceResponse)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.NotEmpty(t, assertionInfo.WarningInfo.ProxyRestriction)
	require.Equal(t, 3, assertionInfo.WarningInfo.ProxyRestriction.Count)
	require.Equal(t, []string{}, assertionInfo.WarningInfo.ProxyRestriction.Audience)

	assertionInfo, err = sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString([]byte(assertionInfoResponse)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.NotEmpty(t, assertionInfo.Values)
	require.Equal(t, "phoebe.simon@scaleft.com", assertionInfo.Values["Email"])
	require.Equal(t, "Phoebe", assertionInfo.Values["FirstName"])
	require.Equal(t, "Simon", assertionInfo.Values["LastName"])
	require.Equal(t, "phoebe.simon@scaleft.com", assertionInfo.Values["Login"])

	err = sp.ValidateEncodedResponse(base64.StdEncoding.EncodeToString([]byte(manInTheMiddledResponse)))
	require.Error(t, err)

	err = sp.ValidateEncodedResponse(base64.StdEncoding.EncodeToString([]byte(alteredReferenceURIResponse)))
	require.Error(t, err)

	err = sp.ValidateEncodedResponse(base64.StdEncoding.EncodeToString([]byte(alteredSignedInfoResponse)))
	require.Error(t, err)
}
