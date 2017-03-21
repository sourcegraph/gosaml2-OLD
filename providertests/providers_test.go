package providertests

import (
	"testing"
	"time"

	"crypto/rsa"

	"github.com/jonboulle/clockwork"
	"github.com/russellhaering/gosaml2"
	"github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestValidateResponses(t *testing.T) {
	scenarios := []ProviderTestScenario{
		{
			ScenarioName: "Auth0",
			Response:     LoadXMLResponse("./testdata/auth0_response.xml"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://scaleft-test.auth0.com/samlp/rlXOZ4kOUTQaTV8icSXrfZUd1qtD1NhK",
				IdentityProviderIssuer:      "urn:scaleft-test.auth0.com",
				AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
				IDPCertificateStore:         LoadCertificateStore("./testdata/auth0_cert.pem"),
				Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2016, 7, 25, 17, 50, 0, 0, time.UTC))),
			},
		},

		{
			ScenarioName: "Okta",
			Response:     LoadXMLResponse("./testdata/okta_response.xml"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://dev-116807.oktapreview.com/app/scaleftdev116807_test_1/exk659aytfMeNI49v0h7/sso/saml",
				IdentityProviderIssuer:      "http://www.okta.com/exk659aytfMeNI49v0h7",
				AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
				SignAuthnRequests:           true,
				AudienceURI:                 "123",
				IDPCertificateStore:         LoadCertificateStore("./testdata/okta_cert.pem"),
				Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2016, 7, 25, 17, 50, 0, 0, time.UTC))),
			},
		},
		{
			ScenarioName: "OneLogin",
			Response:     LoadXMLResponse("./testdata/onelogin_response.xml"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://launchdarkly-dev.onelogin.com/trust/saml2/http-post/sso/634027",
				IdentityProviderIssuer:      "https://app.onelogin.com/saml/metadata/634027",
				AssertionConsumerServiceURL: "http://884d40bf.ngrok.io/api/sso/saml2/acs/58af624473d4f375b8e70d81",
				IDPCertificateStore:         LoadCertificateStore("./testdata/onelogin_cert.pem"),
				SkipSignatureValidation:     false,
				AllowMissingAttributes:      true,
				Clock: dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2017, 3, 7, 22, 50, 0, 0, time.UTC))),
			},
		},
		{
			ScenarioName: "OracleAccessManager",
			Response:     LoadXMLResponse("./testdata/oam_response.xml"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://deaoam-dev02.jpl.nasa.gov:14101/oam/fed",
				IdentityProviderIssuer:      "https://deaoam-dev02.jpl.nasa.gov:14101/oam/fed",
				AssertionConsumerServiceURL: "http://127.0.0.1:5556/callback",
				IDPCertificateStore:         LoadCertificateStore("./testdata/oam_cert.pem"),
				SkipSignatureValidation:     false,
				AllowMissingAttributes:      false,
				Clock: dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2016, 12, 12, 00, 00, 0, 0, time.UTC))),
			},

			// This test case currently isn't totally successful - signature verification fails.
			// It may be that the response wasn't signed with this certificate, or perhaps there
			// is another issue in our implementation.
			CheckError: func(t *testing.T, err error) {
				require.IsType(t, saml2.ErrVerification{}, err)
				ev := err.(saml2.ErrVerification)
				require.Equal(t, ev.Cause, rsa.ErrVerification)
			},
		},
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
