package providertests

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/russellhaering/gosaml2"
	"github.com/russellhaering/goxmldsig"
)

func TestValidateResponses(t *testing.T) {
	scenarios := []ProviderTestScenario{
		{
			Response: LoadXMLResponse("./testdata/auth0_response.xml"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://scaleft-test.auth0.com/samlp/rlXOZ4kOUTQaTV8icSXrfZUd1qtD1NhK",
				IdentityProviderIssuer:      "urn:scaleft-test.auth0.com",
				AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
				IDPCertificateStore:         LoadCertificateStore("./testdata/auth0_cert.pem"),
				Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2016, 7, 25, 17, 50, 0, 0, time.UTC))),
			},
		},
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
