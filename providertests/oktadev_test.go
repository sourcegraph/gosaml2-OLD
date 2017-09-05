package providertests

import (
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/russellhaering/gosaml2"
	"github.com/russellhaering/goxmldsig"
)

var oktaScenarioErrors = map[int]string{
	1:  "error validating response: response and/or assertions must be signed",
	3:  "error validating response: Could not verify certificate against trusted certs",
	4:  "error validating response: Unrecognized Destination value, Expected: http://dba9a5fc.ngrok.io/v1/_saml_callback, Actual: fake.identifier.example.com",
	5:  "error validating response: Unrecognized Issuer value, Expected: http://example.com/saml/acs/example, Actual: fake.identifier.example.com",
	7:  "error validating response: missing Issuer element",
	8:  "error validating response: missing NotOnOrAfter attribute on SubjectConfirmationData element",
	9:  "missing NotOnOrAfter attribute on Conditions element",
	10: "missing NotBefore attribute on Conditions element",
	12: "error validating response: Missing ID attribute",
	13: "error validating response: Signature could not be verified",
	14: "error validating response: Unrecognized StatusCode value, Expected: urn:oasis:names:tc:SAML:2.0:status:Success, Actual: Failure",
	15: "error validating response: Unrecognized StatusCode value, Expected: urn:oasis:names:tc:SAML:2.0:status:Success, Actual: urn:oasis:names:tc:SAML:2.0:status:Requester",
}

var oktaScenarioWarnings = map[int]scenarioWarnings{
	6: scenarioWarnings{
		NotInAudience: true,
	},
	11: scenarioWarnings{
		InvalidTime: true,
	},
}

func TestOktaDevCasesLocally(t *testing.T) {
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      "http://example.com/saml/acs/example",
		IdentityProviderIssuer:      "http://example.com/saml/acs/example",
		AssertionConsumerServiceURL: "http://dba9a5fc.ngrok.io/v1/_saml_callback",
		AudienceURI:                 "http://example.com/saml/acs/example",
		IDPCertificateStore:         LoadCertificateStore("./testdata/saml.oktadev.com/oktadev.pem"),
		Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2017, 4, 4, 17, 54, 0, 0, time.UTC))),
	}

	scenarios := []ProviderTestScenario{}

	for i := 0; i < 17; i++ {
		response := LoadRawResponse(fmt.Sprintf("./testdata/saml.oktadev.com/response_%d", i))
		scenarios = append(scenarios, ProviderTestScenario{
			ScenarioName:    fmt.Sprintf("Scenario_%d", i),
			Response:        response,
			ServiceProvider: sp,
			// Capture the value of i by passing it to a function.
			CheckError:       scenarioErrorChecker(i, oktaScenarioErrors),
			CheckWarningInfo: scenarioWarningChecker(i, oktaScenarioWarnings),
		})
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
