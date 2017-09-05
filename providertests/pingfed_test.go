package providertests

import (
	"fmt"
	"testing"

	"github.com/russellhaering/gosaml2"
)

var pingFedScenarioErrors = map[int]string{
	// 01 - signed(Response(Assertion)) - no KeyInfo (no IDP signing certificate included)
	// By default, PingFed does not include the KeyInfo element (which would include the
	// IDP signing certificate) in Response.  Most other IDPs include KeyInfo element.
	// gosaml2 is ok with this as long as the SP has only one IDP signing certificate
	// for this relationship (it does not have to guess at to which cert to use).
	// Note: Response.Destination is set.
	01: "",
	// 02 - signed(Response(Assertion)) - with KeyInfo (including IDP signing certificate)
	// Same as pfed11_response_01 except KeyInfo is included.
	// Note: Response.Destination is set.
	02: "",
	// 03 - Response(signed(Assertion))
	// As with 01, KeyInfo element is not included (not a bug).  Unlike 01,
	// Response.Destination is NOT set.  Most IDPs (including PingOne) always includes Response.Destination.
	// PingFed only includes Response.Destination when the Response is signed.
	// SAML Core 2.0 defines Response.Destination as [Optional].
	// Thus, PingFed is not in not including Destination.  Before a fix, gosaml2 required
	// Response.Destination.  gosaml2 now only checks the value of Response.Destination if it
	// is set (mandated by SAML Core 2.0).
	03: "",
	// 05 - signed(Response(encrypted(Assertion))) - no encryption certificate included in Assertion
	// PingFed does not include the SP encryption certificate and it does not seem to have an option for it.
	// OneLogin (see olgn09/olgn09_response_05.b64) also does not include SP encryption certificate by default.
	// FIXME: gosaml2 needs to handle this.
	05: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: key decryption attempted with mismatched cert, SP cert(cd:f6:7c:e9), assertion cert()",
}

var pingFedScenarioWarnings = map[int]scenarioWarnings{}

var pingFedAtTimes = map[int]string{}

func TestPingFedCasesLocally(t *testing.T) {
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      "https://saml.test.nope:9031/eid/sxpmrhbkzn", // not required for these tests
		IdentityProviderIssuer:      "https://saml.test.nope:9031/eid/sxpmrhbkzn",
		AssertionConsumerServiceURL: "https://saml.test.nope/session/sso/saml/acs/hp24dqnpvq",
		AudienceURI:                 "https://saml.test.nope/session/sso/saml/spentityid/hp24dqnpvq",
		IDPCertificateStore:         LoadCertificateStore("./testdata/pingfed/idp.signing.cert"),
		SPKeyStore:                  LoadKeyStore("./testdata/pingfed/sp.encryption.cert", "./testdata/pingfed/sp.encryption.key"),
		SPSigningKeyStore:           LoadKeyStore("./testdata/pingfed/sp.signing.cert", "./testdata/pingfed/sp.signing.key"),
		ValidateEncryptionCert:      true,
	}

	scenarios := []ProviderTestScenario{}
	for _, idx := range scenarioIndexes(pingFedScenarioErrors, pingFedScenarioWarnings) {
		response := LoadRawResponse(fmt.Sprintf("./testdata/pingfed/pfed11_response_%02d.b64", idx))
		scenarios = append(scenarios, ProviderTestScenario{
			ScenarioName:     fmt.Sprintf("Scenario_%02d", idx),
			Response:         response,
			ServiceProvider:  spAtTime(sp, getAtTime(idx, pingFedAtTimes), response),
			CheckError:       scenarioErrorChecker(idx, pingFedScenarioErrors),
			CheckWarningInfo: scenarioWarningChecker(idx, pingFedScenarioWarnings),
		})
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
