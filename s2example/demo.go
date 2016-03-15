package main

import (
	"io"
	"net/http"

	"github.com/russellhaering/gosaml2"
	"github.com/russellhaering/goxmldsig"
)

func main() {
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      "https://dev-116807.oktapreview.com/app/scaleftdev116807_scaleft_1/exk5zt0r12Edi4rD20h7/sso/saml",
		IdentityProviderIssuer:      "http://www.okta.com/exk5zt0r12Edi4rD20h7",
		AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
		SignAuthnRequests:           true,
		IDPCertificateStore:         nil,
		SPKeyStore:                  dsig.RandomKeyStoreForTest(),
	}

	http.HandleFunc("/v1/_saml_callback", func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			panic(err)
		}

		err = sp.ValidateEncodedResponse(req.FormValue("SAMLResponse"))
		if err != nil {
			panic(err)
		}

		io.WriteString(rw, "nope")
	})

	authUrl, err := sp.BuildAuthURL("")
	if err != nil {
		panic(err)
	}

	println(authUrl)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}
