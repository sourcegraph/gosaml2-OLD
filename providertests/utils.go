package providertests

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/russellhaering/gosaml2"
	"github.com/russellhaering/goxmldsig"
)

func LoadXMLResponse(path string) string {
	xml, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(xml)
}

func LoadRawResponse(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return string(data)
}

func LoadCertificateStore(path string) dsig.X509CertificateStore {
	encoded, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(encoded)
	if block == nil {
		panic("no certificate block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	return &dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}
}

type ProviderTestScenario struct {
	ScenarioName     string
	Response         string
	ServiceProvider  *saml2.SAMLServiceProvider
	CheckError       func(*testing.T, error)
	CheckWarningInfo func(*testing.T, *saml2.WarningInfo)
}
