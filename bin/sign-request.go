package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
	"crypto"
	"crypto/rand"
	"math/big"
)

type SignRequestType int

const (
	LEAF_CERT_VERSION_1 SignRequestType = iota
	LEAF_CERT_VERSION_2
	LEAF_CERT_PATHLEN_PRESENT
	LEAF_CERT_EMPTY_ISSUER
)

var defaultRootCAName = &pkix.Name{
                Country:            []string{"IN"},
                Province:           []string{"KA"},
                Locality:           []string{"BGL"},
                Organization:       []string{"CSCO"},
                OrganizationalUnit: []string{"MIG"},
                CommonName:         "EXAMPLE-CA.cisco.com",
}

var defaultIntermed1CAName = &pkix.Name{
                Country:            []string{"IN"},
                Province:           []string{"KA"},
                Locality:           []string{"BGL"},
                Organization:       []string{"CSCO"},
                OrganizationalUnit: []string{"MIG"},
                CommonName:         "EXAMPLE-INTERMED1-CA.cisco.com",
}



func loadDefaultCAKeys(defaultCADirectoryPath string) (crypto.PrivateKey, crypto.PrivateKey) {
	rootCAKey      := LoadKey(fmt.Sprintf("%s/root-ca-key.pem", defaultCADirectoryPath))
	intermed1CAKey := LoadKey(fmt.Sprintf("%s/intermed1-ca-key.pem", defaultCADirectoryPath))
	return rootCAKey, intermed1CAKey
}

func loadDefaultCACerts(defaultCADirectoryPath string) (*badcert.Certificate, *badcert.Certificate) {
        rootCACert      := ReadCertificate(fmt.Sprintf("%s/root-ca-cert.pem", defaultCADirectoryPath))
        intermed1CACert := ReadCertificate(fmt.Sprintf("%s/intermed1-ca-cert.pem", defaultCADirectoryPath))
	return rootCACert, intermed1CACert
}


//TODO: Instead of this, need to create a CA on request, and use from there
//That way, theres no risk of running out of serial numbers etc
//We can also start HTTP server for CRL and OCSP server upon that on the fly
func SignRequestBadCertLeafVersion1(signRequestCertOutputDirectory string, requestFilePath string, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey,
   rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeaf1Extensions badcert.ExtensionSlice
       var modifiedLeaf2Extensions badcert.ExtensionSlice
       
       certRequest = ReadCertificateRequest(requestFilePath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
       
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber1, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }
       badLeaf1Recipe        := BuildDefaultLeafRecipe().SetVersion1().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber1)
       modifiedLeaf1Extensions = badLeaf1Recipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
       badLeaf1Recipe.SetExtensions(modifiedLeaf1Extensions)
       badLeaf1Recipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
       certChain1 := CreateBadCertificateChain(" ", nil, true, true, false, badLeaf1Recipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       
       serialNumber2, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }
       badLeaf2Recipe        := BuildDefaultLeafRecipe().SetVersion1().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber2)
       modifiedLeaf2Extensions = badLeaf2Recipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
       badLeaf2Recipe.SetExtensions(modifiedLeaf2Extensions) 
       badLeaf2Recipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
       certChain2 := CreateBadCertificateChain(" ", nil, true, true, false, badLeaf2Recipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       
       badCertificateChains := CreateBadCertificateChains(certChain1, certChain2)
       for index, badCertificateChain := range badCertificateChains {
                testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-VERSION-1-%d.json", signRequestCertOutputDirectory, index))
       }
}

func SignRequestBadCertLeafVersion2(signRequestCertOutputDirectory string, requestFilePath string, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey,
   rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeaf1Extensions badcert.ExtensionSlice
       var modifiedLeaf2Extensions badcert.ExtensionSlice

       certRequest = ReadCertificateRequest(requestFilePath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
        
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber1, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }
       badLeaf1Recipe        := BuildDefaultLeafRecipe().SetVersion2().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber1)
       modifiedLeaf1Extensions = badLeaf1Recipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
       badLeaf1Recipe.SetExtensions(modifiedLeaf1Extensions)
       badLeaf1Recipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
       certChain1 := CreateBadCertificateChain(" ", nil, true, true, false, badLeaf1Recipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       
       serialNumber2, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }
       badLeaf2Recipe        := BuildDefaultLeafRecipe().SetVersion2().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber2)
       modifiedLeaf2Extensions = badLeaf2Recipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
       badLeaf2Recipe.SetExtensions(modifiedLeaf2Extensions) 
       badLeaf2Recipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
       certChain2 := CreateBadCertificateChain(" ", nil, true, true, false, badLeaf2Recipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       
       badCertificateChains := CreateBadCertificateChains(certChain1, certChain2)
       for index, badCertificateChain := range badCertificateChains {
                testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-VERSION-2-%d.json", signRequestCertOutputDirectory, index))
       }
}

func SignRequestBadCertLeafPathlenPresent(signRequestCertOutputDirectory string, requestFilePath string, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
}

func SignRequestBadCertLeafEmptyIssuer(signRequestCertOutputDirectory string, requestFilePath string, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
}


func SignRequest(signRequestCertOutputDirectory string, signRequestType SignRequestType, requestFilePath string) {
	CreateDirectory(signRequestCertOutputDirectory)

	//NOTE, we also need to pass the correct sigalgo parameter to this
        rootCAKey, intermed1CAKey   := loadDefaultCAKeys("./CA")
	rootCACert, intermed1CACert := loadDefaultCACerts("./CA")

	if (signRequestType == LEAF_CERT_VERSION_1) {
		SignRequestBadCertLeafVersion1(signRequestCertOutputDirectory, requestFilePath, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (signRequestType == LEAF_CERT_VERSION_2) {
		SignRequestBadCertLeafVersion2(signRequestCertOutputDirectory, requestFilePath, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (signRequestType == LEAF_CERT_PATHLEN_PRESENT) {
		SignRequestBadCertLeafPathlenPresent(signRequestCertOutputDirectory, requestFilePath, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (signRequestType == LEAF_CERT_EMPTY_ISSUER) {
		SignRequestBadCertLeafEmptyIssuer(signRequestCertOutputDirectory, requestFilePath, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else {
		panic(errors.New("Unknown sign request type"))
	}
}
