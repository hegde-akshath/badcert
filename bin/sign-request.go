package main

import (
	"errors"
	"fmt"
	"os"
	"encoding/pem"
	"net"
	"net/url"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
	"crypto"
)

type SignRequestType int

const (
	LEAF_CERT_VERSION_1 SignRequestType = iota
	LEAF_CERT_VERSION_2
	LEAF_CERT_PATHLEN_PRESENT
	LEAF_CERT_EMPTY_ISSUER
)


func LoadKey(filepath string) (crypto.PrivateKey) {
    keyPem, err := os.ReadFile(filepath)
    if err != nil {
	    panic(err)
    }
    
    keyDer, _ := pem.Decode(keyPem)
    if keyDer == nil {
	    panic(errors.New("Failed to decode first PEM block"))
    }
    
    //NOTE: Parsing only PKCS8 for now
    key, err := badcert.ParsePKCS8PrivateKey(keyDer.Bytes)
    if err != nil {
	    panic(err)
    }
    
    return key    
}


func LoadDefaultCAKeys(defaultCADirectoryPath string) (crypto.PrivateKey, crypto.PrivateKey) {
	rootCAKey      := LoadKey(fmt.Sprintf("%s/root-key.pem", defaultCADirectoryPath))
	intermed1CAKey := LoadKey(fmt.Sprintf("%s/intermediate-key.pem", defaultCADirectoryPath))
	return rootCAKey, intermed1CAKey
}

func ReadCertificateRequest(requestFilePath string) (*badcert.CertificateRequest) {
	csrPem, err := os.ReadFile(requestFilePath)
        if err != nil {
		panic(err)
        }
    
        pemDer, _ := pem.Decode(csrPem)
        if pemDer == nil {
                panic(errors.New("Failed to extract first PEM block in request file"))
        }
    
        certRequest, err := badcert.ParseCertificateRequest(pemDer.Bytes)
        if err != nil {
                panic(err)
        }

	err = certRequest.CheckSignature()
	if err != nil {
		panic(err)
	}

        return certRequest
}

func SignRequestBadCertLeafVersion1(signRequestCertOutputDirectory string, requestFilePath string, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeaf1Extensions badcert.ExtensionSlice
       var modifiedLeaf2Extensions badcert.ExtensionSlice
       var defaultRootCAName *pkix.Name
       var defaultIntermed1CAName *pkix.Name

       defaultRootCAName = &pkix.Name{
                Country:            []string{"IN"},
                Province:           []string{"KA"},
                Locality:           []string{"BGL"},
                Organization:       []string{"CSCO"},
                OrganizationalUnit: []string{"MIG"},
                CommonName:         "EXAMPLE-CA.cisco.com",
        }

        defaultIntermed1CAName = &pkix.Name{
                Country:            []string{"IN"},
                Province:           []string{"KA"},
                Locality:           []string{"BGL"},
                Organization:       []string{"CSCO"},
                OrganizationalUnit: []string{"MIG"},
                CommonName:         "EXAMPLE-INTERMED1-CA.cisco.com",
        }

       certRequest = ReadCertificateRequest(requestFilePath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
             
       badLeafRecipe1        := BuildDefaultLeafRecipe().SetVersion1().SetSubject(&subject).SetIssuer(defaultRootCAName)
       modifiedLeaf1Extensions = badLeafRecipe1.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs)
       badLeafRecipe1.SetExtensions(modifiedLeaf1Extensions)
       badLeafRecipe1.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)

       badLeafRecipe2        := BuildDefaultLeafRecipe().SetVersion1().SetSubject(&subject).SetIssuer(defaultIntermed1CAName)
       modifiedLeaf2Extensions = badLeafRecipe2.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs)
       badLeafRecipe2.SetExtensions(modifiedLeaf2Extensions) 
       badLeafRecipe2.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
       
       f1, err := os.Create(fmt.Sprintf("%s/LEAF-CERT-VERSION-1-1.pem", signRequestCertOutputDirectory))
       if err != nil {
	       panic(err)
       }
       defer f1.Close()
       badLeafRecipe1.WriteCertificatePem(f1)

       f2, err := os.Create(fmt.Sprintf("%s/LEAF-CERT-VERSION-1-2.pem", signRequestCertOutputDirectory))
       if err != nil {
	       panic(err)
       }
       defer f2.Close()
       badLeafRecipe2.WriteCertificatePem(f2) 
}

func SignRequestBadCertLeafVersion2(signRequestCertOutputDirectory string, requestFilePath string, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeaf1Extensions badcert.ExtensionSlice
       var modifiedLeaf2Extensions badcert.ExtensionSlice
       var defaultRootCAName *pkix.Name
       var defaultIntermed1CAName *pkix.Name

       defaultRootCAName = &pkix.Name{
                Country:            []string{"IN"},
                Province:           []string{"KA"},
                Locality:           []string{"BGL"},
                Organization:       []string{"CSCO"},
                OrganizationalUnit: []string{"MIG"},
                CommonName:         "EXAMPLE-CA.cisco.com",
        }

	defaultIntermed1CAName = &pkix.Name{
                Country:            []string{"IN"},
                Province:           []string{"KA"},
                Locality:           []string{"BGL"},
                Organization:       []string{"CSCO"},
                OrganizationalUnit: []string{"MIG"},
                CommonName:         "EXAMPLE-INTERMED1-CA.cisco.com",
        }


       certRequest = ReadCertificateRequest(requestFilePath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
       
       badLeafRecipe1        := BuildDefaultLeafRecipe().SetVersion2().SetSubject(&subject).SetIssuer(defaultRootCAName)
       modifiedLeaf1Extensions = badLeafRecipe1.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs)
       badLeafRecipe1.SetExtensions(modifiedLeaf1Extensions)
       badLeafRecipe1.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)

       badLeafRecipe2        := BuildDefaultLeafRecipe().SetVersion2().SetSubject(&subject).SetIssuer(defaultIntermed1CAName)
       modifiedLeaf2Extensions = badLeafRecipe2.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs)
       badLeafRecipe2.SetExtensions(modifiedLeaf2Extensions) 
       badLeafRecipe2.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
       
       f1, err := os.Create(fmt.Sprintf("%s/LEAF-CERT-VERSION-2-1.pem", signRequestCertOutputDirectory))
       if err != nil {
	       panic(err)
       }
       defer f1.Close()
       badLeafRecipe1.WriteCertificatePem(f1)

       f2, err := os.Create(fmt.Sprintf("%s/LEAF-CERT-VERSION-2-2.pem", signRequestCertOutputDirectory))
       if err != nil {
	       panic(err)
       }
       defer f2.Close()
       badLeafRecipe2.WriteCertificatePem(f2)
}

func SignRequestBadCertLeafPathlenPresent(signRequestCertOutputDirectory string, requestFilePath string, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey) {
}

func SignRequestBadCertLeafEmptyIssuer(signRequestCertOutputDirectory string, requestFilePath string, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey) {
}





func SignRequest(signRequestCertOutputDirectory string, signRequestType SignRequestType, requestFilePath string) {
	//NOTE, we also need to pass the correct sigalgo parameter to this
        rootCAKey, intermed1CAKey := LoadDefaultCAKeys("./CA")

	if (signRequestType == LEAF_CERT_VERSION_1) {
		SignRequestBadCertLeafVersion1(signRequestCertOutputDirectory, requestFilePath, rootCAKey, intermed1CAKey)
	} else if (signRequestType == LEAF_CERT_VERSION_2) {
		SignRequestBadCertLeafVersion2(signRequestCertOutputDirectory, requestFilePath, rootCAKey, intermed1CAKey)
	} else if (signRequestType == LEAF_CERT_PATHLEN_PRESENT) {
		SignRequestBadCertLeafPathlenPresent(signRequestCertOutputDirectory, requestFilePath, rootCAKey, intermed1CAKey)
	} else if (signRequestType == LEAF_CERT_EMPTY_ISSUER) {
		SignRequestBadCertLeafEmptyIssuer(signRequestCertOutputDirectory, requestFilePath, rootCAKey, intermed1CAKey)
	} else {
		panic(errors.New("Unknown sign request type"))
	}
}
