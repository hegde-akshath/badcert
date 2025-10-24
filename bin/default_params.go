package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/rand"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
	"math/big"
	"time"
)

type DefaultCertificateParams struct {
	RootCAKey crypto.PrivateKey
	RootCAPubkey crypto.PublicKey
	Intermed1CAKey crypto.PrivateKey
	Intermed1CAPubkey crypto.PublicKey
        LeafKey crypto.PrivateKey
	LeafPubkey crypto.PublicKey
	RootCAName *pkix.Name
	Intermed1CAName *pkix.Name
	LeafName *pkix.Name
	RootCAValidity badcert.BadCertValidity
	Intermed1CAValidity badcert.BadCertValidity
	LeafValidity badcert.BadCertValidity
	SignatureAlgorithm badcert.SignatureAlgorithm
}


func GenerateDefaultCertificateParams() (*DefaultCertificateParams) {
	var err error
        var defaultCertificateParams DefaultCertificateParams

        defaultCertificateParams.RootCAKey, err = rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                panic(err)
        }

	_, defaultCertificateParams.RootCAPubkey = badcert.GetSignerFromKey(defaultCertificateParams.RootCAKey)

	defaultCertificateParams.Intermed1CAKey, err = rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                panic(err)
        }

	_, defaultCertificateParams.Intermed1CAPubkey = badcert.GetSignerFromKey(defaultCertificateParams.Intermed1CAKey)
        
	defaultCertificateParams.LeafKey, err = rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                panic(err)
        }

	_, defaultCertificateParams.LeafPubkey = badcert.GetSignerFromKey(defaultCertificateParams.LeafKey)
        
	defaultCertificateParams.RootCAName = &pkix.Name{
		Country:            []string{"IN"},
		Province:           []string{"KA"},
		Locality:           []string{"BGL"},
                Organization:       []string{"CSCO"},
                OrganizationalUnit: []string{"MIG"},
                CommonName:         "BADCERT-ROOT-CA.cisco.com",
        }

	defaultCertificateParams.Intermed1CAName = &pkix.Name{
		Country:            []string{"IN"},
		Province:           []string{"KA"},
		Locality:           []string{"BGL"},
                Organization:       []string{"CSCO"},
                OrganizationalUnit: []string{"MIG"},
                CommonName:         "BADCERT-INTERMED1-CA.cisco.com",
        }

	defaultCertificateParams.LeafName = &pkix.Name{
		Country:            []string{"IN"},
		Province:           []string{"KA"},
		Locality:           []string{"BGL"},
                Organization:       []string{"CSCO"},
                OrganizationalUnit: []string{"MIG"},
                CommonName:         "BADCERT-LEAF.cisco.com",
        }

	defaultCertificateParams.SignatureAlgorithm = badcert.SHA256WithRSA
        
	currentTime := time.Now()

	//ROOT CA Certificate is valid for 5 years
        defaultCertificateParams.RootCAValidity = badcert.BadCertValidity{
		                    NotBefore: currentTime,
				    NotAfter: currentTime.Add(5 * 365 * 24 * time.Hour),
				  }
	
	//Intermed1 CA Certificate is valid for 3 years
        defaultCertificateParams.Intermed1CAValidity = badcert.BadCertValidity{
		                         NotBefore: currentTime,
				         NotAfter: currentTime.Add(3 * 365 * 24 * time.Hour),
				       }

	//Leaf Certificate is valid for an year
        defaultCertificateParams.LeafValidity = badcert.BadCertValidity{
		                         NotBefore: currentTime,
				         NotAfter: currentTime.Add(1 * 365 * 24 * time.Hour),
				       }
        
	return &defaultCertificateParams
}


func BuildDefaultRootCAExtensions() (badcert.ExtensionSlice) {
        return(badcert.CreateExtensions().SetBasicConstraintsExtension(true, true, 1, false).SetKeyUsageExtension(true, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCertSign|badcert.KeyUsageCRLSign).SetAKIDExtensionFromKey(false, defaultCertificateParams.RootCAPubkey).SetSKIDExtensionFromKey(false, defaultCertificateParams.RootCAPubkey).SetSANExtension(false, []string{"BADCERT-ROOT-CA.cisco.com"}, nil, nil, nil))
}

func BuildDefaultIntermed1CAExtensions() (badcert.ExtensionSlice) {
        return(badcert.CreateExtensions().SetBasicConstraintsExtension(true, true, 0, true).SetKeyUsageExtension(true, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCertSign|badcert.KeyUsageCRLSign).SetAKIDExtensionFromKey(false, defaultCertificateParams.RootCAPubkey).SetSKIDExtensionFromKey(false, defaultCertificateParams.Intermed1CAPubkey).SetSANExtension(false, []string{"BADCERT-INTERMED1-CA.cisco.com"}, nil, nil, nil))
}

func BuildDefaultLeafExtensions() (badcert.ExtensionSlice) {
        extKeyUsageSlice := []badcert.ExtKeyUsage{badcert.ExtKeyUsageServerAuth}
        return(badcert.CreateExtensions().SetBasicConstraintsExtension(true, false, 0, false).SetKeyUsageExtension(true, badcert.KeyUsageDigitalSignature).SetExtKeyUsageExtension(false, extKeyUsageSlice).SetAKIDExtensionFromKey(false, defaultCertificateParams.Intermed1CAPubkey).SetSKIDExtensionFromKey(false, defaultCertificateParams.LeafPubkey).SetSANExtension(false, []string{"BADCERT-LEAF.cisco.com"}, nil, nil, nil))
}

func BuildDefaultRootCARecipe() (*badcert.BadCertificate) {
	rootCACertificate := badcert.CreateBadCertificate().SetVersion3().SetSerialNumber(big.NewInt(1)).SetIssuer(defaultCertificateParams.RootCAName).SetSubject(defaultCertificateParams.RootCAName).SetValidity(&defaultCertificateParams.RootCAValidity.NotBefore, &defaultCertificateParams.RootCAValidity.NotAfter).SetExtensions(BuildDefaultRootCAExtensions()).SetCertificatePublicKey(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	return rootCACertificate
}

func BuildDefaultIntermed1CARecipe() (*badcert.BadCertificate) {
	intermed1CACertificate := badcert.CreateBadCertificate().SetVersion3().SetSerialNumber(big.NewInt(2)).SetIssuer(defaultCertificateParams.RootCAName).SetSubject(defaultCertificateParams.Intermed1CAName).SetValidity(&defaultCertificateParams.Intermed1CAValidity.NotBefore, &defaultCertificateParams.Intermed1CAValidity.NotAfter).SetExtensions(BuildDefaultIntermed1CAExtensions()).SetCertificatePublicKey(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
	return intermed1CACertificate
}

func BuildDefaultLeafRecipe() (*badcert.BadCertificate) {
	leafCertificate := badcert.CreateBadCertificate().SetVersion3().SetSerialNumber(big.NewInt(3)).SetIssuer(defaultCertificateParams.Intermed1CAName).SetSubject(defaultCertificateParams.LeafName).SetValidity(&defaultCertificateParams.LeafValidity.NotBefore, &defaultCertificateParams.LeafValidity.NotAfter).SetExtensions(BuildDefaultLeafExtensions()).SetCertificatePublicKey(defaultCertificateParams.LeafKey, defaultCertificateParams.SignatureAlgorithm)
	return leafCertificate
}



