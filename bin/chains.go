package main

import (
	"crypto"
	"os"
	"fmt"
	"github.com/hegde-akshath/badcert"
)

type BadCertificateChain struct {
	CertProfileDescription string
	LeafPrivateKey crypto.PrivateKey
	IsRootCACertValid bool
	IsIntermedCACertChainValid bool
	IsLeafCertValid bool
	Chain []*badcert.BadCertificate
}

type BadCertificateChains []BadCertificateChain

func WriteBadCertChain(badCertificateChain BadCertificateChain, filepath string) {
	f, err := os.Create(filepath)
	if err != nil {
		panic(err)
	}
        defer f.Close()
        
	badcert.WriteCertificateChainPem(badCertificateChain.Chain, f)
}

func GenerateCertificateProfileDescription(certProfileBaseDescription string, isRootCACertValid bool, isIntermedCACertChainValid bool, isLeafCertValid bool) string {
	boolToString := map[bool]string{true: "Valid", false: "Invalid"}
	return certProfileBaseDescription + fmt.Sprintf(" RootCACert: %s, IntermediateCACertChain: %s, LeafCert: %s", boolToString[isRootCACertValid],
	       boolToString[isIntermedCACertChainValid], boolToString[isLeafCertValid])
}

func CreateBadCertificateChain(certProfileDescription string, leafPrivateKey crypto.PrivateKey, isRootCACertValid bool, isIntermedCACertChainValid bool, isLeafCertValid bool, certs...*badcert.BadCertificate) (BadCertificateChain) {
	var badCertChain BadCertificateChain

	badCertChain.Chain = make([]*badcert.BadCertificate, 0, len(certs))
        
	for _, cert := range certs {
		badCertChain.Chain = append(badCertChain.Chain, cert)
	}
	badCertChain.CertProfileDescription     = GenerateCertificateProfileDescription(certProfileDescription, isRootCACertValid, isIntermedCACertChainValid, isLeafCertValid)
	badCertChain.LeafPrivateKey             = leafPrivateKey
	badCertChain.IsRootCACertValid          = isRootCACertValid
	badCertChain.IsIntermedCACertChainValid = isIntermedCACertChainValid
	badCertChain.IsLeafCertValid            = isLeafCertValid
	return badCertChain
}

func CreateBadCertificateChains(certChains...BadCertificateChain) (BadCertificateChains) {
	badCertChains := make([]BadCertificateChain, 0, len(certChains))

	for _, certChain := range certChains {
		badCertChains = append(badCertChains, certChain)
	}
        
	return BadCertificateChains(badCertChains)
}



//This is meant to be a quick generator of combinations of  3 level cert chain. The keys used for signing are from default parameters
//So it can't be sued in cases where the bad certificate is created due to modification related to key or signature params
//Or a chain with a different setup
//In such cases, use the underlying cert generation functions directly
func BuildBadCertificateChains(badRootCARecipe *badcert.BadCertificate, badIntermed1CARecipe *badcert.BadCertificate, badLeafRecipe *badcert.BadCertificate, certProfileBaseDescription string) (*BadCertificateChains) {
	goodRootCARecipe      := BuildDefaultRootCARecipe()
        goodIntermed1CARecipe := BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        := BuildDefaultLeafRecipe()
 
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        
	certChain1 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, true, true, true,    goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe)
	certChain2 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, true, true, false,   badLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe)
	certChain3 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, true, false, true,   goodLeafRecipe, badIntermed1CARecipe, goodRootCARecipe)
	certChain4 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, true, false, false,  badLeafRecipe, badIntermed1CARecipe, goodRootCARecipe)
	certChain5 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, false, true, true,   goodLeafRecipe, goodIntermed1CARecipe, badRootCARecipe)
	certChain6 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, false, true, false,  badLeafRecipe, goodIntermed1CARecipe, badRootCARecipe)
	certChain7 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, false, false, true,  goodLeafRecipe, badIntermed1CARecipe, badRootCARecipe)
	certChain8 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, false, false, false, badLeafRecipe, badIntermed1CARecipe, badRootCARecipe)
	

	badCertificateChains := CreateBadCertificateChains(certChain1, certChain2, certChain3, certChain4, certChain5, certChain6, certChain7, certChain8)
	return &badCertificateChains
}

//This is meant to be a quick generator of combinations of  3 level cert chain. The keys used for signing are from default parameters
//So it can't be sued in cases where the bad certificate is created due to modification related to key or signature params
//Or a chain with a different setup
//In such cases, use the underlying cert generation functions directly
func BuildBadCACertificateChains(badRootCARecipe *badcert.BadCertificate, badIntermed1CARecipe *badcert.BadCertificate, certProfileBaseDescription string) (*BadCertificateChains) {
	goodRootCARecipe      := BuildDefaultRootCARecipe()
        goodIntermed1CARecipe := BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        := BuildDefaultLeafRecipe()
 
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        
	certChain1 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, true, true, true,   goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe)
	certChain2 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, true, false, true,  goodLeafRecipe, badIntermed1CARecipe, goodRootCARecipe)	
	certChain3 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, false, true, true,  goodLeafRecipe, goodIntermed1CARecipe, badRootCARecipe)
	certChain4 := CreateBadCertificateChain(certProfileBaseDescription, defaultCertificateParams.LeafKey, false, false, true, goodLeafRecipe, badIntermed1CARecipe, badRootCARecipe)

	badCertificateChains := CreateBadCertificateChains(certChain1, certChain2, certChain3, certChain4)
	return &badCertificateChains
}

