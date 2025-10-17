package main

import (
	"fmt"
	"flag"
	"os"
	"errors"
	"path/filepath"
	"strings"
	"crypto/rsa"
	"crypto/rand"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
	"math/big"
	"time"
)

type DefaultCertificateParams struct {
	RootCAKey *rsa.PrivateKey
	Intermed1CAKey *rsa.PrivateKey
        LeafKey *rsa.PrivateKey
	RootCAName *pkix.Name
	Intermed1CAName *pkix.Name
	LeafName *pkix.Name
	RootCAValidity badcert.BadCertValidity
	Intermed1CAValidity badcert.BadCertValidity
	LeafValidity badcert.BadCertValidity
	SignatureAlgorithm badcert.SignatureAlgorithm
}

var defaultCertificateParams DefaultCertificateParams


func GenerateDefaultCertificateParams() {
	var err error

        defaultCertificateParams.RootCAKey, err = rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                panic(err)
        }

	defaultCertificateParams.Intermed1CAKey, err = rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                panic(err)
        }

        defaultCertificateParams.LeafKey, err = rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                panic(err)
        }

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
}


func BuildDefaultRootCAExtensions() (badcert.ExtensionSlice) {
        return(badcert.CreateExtensions().SetBasicConstraintsExtension(true, true, 1, false).SetKeyUsageExtension(true, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCertSign|badcert.KeyUsageCRLSign).SetAKIDExtensionFromKey(false, defaultCertificateParams.RootCAKey).SetSKIDExtensionFromKey(false, defaultCertificateParams.RootCAKey).SetSANExtension(false, []string{"BADCERT-ROOT-CA.cisco.com"}, nil, nil, nil))
}

func BuildDefaultIntermed1CAExtensions() (badcert.ExtensionSlice) {
        return(badcert.CreateExtensions().SetBasicConstraintsExtension(true, true, 0, true).SetKeyUsageExtension(true, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCertSign|badcert.KeyUsageCRLSign).SetAKIDExtensionFromKey(false, defaultCertificateParams.RootCAKey).SetSKIDExtensionFromKey(false, defaultCertificateParams.Intermed1CAKey).SetSANExtension(false, []string{"BADCERT-INTERMED1-CA.cisco.com"}, nil, nil, nil))
}

func BuildDefaultLeafExtensions() (badcert.ExtensionSlice) {
        extKeyUsageSlice := []badcert.ExtKeyUsage{badcert.ExtKeyUsageServerAuth}
        return(badcert.CreateExtensions().SetBasicConstraintsExtension(true, false, 0, false).SetKeyUsageExtension(true, badcert.KeyUsageDigitalSignature).SetExtKeyUsageExtension(false, extKeyUsageSlice).SetAKIDExtensionFromKey(false, defaultCertificateParams.Intermed1CAKey).SetSKIDExtensionFromKey(false, defaultCertificateParams.LeafKey).SetSANExtension(false, []string{"BADCERT-LEAF.cisco.com"}, nil, nil, nil))
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


//This is meant to be a quick generator of combinations of  3 level cert chain. The keys used for signing are from default parameters
//So it can't be sued in cases where the bad certificate is created due to modification related to key or signature params
//Or a chain with a different setup
//In such cases, use the underlying cert generation functions directly
func BuildBadCertificateChains(badRootCARecipe *badcert.BadCertificate, badIntermed1CARecipe *badcert.BadCertificate, badLeafRecipe *badcert.BadCertificate, outputDirectory string) {
        goodRootCARecipe      := BuildDefaultRootCARecipe()
        goodIntermed1CARecipe := BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        := BuildDefaultLeafRecipe()
 
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        
	certChain1 := []*badcert.BadCertificate{badRootCARecipe}
	badcert.WriteCertificateChainPem(certChain1, fmt.Sprintf("%s/1.pem", outputDirectory))

	certChain2 := []*badcert.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, badRootCARecipe}
	badcert.WriteCertificateChainPem(certChain2, fmt.Sprintf("%s/2.pem", outputDirectory))

	certChain3 := []*badcert.BadCertificate{goodLeafRecipe, badIntermed1CARecipe, goodRootCARecipe}
	badcert.WriteCertificateChainPem(certChain3, fmt.Sprintf("%s/3.pem", outputDirectory))
	
	certChain4 := []*badcert.BadCertificate{goodLeafRecipe, badIntermed1CARecipe, badRootCARecipe}
	badcert.WriteCertificateChainPem(certChain4, fmt.Sprintf("%s/4.pem", outputDirectory))
	
	certChain5 := []*badcert.BadCertificate{badLeafRecipe, goodIntermed1CARecipe, badRootCARecipe}
	badcert.WriteCertificateChainPem(certChain5, fmt.Sprintf("%s/5.pem", outputDirectory))
	
	certChain6 := []*badcert.BadCertificate{badLeafRecipe, badIntermed1CARecipe, goodRootCARecipe}
	badcert.WriteCertificateChainPem(certChain6, fmt.Sprintf("%s/6.pem", outputDirectory))
	
	certChain7 := []*badcert.BadCertificate{badLeafRecipe, badIntermed1CARecipe, badRootCARecipe}
	badcert.WriteCertificateChainPem(certChain7, fmt.Sprintf("%s/7.pem", outputDirectory))
	
	certChain8 := []*badcert.BadCertificate{badLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	badcert.WriteCertificateChainPem(certChain8, fmt.Sprintf("%s/8.pem", outputDirectory))
}

//This is meant to be a quick generator of combinations of  3 level cert chain. The keys used for signing are from default parameters
//So it can't be sued in cases where the bad certificate is created due to modification related to key or signature params
//Or a chain with a different setup
//In such cases, use the underlying cert generation functions directly
func BuildBadCACertificateChains(badRootCARecipe *badcert.BadCertificate, badIntermed1CARecipe *badcert.BadCertificate, outputDirectory string) {
        goodRootCARecipe      := BuildDefaultRootCARecipe()
        goodIntermed1CARecipe := BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        := BuildDefaultLeafRecipe()
 
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        
	certChain1 := []*badcert.BadCertificate{badRootCARecipe}
	badcert.WriteCertificateChainPem(certChain1, fmt.Sprintf("%s/1.pem", outputDirectory))

	certChain2 := []*badcert.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, badRootCARecipe}
	badcert.WriteCertificateChainPem(certChain2, fmt.Sprintf("%s/2.pem", outputDirectory))

	certChain3 := []*badcert.BadCertificate{goodLeafRecipe, badIntermed1CARecipe, goodRootCARecipe}
	badcert.WriteCertificateChainPem(certChain3, fmt.Sprintf("%s/3.pem", outputDirectory))
	
	certChain4 := []*badcert.BadCertificate{goodLeafRecipe, badIntermed1CARecipe, badRootCARecipe}
	badcert.WriteCertificateChainPem(certChain4, fmt.Sprintf("%s/4.pem", outputDirectory))
}


//Extensions are present but version is 1
//Extensions are present but version is 2
func X509_VERSION_1(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	
	err = os.Mkdir(fmt.Sprintf("%s/X509-VERSION-1/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	
	err = os.Mkdir(fmt.Sprintf("%s/X509-VERSION-1/1", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }

	err = os.Mkdir(fmt.Sprintf("%s/X509-VERSION-1/2", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }

	outputFilePrefix = fmt.Sprintf("%s/X509-VERSION-1/1/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe().SetVersion1()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetVersion1()
        badLeafRecipe        = BuildDefaultLeafRecipe().SetVersion1()
        BuildBadCertificateChains(badRootCARecipe, badIntermed1CARecipe, badLeafRecipe, outputFilePrefix)
	
	outputFilePrefix = fmt.Sprintf("%s/X509-VERSION-1/2/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe().SetVersion2()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetVersion2()
        badLeafRecipe        = BuildDefaultLeafRecipe().SetVersion2()
        BuildBadCertificateChains(badRootCARecipe, badIntermed1CARecipe, badLeafRecipe, outputFilePrefix)
}


//Basic Constraints Extension is present, CA is set to true and key usage contains keyCertSign. But the subject field is empty
func X509_SUBJECT_1(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var emptySubject *pkix.Name
        
	emptySubject = &pkix.Name{}

	err = os.Mkdir(fmt.Sprintf("%s/X509-SUBJECT-1/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	
	outputFilePrefix = fmt.Sprintf("%s/X509-SUBJECT-1/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe().SetSubject(emptySubject)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetSubject(emptySubject)
	BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, outputFilePrefix)
}

//Leaf certificate contains subject name information in SAN, the Subject field is empty, but SAN is not marked as critical
func X509_SUBJECT_2(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
        var certChain []*badcert.BadCertificate 
	var emptySubject *pkix.Name
        
	emptySubject = &pkix.Name{}
	
	err = os.Mkdir(fmt.Sprintf("%s/X509-SUBJECT-2/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	

	outputFilePrefix = fmt.Sprintf("%s/X509-SUBJECT-2/", outputDirectory)
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        badLeafRecipe        = BuildDefaultLeafRecipe().SetSubject(emptySubject)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = []*badcert.BadCertificate{badLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	badcert.WriteCertificateChainPem(certChain, fmt.Sprintf("%s/1.pem", outputFilePrefix))
}




//Basic Constraints Extension is present, and CA is set to false, but key usage contains keyCertSign
func X509_EXT_BASIC_CONST_1(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice

	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-1/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	
	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-1/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, outputFilePrefix)
}

//Basic Constraints Extension is absent, but key usage contains keyCertSign
//Basic Constraints Extension is present, and CA is set to false, but key usage contains keyCertSign
func X509_EXT_BASIC_CONST_2(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice

	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-2/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	
	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-2/1/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }

	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-2/2/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-2/1/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, outputFilePrefix)

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-2/2/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, outputFilePrefix)
}



//Basic Constraints Extension is absent, but key usage contains keyCertSign and/or the key is used to validate signatures on certificates
//Basic constraints extension is present, but hasn't been marked as critical. key usage contains keyCertSign and/or the key is used to validate signatures on certificates
func X509_EXT_BASIC_CONST_3(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice

	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-3/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	
	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-3/1/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }

	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-3/2/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-3/1/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, outputFilePrefix)

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-3/2/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, outputFilePrefix)

}


//Leaf certificate contains basic constraints extension set to false, and KeyCertSign extension is absent in keyusage. Basic constraint extension is marked as critical
//Leaf certificate contains basic constraints extension set to false, and KeyCertSign extension is absent in keyusage. Basic constraint extension is not marked as critical
//The certificate should be processed without issue in both of the cases above 
func X509_EXT_BASIC_CONST_5(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
        var certChain []*badcert.BadCertificate 
	
	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-5/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-5/", outputDirectory)
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = []*badcert.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	badcert.WriteCertificateChainPem(certChain, fmt.Sprintf("%s/1.pem", outputFilePrefix))

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-5/", outputDirectory)
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, false, 0, false)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = []*badcert.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	badcert.WriteCertificateChainPem(certChain, fmt.Sprintf("%s/2.pem", outputFilePrefix))
}


//Basic Constraints Extension is present, keyCertSign bit is set and CA is set to false. But the pathlen attribute is still included
//Basic Constraints Extension is present, keyCertSign bit is not set and CA is set to true. But the pathlen attribute is still included
func X509_EXT_BASIC_CONST_6(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice

	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-6/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	
	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-6/1/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }

	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-6/2/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-6/1/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, outputFilePrefix)

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-6/2/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageEncipherOnly)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageEncipherOnly)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, outputFilePrefix)
}


/*
//Basic Constraints Extension is present, keyCertSign bit is set and CA is set to true. But the pathlen attribute contains a negative integer
func X509_EXT_BASIC_CONST_7(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice

	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-BASIC-CONST-7/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	
	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-7/", outputDirectory)
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -2, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -2, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, outputFilePrefix)
}
*/


//SAN extension is present in the leaf certificate and names of more than one form are present
//SAN extension is present in the leaf certificate and multiple instances of names of more than one form are present
//The certificate should be processed without issue in both of the cases above 
func X509_EXT_SAN_1(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
        var certChain []*badcert.BadCertificate 
	
	err = os.Mkdir(fmt.Sprintf("%s/X509-EXT-SAN-1/", outputDirectory), 0755)
        if err != nil {
                panic(err)
        }
	
	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-SAN-1/", outputDirectory)
        goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, []string{"BADCERT-LEAF-DNSNAME-1.cisco.com"}, []string{"user1@cisco.com"}, nil, nil)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = []*badcert.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	badcert.WriteCertificateChainPem(certChain, fmt.Sprintf("%s/1.pem", outputFilePrefix))

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-SAN-1/", outputDirectory)
        goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, []string{"BADCERT-LEAF-DNSNAME-1.cisco.com", "BADCERT-LEAF-DNSNAME-2.cisco.com"}, []string{"user1@cisco.com", "user2@cisco.com"}, nil, nil)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = []*badcert.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	badcert.WriteCertificateChainPem(certChain, fmt.Sprintf("%s/2.pem", outputFilePrefix))
}

func GenerateX509VersionCerts(outputDirectory string) {
	X509_VERSION_1(outputDirectory)
}

func GenerateX509SubjectCerts(outputDirectory string) {
        X509_SUBJECT_1(outputDirectory)
}

func GenerateX509ExtBasicConstCerts(outputDirectory string) {
        X509_EXT_BASIC_CONST_1(outputDirectory)
	X509_EXT_BASIC_CONST_2(outputDirectory)
	X509_EXT_BASIC_CONST_3(outputDirectory)
        X509_EXT_BASIC_CONST_5(outputDirectory)
        X509_EXT_BASIC_CONST_6(outputDirectory)
        //X509_EXT_BASIC_CONST_7(outputDirectory)
}

func GenerateSANCerts(outputDirectory string) {
        X509_EXT_SAN_1(outputDirectory)
}

func GenerateCerts(outputDirectory string) {
	GenerateX509VersionCerts(outputDirectory)
	GenerateX509SubjectCerts(outputDirectory)
	GenerateX509ExtBasicConstCerts(outputDirectory)
	GenerateSANCerts(outputDirectory)
}

func CreateOutputDirectory(outputDirectory string) {
    outputDirectory = strings.TrimSpace(outputDirectory)
    outputDirectory = filepath.Clean(outputDirectory)

    absPath, _ := filepath.Abs(outputDirectory)
    fmt.Println("Absolute Output Directory Path: ", absPath)

    _, err := os.Stat(absPath) 
    if errors.Is(err, os.ErrNotExist) {
        err := os.Mkdir(absPath, 0755)
        if err != nil {
            panic(err)
        }
        fmt.Println("Directory created:", absPath)
	return
    }

    if err != nil {
        panic(err)
    } 

    panic(fmt.Errorf("Directory already exists: %v", absPath))
}

func main() {
	outputDirectory := flag.String("o", "certs/", "Output directory path")
        flag.Parse()
        
	CreateOutputDirectory(*outputDirectory)
	GenerateDefaultCertificateParams()
	GenerateCerts(*outputDirectory)
}
