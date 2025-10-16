package main

import (
	"fmt"
	"flag"
	"os"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
	RootCAValidity x509.BadCertValidity
	Intermed1CAValidity x509.BadCertValidity
	LeafValidity x509.BadCertValidity
	SignatureAlgorithm x509.SignatureAlgorithm
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

	defaultCertificateParams.SignatureAlgorithm = x509.SHA256WithRSA
        
	currentTime := time.Now()

	//ROOT CA Certificate is valid for 5 years
        defaultCertificateParams.RootCAValidity = x509.BadCertValidity{
		                    NotBefore: currentTime,
				    NotAfter: currentTime.Add(5 * 365 * 24 * time.Hour),
				  }
	
	//Intermed1 CA Certificate is valid for 3 years
        defaultCertificateParams.Intermed1CAValidity = x509.BadCertValidity{
		                         NotBefore: currentTime,
				         NotAfter: currentTime.Add(3 * 365 * 24 * time.Hour),
				       }

	//Leaf Certificate is valid for an year
        defaultCertificateParams.LeafValidity = x509.BadCertValidity{
		                         NotBefore: currentTime,
				         NotAfter: currentTime.Add(1 * 365 * 24 * time.Hour),
				       }
}


func BuildDefaultRootCAExtensions() (x509.ExtensionSlice) {
        return(x509.CreateExtensions().SetBasicConstraintsExtension(true, true, 1, false).SetKeyUsageExtension(true, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign).SetAKIDExtensionFromKey(false, defaultCertificateParams.RootCAKey).SetSKIDExtensionFromKey(false, defaultCertificateParams.RootCAKey).SetSANExtension(false, []string{"BADCERT-ROOT-CA.cisco.com"}, nil, nil, nil))
}

func BuildDefaultIntermed1CAExtensions() (x509.ExtensionSlice) {
        return(x509.CreateExtensions().SetBasicConstraintsExtension(true, true, 0, true).SetKeyUsageExtension(true, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign).SetAKIDExtensionFromKey(false, defaultCertificateParams.RootCAKey).SetSKIDExtensionFromKey(false, defaultCertificateParams.Intermed1CAKey).SetSANExtension(false, []string{"BADCERT-INTERMED1-CA.cisco.com"}, nil, nil, nil))
}

func BuildDefaultLeafExtensions() (x509.ExtensionSlice) {
        extKeyUsageSlice := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
        return(x509.CreateExtensions().SetBasicConstraintsExtension(true, false, 0, false).SetKeyUsageExtension(true, x509.KeyUsageDigitalSignature).SetExtKeyUsageExtension(false, extKeyUsageSlice).SetAKIDExtensionFromKey(false, defaultCertificateParams.Intermed1CAKey).SetSKIDExtensionFromKey(false, defaultCertificateParams.LeafKey).SetSANExtension(false, []string{"BADCERT-LEAF.cisco.com"}, nil, nil, nil))
}

func BuildDefaultRootCARecipe() (*x509.BadCertificate) {
	rootCACertificate := x509.CreateBadCertificate().SetVersion3().SetSerialNumber(big.NewInt(1)).SetIssuer(defaultCertificateParams.RootCAName).SetSubject(defaultCertificateParams.RootCAName).SetValidity(&defaultCertificateParams.RootCAValidity.NotBefore, &defaultCertificateParams.RootCAValidity.NotAfter).SetExtensions(BuildDefaultRootCAExtensions()).SetCertificatePublicKey(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	return rootCACertificate
}

func BuildDefaultIntermed1CARecipe() (*x509.BadCertificate) {
	intermed1CACertificate := x509.CreateBadCertificate().SetVersion3().SetSerialNumber(big.NewInt(2)).SetIssuer(defaultCertificateParams.RootCAName).SetSubject(defaultCertificateParams.Intermed1CAName).SetValidity(&defaultCertificateParams.Intermed1CAValidity.NotBefore, &defaultCertificateParams.Intermed1CAValidity.NotAfter).SetExtensions(BuildDefaultIntermed1CAExtensions()).SetCertificatePublicKey(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
	return intermed1CACertificate
}

func BuildDefaultLeafRecipe() (*x509.BadCertificate) {
	leafCertificate := x509.CreateBadCertificate().SetVersion3().SetSerialNumber(big.NewInt(3)).SetIssuer(defaultCertificateParams.Intermed1CAName).SetSubject(defaultCertificateParams.LeafName).SetValidity(&defaultCertificateParams.LeafValidity.NotBefore, &defaultCertificateParams.LeafValidity.NotAfter).SetExtensions(BuildDefaultLeafExtensions()).SetCertificatePublicKey(defaultCertificateParams.LeafKey, defaultCertificateParams.SignatureAlgorithm)
	return leafCertificate
}


//This is meant to be a quick generator of combinations of  3 level cert chain. The keys used for signing are from default parameters
//So it can't be sued in cases where the bad certificate is created due to modification related to key or signature params
//Or a chain with a different setup
//In such cases, use the underlying cert generation functions directly
func BuildBadCertificateChains(badRootCARecipe *x509.BadCertificate, badIntermed1CARecipe *x509.BadCertificate, badLeafRecipe *x509.BadCertificate, outputDirectory string) {
        goodRootCARecipe      := BuildDefaultRootCARecipe()
        goodIntermed1CARecipe := BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        := BuildDefaultLeafRecipe()
 
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        
	certChain1 := []*x509.BadCertificate{badRootCARecipe}
	x509.WriteCertificateChainPem(certChain1, fmt.Sprintf("%s/1.pem", outputDirectory))

	certChain2 := []*x509.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, badRootCARecipe}
	x509.WriteCertificateChainPem(certChain2, fmt.Sprintf("%s/2.pem", outputDirectory))

	certChain3 := []*x509.BadCertificate{goodLeafRecipe, badIntermed1CARecipe, goodRootCARecipe}
	x509.WriteCertificateChainPem(certChain3, fmt.Sprintf("%s/3.pem", outputDirectory))
	
	certChain4 := []*x509.BadCertificate{goodLeafRecipe, badIntermed1CARecipe, badRootCARecipe}
	x509.WriteCertificateChainPem(certChain4, fmt.Sprintf("%s/4.pem", outputDirectory))
	
	certChain5 := []*x509.BadCertificate{badLeafRecipe, goodIntermed1CARecipe, badRootCARecipe}
	x509.WriteCertificateChainPem(certChain5, fmt.Sprintf("%s/5.pem", outputDirectory))
	
	certChain6 := []*x509.BadCertificate{badLeafRecipe, badIntermed1CARecipe, goodRootCARecipe}
	x509.WriteCertificateChainPem(certChain6, fmt.Sprintf("%s/6.pem", outputDirectory))
	
	certChain7 := []*x509.BadCertificate{badLeafRecipe, badIntermed1CARecipe, badRootCARecipe}
	x509.WriteCertificateChainPem(certChain7, fmt.Sprintf("%s/7.pem", outputDirectory))
	
	certChain8 := []*x509.BadCertificate{badLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	x509.WriteCertificateChainPem(certChain8, fmt.Sprintf("%s/8.pem", outputDirectory))
}

//This is meant to be a quick generator of combinations of  3 level cert chain. The keys used for signing are from default parameters
//So it can't be sued in cases where the bad certificate is created due to modification related to key or signature params
//Or a chain with a different setup
//In such cases, use the underlying cert generation functions directly
func BuildBadCACertificateChains(badRootCARecipe *x509.BadCertificate, badIntermed1CARecipe *x509.BadCertificate, outputDirectory string) {
        goodRootCARecipe      := BuildDefaultRootCARecipe()
        goodIntermed1CARecipe := BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        := BuildDefaultLeafRecipe()
 
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        
	certChain1 := []*x509.BadCertificate{badRootCARecipe}
	x509.WriteCertificateChainPem(certChain1, fmt.Sprintf("%s/1.pem", outputDirectory))

	certChain2 := []*x509.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, badRootCARecipe}
	x509.WriteCertificateChainPem(certChain2, fmt.Sprintf("%s/2.pem", outputDirectory))

	certChain3 := []*x509.BadCertificate{goodLeafRecipe, badIntermed1CARecipe, goodRootCARecipe}
	x509.WriteCertificateChainPem(certChain3, fmt.Sprintf("%s/3.pem", outputDirectory))
	
	certChain4 := []*x509.BadCertificate{goodLeafRecipe, badIntermed1CARecipe, badRootCARecipe}
	x509.WriteCertificateChainPem(certChain4, fmt.Sprintf("%s/4.pem", outputDirectory))
}


//Extensions are present but version is 1
//Extensions are present but version is 2
func X509_VERSION_1(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *x509.BadCertificate
	var badIntermed1CARecipe *x509.BadCertificate
	var badLeafRecipe *x509.BadCertificate
	
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

//Basic Constraints Extension is present, and CA is set to false, but key usage contains KeyCertSign
func X509_EXT_BASIC_CONST_1(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *x509.BadCertificate
	var badIntermed1CARecipe *x509.BadCertificate
	var modifiedRootCAExtensions x509.ExtensionSlice
	var modifiedIntermed1CAExtensions x509.ExtensionSlice

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
 
//Basic Constraints Extension is absent, but key usage contains KeyCertSign and/or the key is used to validate signatures on certificates
//Basic constraints extension is present, but hasn't been marked as critical. key usage contains KeyCertSign and/or the key is used to validate signatures on certificates
func X509_EXT_BASIC_CONST_3(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var badRootCARecipe *x509.BadCertificate
	var badIntermed1CARecipe *x509.BadCertificate
	var modifiedRootCAExtensions x509.ExtensionSlice
	var modifiedIntermed1CAExtensions x509.ExtensionSlice

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
        var goodRootCARecipe *x509.BadCertificate
	var goodIntermed1CARecipe *x509.BadCertificate
	var goodLeafRecipe *x509.BadCertificate
	var modifiedLeafExtensions x509.ExtensionSlice
        var certChain []*x509.BadCertificate 
	
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
        certChain = []*x509.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	x509.WriteCertificateChainPem(certChain, fmt.Sprintf("%s/1.pem", outputFilePrefix))

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-BASIC-CONST-5/", outputDirectory)
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, false, 0, false)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = []*x509.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	x509.WriteCertificateChainPem(certChain, fmt.Sprintf("%s/2.pem", outputFilePrefix))
}

//SAN extension is present in the leaf certificate and names of more than one form are present
//SAN extension is present in the leaf certificate and multiple instances of names of more than one form are present
//The certificate should be processed without issue in both of the cases above 
func X509_EXT_SAN_1(outputDirectory string) {
	var err error
	var outputFilePrefix string
        var goodRootCARecipe *x509.BadCertificate
	var goodIntermed1CARecipe *x509.BadCertificate
	var goodLeafRecipe *x509.BadCertificate
	var modifiedLeafExtensions x509.ExtensionSlice
        var certChain []*x509.BadCertificate 
	
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
        certChain = []*x509.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	x509.WriteCertificateChainPem(certChain, fmt.Sprintf("%s/1.pem", outputFilePrefix))

	outputFilePrefix = fmt.Sprintf("%s/X509-EXT-SAN-1/", outputDirectory)
        goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, []string{"BADCERT-LEAF-DNSNAME-1.cisco.com", "BADCERT-LEAF-DNSNAME-2.cisco.com"}, []string{"user1@cisco.com", "user2@cisco.com"}, nil, nil)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = []*x509.BadCertificate{goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe}
	x509.WriteCertificateChainPem(certChain, fmt.Sprintf("%s/2.pem", outputFilePrefix))
}


func GenerateCerts(outputDirectory string) {
	X509_VERSION_1(outputDirectory)
        X509_EXT_BASIC_CONST_1(outputDirectory)
        X509_EXT_BASIC_CONST_3(outputDirectory)
        X509_EXT_BASIC_CONST_5(outputDirectory)
        X509_EXT_SAN_1(outputDirectory)
}


func main() {
	outputDirectory := flag.String("o", "./certs/", "Output directory path")
        flag.Parse()
         
	GenerateDefaultCertificateParams()
	
	GenerateCerts(*outputDirectory)
}
