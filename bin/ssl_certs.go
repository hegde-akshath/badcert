package main

import (
	"fmt"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
)

/*
Requirements for a Good Intermediate CA certificate 
1)Certificate Version must be 3  
2)Basic Constraints Extension must be present  
3)Basic Constraints Extension must be marked as critical  
4)Basic Constraints Extension must contain CA = true  
5)Key Usage Extension must be present 
6)Key Usage Extension must be marked as critical (recommended by RFC but not enforced by openssl) 
7)Key Usage Extension must contain keyCertSign bit 
8)If pathlen is not equal to –1 (which is the default value), then basic constraints extension must be present, and CA must be set to true. (The converse is not true(?), that is if CA conditions are met, pathlen is not mandatory) 
9)If pathlen is not equal to –1 (which is the default value), then key usage extension must be present and keyCertSign bit must be set. (The converse is not true(?), that is if key usage extension is present and keyCertSign bit is set, pathlen is not mandatory) 
10)If Path length is present in Basic Constraints Extension, then it must be >= 0  
11)Issuer name must not be empty 
12)Subject name must not be empty 
13)If SAN is present, it should contain atleast one name 
14)Sigalgo field in TBSCert should match with the field in Certificate 
15)AKID extension must be present, must contain a KeyId and must not be set to critical 
16)SKID extension must be present, and must not be set to critical 


Requirements for a Good Leaf Certificates 
1)Version must be 3 
2)If KeyUsage extension is present, it must not contain keyCertSign bit 
3)If BasicConstraints extensions is present, CA must be set to false 
4)Pathlen must not be present 
5) Issuer name must not be empty 
6) If there is no SAN set, then subject name must not be empty 
7) If the subject name is empty and SAN is set, then SAN must be critical 
8) If SAN is present, it should contain atleast one name 
9) Sig Algo field in TBSCert must match with the sig alg field in Certificate 
10) AKID must be present, contain a KeyId, and must not be critical 
11) SKID is not mandatory, but if present, must not be critical 
*/


/*
Test Description: Intermedicate CA version is 1
Applicable To: Intermediate CA
*/
func SSL_CERT_1(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "X509 certificate version is not 3")

	certProfileDescription := "Intermedicate CA version is 1"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe().SetVersion1()
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()	

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

        certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-1-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Intermedicate CA version is 2
Applicable To: Intermediate CA
*/
func SSL_CERT_2(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "X509 certificate version is not 3")

	certProfileDescription := "Intermedicate CA version is 2"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe().SetVersion2()
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-2-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Basic Constraints is absent in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_3(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Basic Constraints extension not found in certificate")

	certProfileDescription := "Basic Constraints is absent in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-3-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Basic Constraints is not critical in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_4(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Basic Constraints extension is not marked critical")

	certProfileDescription := "Basic Constraints is not critical in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()        
	badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe        = BuildDefaultLeafRecipe()
	
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()


	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-4-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Basic Constraints has CA set to false in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_5(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Basic Constraints extension 'CA' flag is not set")

	certProfileDescription := "Basic Constraints has CA set to false in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe      = BuildDefaultLeafRecipe()
	
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-5-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: KeyUsage Extension is absent in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_6(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Usage extension not found in certificate")

	certProfileDescription := "KeyUsage Extension is absent in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-6-CAT1-%d.json", outputDirectory, index))	
}


/*
Test Description: KeyUsage Extension doesn't contain keyCertSign bit in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_7(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Usage extension missing keyCertSign flag")

	certProfileDescription := "KeyUsage Extension doesn't contain keyCertSign bit in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(true, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCRLSign)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-7-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Pathlen attribute of BasicConstraints Extension is -2 in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_8(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Basic Constraints extension 'pathlen' is negative")

	certProfileDescription := "Pathlen attribute of BasicConstraints Extension is -2 in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -2, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe      = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-8-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Issuer is empty in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_9(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "No name entries found in issuer")

	certProfileDescription := "Issuer is empty in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
	badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe().SetIssuer(&pkix.Name{})
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-9-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Subject is empty in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_10(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "No name entries found in subject")

	certProfileDescription := "Subject is empty in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe().SetSubject(&pkix.Name{})
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-10-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: SAN is present but contains no names in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_11(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "No general names found in Subject Alternative Name extension")

	certProfileDescription := "SAN is present but contains no names in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, nil, nil, nil, nil)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe      = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-11-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Signature Algorithm field in certificate doesn't match with the algorithm in signed certificate
Applicable To: Intermediate CA
*/
func SSL_CERT_12(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Signature algorithm mismatch")

	certProfileDescription := "Signature Algorithm field in certificate doesn't match with the algorithm in signed certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe().SetSignatureAlgorithmFromPrivateKey(defaultCertificateParams.Intermed1CAKey, badcert.SHA384WithRSA)
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-12-CAT1-%d.json", outputDirectory, index))	
}


/*
Test Description: AKID Extension is not present in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_13(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Authority Key Identifier extension not found")

	certProfileDescription := "AKID Extension is not present in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetAKIDExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-13-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: AKID Extension is present but contains no KeyId in Intermediate CA
Applicable To: Intermediate CA
func SSL_CERT_14(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Identifier in Authority Key Identifier extension is empty")

	certProfileDescription := "AKID Extension is present but contains no KeyId in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtension(false, nil)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-14-CAT1-%d.json", outputDirectory, index))	
}
*/

/*
Test Description: AKID Extension is set to critical in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_15(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Authority Key Identifier extension is marked critical")

	certProfileDescription := "AKID Extension is set to critical in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(true, defaultCertificateParams.RootCAPubkey)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe      = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-15-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: SKID Extension is not present in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_16(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject Key Identifier extension not found")

	certProfileDescription := "SKID Extension is not present in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSKIDExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-16-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: SKID Extension is set to critical in Intermediate CA
Applicable To: Intermediate CA
*/
func SSL_CERT_17(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject Key Identifier extension is marked critical")

	certProfileDescription := "SKID Extension is set to critical in Intermediate CA"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe  = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(true, defaultCertificateParams.Intermed1CAPubkey)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	goodLeafRecipe        = BuildDefaultLeafRecipe()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe,badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-CERT-17-CAT1-%d.json", outputDirectory, index))	
}


/*
Test Description: Leaf certificate version is 1
Applicable To: Leaf
*/
func SSL_LEAF_CERT_1(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "X509 certificate version is not 3")

	certProfileDescription := "Leaf certificate version is 1"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe         = BuildDefaultLeafRecipe().SetVersion1()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-1-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Leaf certificate version is 2
Applicable To: Leaf
*/
func SSL_LEAF_CERT_2(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "X509 certificate version is not 3")

	certProfileDescription := "Leaf certificate version is 2"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe         = BuildDefaultLeafRecipe().SetVersion2()

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-2-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: KeyUsage extension contains keyCertSign in leaf certificate
Applicable To: Leaf
*/
func SSL_LEAF_CERT_3(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Usage extension 'keyCertSign' flag is present in leaf certificate")

	certProfileDescription := "KeyUsage extension contains keyCertSign in leaf certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe         = BuildDefaultLeafRecipe()
        modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageCertSign)
        badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-3-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: BasicConstraints extension contains CA=true in leaf certificate
Applicable To: Leaf
*/
func SSL_LEAF_CERT_4(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Basic Constraints extension 'CA' flag is true in leaf certificate")

	certProfileDescription := "BasicConstraints extension contains CA=true in leaf certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe         = BuildDefaultLeafRecipe()
        modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 0, false)
        badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-4-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Issuer name is empty in leaf certificate
Applicable To: Leaf
*/
func SSL_LEAF_CERT_5(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "No name entries found in issuer")

	certProfileDescription := "Issuer name is empty in leaf certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe         = BuildDefaultLeafRecipe().SetIssuer(&pkix.Name{})

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-5-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: SAN extension is not present and Subject name is empty in leaf certificate
Applicable To: Leaf
*/
func SSL_LEAF_CERT_6(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject is empty and Subject Alternative Name extension is absent")

	certProfileDescription := "SAN extension is not present and Subject name is empty in leaf certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe         = BuildDefaultLeafRecipe().SetSubject(&pkix.Name{})
        modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension()
        badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-6-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Subject name is empty and SAN extension is set but not marked as critical in leaf certificate
Applicable To: Leaf
*/
func SSL_LEAF_CERT_7(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject is empty and Subject Alternative Name extension is not marked critical")

	certProfileDescription := "Subject name is empty and SAN extension is set but not marked as critical in leaf certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe         = BuildDefaultLeafRecipe().SetSubject(&pkix.Name{})
        modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, []string{"BADCERT-LEAF.cisco.com"}, nil, nil, nil)
        badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()
	
	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-7-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: Signature Algorithm field in certificate doesn't match with the algorithm in signed certificate in leaf
Applicable To: Leaf
*/
func SSL_LEAF_CERT_8(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Signature algorithm mismatch")

	certProfileDescription := "Signature Algorithm field in certificate doesn't match with the algorithm in signed certificate in leaf"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe      = BuildDefaultLeafRecipe().SetSignatureAlgorithmFromPrivateKey(defaultCertificateParams.LeafKey, badcert.SHA384WithRSA)

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-8-CAT1-%d.json", outputDirectory, index))	
}


/*
Test Description: AKID Extension is not present in Leaf certificate
Applicable To: Leaf
*/
func SSL_LEAF_CERT_9(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Authority Key Identifier extension not found")

	certProfileDescription := "AKID Extension is not present in Leaf certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
	goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe      = BuildDefaultLeafRecipe().SetIsCertificateValid(false)
	modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetAKIDExtension()
        badLeafRecipe.SetExtensions(modifiedLeafExtensions)

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-9-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: AKID Extension is present but contains no KeyId in Leaf certificate
Applicable To: Leaf
func SSL_LEAF_CERT_10(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Identifier in Authority Key Identifier extension is empty")

	certProfileDescription := "AKID Extension is present but contains no KeyId in Leaf certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe      = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtension(false, nil)
        badLeafRecipe.SetExtensions(modifiedLeafExtensions)

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-10-CAT1-%d.json", outputDirectory, index))	
}
*/

/*
Test Description: AKID Extension is set to critical in Leaf certificate
Applicable To: Leaf
*/
func SSL_LEAF_CERT_11(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Authority Key Identifier extension is marked critical")

	certProfileDescription := "AKID Extension is set to critical in Leaf certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe      = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(true, defaultCertificateParams.Intermed1CAPubkey)
        badLeafRecipe.SetExtensions(modifiedLeafExtensions)

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-11-CAT1-%d.json", outputDirectory, index))
}

/*
Test Description: SKID Extension is set to critical in Leaf certificate
Applicable To: Leaf
*/
func SSL_LEAF_CERT_12(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject Key Identifier extension is marked critical in leaf certificate")

	certProfileDescription := "SKID Extension is set to critical in Leaf certificate"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	badLeafRecipe         = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(true, defaultCertificateParams.LeafPubkey)
        badLeafRecipe.SetExtensions(modifiedLeafExtensions)

	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        badLeafRecipe.SetIsCertificateValid(false).SetExpectedLogs(expectedLogs).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe,goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/SSL-LEAF-CERT-12-CAT1-%d.json", outputDirectory, index))
}



func GenerateSSLCerts(sslCertOutputDirectory string) {
	CreateDirectory(sslCertOutputDirectory)
	SSL_CERT_1(sslCertOutputDirectory)
	SSL_CERT_2(sslCertOutputDirectory)
	SSL_CERT_3(sslCertOutputDirectory)
	SSL_CERT_4(sslCertOutputDirectory)
	SSL_CERT_5(sslCertOutputDirectory)
	SSL_CERT_6(sslCertOutputDirectory)
	SSL_CERT_7(sslCertOutputDirectory)
	SSL_CERT_8(sslCertOutputDirectory)
	SSL_CERT_9(sslCertOutputDirectory)
	SSL_CERT_10(sslCertOutputDirectory)
	SSL_CERT_11(sslCertOutputDirectory)
	SSL_CERT_12(sslCertOutputDirectory)
	SSL_CERT_13(sslCertOutputDirectory)
	//SSL_CERT_14(sslCertOutputDirectory)
	SSL_CERT_15(sslCertOutputDirectory)
	SSL_CERT_16(sslCertOutputDirectory)
	SSL_CERT_17(sslCertOutputDirectory)


	SSL_LEAF_CERT_1(sslCertOutputDirectory)
	SSL_LEAF_CERT_2(sslCertOutputDirectory)
	SSL_LEAF_CERT_3(sslCertOutputDirectory)
	SSL_LEAF_CERT_4(sslCertOutputDirectory)
	SSL_LEAF_CERT_5(sslCertOutputDirectory)
	SSL_LEAF_CERT_6(sslCertOutputDirectory)
	SSL_LEAF_CERT_7(sslCertOutputDirectory)
	SSL_LEAF_CERT_8(sslCertOutputDirectory)
	SSL_LEAF_CERT_9(sslCertOutputDirectory)
	//SSL_LEAF_CERT_10(sslCertOutputDirectory)
	SSL_LEAF_CERT_11(sslCertOutputDirectory)
	SSL_LEAF_CERT_12(sslCertOutputDirectory)

}
