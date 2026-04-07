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


Requirements for a Good Self Signed CA Certificates 
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
15)AKID extension is not mandatory. But if present, must not be set to critical 
16)SKID extension must be present, and must not be set to critical
*/


/*
Test Description: Certificate Version is not correct(version 1), but all other fields are as expected
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_1(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var badCertificateChain BadCertificateChain
        var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "X509 certificate version is not 3")
        
	certProfileDescription := "Certificate Version is 1"
	badRootCARecipe      = BuildDefaultRootCARecipe().SetVersion1()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetVersion1()
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-1-CAT1-%d.json", outputDirectory, index))
	}
}


/*
Test Description: Certificate Version is not correct(version 2), but all other fields are as expected
Applicable To: Self Signed Root CA, Intermediate CA.
*/
func CA_AUTHENTICATE_CERT_2(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var badCertificateChain BadCertificateChain
        var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "X509 certificate version is not 3")
 
	certProfileDescription := "Certificate Version is 2"
	badRootCARecipe      = BuildDefaultRootCARecipe().SetVersion2()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetVersion2()
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
		testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-2-CAT1-%d.json", outputDirectory, index))
	}
}

/*
Test Description: In Self Signed Root CA and Intermediate CA, Basic Constraints Extension is absent.
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_3(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Basic Constraints extension not found in certificate")
 
	certProfileDescription := "Basic Constraints Extension is absent"
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)

	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
                testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-3-CAT1-%d.json", outputDirectory, index))	
	}
}


/*
Test Description: Basic Constraints Extension is not marked as critical
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_4(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Basic Constraints extension is not marked critical")
 
	certProfileDescription := "Basic Constraints Extension is not marked as critical"
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-4-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Test Description: Basic Constraints Extension contains CA = false
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_5(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Basic Constraints extension 'CA' flag is not set")
 
	certProfileDescription := "Basic Constraints Extension contains CA = false"
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-5-CAT1-%d.json", outputDirectory, index))	
	}
}


/*
Test Description: Path length constraint field is -2
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_6(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Basic Constraints extension 'pathlen' is negative")
 
	certProfileDescription := "Path length constraint field is -2"
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -2, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -2, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-6-CAT1-%d.json", outputDirectory, index))	
	}

}

/*
Test Description: Key Usage Extension is absent
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_7(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Usage extension not found in certificate")
 
	certProfileDescription := "Key Usage Extension is absent"
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetKeyUsageExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-7-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Test Description: Key Usage Extension doesn't contain keyCertSign bit
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_8(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Usage extension missing keyCertSign flag")
 
	certProfileDescription := "Key Usage Extension doesn't contain keyCertSign bit"
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCRLSign)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCRLSign)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-8-CAT1-%d.json", outputDirectory, index))	
	}
}


/*
Test Description: Issuer Name is empty, but all other fields are as expected.
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_9(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var badCertificateChain BadCertificateChain
        var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "No name entries found in issuer")
 
	certProfileDescription := "Issuer Name is Empty"
	badRootCARecipe      = BuildDefaultRootCARecipe().SetIssuer(&pkix.Name{})
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetIssuer(&pkix.Name{})
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
		testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-9-CAT1-%d.json", outputDirectory, index))
	}
}

/*
Test Description: Subject Name is empty, but all other fields are as expected.
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_10(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var badCertificateChain BadCertificateChain
        var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "No name entries found in subject")
 
	certProfileDescription := "Subject Name is Empty"
	badRootCARecipe      = BuildDefaultRootCARecipe().SetSubject(&pkix.Name{})
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetSubject(&pkix.Name{})
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
		testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-10-CAT1-%d.json", outputDirectory, index))
	}
}


/*
Test Description: SAN is present but contains no names
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_11(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "No general names found in Subject Alternative Name extension")
 
	certProfileDescription := "SAN is present but contains no names"
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, nil, nil, nil, nil)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, nil, nil, nil, nil)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-11-CAT1-%d.json", outputDirectory, index))	
	}
}


/*
Test Description: Signature Algorithm field in certificate doesn't match with the algorithm in signed certificate, but all other fields are as expected
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_12(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var badCertificateChain BadCertificateChain
        var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Signature algorithm mismatch")
 
	certProfileDescription := "Signature Algorithm field in certificate doesn't match with the algorithm in signed certificate"
	badRootCARecipe      = BuildDefaultRootCARecipe().SetSignatureAlgorithmFromPrivateKey(defaultCertificateParams.RootCAKey, badcert.SHA384WithRSA)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetSignatureAlgorithmFromPrivateKey(defaultCertificateParams.Intermed1CAKey, badcert.SHA384WithRSA)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
		testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-12-CAT1-%d.json", outputDirectory, index))
	}
}

/*
Test Description: SKID is absent
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_13(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject Key Identifier extension not found")
 
	certProfileDescription := "SKID is absent"
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetSKIDExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSKIDExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-13-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Test Description: SKID is present, but marked as critical
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_14(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject Key Identifier extension is marked critical")
 
	certProfileDescription := "SKID is present, but marked as critical"
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(true, defaultCertificateParams.RootCAPubkey)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(true, defaultCertificateParams.Intermed1CAPubkey)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-14-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Test Description: AKID is not present
Applicable To: Intermediate CA
*/
func CA_AUTHENTICATE_CERT_15(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Authority Key Identifier extension not found")
 
	certProfileDescription := "AKID is not present"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetAKIDExtension()
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
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-15-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: AKID is present, but KeyId is empty
Applicable To: Intermediate CA
*/
func CA_AUTHENTICATE_CERT_16(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Identifier in Authority Key Identifier extension is empty")
 
	certProfileDescription := "AKID is present, but KeyId is empty"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(false, nil)
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
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-16-CAT1-%d.json", outputDirectory, index))	
}


/*
Test Description: AKID is present, but set to critical
Applicable To: Intermediate CA
*/
func CA_AUTHENTICATE_CERT_17(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Authority Key Identifier extension is marked critical")
 
	certProfileDescription := "AKID is present, but set to critical"
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
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-17-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: AKID is present, but set to critical
Applicable To: Root CA
*/
func CA_AUTHENTICATE_CERT_18(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var goodIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Authority Key Identifier extension is marked critical")
 
	certProfileDescription := "AKID is present, but set to critical"
	badRootCARecipe      = BuildDefaultRootCARecipe()
	modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(true, defaultCertificateParams.RootCAPubkey)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	goodLeafRecipe      = BuildDefaultLeafRecipe()

	badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badRootCARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, false, true, true, goodLeafRecipe,goodIntermed1CARecipe,badRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-18-CAT1-%d.json", outputDirectory, index))	
}

/*
Test Description: AKID is present, but KeyId is empty
Applicable To: Root CA
*/
func CA_AUTHENTICATE_CERT_21(outputDirectory string) {
    var badRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var goodIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Identifier in Authority Key Identifier extension is empty")
 
	certProfileDescription := "AKID is present, but KeyId is empty"
	badRootCARecipe      = BuildDefaultRootCARecipe()
	modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(false, nil)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
	goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	goodLeafRecipe      = BuildDefaultLeafRecipe()

	badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badRootCARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, false, true, true, goodLeafRecipe,goodIntermed1CARecipe,badRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-21-CAT1-%d.json", outputDirectory, index))	
}


/*
Test Description: SKID is present, but KeyId is empty
Applicable To: Root CA
*/
func CA_AUTHENTICATE_CERT_22(outputDirectory string) {
    var badRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var goodIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Identifier in Subject Key Identifier extension is empty")
 
	certProfileDescription := "SKID is present, but KeyId is empty"
	badRootCARecipe      = BuildDefaultRootCARecipe()
	modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(false, nil)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
	goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	goodLeafRecipe      = BuildDefaultLeafRecipe()

	badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badRootCARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()
	
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, false, true, true, goodLeafRecipe,goodIntermed1CARecipe,badRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-22-CAT1-%d.json", outputDirectory, index))	
}


/*
Test Description: SAN is absent
Applicable To: Root CA
*/
func CA_AUTHENTICATE_CERT_23(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var goodIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject Alternative Name extension not found")
 
	certProfileDescription := "SAN is absent"
	badRootCARecipe      = BuildDefaultRootCARecipe()
	modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetSANExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	goodLeafRecipe      = BuildDefaultLeafRecipe()

	badRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badRootCARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)

	goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()

	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	certChain := CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, false, true, true, goodLeafRecipe,goodIntermed1CARecipe,badRootCARecipe)
	testCertData := CreateTestCertData(certChain)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-23-CAT1-%d.json", outputDirectory, index))	
}


/*
Test Description: SAN is absent
Applicable To: Intermediate CA
*/
func CA_AUTHENTICATE_CERT_24(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject Alternative Name extension not found")
 
	certProfileDescription := "SAN is not present"
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSANExtension()
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
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-24-CAT1-%d.json", outputDirectory, index))	
}




func GenerateCAAuthenticateCerts(caAuthenticateCertOutputDirectory string) {
	CreateDirectory(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_1(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_2(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_3(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_4(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_5(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_6(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_7(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_8(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_9(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_10(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_11(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_12(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_13(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_14(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_15(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_16(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_17(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_18(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_21(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_22(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_23(caAuthenticateCertOutputDirectory)
	CA_AUTHENTICATE_CERT_24(caAuthenticateCertOutputDirectory)
}
