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
func CA_AUTHENTICATE_CERT_BAD_01(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-01-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-01-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}


/*
Test Description: Certificate Version is not correct(version 2), but all other fields are as expected
Applicable To: Self Signed Root CA, Intermediate CA.
*/
func CA_AUTHENTICATE_CERT_BAD_02(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-02-CAT1-%d", index)
		testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-02-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: In Self Signed Root CA and Intermediate CA, Basic Constraints Extension is absent.
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_03(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-03-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-03-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}


/*
Test Description: Basic Constraints Extension is not marked as critical
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_04(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-04-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-04-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: Basic Constraints Extension contains CA = false
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_05(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-05-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-05-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}


/*
Test Description: Path length constraint field is -2
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_06(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-06-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-06-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}

}

/*
Test Description: Key Usage Extension is absent
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_07(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-07-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-07-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: Key Usage Extension doesn't contain keyCertSign bit
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_08(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-08-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-08-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}


/*
Test Description: Issuer Name is empty, but all other fields are as expected.
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_09(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-09-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-09-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: Subject Name is empty, but all other fields are as expected.
Applicable To: Self Signed Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_10(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-10-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-10-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: Signature Algorithm field in certificate doesn't match with the algorithm in signed certificate, but all other fields are as expected
Applicable To: Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_11(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-11-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-11-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}


/*
Test Description: SAN is present but contains no names
Applicable To: Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_12(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
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
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-12-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-12-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}


/*
Test Description: SKID is not present
Applicable To: Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_13(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
    var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject Key Identifier extension not found")
 
	certProfileDescription := "SKID is not present"

	badRootCARecipe               = BuildDefaultRootCARecipe()
    modifiedRootCAExtensions      = badRootCARecipe.GetExtensions().UnsetSKIDExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
    
	badIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSKIDExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	    testCertData := CreateTestCertData(badCertificateChain)
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-13-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-13-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: SKID is present, but marked as critical
Applicable To: Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_14(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
    var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Subject Key Identifier extension is marked critical")
 
	certProfileDescription := "SKID is present, but marked as critical"
	
	badRootCARecipe               = BuildDefaultRootCARecipe()
    modifiedRootCAExtensions      = badRootCARecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(true, defaultCertificateParams.RootCAPubkey)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
    
	badIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(true, defaultCertificateParams.Intermed1CAPubkey)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	    testCertData := CreateTestCertData(badCertificateChain)
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-14-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-14-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: SKID is present, but KeyId is empty
Applicable To: Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_15(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
    var badRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Identifier in Subject Key Identifier extension is empty")
 
	certProfileDescription := "SKID is present, but KeyId is empty"
	
	badRootCARecipe               = BuildDefaultRootCARecipe()
	modifiedRootCAExtensions      = badRootCARecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(false, nil)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)

    badIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(false, nil)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)

	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	    testCertData := CreateTestCertData(badCertificateChain)
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-15-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-15-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}

}

/*
Test Description: AKID is not present
Applicable To: Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_16(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
	var goodRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Authority Key Identifier extension not found")
 
	certProfileDescription := "AKID is not present in Intermediate CA Certificate"

	goodRootCARecipe              = BuildDefaultRootCARecipe()
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

    badIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetAKIDExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
    badIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey,defaultCertificateParams.SignatureAlgorithm)
	badIntermed1CARecipe.SetIsCertificateValid(false).SetIdentityString().SetExpectedLogs(expectedLogs)
	
	goodLeafRecipe = BuildDefaultLeafRecipe()
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	badCertificateChain = CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, false, true, goodLeafRecipe, badIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(badCertificateChain)
	testId := fmt.Sprintf("CA-AUTH-CERT-BAD-16-CAT1-%d", index)
	testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-16-CAT1-%d.json", outputDirectory, index))
	pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
}


/*
Test Description: AKID is present, but set to critical
Applicable To: Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_17(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
	var badRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Authority Key Identifier extension is marked critical")
 
	certProfileDescription := "AKID is present, but set to critical"
 
	badRootCARecipe               = BuildDefaultRootCARecipe()
	modifiedRootCAExtensions      = badRootCARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(true, defaultCertificateParams.RootCAPubkey)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
   
	badIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(true, defaultCertificateParams.RootCAPubkey)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)

	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	    testCertData := CreateTestCertData(badCertificateChain)
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-17-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-17-CAT1-%d.json", outputDirectory, index))	
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}

}

/*
Test Description: AKID is present, but KeyId is empty
Applicable To: Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_18(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
	var badRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var expectedLogs []string

	expectedLogs = append(expectedLogs, "Key Identifier in Authority Key Identifier extension is empty")
 
	certProfileDescription := "AKID is present, but KeyId is empty"
    
	badRootCARecipe               = BuildDefaultRootCARecipe()
	modifiedRootCAExtensions      = badRootCARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(false, nil)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)

	badIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(false, nil)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)

	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, expectedLogs, expectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	    testCertData := CreateTestCertData(badCertificateChain)
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-18-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-18-CAT1-%d.json", outputDirectory, index))	
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: 
Version is 1 in Root CA
Basic Constraints Absent in Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_19(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
	var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var rootCAExpectedLogs []string
	var intermed1CAExpectedLogs []string

	rootCAExpectedLogs      = append(rootCAExpectedLogs, "X509 certificate version is not 3")
	intermed1CAExpectedLogs = append(intermed1CAExpectedLogs, "Basic Constraints extension not found in certificate")

	certProfileDescription := "Version is 1 in Root CA. Basic Constraints is absent in Intermediate CA"
    
	badRootCARecipe               = BuildDefaultRootCARecipe().SetVersion1()

	badIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)

	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, rootCAExpectedLogs, intermed1CAExpectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	    testCertData := CreateTestCertData(badCertificateChain)
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-19-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-19-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: 
SKID extension is absent in Root CA
KeyUsage extension doesn't contain keyCertSign in Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_20(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
	var badRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
    var rootCAExpectedLogs []string
	var intermed1CAExpectedLogs []string

	rootCAExpectedLogs      = append(rootCAExpectedLogs, "Subject Key Identifier extension not found")
	intermed1CAExpectedLogs = append(intermed1CAExpectedLogs, "Key Usage extension missing keyCertSign flag")
 
	certProfileDescription := "SKID extension is absent in Root CA. KeyUsage extension doesn't contain keyCertSign in Intermediate CA"
    
	badRootCARecipe               = BuildDefaultRootCARecipe().SetVersion1()
    modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetSKIDExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)

	badIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()	
    modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCRLSign)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)

	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, rootCAExpectedLogs, intermed1CAExpectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	    testCertData := CreateTestCertData(badCertificateChain)
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-20-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-20-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: 
Version is 1 in Root CA. AKID contains no KeyId in Root CA
Basic Constraints Absent in Intermediate CA. SAN contains no names in Intermediate CA
*/
func CA_AUTHENTICATE_CERT_BAD_21(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
	var badRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var badCertificateChain BadCertificateChain
	var index int
	var rootCAExpectedLogs []string
	var intermed1CAExpectedLogs []string

	rootCAExpectedLogs      = append(rootCAExpectedLogs, "X509 certificate version is not 3")
	rootCAExpectedLogs      = append(rootCAExpectedLogs, "Key Identifier in Authority Key Identifier extension is empty")

	intermed1CAExpectedLogs = append(intermed1CAExpectedLogs, "Basic Constraints extension not found in certificate")
	intermed1CAExpectedLogs = append(intermed1CAExpectedLogs, "No general names found in Subject Alternative Name extension")

	certProfileDescription := "Version is 1 in Root CA. AKID contains no KeyId in Root CA. Basic Constraints is absent in Intermediate CA. SAN contains no names in Intermediate CA"
    
	badRootCARecipe               = BuildDefaultRootCARecipe().SetVersion1()
    modifiedRootCAExtensions      = badRootCARecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtensionFromKey(false, nil)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)

	badIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, nil, nil, nil, nil)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, certProfileDescription, rootCAExpectedLogs, intermed1CAExpectedLogs)
	for index, badCertificateChain = range *badCertificateChains {
	    testCertData := CreateTestCertData(badCertificateChain)
		testId := fmt.Sprintf("CA-AUTH-CERT-BAD-21-CAT1-%d", index)
        testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-BAD-21-CAT1-%d.json", outputDirectory, index))
	    pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
	}
}

/*
Test Description: SAN is not present
Applicable To: Root CA, Intermediate CA
*/
func CA_AUTHENTICATE_CERT_GOOD_01(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
    var goodRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var goodIntermed1CARecipe *badcert.BadCertificate
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var goodLeafRecipe *badcert.BadCertificate
	var goodCertificateChain BadCertificateChain
	var index int
 
	certProfileDescription := "SAN is not present"

	goodRootCARecipe              = BuildDefaultRootCARecipe()
	modifiedRootCAExtensions      = goodRootCARecipe.GetExtensions().UnsetSANExtension()
	goodRootCARecipe.SetExtensions(modifiedRootCAExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(true).SetIdentityString()

    goodIntermed1CARecipe         = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = goodIntermed1CARecipe.GetExtensions().UnsetSANExtension()
	goodIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
    goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey,defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()
	
	goodLeafRecipe = BuildDefaultLeafRecipe()
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	goodCertificateChain = CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, true, goodLeafRecipe, goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(goodCertificateChain)
	testId := fmt.Sprintf("CA-AUTH-CERT-GOOD-01-CAT1-%d", index)
	testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-GOOD-01-CAT1-%d.json", outputDirectory, index))
	pythonCertDataGenerator.AddTestCertData(testId, testCertData)

} 

/*
Test Description: AKID is not present
Applicable To: Root CA
*/
func CA_AUTHENTICATE_CERT_GOOD_02(outputDirectory string, pythonCertDataGenerator *PythonCertDataGenerator) {
	var goodRootCARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var goodIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var goodCertificateChain BadCertificateChain
	var index int
 
	certProfileDescription := "AKID is not present in Root CA Certificate"

	goodRootCARecipe          = BuildDefaultRootCARecipe()
	modifiedRootCAExtensions = goodRootCARecipe.GetExtensions().UnsetAKIDExtension()
	goodRootCARecipe.SetExtensions(modifiedRootCAExtensions)	
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodRootCARecipe.SetIsCertificateValid(false).SetIdentityString()

    goodIntermed1CARecipe          = BuildDefaultIntermed1CARecipe()
    goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey,defaultCertificateParams.SignatureAlgorithm)
	goodIntermed1CARecipe.SetIsCertificateValid(true).SetIdentityString()
	
	goodLeafRecipe = BuildDefaultLeafRecipe()
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SetIsCertificateValid(true).SetIdentityString()

	goodCertificateChain = CreateBadCertificateChain(certProfileDescription, defaultCertificateParams.LeafKey, true, true, true, goodLeafRecipe, goodIntermed1CARecipe,goodRootCARecipe)
	testCertData := CreateTestCertData(goodCertificateChain)
	testId := fmt.Sprintf("CA-AUTH-CERT-GOOD-02-CAT1-%d", index)
	testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CA-AUTH-CERT-GOOD-02-CAT1-%d.json", outputDirectory, index))
	pythonCertDataGenerator.AddTestCertData(testId, testCertData) 
}




func GenerateCAAuthenticateCerts(caAuthenticateCertOutputDirectory string) {	
    var pythonCertDataGenerator *PythonCertDataGenerator
	
	pythonCertDataGenerator = NewPythonCertDataGenerator()

	CreateDirectory(caAuthenticateCertOutputDirectory)
    
	CA_AUTHENTICATE_CERT_BAD_01(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_02(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_03(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_04(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_05(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_06(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_07(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_08(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_09(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_10(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_11(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_12(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_13(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_14(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_15(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_16(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_17(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_18(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_19(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_20(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_BAD_21(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)

	CA_AUTHENTICATE_CERT_GOOD_01(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)
	CA_AUTHENTICATE_CERT_GOOD_02(caAuthenticateCertOutputDirectory, pythonCertDataGenerator)

	pythonCertDataGenerator.WritePythonCertDataFile("CA_AUTH_CERT_PROFILES_VAR", "prefetched_ca_auth_cert_profiles.py")

}
