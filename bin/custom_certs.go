package main

import (
	"fmt"
	"github.com/hegde-akshath/badcert"
)

/* TEMPLATE 
Certificate Version must be 3
Basic Constraints Extension must be present
Basic Constraints Extension must be marked as critical
Basic Constraints Extension must contain CA = true
Path length constraint field must be present
Path length constraint field must be >= 0
Key Usage Extension must be present
Key Usage Extension must be marked as critical
Key Usage Extension must contain keyCertSign bit
*/


/*
Certificate Version is 1
Basic Constraints Extension is present
Basic Constraints Extension is marked as critical
Basic Constraints Extension contains CA = true
Path length constraint field is present
Path length constraint field is >= 0
Key Usage Extension is present
Key Usage Extension is marked as critical
Key Usage Extension contains keyCertSign bit
*/
func CUSTOM_CERT_1(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var badCertificateChain BadCertificateChain
        var index int

	badRootCARecipe      = BuildDefaultRootCARecipe().SetVersion1()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetVersion1()
        badLeafRecipe        = BuildDefaultLeafRecipe().SetVersion1()
	badCertificateChains := BuildBadCertificateChains(badRootCARecipe, badIntermed1CARecipe, badLeafRecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-1-CAT1-%d.json", outputDirectory, index))
	}
}

/*
Certificate Version is 2
Basic Constraints Extension is present
Basic Constraints Extension is marked as critical
Basic Constraints Extension contains CA = true
Path length constraint field is present
Path length constraint field is >= 0
Key Usage Extension is present
Key Usage Extension is marked as critical
Key Usage Extension contains keyCertSign bit
*/
func CUSTOM_CERT_2(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
	var badCertificateChain BadCertificateChain
        var index int

	badRootCARecipe      = BuildDefaultRootCARecipe().SetVersion2()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetVersion2()
        badLeafRecipe        = BuildDefaultLeafRecipe().SetVersion2()
	badCertificateChains := BuildBadCertificateChains(badRootCARecipe, badIntermed1CARecipe, badLeafRecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
		testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-2-CAT1-%d.json", outputDirectory, index))
	}
}

/*
Certificate Version is 3
Basic Constraints Extension is absent
Path length constraint field is present
Path length constraint field is >= 0
Key Usage Extension is present
Key Usage Extension is marked as critical
Key Usage Extension contains keyCertSign bit
*/
func CUSTOM_CERT_3(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var index int
	var badCertificateChain BadCertificateChain

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
                testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-3-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Certificate Version is 3
Basic Constraints Extension is present
Basic Constraints Extension is not marked as critical
Basic Constraints Extension contains CA = true
Path length constraint field is present
Path length constraint field is >= 0
Key Usage Extension is present
Key Usage Extension is marked as critical
Key Usage Extension contains keyCertSign bit
*/
func CUSTOM_CERT_4(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var index int
	var badCertificateChain BadCertificateChain

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-4-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Certificate Version is 3
Basic Constraints Extension is present
Basic Constraints Extension is marked as critical
Basic Constraints Extension contains CA = false
Path length constraint field is present
Path length constraint field is >= 0
Key Usage Extension is present
Key Usage Extension is marked as critical
Key Usage Extension contains keyCertSign bit
*/
func CUSTOM_CERT_5(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var index int
	var badCertificateChain BadCertificateChain

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-5-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Certificate Version is 3
Basic Constraints Extension is present
Basic Constraints Extension is marked as critical
Basic Constraints Extension contains CA = true
Path length constraint field is absent
Key Usage Extension is present
Key Usage Extension is marked as critical
Key Usage Extension contains keyCertSign bit
*/
func CUSTOM_CERT_6(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var index int
	var badCertificateChain BadCertificateChain

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, 0, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-6-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Certificate Version is 3
Basic Constraints Extension is present
Basic Constraints Extension is marked as critical
Basic Constraints Extension contains CA = true
Path length constraint field is present
Path length constraint field is -2
Key Usage Extension is present
Key Usage Extension is marked as critical
Key Usage Extension contains keyCertSign bit
*/
func CUSTOM_CERT_7(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var index int
	var badCertificateChain BadCertificateChain

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -2, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -2, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-7-CAT1-%d.json", outputDirectory, index))	
	}

}

/*
Certificate Version is 3
Basic Constraints Extension is present
Basic Constraints Extension is marked as critical
Basic Constraints Extension contains CA = true
Path length constraint field is present
Path length constraint field is >= 0
Key Usage Extension is absent
*/
func CUSTOM_CERT_8(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var index int
	var badCertificateChain BadCertificateChain

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetKeyUsageExtension()
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension()
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-8-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Certificate Version is 3
Basic Constraints Extension is present
Basic Constraints Extension is marked as critical
Basic Constraints Extension contains CA = true
Path length constraint field is present
Path length constraint field is -2
Key Usage Extension is present
Key Usage Extension is not marked as critical
Key Usage Extension contains keyCertSign bit
*/
func CUSTOM_CERT_9(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var index int
	var badCertificateChain BadCertificateChain

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCertSign|badcert.KeyUsageCRLSign)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCertSign|badcert.KeyUsageCRLSign)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-9-CAT1-%d.json", outputDirectory, index))	
	}
}

/*
Certificate Version is 3
Basic Constraints Extension is present
Basic Constraints Extension is marked as critical
Basic Constraints Extension contains CA = true
Path length constraint field is present
Path length constraint field is -2
Key Usage Extension is present
Key Usage Extension is marked as critical
Key Usage Extension doesn't contain keyCertSign bit
*/
func CUSTOM_CERT_10(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
	var index int
	var badCertificateChain BadCertificateChain

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(true, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCRLSign)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(true, badcert.KeyUsageDigitalSignature|badcert.KeyUsageCRLSign)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
	        testCertData := CreateTestCertData(badCertificateChain)
                testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/CUSTOM-CERT-10-CAT1-%d.json", outputDirectory, index))	
	}
}



func GenerateCustomCerts(outputDirectory string) {
	CUSTOM_CERT_1(outputDirectory)
	CUSTOM_CERT_2(outputDirectory)
	CUSTOM_CERT_3(outputDirectory)
	CUSTOM_CERT_4(outputDirectory)
	CUSTOM_CERT_5(outputDirectory)
	CUSTOM_CERT_6(outputDirectory)
	CUSTOM_CERT_7(outputDirectory)
	CUSTOM_CERT_8(outputDirectory)
	CUSTOM_CERT_9(outputDirectory)
	CUSTOM_CERT_10(outputDirectory)
}
