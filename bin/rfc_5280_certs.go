package main

import (
	"fmt"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
)


//Extensions are present but version is 1
//Extensions are present but version is 2
func X509_VERSION_1(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
        var index int
	var badCertificateChain BadCertificateChain

	badRootCARecipe      = BuildDefaultRootCARecipe().SetVersion1()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetVersion1()
        badLeafRecipe        = BuildDefaultLeafRecipe().SetVersion1()
	badCertificateChains := BuildBadCertificateChains(badRootCARecipe, badIntermed1CARecipe, badLeafRecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-VERSION-1-CAT1-%d.pem", outputDirectory, index))
	}

	badRootCARecipe      = BuildDefaultRootCARecipe().SetVersion2()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetVersion2()
        badLeafRecipe        = BuildDefaultLeafRecipe().SetVersion2()
	badCertificateChains = BuildBadCertificateChains(badRootCARecipe, badIntermed1CARecipe, badLeafRecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-VERSION-1-CAT2-%d.pem", outputDirectory, index))
	}


}


//Basic Constraints Extension is present, CA is set to true and key usage contains keyCertSign. But the subject field is empty
func X509_SUBJECT_1(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var emptySubject *pkix.Name
        var index int
	var badCertificateChain BadCertificateChain

	emptySubject = &pkix.Name{}
	
	badRootCARecipe      = BuildDefaultRootCARecipe().SetSubject(emptySubject)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetSubject(emptySubject)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-SUBJECT-1-CAT1-%d.pem", outputDirectory, index))
	}
}

//Leaf certificate contains subject name information in SAN, the Subject field is empty, but SAN is not marked as critical
func X509_SUBJECT_2(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var badLeafRecipe *badcert.BadCertificate
        var certChain BadCertificateChain
	var emptySubject *pkix.Name
        	
	emptySubject = &pkix.Name{}
	        
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        badLeafRecipe        = BuildDefaultLeafRecipe().SetSubject(emptySubject)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	badLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = CreateBadCertificateChain(" ", defaultCertificateParams.LeafKey, true, true, false, badLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe)
	WriteBadCertChain(certChain, fmt.Sprintf("%s/X509-SUBJECT-2-CAT1-1.pem", outputDirectory))
}




//Basic Constraints Extension is present, and CA is set to false, but key usage contains keyCertSign
func X509_EXT_BASIC_CONST_1(outputDirectory string) {
        var badRootCARecipe *badcert.BadCertificate
	var badIntermed1CARecipe *badcert.BadCertificate
	var modifiedRootCAExtensions badcert.ExtensionSlice
	var modifiedIntermed1CAExtensions badcert.ExtensionSlice
		
	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain := range *badCertificateChains {
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-1-CAT1-%d.pem", outputDirectory, index))
	}
}

//Basic Constraints Extension is absent, but key usage contains keyCertSign
//Basic Constraints Extension is present, and CA is set to false, but key usage contains keyCertSign
func X509_EXT_BASIC_CONST_2(outputDirectory string) {
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
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-2-CAT1-%d.pem", outputDirectory, index))
	}

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains = BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-2-CAT2-%d.pem", outputDirectory, index))
	}
}



//Basic Constraints Extension is absent, but key usage contains keyCertSign and/or the key is used to validate signatures on certificates
//Basic constraints extension is present, but hasn't been marked as critical. key usage contains keyCertSign and/or the key is used to validate signatures on certificates
func X509_EXT_BASIC_CONST_3(outputDirectory string) {
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
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-3-CAT1-%d.pem", outputDirectory, index))
	}

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 1, false)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, true, 0, false)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains = BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-3-CAT2-%d.pem", outputDirectory, index))
	}
}


//Leaf certificate contains basic constraints extension set to false, and KeyCertSign extension is absent in keyusage. Basic constraint extension is marked as critical
//Leaf certificate contains basic constraints extension set to false, and KeyCertSign extension is absent in keyusage. Basic constraint extension is not marked as critical
//The certificate should be processed without issue in both of the cases above 
func X509_EXT_BASIC_CONST_5(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
        var certChain BadCertificateChain 
			
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 0, false)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = CreateBadCertificateChain(" ", defaultCertificateParams.LeafKey, true, true, true, goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe)
	WriteBadCertChain(certChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-5-CAT1-1.pem", outputDirectory))

	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(false, false, 0, false)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = CreateBadCertificateChain(" ", defaultCertificateParams.LeafKey, true, true, true, goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe)
	WriteBadCertChain(certChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-5-CAT2-1.pem", outputDirectory))
}


//Basic Constraints Extension is present, keyCertSign bit is set and CA is set to false. But the pathlen attribute is still included
//Basic Constraints Extension is present, keyCertSign bit is not set and CA is set to true. But the pathlen attribute is still included
func X509_EXT_BASIC_CONST_6(outputDirectory string) {
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
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-6-CAT1-%d.pem", outputDirectory, index))
	}

	badRootCARecipe      = BuildDefaultRootCARecipe()
        modifiedRootCAExtensions = badRootCARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageEncipherOnly)
	badRootCARecipe.SetExtensions(modifiedRootCAExtensions)
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
	modifiedIntermed1CAExtensions = badIntermed1CARecipe.GetExtensions().UnsetKeyUsageExtension().SetKeyUsageExtension(false, badcert.KeyUsageEncipherOnly)
	badIntermed1CARecipe.SetExtensions(modifiedIntermed1CAExtensions)
	badCertificateChains = BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, " ")
	for index, badCertificateChain = range *badCertificateChains {
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-6-CAT2-%d.pem", outputDirectory, index))
	}
}

//Basic Constraints Extension is present, keyCertSign bit is set and CA is set to true. But the pathlen attribute contains a negative integer
func X509_EXT_BASIC_CONST_7(outputDirectory string) {
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
	badCertificateChains := BuildBadCACertificateChains(badRootCARecipe, badIntermed1CARecipe, "")
	for index, badCertificateChain = range *badCertificateChains {
		WriteBadCertChain(badCertificateChain, fmt.Sprintf("%s/X509-EXT-BASIC-CONST-7-CAT1-%d.pem", outputDirectory, index))
	}
}


//SAN extension is present in the leaf certificate and names of more than one form are present
//SAN extension is present in the leaf certificate and multiple instances of names of more than one form are present
//The certificate should be processed without issue in both of the cases above 
func X509_EXT_SAN_1(outputDirectory string) {
        var goodRootCARecipe *badcert.BadCertificate
	var goodIntermed1CARecipe *badcert.BadCertificate
	var goodLeafRecipe *badcert.BadCertificate
	var modifiedLeafExtensions badcert.ExtensionSlice
        var certChain BadCertificateChain
		
	goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, []string{"BADCERT-LEAF-DNSNAME-1.cisco.com"}, []string{"user1@cisco.com"}, nil, nil)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = CreateBadCertificateChain("", defaultCertificateParams.LeafKey, true, true, true, goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe)
	WriteBadCertChain(certChain, fmt.Sprintf("%s/X509-EXT-SAN-1-CAT1-1.pem", outputDirectory))
	
        goodRootCARecipe      = BuildDefaultRootCARecipe()
        goodIntermed1CARecipe = BuildDefaultIntermed1CARecipe()
        goodLeafRecipe        = BuildDefaultLeafRecipe()
	modifiedLeafExtensions = goodLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, []string{"BADCERT-LEAF-DNSNAME-1.cisco.com", "BADCERT-LEAF-DNSNAME-2.cisco.com"}, []string{"user1@cisco.com", "user2@cisco.com"}, nil, nil)
	goodLeafRecipe.SetExtensions(modifiedLeafExtensions)
	goodRootCARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
        goodIntermed1CARecipe.SignTBS(defaultCertificateParams.RootCAKey, defaultCertificateParams.SignatureAlgorithm)
	goodLeafRecipe.SignTBS(defaultCertificateParams.Intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
        certChain = CreateBadCertificateChain("", defaultCertificateParams.LeafKey, true, true, true, goodLeafRecipe, goodIntermed1CARecipe, goodRootCARecipe)
	WriteBadCertChain(certChain, fmt.Sprintf("%s/X509-EXT-SAN-1-CAT1-2.pem", outputDirectory))
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
        X509_EXT_BASIC_CONST_7(outputDirectory)
}

func GenerateSANCerts(outputDirectory string) {
        X509_EXT_SAN_1(outputDirectory)
}

func GenerateRFC5280Certs(outputDirectory string) {
	GenerateX509VersionCerts(outputDirectory)
	GenerateX509SubjectCerts(outputDirectory)
	GenerateX509ExtBasicConstCerts(outputDirectory)
	GenerateSANCerts(outputDirectory)
}


