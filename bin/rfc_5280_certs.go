package main

import (
	"fmt"
	"os"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
)


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


