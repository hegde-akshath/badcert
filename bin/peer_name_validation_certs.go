package main

import (
        "fmt"
	"net"
        "github.com/hegde-akshath/badcert"
        "github.com/hegde-akshath/badcert/pkix"
)


/*1)Subject CN Present. SAN DNS Present. SAN IP Present
  2)Subject CN Present. SAN DNS Present. SAN IP Absent
  3)Subject CN Present. SAN DNS Absent.  SAN IP Present
  4)Subject CN Present. SAN DNS Absent.  SAN IP Absent
  5)Subject CN Absent.  SAN DNS Present. SAN IP Present
  6)Subject CN Absent.  SAN DNS Present. SAN IP Absent
  7)Subject CN Absent.  SAN DNS Absent.  SAN IP Present
  8)Subject CN Absent.  SAN DNS Absent.  SAN IP Absent.
  9)

/*
Test Description: Intermedicate CA version is 1
Applicable To: Intermediate CA
*/
func PEER_NAME_VALIDATION_CERT(caDirectory string, outputDirectory string, leafPrivateKeyPath string, certRequestSigner CertRequestSigner, subjectCN string, sanDNS string, sanIP string) { 
	var certChain BadCertificateChain
	var sanDNSSlice []string
	var sanIPSlice []net.IP

	leafPrivateKey := LoadKey(leafPrivateKeyPath)
        
	//NOTE, we also need to pass the correct sigalgo parameter to this
        rootCAKey, intermed1CAKey   := loadDefaultCAKeys(caDirectory)
        rootCACert, intermed1CACert := loadDefaultCACerts(caDirectory)

	certProfileDescription := "Peer Name Validation"
        
	_, leafPubKey := badcert.GetSignerFromKey(leafPrivateKey)
        
	if sanDNS != "" {
		sanDNSSlice = []string{sanDNS}
	} else {
		sanDNSSlice = nil
	}

	if sanIP != "" {
		sanIPSlice = []net.IP{net.ParseIP(sanIP)}
	} else {
		sanIPSlice = nil
	}
	
        if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
		defaultLeafRecipe := BuildDefaultLeafRecipe().SetIssuer(&rootCACert.Subject).SetSubject(&pkix.Name{CommonName: subjectCN}).SetCertificatePublicKey(leafPubKey)
		modifiedLeafExtensions := defaultLeafRecipe.GetExtensions().UnsetSANExtension().UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, leafPubKey)
	        if sanDNSSlice != nil || sanIPSlice != nil {
			modifiedLeafExtensions = modifiedLeafExtensions.SetSANExtension(false, sanDNSSlice, nil, sanIPSlice, nil)
		}
		defaultLeafRecipe.SetExtensions(modifiedLeafExtensions)
	        defaultLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
		certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, true, defaultLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
	        defaultLeafRecipe := BuildDefaultLeafRecipe().SetIssuer(&intermed1CACert.Subject).SetSubject(&pkix.Name{CommonName: subjectCN}).SetCertificatePublicKey(leafPubKey)
		modifiedLeafExtensions := defaultLeafRecipe.GetExtensions().UnsetSANExtension().UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, leafPubKey)
	        if sanDNSSlice != nil || sanIPSlice != nil {
			modifiedLeafExtensions = modifiedLeafExtensions.SetSANExtension(false, sanDNSSlice, nil, sanIPSlice, nil)
		}
		defaultLeafRecipe.SetExtensions(modifiedLeafExtensions)	
	        defaultLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
		certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, true, defaultLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/PEER-NAME-VALIDATION.json", outputDirectory))
}



func GeneratePeerNameValidationCerts(caDirectory string, peerNameValidationCertOutputDirectory string, leafPrivateKeyPath string, certRequestSigner CertRequestSigner, subjectCN string, sanDNS string, sanIP string) {
        CreateDirectory(peerNameValidationCertOutputDirectory)

	PEER_NAME_VALIDATION_CERT(caDirectory, peerNameValidationCertOutputDirectory, leafPrivateKeyPath, certRequestSigner, subjectCN, sanDNS, sanIP)
}
