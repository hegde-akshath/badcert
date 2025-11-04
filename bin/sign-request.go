package main

import (
	"errors"
	"fmt"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
	"crypto"
)


/*
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

type CertRequestSigner int
type CertRequestType int

const (
	CERT_REQUEST_SIGNER_ROOT CertRequestSigner = iota
	CERT_REQUEST_SIGNER_INTERMED1
)

const (
	LEAF_CERT_VERSION_1 CertRequestType = iota
	LEAF_CERT_VERSION_2
	LEAF_CERT_BASIC_CONSTRAINTS_CA_TRUE
	LEAF_CERT_KEYUSAGE_KEYCERTSIGN
	LEAF_CERT_PATHLEN_PRESENT
	LEAF_CERT_EMPTY_ISSUER
	LEAF_CERT_NO_SAN_EMPTY_SUBJECT
	LEAF_CERT_NO_SUBJECT_SAN_NOT_CRITICAL
	LEAF_CERT_SAN_PRESENT_BUT_EMPTY
	LEAF_CERT_SIG_ALG_MISMATCH
	LEAF_CERT_AKID_NOT_PRESENT
	LEAF_CERT_AKID_NO_KEYID
	LEAF_CERT_AKID_CRITICAL
	LEAF_CERT_SKID_CRITICAL
)


func loadDefaultCAKeys(defaultCADirectoryPath string) (crypto.PrivateKey, crypto.PrivateKey) {
	rootCAKey      := LoadKey(fmt.Sprintf("%s/root-ca-key.pem", defaultCADirectoryPath))
	intermed1CAKey := LoadKey(fmt.Sprintf("%s/intermed1-ca-key.pem", defaultCADirectoryPath))
	return rootCAKey, intermed1CAKey
}

func loadDefaultCACerts(defaultCADirectoryPath string) (*badcert.Certificate, *badcert.Certificate) {
        rootCACert      := ReadCertificate(fmt.Sprintf("%s/root-ca-cert.pem", defaultCADirectoryPath))
        intermed1CACert := ReadCertificate(fmt.Sprintf("%s/intermed1-ca-cert.pem", defaultCADirectoryPath))
	return rootCACert, intermed1CACert
}


//TODO: Instead of this, need to create a CA on request, and use from there
//That way, theres no risk of running out of serial numbers etc
//We can also start HTTP server for CRL and OCSP server upon that on the fly
func SignRequestBadCertLeafVersion1(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey,
   rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf Cert Version is 1"
       
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       badLeafRecipe = badLeafRecipe.SetVersion1()
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       badLeafRecipe = badLeafRecipe.SetVersion1()               
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)      
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-VERSION-1.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafVersion2(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey,
   rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf Cert Version is 2"
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
       	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       badLeafRecipe = badLeafRecipe.SetVersion2()
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
       	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       badLeafRecipe = badLeafRecipe.SetVersion2()               
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-VERSION-2.json", signRequestCertOutputDirectory))
}


func SignRequestBadCertLeafBasicConstraintsCATrue(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf Cert contains CA = true in Basic Constraints extension"
               
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -1, false)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert)) 
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, true, -1, false)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert)) 
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-BASIC-CONSTRAINTS-CA-TRUE.json", signRequestCertOutputDirectory))
}


func SignRequestBadCertLeafKeyusageKeycertsign(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)
         
       certProfileDescription := "Leaf Cert contains keyCertSign bit in Key Usage extension"
       
       modifiedKeyUsage := badcert.KeyUsageCertSign
       if certRequestFields.KeyUsage != nil {
	       modifiedKeyUsage = modifiedKeyUsage | (*certRequestFields.KeyUsage)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions()
               if certRequestFields.KeyUsage != nil {
		       modifiedLeafExtensions = modifiedLeafExtensions.UnsetKeyUsageExtension()
               }
	       modifiedLeafExtensions = modifiedLeafExtensions.SetKeyUsageExtension(false, modifiedKeyUsage)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert)) 
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions()
	       if certRequestFields.KeyUsage != nil {
		       modifiedLeafExtensions = modifiedLeafExtensions.UnsetKeyUsageExtension()
               }
	       modifiedLeafExtensions = modifiedLeafExtensions.SetKeyUsageExtension(false, modifiedKeyUsage)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-KEYUSAGE-KEYCERTSIGN.json", signRequestCertOutputDirectory))

}


func SignRequestBadCertLeafPathlenPresent(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)
 
       certProfileDescription := "Leaf Cert contains pathlen attribute in Basic Constraints extension"
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))  
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert)) 
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-PATHLEN-PRESENT.json", signRequestCertOutputDirectory))

}

func SignRequestBadCertLeafEmptyIssuer(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)
 
       certProfileDescription := "Leaf Cert contains empty issuer field"
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId).SetIssuer(&pkix.Name{})
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))   
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId).SetIssuer(&pkix.Name{})
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-EMPTY-ISSUER.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafNoSanEmptySubject(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf cert has no SAN extension but subject field is empty as well"
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId).SetSubject(&pkix.Name{})
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions()
	       if certRequestFields.IsSANSet == true {
		       modifiedLeafExtensions = modifiedLeafExtensions.UnsetSANExtension()
               }
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))   
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId).SetSubject(&pkix.Name{})
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions()
	       if certRequestFields.IsSANSet == true {
		       modifiedLeafExtensions = modifiedLeafExtensions.UnsetSANExtension()
               }
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-NO-SAN-EMPTY-SUBJECT.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafNoSubjectSanNotCritical(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       if certRequestFields.IsSANSet == false {
	       panic(fmt.Errorf("Certificate Request should contain SAN extension in attributes"))
       }
       
       certProfileDescription := "Leaf cert has empty Subject but SAN extension is not marked critical"
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId).SetSubject(&pkix.Name{})
	       //Extenions don't need to be modified as the above function already creates SAN extension as non critical
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))   
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId).SetSubject(&pkix.Name{})
	       //Extenions don't need to be modified as the above function already creates SAN extension as non critical
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-NO-SAN-EMPTY-SUBJECT.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafSanPresentButEmpty(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf cert contains SAN extension but it is empty"
      
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions()
	       if certRequestFields.IsSANSet == true {
		       modifiedLeafExtensions = modifiedLeafExtensions.UnsetSANExtension()
               }
               modifiedLeafExtensions = modifiedLeafExtensions.SetSANExtension(false, nil, nil, nil, nil)	
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))   
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions()
	       if certRequestFields.IsSANSet == true {
		       modifiedLeafExtensions = modifiedLeafExtensions.UnsetSANExtension()
               }
               modifiedLeafExtensions = modifiedLeafExtensions.SetSANExtension(false, nil, nil, nil, nil)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }


       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-SAN-PRESENT-BUT-EMPTY.json", signRequestCertOutputDirectory))

}

func SignRequestBadCertLeafSigalgMismatch(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {	
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf cert sigalg field doesn't match the algorithm field in signature"
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId).SetSignatureAlgorithmFromPrivateKey(rootCAKey, badcert.SHA384WithRSA)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))   
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId).SetSignatureAlgorithmFromPrivateKey(intermed1CAKey, badcert.SHA384WithRSA)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }
        
       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-SIGALG-MISMATCH.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafAKIDNotPresent(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf cert doesn't contain AKID extension"
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetAKIDExtension()
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))   
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetAKIDExtension()
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-AKID-NOT-PRESENT.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafAKIDNoKeyid(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf cert contains no KeyId in AKID extension"
 
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtension(false, nil)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))   
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtension(false, nil)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-AKID-NO-KEYID.json", signRequestCertOutputDirectory))
}


func SignRequestBadCertLeafAKIDCritical(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf cert contains AKID extension marked as critical"
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtension(true, rootCACert.SubjectKeyId)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))   
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetAKIDExtension().SetAKIDExtension(true, intermed1CACert.SubjectKeyId)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }
 
       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-AKID-CRITICAL.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafSKIDCritical(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var certRequestFields *CertificateRequestFields
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       certRequestFields = ExtractCertRequestFields(certRequest)

       certProfileDescription := "Leaf cert contains SKID extension marked as critical"
       
       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &rootCACert.Subject, rootCACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(true, certRequest.PublicKey)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))   
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildLeafCertFromCertRequest(certRequestFields, &intermed1CACert.Subject, intermed1CACert.SubjectKeyId)
	       modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetSKIDExtension().SetSKIDExtensionFromKey(true, certRequest.PublicKey)
	       badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	       badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(certProfileDescription, nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))  
       }
 
       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-SKID-CRITICAL.json", signRequestCertOutputDirectory))
}



func SignRequest(defaultCADirectory string, signRequestCertOutputDirectory string, certRequestType CertRequestType, certRequestPath string, certRequestSigner CertRequestSigner) {
	CreateDirectory(signRequestCertOutputDirectory)

	//NOTE, we also need to pass the correct sigalgo parameter to this
        rootCAKey, intermed1CAKey   := loadDefaultCAKeys(defaultCADirectory)
	rootCACert, intermed1CACert := loadDefaultCACerts(defaultCADirectory)
	
	if (certRequestType == LEAF_CERT_VERSION_1) {
		fmt.Println("Generating Leaf Certificate with Version 1")
		SignRequestBadCertLeafVersion1(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_VERSION_2) {
		fmt.Println("Generating Leaf Certificate with Version 2")
		SignRequestBadCertLeafVersion2(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_BASIC_CONSTRAINTS_CA_TRUE) {
		fmt.Println("Generating Leaf Certificate with BasicConstraints extension containing CA set to True")
		SignRequestBadCertLeafBasicConstraintsCATrue(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_KEYUSAGE_KEYCERTSIGN) {
		fmt.Println("Generating Leaf Certificate with KeyUsage containing keyCertSign bit")
		SignRequestBadCertLeafKeyusageKeycertsign(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_PATHLEN_PRESENT) {
		fmt.Println("Generating Leaf Certificate with pathlen attribute present in Basic Constraints Extension")
		SignRequestBadCertLeafPathlenPresent(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_EMPTY_ISSUER) {
		fmt.Println("Generating Leaf Certificate with empty issuer")
		SignRequestBadCertLeafEmptyIssuer(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_NO_SAN_EMPTY_SUBJECT) {
		fmt.Println("Generating Leaf Certificate with no SAN extensin and also an empty subject")
		SignRequestBadCertLeafNoSanEmptySubject(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_NO_SUBJECT_SAN_NOT_CRITICAL) {
		fmt.Println("Generating Leaf Certificate with no subject and SAN is set but not critical")
		SignRequestBadCertLeafNoSubjectSanNotCritical(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_SAN_PRESENT_BUT_EMPTY) {
		fmt.Println("Generating Leaf Certificate with SAN extension but contents empty")
		SignRequestBadCertLeafSanPresentButEmpty(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_SIG_ALG_MISMATCH) {
		fmt.Println("Generating Leaf Certificate with mismatch in sigalg fields")
		SignRequestBadCertLeafSigalgMismatch(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_AKID_NOT_PRESENT) {
		fmt.Println("Generating Leaf Certificate with AKID extension absent")
		SignRequestBadCertLeafAKIDNotPresent(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_AKID_NO_KEYID) {
		fmt.Println("Generating Leaf Certificate with AKID extension containing no KeyId")
		SignRequestBadCertLeafAKIDNoKeyid(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_AKID_CRITICAL) {
		fmt.Println("Generating Leaf Certificate with AKID extension marked critical")
		SignRequestBadCertLeafAKIDCritical(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_SKID_CRITICAL) {
		fmt.Println("Generating Leaf Certificate with SKID extension marked critical")
		SignRequestBadCertLeafSKIDCritical(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	}  else {
		panic(errors.New("Unknown sign request type"))
	}
}
