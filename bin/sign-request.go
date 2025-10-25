package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
	"crypto"
	"crypto/rand"
	"math/big"
)

type CertRequestType int

const (
	LEAF_CERT_VERSION_1 CertRequestType = iota
	LEAF_CERT_VERSION_2
	LEAF_CERT_PATHLEN_PRESENT
	LEAF_CERT_EMPTY_ISSUER
	LEAF_CERT_NO_SAN_EMPTY_SUBJECT
	LEAF_CERT_SAN_PRESENT_BUT_EMPTY
	LEAF_CERT_SIG_ALG_MISMATCH
	LEAF_CERT_AKID_CRITICAL
	LEAF_CERT_SKID_CRITICAL
	LEAF_CERT_AKID_NOT_PRESENT
)

type CertRequestSigner int

const (
	CERT_REQUEST_SIGNER_ROOT CertRequestSigner = iota
	CERT_REQUEST_SIGNER_INTERMED1
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
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
       
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildDefaultLeafRecipe().SetVersion1().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
	       badLeafRecipe := BuildDefaultLeafRecipe().SetVersion1().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)      
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-VERSION-1.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafVersion2(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey,
   rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
        
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildDefaultLeafRecipe().SetVersion2().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildDefaultLeafRecipe().SetVersion2().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-VERSION-2.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafPathlenPresent(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
       
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe  := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey).UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey).UnsetBasicConstraintsExtension().SetBasicConstraintsExtension(true, false, 1, false)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-PATHLEN-PRESENT.json", signRequestCertOutputDirectory))

}

func SignRequestBadCertLeafEmptyIssuer(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
       
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&pkix.Name{}).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert)) 
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
	       badLeafRecipe := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&pkix.Name{}).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-EMPTY-ISSUER.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafNoSanEmptySubject(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
         
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe := BuildDefaultLeafRecipe().SetSubject(&pkix.Name{}).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert)) 
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe := BuildDefaultLeafRecipe().SetSubject(&pkix.Name{}).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-NO-SAN-EMPTY-SUBJECT.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafSanPresentButEmpty(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       
       subject        = certRequest.Subject
        
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, nil, nil, nil, nil).UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert)) 
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
	       badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, nil, nil, nil, nil).UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert)) 
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-SAN-PRESENT-BUT-EMPTY.json", signRequestCertOutputDirectory))

}

/*
func SignRequestBadCertLeafSigalgMismatch(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {	
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
        
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber).SetSignatureAlgorithm(badcert.SHA384WithRSA)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber).SetSignatureAlgorithm(badcert.SHA384WithRSA)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       
       }
 
       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-SIGALG-MISMATCH.json", signRequestCertOutputDirectory))
}
*/


func SignRequestBadCertLeafAKIDCritical(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
        
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(true, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(true, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }
 
       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-AKID-CRITICAL.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafSKIDCritical(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
        
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, rootCACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(true, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
               badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().SetAKIDExtension(false, intermed1CACert.SubjectKeyId).UnsetSKIDExtension().SetSKIDExtensionFromKey(true, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-SKID-CRITICAL.json", signRequestCertOutputDirectory))
}

func SignRequestBadCertLeafAKIDNotPresent(signRequestCertOutputDirectory string, certRequestPath string, certRequestSigner CertRequestSigner, rootCAKey crypto.PrivateKey, intermed1CAKey crypto.PrivateKey, rootCACert *badcert.Certificate, intermed1CACert *badcert.Certificate) {
       var certRequest *badcert.CertificateRequest
       var subject pkix.Name
       var dnsNames []string
       var emailAddresses []string
       var ipAddresses []net.IP
       var URIs []*url.URL
       var modifiedLeafExtensions badcert.ExtensionSlice
       var certChain BadCertificateChain

       certRequest = ReadCertificateRequest(certRequestPath)
       
       subject        = certRequest.Subject
       dnsNames       = certRequest.DNSNames
       emailAddresses = certRequest.EmailAddresses
       ipAddresses    = certRequest.IPAddresses
       URIs           = certRequest.URIs
        
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
		panic(err)
       }

       if certRequestSigner == CERT_REQUEST_SIGNER_ROOT {
	       badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&rootCACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions)
               badLeafRecipe.SignTBS(rootCAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(rootCACert))
       } else if certRequestSigner == CERT_REQUEST_SIGNER_INTERMED1 {
	       badLeafRecipe        := BuildDefaultLeafRecipe().SetSubject(&subject).SetIssuer(&intermed1CACert.Subject).SetSerialNumber(serialNumber)
               modifiedLeafExtensions = badLeafRecipe.GetExtensions().UnsetSANExtension().SetSANExtension(false, dnsNames, emailAddresses, ipAddresses, URIs).UnsetAKIDExtension().UnsetSKIDExtension().SetSKIDExtensionFromKey(false, certRequest.PublicKey)
               badLeafRecipe.SetExtensions(modifiedLeafExtensions) 
               badLeafRecipe.SignTBS(intermed1CAKey, defaultCertificateParams.SignatureAlgorithm)
               certChain = CreateBadCertificateChain(" ", nil, true, true, false, badLeafRecipe, badcert.CreateBadCertificateFromCertificate(intermed1CACert), badcert.CreateBadCertificateFromCertificate(rootCACert))
       }

       testCertData := CreateTestCertData(certChain)
       testCertData.WriteTestCertDataJson(fmt.Sprintf("%s/LEAF-CERT-AKID-NOT-PRESENT.json", signRequestCertOutputDirectory))
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
	} else if (certRequestType == LEAF_CERT_PATHLEN_PRESENT) {
		fmt.Println("Generating Leaf Certificate with pathlen attribute present in Basic Constraints Extension")
		SignRequestBadCertLeafPathlenPresent(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_EMPTY_ISSUER) {
		fmt.Println("Generating Leaf Certificate with empty issuer")
		SignRequestBadCertLeafEmptyIssuer(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_NO_SAN_EMPTY_SUBJECT) {
		fmt.Println("Generating Leaf Certificate with no SAN extensin and also an empty subject")
		SignRequestBadCertLeafNoSanEmptySubject(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_SAN_PRESENT_BUT_EMPTY) {
		fmt.Println("Generating Leaf Certificate with SAN extension but contents empty")
		SignRequestBadCertLeafSanPresentButEmpty(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_AKID_CRITICAL) {
		fmt.Println("Generating Leaf Certificate with AKID extension marked critical")
		SignRequestBadCertLeafAKIDCritical(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_SKID_CRITICAL) {
		fmt.Println("Generating Leaf Certificate with SKID extension marked critical")
		SignRequestBadCertLeafSKIDCritical(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else if (certRequestType == LEAF_CERT_AKID_NOT_PRESENT) {
		fmt.Println("Generating Leaf Certificate with AKID extension absent")
		SignRequestBadCertLeafAKIDNotPresent(signRequestCertOutputDirectory, certRequestPath, certRequestSigner, rootCAKey, intermed1CAKey, rootCACert, intermed1CACert)
	} else {
		panic(errors.New("Unknown sign request type"))
	}
}
