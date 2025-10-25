package main

import (
	"fmt"
	"flag"
	"errors"
	"path/filepath"
)



var defaultCertificateParams *DefaultCertificateParams


func main() {
	commandType         := flag.String("command", "custom-certs", "Command To run(custom-certs | rfc-5280-certs | sign-request)")
	certOutputDirectory := flag.String("cert_dir", "certs/", "Certificate output directory path")
	certRequestType     := flag.Int("cert_request_type", int(LEAF_CERT_VERSION_1), "Type of leaf certificate to create during signing")
	certRequestPath     := flag.String("cert_request_path", "req.pem", "Path to certificate signing request file")
	certRequestSigner   := flag.Int("cert_request_signer", int(CERT_REQUEST_SIGNER_ROOT), "Key to use for signing certificate request file")
	defaultCADirectory  := flag.String("default_ca_dir", "CA/", "Default CA Directory Path")
	flag.Parse()
        
        absPath, _ := filepath.Abs(*certOutputDirectory)
	CreateDirectory(*certOutputDirectory)

	defaultCertificateParams = GenerateDefaultCertificateParams()
	
	if (*commandType == "rfc-5280-certs") {
		rfc5280CertOutputDirectory := fmt.Sprintf("%s/rfc-5280-certs/", absPath)
	        GenerateRFC5280Certs(rfc5280CertOutputDirectory)
	} else if (*commandType == "custom-certs") {
	        customCertOutputDirectory := fmt.Sprintf("%s/custom-certs/", absPath)
	        GenerateCustomCerts(customCertOutputDirectory)
	} else if (*commandType == "sign-request") {
		signRequestCertOutputDirectory := fmt.Sprintf("%s/sign-request/", absPath)
		SignRequest(*defaultCADirectory, signRequestCertOutputDirectory, CertRequestType(*certRequestType), *certRequestPath, CertRequestSigner(*certRequestSigner))
	} else {
		panic(errors.New("Invalid command type"))
	}


}
