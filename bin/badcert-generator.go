package main

import (
	"fmt"
	"flag"
	"errors"
	"path/filepath"
)



var defaultCertificateParams *DefaultCertificateParams


func main() {
	commandType         := flag.String("command", "custom-certs", "Command To Run(custom-certs | rfc-5280-certs | sign-request)")
	certOutputDirectory := flag.String("cert_dir", "certs/", "Certificate Output Directory Path")
	signRequestType     := flag.Int("sign_request_type", 0, "Type of leaf certificate to create during signing")
	requestFilePath     := flag.String("request_file_path", "req.pem", "Path to Certificate Signing Request File")
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
		SignRequest(signRequestCertOutputDirectory, SignRequestType(*signRequestType), *requestFilePath)
	} else {
		panic(errors.New("Invalid command type"))
	}


}
