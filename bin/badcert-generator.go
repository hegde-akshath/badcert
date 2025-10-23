package main

import (
	"fmt"
	"flag"
	"os"
	"errors"
	"path/filepath"
	"strings"
)



var defaultCertificateParams *DefaultCertificateParams


func CreateOutputDirectory(outputDirectory string) {
    outputDirectory = strings.TrimSpace(outputDirectory)
    outputDirectory = filepath.Clean(outputDirectory)

    absPath, _ := filepath.Abs(outputDirectory)
    fmt.Println("Absolute Output Directory Path: ", absPath)

    //Can change this to MkdirALL or create only directories needed within subcommands
    _, err := os.Stat(absPath) 
    if errors.Is(err, os.ErrNotExist) {
        err := os.Mkdir(absPath, 0755)
        if err != nil {
            panic(err)
        }
        fmt.Println("Directory created:", absPath)
        
	rfc5280CertOutputDirectory := fmt.Sprintf("%s/rfc-5280-certs/", absPath)
	err = os.Mkdir(rfc5280CertOutputDirectory, 0755)
        if err != nil {
            panic(err)
        }
        fmt.Println("Directory created:", rfc5280CertOutputDirectory)

	customCertOutputDirectory := fmt.Sprintf("%s/custom-certs/", absPath)
	err = os.Mkdir(customCertOutputDirectory, 0755)
        if err != nil {
            panic(err)
        }
        fmt.Println("Directory created:", customCertOutputDirectory)

	signRequestCertOutputDirectory := fmt.Sprintf("%s/sign-request/", absPath)
	err = os.Mkdir(signRequestCertOutputDirectory, 0755)
        if err != nil {
            panic(err)
        }
        fmt.Println("Directory created:", signRequestCertOutputDirectory)

	return
    }

    if err != nil {
        panic(err)
    } 

    panic(fmt.Errorf("Directory already exists: %v", absPath))
}

func main() {
	commandType         := flag.String("command", "custom-certs", "Command To Run(custom-certs | rfc-5280-certs | sign-request)")
	certOutputDirectory := flag.String("cert_dir", "certs/", "Certificate Output Directory Path")
	signRequestType     := flag.Int("sign_request_type", 0, "Type of leaf certificate to create during signing")
	requestFilePath     := flag.String("request_file_path", "req.pem", "Path to Certificate Signing Request File")
	flag.Parse()
        
        absPath, _ := filepath.Abs(*certOutputDirectory)
	CreateOutputDirectory(*certOutputDirectory)

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
