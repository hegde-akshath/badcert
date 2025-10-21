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

    //Can change this to MkdirALl
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

	return
    }

    if err != nil {
        panic(err)
    } 

    panic(fmt.Errorf("Directory already exists: %v", absPath))
}

func main() {
	certOutputDirectory := flag.String("o", "certs/", "Certificate Output Directory Path")
        flag.Parse()
        
        absPath, _ := filepath.Abs(*certOutputDirectory)
	rfc5280CertOutputDirectory := fmt.Sprintf("%s/rfc-5280-certs/", absPath)
	customCertOutputDirectory := fmt.Sprintf("%s/custom-certs/", absPath)

	CreateOutputDirectory(*certOutputDirectory)
	defaultCertificateParams = GenerateDefaultCertificateParams()
	GenerateRFC5280Certs(rfc5280CertOutputDirectory)
	GenerateCustomCerts(customCertOutputDirectory)
}
