package main

import (
	"os"
	"fmt"
	"errors"
	"github.com/hegde-akshath/badcert"
        "crypto"
	"encoding/pem"
	"strings"
	"path/filepath"
)


func CreateDirectory(directoryPath string) {
    directoryPath = strings.TrimSpace(directoryPath)
    directoryPath = filepath.Clean(directoryPath)

    absPath, _ := filepath.Abs(directoryPath)
    fmt.Println("Absolute Output Directory Path: ", absPath)

    //Can change this to MkdirALL or create only directories needed within subcommands
    _, err := os.Stat(absPath) 
    if errors.Is(err, os.ErrNotExist) {
        err := os.Mkdir(absPath, 0755)
        if err != nil {
            panic(err)
        }
        fmt.Println("Directory created:", absPath)
	return
    }

    if (err != nil) {
        panic(err)
    }
    
    panic(fmt.Errorf("Directory already exists: %v", absPath))
}



func LoadKey(filepath string) (crypto.PrivateKey) {
    keyPem, err := os.ReadFile(filepath)
    if err != nil {
	    panic(err)
    }
    
    keyDer, _ := pem.Decode(keyPem)
    if keyDer == nil {
	    panic(errors.New("Failed to decode first PEM block"))
    }
    
    //NOTE: Parsing only PKCS8 for now
    key, err := badcert.ParsePKCS8PrivateKey(keyDer.Bytes)
    if err != nil {
	    panic(err)
    }
    
    return key    
}

func ReadCertificateRequest(requestFilePath string) (*badcert.CertificateRequest) {
	csrPem, err := os.ReadFile(requestFilePath)
        if err != nil {
		panic(err)
        }
    
        csrDer, _ := pem.Decode(csrPem)
        if csrDer == nil {
                panic(errors.New("Failed to extract first PEM block in request file"))
        }
    
        certRequest, err := badcert.ParseCertificateRequest(csrDer.Bytes)
        if err != nil {
                panic(err)
        }

	err = certRequest.CheckSignature()
	if err != nil {
		panic(err)
	}

        return certRequest
}

func ReadCertificate(certFilePath string) (*badcert.Certificate) {
        certPem, err := os.ReadFile(certFilePath)
        if err != nil {
		panic(err)
        }

	certDer, _ := pem.Decode(certPem)
	if certDer == nil {
                panic(errors.New("Failed to extract first PEM block in certificate file"))
	}

	cert, err := badcert.ParseCertificate(certDer.Bytes)
	if err != nil {
		panic(err)
        }
	return cert
}
