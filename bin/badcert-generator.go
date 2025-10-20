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

    _, err := os.Stat(absPath) 
    if errors.Is(err, os.ErrNotExist) {
        err := os.Mkdir(absPath, 0755)
        if err != nil {
            panic(err)
        }
        fmt.Println("Directory created:", absPath)
	return
    }

    if err != nil {
        panic(err)
    } 

    panic(fmt.Errorf("Directory already exists: %v", absPath))
}

func main() {
	outputDirectory := flag.String("o", "certs/", "Output directory path")
        flag.Parse()
        
	CreateOutputDirectory(*outputDirectory)
	defaultCertificateParams = GenerateDefaultCertificateParams()
	GenerateRFC5280Certs(*outputDirectory)
	GenerateCustomCerts(*outputDirectory)
}
