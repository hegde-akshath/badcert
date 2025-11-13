package main

import (
	"os"
        "fmt"
	"bytes"
        "github.com/hegde-akshath/badcert"
        "crypto"
	"encoding/json"
	"encoding/pem"
)

type CADetails struct {
	RootCAPrivateKey      string
	Intermed1CAPrivateKey string
	RootCACertPem         string
	Intermed1CACertPem    string
	CACertChainPem        string
	NumCACerts            uint8
}

func loadRootCA(caDirectoryPath string) (crypto.PrivateKey, *badcert.Certificate) {
        rootCAKey      := LoadKey(fmt.Sprintf("%s/root-ca-key.pem", caDirectoryPath))
	rootCACert     := LoadCertificate(fmt.Sprintf("%s/root-ca-cert.pem", caDirectoryPath))
	return rootCAKey, rootCACert
}

func loadIntermed1CA(caDirectoryPath string) (crypto.PrivateKey, *badcert.Certificate) {
        intermed1CAKey := LoadKey(fmt.Sprintf("%s/intermed1-ca-key.pem", caDirectoryPath))
        intermed1CACert := LoadCertificate(fmt.Sprintf("%s/intermed1-ca-cert.pem", caDirectoryPath))
        return intermed1CAKey, intermed1CACert
}

func CreateCADetails(caDirectory string, getCADetailsOutputDirectory string) (*CADetails) {
	var caDetails CADetails
	var buf bytes.Buffer

	//NOTE, we also need to pass the correct sigalgo parameter to this
        rootCAPrivateKey, rootCACert           := loadRootCA(caDirectory)
        intermed1CAPrivateKey, intermed1CACert := loadIntermed1CA(caDirectory)
        
	rootCAPrivateKeyBytes, err := badcert.MarshalPKCS8PrivateKey(rootCAPrivateKey)
        if err != nil {
		panic(err)
        } 
	rootCAPrivateKeyPEM := &pem.Block{
                            Type:  "PRIVATE KEY",
                            Bytes: rootCAPrivateKeyBytes,
                         }

        pem.Encode(&buf, rootCAPrivateKeyPEM)
        caDetails.RootCAPrivateKey = buf.String()
	buf.Reset()

	intermed1CAPrivateKeyBytes, err := badcert.MarshalPKCS8PrivateKey(intermed1CAPrivateKey)
        if err != nil {
		panic(err)
        }
	intermed1CAPrivateKeyPEM := &pem.Block{
                            Type:  "PRIVATE KEY",
                            Bytes: intermed1CAPrivateKeyBytes,
                         }

        pem.Encode(&buf, intermed1CAPrivateKeyPEM)
        caDetails.Intermed1CAPrivateKey = buf.String()
	buf.Reset()

	caDetails.NumCACerts = 2
        
	caDetails.RootCACertPem = string(pem.EncodeToMemory(
		                       &pem.Block {
		                           Type:  "CERTIFICATE",
		                           Bytes: rootCACert.Raw,
	                               }))


	caDetails.Intermed1CACertPem = string(pem.EncodeToMemory(
		                            &pem.Block {
		                                Type:  "CERTIFICATE",
		                                Bytes: intermed1CACert.Raw,
	                                    }))


	caDetails.CACertChainPem = caDetails.Intermed1CACertPem + "\n" + caDetails.RootCACertPem
        
	return &caDetails
}

func (caDetails *CADetails) WriteCADetailsJson(filepath string) {
	var err error
        var jsonData []byte
        var f *os.File

	jsonData, err = json.Marshal(*caDetails)
        if err != nil {
                panic(err)
        }

        f, err = os.Create(filepath)
        if err != nil {
                panic(err)
        }

        defer f.Close()
        f.Write(jsonData)
}

func GetCADetails(caDirectory string, getCADetailsOutputDirectory string) {
	CreateDirectory(getCADetailsOutputDirectory)
	caDetails := CreateCADetails(caDirectory, getCADetailsOutputDirectory)
	filepath := fmt.Sprintf("%s/CA-DETAILS.json", getCADetailsOutputDirectory)
	caDetails.WriteCADetailsJson(filepath)
}
