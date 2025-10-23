package main

import (
	"bytes"
	"errors"
	"github.com/hegde-akshath/badcert"
	"os"
	"encoding/json"
	"encoding/pem"
)

type TestCertData struct {
	CertProfileDescription string
	LeafPrivateKey string
	RootCACertPem string
	IntermedCACertChainPem string
	LeafCertPem string
	IsRootCACertValid bool
	IsIntermedCACertChainValid bool
	IsLeafCertValid bool
} 

func CreateTestCertData(badCertChain BadCertificateChain) (*TestCertData) {
	var testCertData TestCertData
        var buf bytes.Buffer

	certChainLength := len(badCertChain.Chain)
	
	if certChainLength < 1 {
		panic(errors.New("Only a single cert present in chain"))
	}
        
	privateKeyBytes, err := badcert.MarshalPKCS8PrivateKey(badCertChain.LeafPrivateKey)
	if err != nil {
		panic(err)
	}

        privateKeyPEM := &pem.Block{
                           Type:  "PRIVATE KEY",
                           Bytes: privateKeyBytes,
        }
        pem.Encode(&buf, privateKeyPEM)
	testCertData.LeafPrivateKey = buf.String()
	buf.Reset()

	badLeafCert := badCertChain.Chain[0]
	badLeafCert.WriteCertificatePem(&buf)
	testCertData.LeafCertPem = buf.String()
	buf.Reset()
        
	badcert.WriteCertificateChainPem(badCertChain.Chain[1:(certChainLength - 1)], &buf)
        testCertData.IntermedCACertChainPem = buf.String()
	buf.Reset()
        
	rootCACert := badCertChain.Chain[certChainLength - 1]
        rootCACert.WriteCertificatePem(&buf)
	testCertData.RootCACertPem = buf.String()
	buf.Reset()
         
	testCertData.IsRootCACertValid          = badCertChain.IsRootCACertValid
	testCertData.IsIntermedCACertChainValid = badCertChain.IsIntermedCACertChainValid
	testCertData.IsLeafCertValid            = badCertChain.IsLeafCertValid 
	testCertData.CertProfileDescription     = badCertChain.CertProfileDescription 

	return &testCertData	    
}

func (testCertData *TestCertData) WriteTestCertDataJson(filepath string) {
	var err error
	var jsonData []byte
        var f *os.File

	jsonData, err = json.Marshal(*testCertData)
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

