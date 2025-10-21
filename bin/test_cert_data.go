package main

import (
	"bytes"
	"github.com/hegde-akshath/badcert"
	"os"
	"encoding/json"
)

type TestCertData struct {
	CertChainPem string
	LeafPresent bool
	IntermedCAPresent bool
	IsValid bool
}

func CreateTestCertData(badCertChain BadCertificateChain, leafPresent bool, intermedCAPresent bool, isValid bool) (*TestCertData) {
	var testCertData TestCertData
        var buf bytes.Buffer

	testCertData.LeafPresent       = leafPresent
	testCertData.IntermedCAPresent = intermedCAPresent
	testCertData.IsValid           = isValid
        
	badcert.WriteCertificateChainPem([]*badcert.BadCertificate(badCertChain), &buf)
        testCertData.CertChainPem = buf.String()
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

