package main

import (
	"bytes"
	"github.com/hegde-akshath/badcert"
	"os"
	"encoding/json"
)

type TestCertData struct {
	CACertChainPem string
	LeafCertPem string
	IsValid bool
}

func CreateTestCertData(badCertChain BadCertificateChain, leafPresent bool, isValid bool) (*TestCertData) {
	var testCertData TestCertData
        var buf bytes.Buffer
        var caStartIndex int

	testCertData.IsValid           = isValid
	
	if leafPresent {
		badLeafCert := []*badcert.BadCertificate(badCertChain)[0]
		badLeafCert.WriteCertificatePem(&buf)
		testCertData.LeafCertPem = buf.String()
		buf.Reset()
		caStartIndex = 1
	}

	badcert.WriteCertificateChainPem([]*badcert.BadCertificate(badCertChain)[caStartIndex:], &buf)
        testCertData.CACertChainPem = buf.String()
	buf.Reset()
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

