package main

import (
	"os"
	"github.com/hegde-akshath/badcert"
)

func CreateAndWriteBadCertChain(badCertificateChain BadCertificateChain, filepath string) {
	f, err := os.Create(filepath)
	if err != nil {
		panic(err)
	}
        defer f.Close()
        
	badcert.WriteCertificateChainPem([]*badcert.BadCertificate(badCertificateChain), f)
}
