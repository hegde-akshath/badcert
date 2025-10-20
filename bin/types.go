package main

import (
	"github.com/hegde-akshath/badcert"
)

type BadCertificateChain []*badcert.BadCertificate
type BadCertificateChains []BadCertificateChain

func CreateBadCertificateChain(certs...*badcert.BadCertificate) (BadCertificateChain) {
	badCertChain := make(BadCertificateChain, 0, len(certs))
        
	for _, cert := range certs {
		badCertChain = append([]*badcert.BadCertificate(badCertChain), cert)
	}
	return BadCertificateChain(badCertChain)
}

func CreateBadCertificateChains(certChains...BadCertificateChain) (BadCertificateChains) {
	badCertChains := make(BadCertificateChains, 0, len(certChains))

	for _, certChain := range certChains {
		badCertChains = append(badCertChains, []*badcert.BadCertificate(certChain))
	}
        
	return BadCertificateChains(badCertChains)
}

