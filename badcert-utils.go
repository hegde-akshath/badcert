package badcert

import (
	"unsafe"
	"crypto/x509"
	"encoding/asn1"
)



func CreateBadCertificateFromX509Certificate(cert *x509.Certificate) (*BadCertificate) {
	var modifiedCert *Certificate
	var tbsCert tbsCertificate
        
	modifiedCert = (*Certificate)(unsafe.Pointer(cert))

	rawTbsCert := modifiedCert.RawTBSCertificate

	_, err := asn1.Unmarshal(rawTbsCert, &tbsCert)
	if err != nil {
		panic(err)
	}
        
	return &BadCertificate{tbscert: &tbsCert, x509Certificate: modifiedCert}

}
