// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 implements a subset of the X.509 standard.
//
// It allows parsing and generating certificates, certificate signing
// requests, certificate revocation lists, and encoded public and private keys.
// It provides a certificate verifier, complete with a chain builder.
//
// The package targets the X.509 technical profile defined by the IETF (RFC
// 2459/3280/5280), and as further restricted by the CA/Browser Forum Baseline
// Requirements. There is minimal support for features outside of these
// profiles, as the primary goal of the package is to provide compatibility
// with the publicly trusted TLS certificate ecosystem and its policies and
// constraints.
//
// On macOS and Windows, certificate verification is handled by system APIs, but
// the package aims to apply consistent validation rules across operating
// systems.
package badcert

import (
	"fmt"
	"io"
	"crypto/rand"
	"crypto/rsa"
	"github.com/hegde-akshath/badcert/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"
	"errors"

	"crypto/sha256"
	"crypto/sha1"
	"net"
	"net/url"
	// Explicitly import these for their crypto.RegisterHash init side-effects.
	// Keep these as blank imports, even if they're imported above.
	_ "crypto/sha512"
)

type X509Version int

const InitialMaxExtensions = 10

const (
	X509Version1 = 0
	X509Version2 = 1
	X509Version3 = 2
	X509VersionInvalid = 10
)

type ExtensionSlice []pkix.Extension

type BadCertValidity struct {
	NotBefore time.Time
	NotAfter time.Time
}

type BadCertificate struct {	
	tbscert *tbsCertificate
        x509Certificate *Certificate

	//Right now, this field is being derived while setting public key and storing it to avoid recalculating
	//But this should not be present here and should be done in a different way
	algorithmIdentifier *pkix.AlgorithmIdentifier	
}

func GetRandomBytes(length int) ([]byte, error) {
    bytes := make([]byte, length)

    _, err := rand.Read(bytes)
    if err != nil {
        return nil, err
    }
    return bytes, nil
}


func GenerateKeyIdFromKey(privKey *rsa.PrivateKey) ([]byte) {
        var keyId []byte

	pubKey := &privKey.PublicKey
        keyidMethod := 1
        
	pubKeyBytes, _, err := marshalPublicKey(pubKey)
	if err != nil {
		panic(err)
	}
        
	if keyidMethod == 1 {
		// SubjectKeyId generated using method 1 in RFC 5280, Section 4.2.1.2:
		//   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		//   value of the BIT STRING subjectPublicKey (excluding the tag,
		//   length, and number of unused bits).
		h := sha1.Sum(pubKeyBytes)
		keyId = h[:]
	} else {
		// SubjectKeyId generated using method 1 in RFC 7093, Section 2:
		//    1) The keyIdentifier is composed of the leftmost 160-bits of the
		//    SHA-256 hash of the value of the BIT STRING subjectPublicKey
		//    (excluding the tag, length, and number of unused bits).
		h := sha256.Sum256(pubKeyBytes)
		keyId = h[:20]
	}

	keyIdBytes, err := asn1.Marshal(keyId)
	if err != nil {
		panic(err)
	}
	return keyIdBytes
}

func NewMarshalBasicConstraints(critical bool, isCA bool, maxPathLen int, maxPathLenZero bool) (pkix.Extension, error) {
	var err error
	ext := pkix.Extension {
		Id: oidExtensionBasicConstraints, 
		Critical: critical,
	       }

	// Leaving MaxPathLen as zero indicates that no maximum path
	// length is desired, unless MaxPathLenZero is set. A value of
	// -1 causes encoding/asn1 to omit the value as desired.
	if maxPathLen == 0 && !maxPathLenZero {
		maxPathLen = -1
	}

	ext.Value, err = asn1.Marshal(basicConstraints{isCA, maxPathLen})
	return ext, err
}

func NewMarshalKeyUsage(critical bool, ku KeyUsage) (pkix.Extension, error) {
	var err error
	ext := pkix.Extension{
		Id: oidExtensionKeyUsage, 
		Critical: critical,
	       }

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	return ext, err
}

func NewMarshalExtKeyUsage(critical bool, extUsages []ExtKeyUsage, unknownUsages []asn1.ObjectIdentifier) (pkix.Extension, error) {
	var err error

	ext := pkix.Extension{
		Id: oidExtensionExtendedKeyUsage,
	        Critical: critical,
	       }

	oids := make([]asn1.ObjectIdentifier, len(extUsages)+len(unknownUsages))
	for i, u := range extUsages {
		if oid, ok := oidFromExtKeyUsage(u); ok {
			oids[i] = oid
		} else {
			return ext, errors.New("x509: unknown extended key usage")
		}
	}

	copy(oids[len(extUsages):], unknownUsages)

	ext.Value, err = asn1.Marshal(oids)
	return ext, err
}

func NewMarshalAKID(critical bool, authorityKeyId []byte) (pkix.Extension, error) {
	var err error

	ext := pkix.Extension {
	        Id: oidExtensionAuthorityKeyId,
		Critical: critical,
	       } 

	ext.Value, err = asn1.Marshal(authKeyId{authorityKeyId})
	return ext, err
}

func NewMarshalSKID(critical bool, subjectKeyId []byte) (pkix.Extension, error) {
        var err error

	ext := pkix.Extension {
	        Id: oidExtensionSubjectKeyId,
		Critical: critical,
	       } 

	ext.Value, err = asn1.Marshal(subjectKeyId)
	return ext, err
}

func NewMarshalSAN(critical bool, DNSNames []string, EmailAddresses []string, IPAddresses []net.IP, URIs []*url.URL) (pkix.Extension, error) {
        var err error
     
	ext := pkix.Extension {
	        Id: oidExtensionSubjectAltName,
		Critical: critical,
	       } 

	ext.Value, err = marshalSANs(DNSNames, EmailAddresses, IPAddresses, URIs)
	return ext, err
}

func CreateBadCertificate() (*BadCertificate) {
	return &BadCertificate{tbscert: &tbsCertificate{}}
}

func CreateExtensions() (ExtensionSlice) {
	extensions := make([]pkix.Extension, 0, InitialMaxExtensions)
	return ExtensionSlice(extensions)
}

func (tbsCert *tbsCertificate) SetVersion(x509Version X509Version)(*tbsCertificate) {
	tbsCert.Version = int(x509Version)
	return tbsCert
}

func (tbsCert *tbsCertificate) SetSerialNumber(serialNumber *big.Int)(*tbsCertificate) {
	tbsCert.SerialNumber = serialNumber
	return tbsCert
}

func (tbsCert *tbsCertificate) SetSignatureAlgorithm(algorithmIdentifier pkix.AlgorithmIdentifier)(*tbsCertificate) {
	tbsCert.SignatureAlgorithm = algorithmIdentifier
	return tbsCert
}

func (tbsCert *tbsCertificate) SetIssuer(issuer *pkix.Name)(*tbsCertificate) {
        asn1Issuer, err := asn1.Marshal(issuer.ToRDNSequence())
	if err != nil {
		panic(err)
	}
        tbsCert.Issuer = asn1.RawValue{FullBytes: asn1Issuer}
	return tbsCert
}

func (tbsCert *tbsCertificate) SetSubject(subject *pkix.Name)(*tbsCertificate) {
        asn1Subject, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		panic(err)
	}
        tbsCert.Subject = asn1.RawValue{FullBytes: asn1Subject}
	return tbsCert
}


func (tbsCert *tbsCertificate) SetValidity(notBefore *time.Time, notAfter *time.Time)(*tbsCertificate) {
	validity := validity{notBefore.UTC(), notAfter.UTC()}
        tbsCert.Validity = validity
	return tbsCert
}

func (tbsCert *tbsCertificate) SetCertificatePublicKey(privKey *rsa.PrivateKey, signatureAlgorithm SignatureAlgorithm) (*tbsCertificate) {
	pubKey := &privKey.PublicKey
	
	signatureAlgorithm, algorithmIdentifier, err := signingParamsForKey(privKey, signatureAlgorithm)
	if err != nil {
		panic(err)
	}

	tbsCert = tbsCert.SetSignatureAlgorithm(algorithmIdentifier)

	pubKeyBytes, pubKeyAlgorithm, err := marshalPublicKey(pubKey)
	if err != nil {
		panic(err)
	}
		
	encodedPublicKey := asn1.BitString{BitLength: len(pubKeyBytes) * 8, Bytes: pubKeyBytes} 
	tbsCert.PublicKey          = publicKeyInfo{nil, pubKeyAlgorithm, encodedPublicKey} 
	return tbsCert
}

func (tbsCert *tbsCertificate) SetSubjectUniqueId(subjectUniqueId []byte) (*tbsCertificate) {
	tbsCert.SubjectUniqueId = asn1.BitString{Bytes: subjectUniqueId, BitLength: len(subjectUniqueId)}
	return tbsCert
}

func (tbsCert *tbsCertificate) SetIssuerUniqueId(issuerUniqueId []byte) (*tbsCertificate) {
	tbsCert.UniqueId = asn1.BitString{Bytes: issuerUniqueId, BitLength: len(issuerUniqueId)}
	return tbsCert
}

func (tbsCert *tbsCertificate) SetExtensions(extensions ExtensionSlice) (*tbsCertificate) {
        tbsCert.Extensions = ([]pkix.Extension)(extensions)
	return tbsCert
}

func (tbsCert *tbsCertificate) GetExtensions() (extensions ExtensionSlice) {
        return((ExtensionSlice)(tbsCert.Extensions))
}

func SearchExtension(extensions ExtensionSlice, oid asn1.ObjectIdentifier) int {
	for index, extension := range (([]pkix.Extension)(extensions)) {
		if extension.Id.Equal(oid) {
			return index
		}
	}
        return -1 
}

func (extensions ExtensionSlice) SetBasicConstraintsExtension(critical bool, isCA bool, maxPathLen int, maxPathLenZero bool)(ExtensionSlice) {
	var err error
	var basicConstraintsExtension pkix.Extension
        var modifiedExtensions []pkix.Extension

	basicConstraintsExtension, err = NewMarshalBasicConstraints(critical, isCA, maxPathLen, maxPathLenZero)
	if err != nil {
		panic(err)
	}
        
	modifiedExtensions = append(([]pkix.Extension)(extensions), basicConstraintsExtension)
	return((ExtensionSlice)(modifiedExtensions))
}

func (extensions ExtensionSlice) UnsetBasicConstraintsExtension()(ExtensionSlice) {
        var modifiedExtensions []pkix.Extension

	index := SearchExtension(extensions, oidExtensionBasicConstraints)
	if index == -1 {
		panic(fmt.Errorf("No extension found"))
	}

	modifiedExtensions = append(([]pkix.Extension)(extensions[:index]), ([]pkix.Extension)(extensions[index + 1:])...)
        return((ExtensionSlice)(modifiedExtensions))
}


func (extensions ExtensionSlice) SetKeyUsageExtension(critical bool, keyUsage KeyUsage)(ExtensionSlice) {
	var err error
	var keyUsageExtension pkix.Extension
        var modifiedExtensions []pkix.Extension

	keyUsageExtension, err = NewMarshalKeyUsage(critical, keyUsage)
	if err != nil {
		panic(err)
	}

	modifiedExtensions = append(([]pkix.Extension)(extensions), keyUsageExtension)
	return((ExtensionSlice)(modifiedExtensions))
}

func (extensions ExtensionSlice) UnsetKeyUsageExtension()(ExtensionSlice) {
        var modifiedExtensions []pkix.Extension

	index := SearchExtension(extensions, oidExtensionKeyUsage)
	if index == -1 {
		panic(fmt.Errorf("No extension found"))
	}

	modifiedExtensions = append(([]pkix.Extension)(extensions[:index]), ([]pkix.Extension)(extensions[index + 1:])...)
        return((ExtensionSlice)(modifiedExtensions))
}

func (extensions ExtensionSlice) SetExtKeyUsageExtension(critical bool, extKeyUsageSlice []ExtKeyUsage)(ExtensionSlice) {
	var err error
	var extKeyUsageExtension pkix.Extension
        var modifiedExtensions []pkix.Extension

	extKeyUsageExtension, err = NewMarshalExtKeyUsage(critical, extKeyUsageSlice, nil)
	if err != nil {
		panic(err)
	}
	modifiedExtensions = append(([]pkix.Extension)(extensions), extKeyUsageExtension)
	return((ExtensionSlice)(modifiedExtensions))
}

func (extensions ExtensionSlice) UnsetExtKeyUsageExtension()(ExtensionSlice) {
        var modifiedExtensions []pkix.Extension

	index := SearchExtension(extensions, oidExtensionExtendedKeyUsage)
	if index == -1 {
		panic(fmt.Errorf("No extension found"))
	}

	modifiedExtensions = append(([]pkix.Extension)(extensions[:index]), ([]pkix.Extension)(extensions[index + 1:])...)
        return((ExtensionSlice)(modifiedExtensions))
}


func (extensions ExtensionSlice) SetAKIDExtension(critical bool, authorityKeyId []byte)(ExtensionSlice) {
	var err error
	var akidExtension pkix.Extension
        var modifiedExtensions []pkix.Extension

	akidExtension, err = NewMarshalAKID(critical, authorityKeyId)
	if err != nil {
		panic(err)
	}
	modifiedExtensions = append(([]pkix.Extension)(extensions), akidExtension)
	return((ExtensionSlice)(modifiedExtensions))
}

func (extensions ExtensionSlice) SetAKIDExtensionFromKey(critical bool, privKey *rsa.PrivateKey)(ExtensionSlice) {
	authorityKeyId := GenerateKeyIdFromKey(privKey)
	return(extensions.SetAKIDExtension(critical, authorityKeyId))
}

func (extensions ExtensionSlice) UnsetAKIDExtension()(ExtensionSlice) {
        var modifiedExtensions []pkix.Extension
	
	index := SearchExtension(extensions, oidExtensionAuthorityKeyId)
	if index == -1 {
		panic(fmt.Errorf("No extension found"))
	}

	modifiedExtensions = append(([]pkix.Extension)(extensions[:index]), ([]pkix.Extension)(extensions[index + 1:])...)
        return((ExtensionSlice)(modifiedExtensions))
}

func (extensions ExtensionSlice) SetSKIDExtension(critical bool, subjectKeyId []byte)(ExtensionSlice) {
	var err error
        var skidExtension pkix.Extension
        var modifiedExtensions []pkix.Extension

	skidExtension, err = NewMarshalSKID(critical, subjectKeyId)
	if err != nil {
		panic(err)
	}
	modifiedExtensions = append(([]pkix.Extension)(extensions), skidExtension)
	return((ExtensionSlice)(modifiedExtensions))
}

func (extensions ExtensionSlice) SetSKIDExtensionFromKey(critical bool, privKey *rsa.PrivateKey)(ExtensionSlice) {
	subjectKeyId := GenerateKeyIdFromKey(privKey)
	return(extensions.SetSKIDExtension(critical, subjectKeyId))
}

func (extensions ExtensionSlice) UnsetSKIDExtension()(ExtensionSlice) {
        var modifiedExtensions []pkix.Extension

	index := SearchExtension(extensions, oidExtensionSubjectKeyId)
	if index == -1 {
		panic(fmt.Errorf("No extension found"))
	}

	modifiedExtensions = append(([]pkix.Extension)(extensions[:index]), ([]pkix.Extension)(extensions[index + 1:])...)
        return((ExtensionSlice)(modifiedExtensions))
}

func (extensions ExtensionSlice) SetSANExtension(critical bool, DNSNames []string, EmailAddresses []string, IPAddresses []net.IP, URIs []*url.URL) (ExtensionSlice) {
	var err error
        var sanExtension pkix.Extension
        var modifiedExtensions []pkix.Extension

	sanExtension, err = NewMarshalSAN(critical, DNSNames, EmailAddresses, IPAddresses, URIs)
	if err != nil {
		panic(err)
	}
	modifiedExtensions = append(([]pkix.Extension)(extensions), sanExtension)
	return((ExtensionSlice)(modifiedExtensions))
}

func (extensions ExtensionSlice) UnsetSANExtension()(ExtensionSlice) {
        var modifiedExtensions []pkix.Extension

	index := SearchExtension(extensions, oidExtensionSubjectAltName)
	if index == -1 {
		panic(fmt.Errorf("No extension found"))
	}

	modifiedExtensions = append(([]pkix.Extension)(extensions[:index]), ([]pkix.Extension)(extensions[index + 1:])...)
        return((ExtensionSlice)(modifiedExtensions))
}

/*********************************** BADCERT INTERFACE FOR APPLICATIONS ************************************************************/

func (badcert *BadCertificate) SetVersion(x509Version X509Version)(*BadCertificate) {
	badcert.tbscert = badcert.tbscert.SetVersion(x509Version)
	return badcert
}

func (badcert *BadCertificate) SetVersion1()(*BadCertificate) {
	badcert = badcert.SetVersion(X509Version1)
	return badcert
}

func (badcert *BadCertificate) SetVersion2()(*BadCertificate) {
	badcert = badcert.SetVersion(X509Version2)
	return badcert
}

func (badcert *BadCertificate) SetVersion3()(*BadCertificate) {
	badcert = badcert.SetVersion(X509Version3)
	return badcert
}

func (badcert *BadCertificate) SetVersionInvalid()(*BadCertificate) {
	badcert = badcert.SetVersion(X509VersionInvalid)
	return badcert
}

func (badcert *BadCertificate) SetSerialNumber(serialNumber *big.Int)(*BadCertificate) {
	badcert.tbscert = badcert.tbscert.SetSerialNumber(serialNumber)
	return badcert
}

func (badcert *BadCertificate) SetSerialNumberNegative()(*BadCertificate) {
	badcert = badcert.SetSerialNumber(big.NewInt(-1))
	return badcert
}

func (badcert *BadCertificate) SetSerialNumber20Bytes()(*BadCertificate) {
	serialNumberBytes, err := GetRandomBytes(20)
	if err != nil {
		panic(err)
	}
        	
	serialNumber := new(big.Int).SetBytes(serialNumberBytes) 
	badcert = badcert.SetSerialNumber(serialNumber)
	return badcert
}

       
func (badcert *BadCertificate) SetSerialNumberGT20Bytes()(*BadCertificate) {
        serialNumberBytes, err := GetRandomBytes(40)
	if err != nil {
		panic(err)
	}

	serialNumber := new(big.Int).SetBytes(serialNumberBytes)
	
	badcert = badcert.SetSerialNumber(serialNumber)
	return badcert
}

func (badcert *BadCertificate) SetIssuer(issuer *pkix.Name)(*BadCertificate) {
        badcert.tbscert = badcert.tbscert.SetIssuer(issuer)
	return badcert
}

func (badcert *BadCertificate) SetSubject(subject *pkix.Name)(*BadCertificate) {
        badcert.tbscert = badcert.tbscert.SetSubject(subject)
	return badcert
}


func (badcert *BadCertificate) SetValidity(notBefore *time.Time, notAfter *time.Time)(*BadCertificate) {
	badcert.tbscert = badcert.tbscert.SetValidity(notBefore, notAfter)
	return badcert
}

func (badcert *BadCertificate) SetSubjectUniqueId(subjectUniqueId []byte)(*BadCertificate) {
	badcert.tbscert = badcert.tbscert.SetSubjectUniqueId(subjectUniqueId)
	return badcert
}

func (badcert *BadCertificate) SetSubjectUniqueIdRandom()(*BadCertificate) {
	randomBytes, err := GetRandomBytes(20)
	if err != nil {
		panic(err)
	}

	badcert.tbscert = badcert.tbscert.SetSubjectUniqueId(randomBytes)
	return badcert
}

func (badcert *BadCertificate) SetIssuerUniqueId(issuerUniqueId []byte)(*BadCertificate) {
	badcert.tbscert = badcert.tbscert.SetIssuerUniqueId(issuerUniqueId)
	return badcert
}

func (badcert *BadCertificate) SetIssuerUniqueIdRandom()(*BadCertificate) {
	randomBytes, err := GetRandomBytes(20)
	if err != nil {
		panic(err)
	}

	badcert.tbscert = badcert.tbscert.SetIssuerUniqueId(randomBytes)
	return badcert
}

func (badcert *BadCertificate) SetExtensions(extensions ExtensionSlice) (*BadCertificate) {
        badcert.tbscert = badcert.tbscert.SetExtensions(extensions)
	return badcert
}

func (badcert *BadCertificate) GetExtensions() (extensions ExtensionSlice) {
        return(badcert.tbscert.GetExtensions())
}

func (badcert *BadCertificate) SetCertificatePublicKey(privKey *rsa.PrivateKey, signatureAlgorithm SignatureAlgorithm) (*BadCertificate) {
	badcert.tbscert = badcert.tbscert.SetCertificatePublicKey(privKey, signatureAlgorithm)
	return badcert
}


func (badcert *BadCertificate) SignTBS(privKey *rsa.PrivateKey, signatureAlgorithm SignatureAlgorithm) (*BadCertificate) {
        signatureAlgorithm, algorithmIdentifier, err := signingParamsForKey(privKey, signatureAlgorithm)
	if err != nil {
		panic(err)
	}

	tbsCertContents, err := asn1.Marshal(*(badcert.tbscert))
	if err != nil {
		panic(err)
	}
        badcert.tbscert.Raw = tbsCertContents

	signature, err := signTBS(tbsCertContents, privKey, signatureAlgorithm, rand.Reader)
	if err != nil {
		panic(err)
	}
        
	certificateBytesInDer, err := asn1.Marshal(certificate{
		                                  TBSCertificate:     *(badcert.tbscert),
		                                  SignatureAlgorithm: algorithmIdentifier,
		                                  SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	                                       })
	if err != nil {
		panic(err)
	}

	badcert.x509Certificate, err = ParseCertificate(certificateBytesInDer)
        if err != nil {
		panic(err)
	}

	return badcert
}

//NOTE: This doesn't verify exactly what we want. In our case, we have created a chain and we are aware of the exact path from leaf to root
//We need to make sure that signatures are valid and the chain has been built succesfully.
//But the method below will say its valid if atleast one path exists from leaf to root, and it can be any path
//It doesn't need to be the exact order we were trying to build
//But since the assumption is that we are the ones building the cert, it seems good enough for time being
func VerifyCertificateChain(badCertChain []*BadCertificate) {
	if (len(badCertChain) < 1) {
	        panic(fmt.Errorf("Invalid cert chain"))
	}

        leafCertificate := badCertChain[0].x509Certificate
        
	intermediateCertPool := NewCertPool()
	for _, certificate := range badCertChain[1 : len(badCertChain) - 1] { 
		intermediateCertPool.AddCert(certificate.x509Certificate)
        }

	rootCertPool         := NewCertPool()
	rootCACertificate    := badCertChain[len(badCertChain) - 1].x509Certificate
	rootCertPool.AddCert(rootCACertificate)

        opts := VerifyOptions{
                  Intermediates: intermediateCertPool,
                  Roots:         rootCertPool,
                }

        _, err := leafCertificate.Verify(opts)
        if err != nil {
                panic(err)
        }
}


func (badcert *BadCertificate) WriteCertificateDer(dest io.Writer) {
	_, err := dest.Write(badcert.x509Certificate.Raw)
        if err != nil {
                panic(err)
        }
}

func (badcert *BadCertificate) WriteCertificatePem(dest io.Writer) { 
	pemBlock := &pem.Block{
                        Type:  "CERTIFICATE",
                        Bytes: badcert.x509Certificate.Raw,
                    }

	err := pem.Encode(dest, pemBlock)
	if err != nil {
		panic(err)
	}
}


func WriteCertificateChainPem(badCertChain []*BadCertificate, dest io.Writer) { 
	for _, badcert := range badCertChain {

	    pemBlock := &pem.Block{
                            Type:  "CERTIFICATE",
                            Bytes: badcert.x509Certificate.Raw,
                        }

	    err := pem.Encode(dest, pemBlock)
	    if err != nil {
	        	panic(err)
	    }
        }
}



