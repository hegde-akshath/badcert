package main

import (
	"os"
	"fmt"
	"errors"
	"github.com/hegde-akshath/badcert"
	"github.com/hegde-akshath/badcert/pkix"
        "crypto"
	"encoding/pem"
	"encoding/asn1"
	"strings"
	"path/filepath"
	"net"
        "net/url"
	"crypto/rand"
        "math/big"
)

//TODO: Need to organize CSR data and operations correctly. Creating this struct as I'm short on time
type CertificateRequestFields struct {
	Subject        pkix.Name
	PubKey         crypto.PublicKey
	KeyUsage       *badcert.KeyUsage
	IsSANSet       bool
	DNSNames       []string
        EmailAddresses []string
        IPAddresses    []net.IP
        URIs           []*url.URL
}

var CertRequestKeyUsageExtNotPresentError = errors.New("Key Usage extenion was not present in certificate request")


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

func GetRequestedKeyUsageFromCSR(certificateRequest *badcert.CertificateRequest) (*badcert.KeyUsage) {
        var keyUsageExtension *pkix.Extension       
	var keyUsageBitString asn1.BitString
        var keyUsage badcert.KeyUsage
        
	keyUsageExtension = badcert.ExtensionSlice(certificateRequest.Extensions).GetKeyUsageExtension()
	if keyUsageExtension == nil {
		return nil
	}

	_, err := asn1.Unmarshal((*keyUsageExtension).Value, &keyUsageBitString)
	if err != nil {
		panic(err)
	}
        
	//This would mean key usage extension was present, but the value was empty
	//This may be useful when we want to generate bad certs ourselves. But in a certificate request I dont see any use for not failing here at the moment
	if len(keyUsageBitString.Bytes) < 0 {
		panic(fmt.Errorf("Invalid Key usage value"))
	}
        
	//All of the defined key usage bits are present in the first bit.
	keyUsage = badcert.KeyUsage(keyUsageBitString.Bytes[0])
        return &keyUsage
}

func ExtractCertRequestFields(certRequest *badcert.CertificateRequest) (*CertificateRequestFields) {
       var certRequestFields CertificateRequestFields
       var sanExtension *pkix.Extension

       certRequestFields.Subject        = certRequest.Subject
       certRequestFields.PubKey         = certRequest.PublicKey
       certRequestFields.DNSNames       = certRequest.DNSNames
       certRequestFields.EmailAddresses = certRequest.EmailAddresses
       certRequestFields.IPAddresses    = certRequest.IPAddresses
       certRequestFields.URIs           = certRequest.URIs

       certRequestFields.KeyUsage = GetRequestedKeyUsageFromCSR(certRequest)
       if certRequestFields.KeyUsage != nil {
           fmt.Printf("Requested key usage = %d", *certRequestFields.KeyUsage)
       }

       sanExtension = badcert.ExtensionSlice(certRequest.Extensions).GetSANExtension()
       if sanExtension == nil {
	       certRequestFields.IsSANSet = false
       } else {
	       certRequestFields.IsSANSet = true
       }

       return &certRequestFields
}

func BuildLeafCertFromCertRequest(certRequestFields *CertificateRequestFields, issuer *pkix.Name, akid []byte) (*badcert.BadCertificate) {
       //TODO: We need to maintain the issued CRL number and revocation info(and other configuration, so we can use from there)
       //NOTE: Not using goCA or other standard tools as the intention here is the ability to generate bad certificates blocked by crypto/x509
       serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
       if err != nil {
                panic(err)
       }

	badLeafRecipe := BuildDefaultLeafRecipe().SetSubject(&certRequestFields.Subject).SetIssuer(issuer).SetSerialNumber(serialNumber).SetCertificatePublicKey(certRequestFields.PubKey)
	modifiedLeafExtensions := badLeafRecipe.GetExtensions().UnsetAKIDExtension().UnsetSKIDExtension().UnsetKeyUsageExtension().UnsetExtKeyUsageExtension().UnsetSANExtension()

	modifiedLeafExtensions = modifiedLeafExtensions.SetAKIDExtension(false, akid)
	modifiedLeafExtensions = modifiedLeafExtensions.SetSKIDExtensionFromKey(false, certRequestFields.PubKey)
        
	if certRequestFields.KeyUsage != nil {
		modifiedLeafExtensions = modifiedLeafExtensions.SetKeyUsageExtension(false, *certRequestFields.KeyUsage)
        }
        
	if certRequestFields.IsSANSet == true {
	        modifiedLeafExtensions = modifiedLeafExtensions.SetSANExtension(false, certRequestFields.DNSNames, certRequestFields.EmailAddresses, certRequestFields.IPAddresses, certRequestFields.URIs)
	}

	badLeafRecipe.SetExtensions(modifiedLeafExtensions)
	return badLeafRecipe
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
