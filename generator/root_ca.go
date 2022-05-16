package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/cjlapao/common-go/helper"
	"github.com/cjlapao/tls-certificate-generator-go/entities"
	"github.com/cjlapao/tls-certificate-generator-go/installer"
)

type X509RootCertificate struct {
	Name                     string
	PrivateKey               *rsa.PrivateKey
	Certificate              *x509.Certificate
	Configuration            entities.CertificateConfig
	IntermidiateCertificates []entities.RootCertificate
	Pem                      []byte
	Csr                      []byte
	PrivateKeyPem            []byte
}

func (rootCA *X509RootCertificate) baseFileName() string {
	baseFileName := strings.ReplaceAll(rootCA.Name, " ", "_")
	if baseFileName == "" {
		baseFileName = strings.ReplaceAll(rootCA.Configuration.CommonName, " ", "_")
	}
	return baseFileName
}

func (rootCA *X509RootCertificate) CertificateFileName() string {
	certificateFileName := "rootca_" + rootCA.baseFileName() + ".crt"
	return certificateFileName
}

func (rootCA *X509RootCertificate) PrivateKeyFileName() string {
	privateKeyFileName := "rootca_" + rootCA.baseFileName() + ".key"
	return privateKeyFileName
}

func (rootCA *X509RootCertificate) CertificateRequestFileName() string {
	certificateRequestFileName := "rootca_" + rootCA.baseFileName() + ".csr"
	return certificateRequestFileName
}

func (rootCA *X509RootCertificate) Generate(config entities.CertificateConfig) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	logger.Debug("Starting to generate root certificate")

	subject := pkix.Name{
		Country:            []string{config.Country},
		Organization:       []string{config.Organization},
		OrganizationalUnit: []string{config.OrganizationalUnit},
		Province:           []string{config.State},
		Locality:           []string{config.City},
		CommonName:         config.CommonName,
	}

	if config.AdminEmailAddress != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(config.AdminEmailAddress),
				},
			},
		}
	}

	rootCertificateTemplate := x509.Certificate{
		SerialNumber: generateSerialNumber(),
		Subject:      subject,
		NotBefore:    time.Now().Add(-10 * time.Second),
		NotAfter:     time.Now().AddDate(config.ExpiresInYears, 0, 0),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageIPSECEndSystem,
			x509.ExtKeyUsageIPSECTunnel,
			x509.ExtKeyUsageIPSECUser,
			x509.ExtKeyUsageOCSPSigning,
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageTimeStamping,
		},
		IsCA:                  true,
		MaxPathLen:            2,
		SignatureAlgorithm:    config.SignatureAlgorithm.ToX509SignatureAlgorithm(),
		DNSNames:              config.FQDNs,
		BasicConstraintsValid: true,
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			policy5,
			policy6,
			rootPolicy3,
			rootPolicy4,
		},
	}

	if config.FQDNs != nil && len(config.FQDNs) > 0 {
		rootCertificateTemplate.DNSNames = config.FQDNs
	}

	if config.IpAddresses != nil && len(config.IpAddresses) > 0 {
		for _, ip := range config.IpAddresses {
			rootCertificateTemplate.IPAddresses = append(rootCertificateTemplate.IPAddresses, net.ParseIP(ip))
		}
	}

	logger.Debug("Starting to generate private key")
	priv, err := rsa.GenerateKey(rand.Reader, int(config.KeySize))
	if err != nil {
		panic(err)
	}

	subjectKeyId, err := generateSubjectKeyId(priv)
	if err == nil {
		rootCertificateTemplate.SubjectKeyId = subjectKeyId
		rootCertificateTemplate.AuthorityKeyId = rootCertificateTemplate.SubjectKeyId
	}

	rootCertificate, rootPemCertificate := generateCertificate(&rootCertificateTemplate, &rootCertificateTemplate, &priv.PublicKey, priv)
	csr, err := generateCertificateRequest(rootCertificate, priv)

	rootCA.PrivateKey = priv
	rootCA.Certificate = rootCertificate
	rootCA.Configuration = config
	rootCA.Pem = rootPemCertificate
	rootCA.Csr = csr
	rootCA.PrivateKeyPem = generatePemPrivateKey(priv)

	return rootCertificate, rootPemCertificate, priv
}

func (rootCA *X509RootCertificate) LoadFromFile() error {
	return nil
}

func (rootCA *X509RootCertificate) Parse(certificate string, privateKey string) error {
	if certificate != "" {
		certBlock, _ := pem.Decode([]byte(certificate))
		if certBlock == nil {
			err := errors.New("no valid certificate block found")
			logger.Error("found error while parsing  pem certificate block, err %v", err.Error())
			return err
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			logger.Error("found error while parsing certificate block, err %v", err.Error())
			return err
		}

		rootCA.Certificate = cert
		rootCA.Pem = []byte(certificate)
	}

	if privateKey != "" {
		privBlock, _ := pem.Decode([]byte(privateKey))
		if privBlock == nil {
			err := errors.New("no valid private key block found")
			logger.Error("found error while parsing  pem private key block, err %v", err.Error())
			return err
		}
		priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			logger.Error("found error while parsing private key block, err %v", err.Error())
			return err
		}

		rootCA.PrivateKey = priv
		rootCA.PrivateKeyPem = []byte(privateKey)
	}
	return nil
}

func (rootCA *X509RootCertificate) SaveToFile() error {
	logger.Debug("Exporting Certificate")
	if helper.FileExists(rootCA.CertificateFileName()) {
		helper.DeleteFile(rootCA.CertificateFileName())
	}

	helper.WriteToFile(string(rootCA.Pem), rootCA.CertificateFileName())

	logger.Debug("Exporting Private Key")
	if helper.FileExists(rootCA.PrivateKeyFileName()) {
		helper.DeleteFile(rootCA.PrivateKeyFileName())
	}

	helper.WriteToFile(string(rootCA.PrivateKeyPem), rootCA.PrivateKeyFileName())

	logger.Debug("Exporting CSR")
	if helper.FileExists(rootCA.CertificateRequestFileName()) {
		helper.DeleteFile(rootCA.CertificateRequestFileName())
	}

	helper.WriteToFile(string(rootCA.Csr), rootCA.CertificateRequestFileName())
	return nil
}

func (rootCA *X509RootCertificate) Install() error {
	instalSvc := installer.Installer{}
	instalSvc.InstallCertificate(rootCA.CertificateFileName(), installer.RootStore)
	return nil
}
