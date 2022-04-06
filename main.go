package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cjlapao/common-go/execution_context"
	"github.com/cjlapao/common-go/helper"
	"github.com/cjlapao/common-go/log"
	"github.com/cjlapao/common-go/version"
	"github.com/cjlapao/tls-certificate-generator-go/config"
	"github.com/cjlapao/tls-certificate-generator-go/generator"
	"github.com/cjlapao/tls-certificate-generator-go/startup"
)

var ctx = execution_context.Get()
var logger = log.Get()
var configSvc = execution_context.Get().Configuration

func main() {
	ctx.Services.Version.Major = 0
	ctx.Services.Version.Minor = 0
	ctx.Services.Version.Build = 0
	ctx.Services.Version.Rev = 1
	ctx.Services.Version.Name = "TLS Certificate Generator"
	ctx.Services.Version.Author = "Carlos Lapao"
	ctx.Services.Version.License = "MIT"
	getVersion := helper.GetFlagSwitch("version", false)
	if getVersion {
		format := helper.GetFlagValue("o", "json")
		switch strings.ToLower(format) {
		case "json":
			fmt.Println(ctx.Services.Version.PrintVersion(int(version.JSON)))
		case "yaml":
			fmt.Println(ctx.Services.Version.PrintVersion(int(version.JSON)))
		default:
			fmt.Println("Please choose a valid format, this can be either json or yaml")
		}
		os.Exit(0)
	}

	ctx.Services.Version.PrintAnsiHeader()

	configFile := helper.GetFlagValue("config", "")
	if configFile != "" {
		logger.Command("Loading configuration from " + configFile)
		configSvc.LoadFromFile(configFile)
	}

	defer func() {
	}()

	startup.Init()

	generateCertificates()
}

func generateCertificates() {
	config := config.Init()
	config.ReadFromFile()

	fmt.Println("|- Root")
	needsSaving := false
	if config.Root != nil && len(config.Root) > 0 {
		for _, rootCert := range config.Root {
			x509RootCert := generator.X509RootCertificate{}
			x509RootCert.Name = rootCert.Name
			if rootCert.PemCertificate == "" {
				x509RootCert.Generate(*rootCert.Config)
				rootCert.PemCertificate = string(x509RootCert.Pem)
				rootCert.PemPrivateKey = string(x509RootCert.PrivateKeyPem)
				needsSaving = true
			} else {
				x509RootCert.Configuration = *rootCert.Config
				x509RootCert.Parse(rootCert.PemCertificate, rootCert.PemPrivateKey)
			}

			fmt.Println("|  |- " + rootCert.Name)
			if config.OutputToFile {
				x509RootCert.SaveToFile()
			}
			x509RootCert.Install()
			for _, intermediateCA := range rootCert.IntermediateCertificates {
				x509IntermediateCert := generator.X509IntermediateCertificate{}
				x509IntermediateCert.Name = intermediateCA.Name
				if intermediateCA.PemCertificate == "" {
					x509IntermediateCert.Generate(&x509RootCert, *intermediateCA.Config)
					intermediateCA.PemCertificate = string(x509IntermediateCert.Pem)
					intermediateCA.PemPrivateKey = string(x509IntermediateCert.PrivateKeyPem)
					needsSaving = true
				} else {
					x509IntermediateCert.Configuration = *intermediateCA.Config
					x509IntermediateCert.Parse(intermediateCA.PemCertificate, intermediateCA.PemPrivateKey)
				}
				fmt.Println("|  |  |- " + intermediateCA.Name)
				if config.OutputToFile {
					x509IntermediateCert.SaveToFile()
				}
				x509IntermediateCert.Install()

				for _, serverCert := range intermediateCA.Certificates {
					x509ServerCert := generator.X509ServerCertificate{}
					x509ServerCert.Name = serverCert.Name
					if serverCert.PemCertificate == "" {
						x509ServerCert.Generate(&x509IntermediateCert, *serverCert.Config)
						serverCert.PemCertificate = string(x509ServerCert.Pem)
						serverCert.PemPrivateKey = string(x509ServerCert.PrivateKeyPem)
						needsSaving = true
					} else {
						x509ServerCert.Configuration = *serverCert.Config
						x509ServerCert.Parse(serverCert.PemCertificate, serverCert.PemPrivateKey)
					}
					fmt.Println("|  |  |  |- " + serverCert.Name)
					if config.OutputToFile {
						x509ServerCert.SaveToFile()
					}
					x509ServerCert.Install()
				}
			}
		}
	}
	if needsSaving {
		config.SaveToFile()
	}

}
