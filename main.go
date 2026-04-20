package main

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/hesusruiz/testcertgen/filesigner"
	"github.com/hesusruiz/testcertgen/x509util"
	"github.com/hesusruiz/vcutils/yaml"
	"github.com/urfave/cli/v2"
)

const (
	defaultIssuerOrigin     = "issuersec.mycredential.eu"
	defaultIssuerQueryPath  = "/apisigner/retrievecredentials"
	defaultIssuerUpdatePath = "/apisigner/updatesignedcredential"
)

func main() {

	version := "v0.10.4"

	// Get the version control info, to embed in the program version
	rtinfo, ok := debug.ReadBuildInfo()
	if ok {
		buildSettings := rtinfo.Settings
		for _, setting := range buildSettings {
			if setting.Key == "vcs.time" {
				version = version + ", built on " + setting.Value
			}
			if setting.Key == "vcs.revision" {
				version = version + ", revision " + setting.Value
			}
		}

	}

	usageText := `certgen [global options] [command [command options]]

	The program generates test eIDAS certificates for testing purposes, using the commands 'createca' and 'create'.`

	app := &cli.App{
		Name:     "certgen",
		Version:  version,
		Compiled: time.Now(),
		Authors: []*cli.Author{
			{
				Name:  "Jesus Ruiz",
				Email: "hesus.ruiz@gmail.com",
			},
		},
		Usage:     "generate eIDAS test certificates",
		UsageText: usageText,

		Commands: []*cli.Command{

			{
				Name:        "createca",
				Aliases:     []string{"ca"},
				Usage:       "create a test eIDAS CA certificate as the root certificate",
				Description: "creates a test eIDAs CA certificate from the data in a YAML file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Required: true,
						Aliases:  []string{"p"},
						EnvVars:  []string{"CERTGEN_PASSWORD"},
						Usage:    "the password to use for encrypting the resulting certificate file",
					},
					&cli.StringFlag{
						Name:    "subject",
						Aliases: []string{"s"},
						Usage:   "input CA certificate data in YAML format `FILE`",
						Value:   "ca_certificate.yaml",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "write CA certificate to `FILE` (do not include the extension, it will be added)",
						Value:   "ca_certificate",
					},
				},
				Action: createCACert,
			},

			{
				Name:        "create",
				Aliases:     []string{"c"},
				Usage:       "create a leaf test eIDAS certificate (requires a CA to be created before)",
				Description: "creates a leaf test eIDAs certificate from the data in a YAML file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Required: true,
						Aliases:  []string{"p"},
						EnvVars:  []string{"CERTGEN_PASSWORD"},
						Usage:    "the password to use for encrypting the resulting certificate file",
					},
					&cli.StringFlag{
						Name:    "cacert",
						Aliases: []string{"ca"},
						Usage:   "CA certificate file in PKCS12 format",
						Value:   "ca_certificate.p12",
					},
					&cli.StringFlag{
						Name:    "subject",
						Aliases: []string{"s"},
						Usage:   "subject input data `FILE` in YAML format",
						Value:   "subject.yaml",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "write certificate data to `FILE` (do not include the extension, it will be added)",
						Value:   "eidascert",
					},
				},
				Action: createCert,
			},

			{
				Name:        "display",
				Aliases:     []string{"d"},
				Usage:       "display an eIDAS certificate",
				Description: "displays an eIDAs certificate from a PEM file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "password",
						Aliases: []string{"p"},
						EnvVars: []string{"CERTGEN_PASSWORD"},
						Usage:   "the password to use for decrypting the certificate file",
					},
					&cli.StringFlag{
						Name:     "input",
						Aliases:  []string{"i"},
						Required: true,
						Usage:    "the name of the `FILE`",
					},
				},
				Action: displayCert,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println("Error:", err)
	}

}

func createCACert(cCtx *cli.Context) error {

	//*******************************
	// Create the CA certificate
	//*******************************

	outputName := cCtx.String("output")
	if outputName == "" {
		outputName = "ca_certificate"
	}
	caFileName := outputName + ".p12"

	// Read the data to include in the CA Certificate
	subjectFileName := cCtx.String("subject")
	if subjectFileName == "" {
		subjectFileName = "eidascert.yaml"
	}
	cd, err := readCertData(subjectFileName)
	if err != nil {
		fmt.Println("file", subjectFileName, "not found, using default values")
		cd = yaml.New("")
	}

	subAttrs := x509util.ELSIName{
		OrganizationIdentifier: cd.String("OrganizationIdentifier", "VATES-55663399H"),
		Organization:           cd.String("Organization", "DOME Foundation"),
		Country:                cd.String("Country", "ES"),
	}

	// Use the default values for the key parameters (RSA, 2048 bits)
	keyparams := x509util.KeyParams{}

	// Create the self-signed CA certificate
	privateCAKey, newCACert, err := x509util.NewCAELSICertificateRaw(subAttrs, keyparams)
	if err != nil {
		return err
	}

	// Save to a file in pkcs12 format, including the private key and the certificate
	pass := cCtx.String("password")
	err = filesigner.SaveCertificateToPkcs12File(caFileName, privateCAKey, newCACert, pass)
	if err != nil {
		return err
	}

	// Save the certificate to a file in PEM format
	pemFileName := outputName + ".pem"
	pemFile, err := os.OpenFile(pemFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", pemFileName, err)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCACert.Raw,
	}

	if err := pem.Encode(pemFile, block); err != nil {
		return err
	}

	if err := pemFile.Close(); err != nil {
		return err
	}

	// //*******************************
	// // Create the leaf certificate
	// //*******************************

	// subjectFileName = "cert.yaml"
	// cd, err = readCertData(subjectFileName)
	// if err != nil {
	// 	fmt.Println("file", subjectFileName, "not found, using default values")
	// 	cd = yaml.New("")
	// }

	// subAttrs = x509util.ELSIName{
	// 	OrganizationIdentifier: cd.String("OrganizationIdentifier", "VATES-55663399H"),
	// 	Organization:           cd.String("Organization", "DOME Marketplace"),
	// 	CommonName:             cd.String("CommonName", "RUIZ JESUS - 12345678V"),
	// 	GivenName:              cd.String("GivenName", "JESUS"),
	// 	Surname:                cd.String("Surname", "RUIZ"),
	// 	EmailAddress:           cd.String("EmailAddress", "jesus@alastria.io"),
	// 	SerialNumber:           cd.String("SerialNumber", "IDCES-12345678V"),
	// 	Country:                cd.String("Country", "ES"),
	// }
	// fmt.Println(subAttrs)

	// // Create the entity certificate, signed by the CA certificate
	// privateKey, newCert, err := x509util.NewELSICertificateRaw(
	// 	newCACert,
	// 	privateCAKey,
	// 	subAttrs,
	// 	keyparams)
	// if err != nil {
	// 	return err
	// }

	// // Save to a file in pkcs12 format, including the private key and the certificate
	// outputFileName = "cert.p12"
	// err = filesigner.SaveCertificateToPkcs12File(outputFileName, privateKey, newCert, pass)
	// if err != nil {
	// 	return err
	// }

	fmt.Printf("Certificate created in: %s\n", caFileName)
	fmt.Printf("Certificate created in: %s\n", pemFileName)
	return nil
}

func createCert(cCtx *cli.Context) error {

	//*******************************
	// Retrieve the CA certificate
	//*******************************

	// Read the data to include in the CA Certificate
	caCertFileName := cCtx.String("cacert")
	pass := cCtx.String("password")

	privateCAKey, caCert, _, err := filesigner.GetPrivateKeyFromFile(caCertFileName, pass)
	if err != nil {
		return err
	}

	//*******************************
	// Create the leaf certificate
	//*******************************

	// Use the default values for the key parameters (RSA, 2048 bits)
	keyparams := x509util.KeyParams{}

	subjectFileName := cCtx.String("subject")
	cd, err := readCertData(subjectFileName)
	if err != nil {
		fmt.Println("file", subjectFileName, "not found, using default values")
		cd = yaml.New("")
	}

	subAttrs := x509util.ELSIName{
		OrganizationIdentifier: cd.String("OrganizationIdentifier", "VATES-22222222J"),
		Organization:           cd.String("Organization", "Clean Air Inc"),
		CommonName:             cd.String("CommonName", "RUIZ JESUS - 12345678V"),
		GivenName:              cd.String("GivenName", "JESUS"),
		Surname:                cd.String("Surname", "RUIZ"),
		EmailAddress:           cd.String("EmailAddress", "jesus@alastria.io"),
		SerialNumber:           cd.String("SerialNumber", "IDCES-12345678V"),
		Country:                cd.String("Country", "ES"),
	}
	fmt.Println(subAttrs)

	// Create the entity certificate, signed by the CA certificate
	privateKey, newCert, err := x509util.NewELSICertificateRaw(
		caCert,
		privateCAKey,
		subAttrs,
		keyparams)
	if err != nil {
		return err
	}

	// Save to a file in pkcs12 format, including the private key and the certificate
	outputBaseName := cCtx.String("output")
	outputFileNameP12 := outputBaseName + ".p12"

	err = filesigner.SaveCertificateToPkcs12File(outputFileNameP12, privateKey, newCert, pass)
	if err != nil {
		return err
	}

	// Save the certificate to a file in PEM format
	pemFileName := outputBaseName + ".pem"
	pemFile, err := os.OpenFile(pemFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", pemFileName, err)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCert.Raw,
	}

	if err := pem.Encode(pemFile, block); err != nil {
		return err
	}

	if err := pemFile.Close(); err != nil {
		return err
	}

	fmt.Printf("Certificate created in: %s\n", outputFileNameP12)
	fmt.Printf("Certificate created in: %s\n", pemFileName)

	return nil
}

func displayCert(cCtx *cli.Context) error {

	// Save to a file in pkcs12 format, including the private key and the certificate
	inputFileName := cCtx.String("input")

	// Determine the extension of the file
	extension := filepath.Ext(inputFileName)
	if extension == "" {
		return fmt.Errorf("input file must have an extension")
	}
	if extension != ".p12" && extension != ".pem" {
		return fmt.Errorf("input file must be a PKCS#12 or PEM file")
	}

	if extension == ".p12" {
		// Read the private key and the certificate from the PKCS#12 file
		_, cert, _, err := filesigner.GetPrivateKeyFromFile(inputFileName, cCtx.String("password"))
		if err != nil {
			return err
		}

		_, issuer, subject, err := x509util.ParseEIDASCertDer(cert.Raw)
		if err != nil {
			return err
		}

		fmt.Println("Issuer:")
		fmt.Printf("%s\n\n", issuer)
		fmt.Println("Subject:")
		fmt.Printf("%s\n", subject)
		return nil
	}

	pemData, err := os.ReadFile(inputFileName)
	if err != nil {
		return err
	}

	_, issuer, subject, err := x509util.ParseCertificateFromPEM(pemData)
	if err != nil {
		return err
	}

	fmt.Println("Issuer:")
	fmt.Printf("%s\n\n", issuer)
	fmt.Println("Subject:")
	fmt.Printf("%s\n", subject)

	return nil
}

// readConfiguration reads a YAML file and creates an easy-to navigate structure
func readCertData(certDataFile string) (*yaml.YAML, error) {
	var cfg *yaml.YAML
	var err error

	cfg, err = yaml.ParseYamlFile(certDataFile)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
