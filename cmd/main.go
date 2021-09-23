package main

import (
	"crypto/x509/pkix"
	"flag"
	log "github.com/sirupsen/logrus"
	"github.com/tomcat-bit/ifritcert"
	"os"
)

var DefaultPermission = os.FileMode(0750)

type App struct {
	ca          *ifritcert.Ca
	cryptoUnits []*ifritcert.CryptoUnit
}

func main() {
	var numRings int
	var bootNodes int
	var tcpPort int
	var udpPort int
	var load bool
	var caDirectory string
	var outputDirectory string

	flag.BoolVar(&load, "load", false, "If true, create a new CA and cryptographic resources. Otherwise, use existing resources.")
	flag.IntVar(&tcpPort, "tcp", 0, "TCP port of the Ifrit client's X.509 certificate.")
	flag.IntVar(&udpPort, "udp", 0, "UDP port of the Ifrit client's X.509 certificate.")
	flag.IntVar(&numRings, "rings", 10, "Number of rings in the Ifrit network.")
	flag.IntVar(&bootNodes, "nodes", 10, "Number of boot nodes in the Ifrit network.")
	flag.StringVar(&outputDirectory, "o", ".", "Directory into which certificates and keys are stored.")
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		log.Println("Missing arguments")
		log.Println("Usage: ifrit-ca-gen.go [OPTIONS...] CRYPTO-DIR HOSTNAME [HOSTNAME...]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	caDirectory = args[0]

	if load {
		// Require CA's directory
		if stat, err := os.Stat(caDirectory); err == nil && !stat.IsDir() {
			log.Printf("%s is not a directory.", caDirectory)
			flag.PrintDefaults()
			os.Exit(1)
		} else if _, err := os.Stat(caDirectory); os.IsNotExist(err) {
			log.Printf("CA's directory at path '%s' does not exist.", caDirectory)
			os.Exit(1)
		}
	}

	// Find all hostnames to generate certs and keys from
	if len(args) == 1 {
		log.Println("No hostname was found")
		log.Println("Usage: ifrit-ca-gen.go [OPTIONS...] CRYPTO-DIR HOSTNAME [HOSTNAME...]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if caDirectory == "" {
		log.Info("CRYPTO-DIR not set. Using default 'ca_dir'.")
		caDirectory = "ca_dir"
	}

	// Generate the ca
	ca, err := createCa(load, caDirectory, numRings, bootNodes)
	if err != nil {
		log.Fatal(err.Error())
	}

	cuConfigs := createCryptoUnitConfigs(outputDirectory, args[1:])
	if err = createCryptoUnits(cuConfigs, ca); err != nil {
		log.Fatal(err.Error())
	}

	// Store all the cryptographic resources for later use
	if err := ca.SavePrivateKey(); err != nil {
		log.Fatal(err.Error())
	}

	if err := ca.SaveCertificate(); err != nil {
		log.Fatal(err.Error())
	}
}

func createCryptoUnitConfigs(outputDirectory string, hostnames []string) []*ifritcert.CryptoUnitConfig {
	configs := make([]*ifritcert.CryptoUnitConfig, 0)
	for _, h := range hostnames {
		c := &ifritcert.CryptoUnitConfig{
			Identity: pkix.Name{
				CommonName: h,
			},
			DNSNames: []string{h},
			Path:     outputDirectory + "/" + h,
		}
		configs = append(configs, c)
	}
	return configs
}

// Reload as many crypto unts as possible. Create new ones, if needed.
func createCryptoUnits(configs []*ifritcert.CryptoUnitConfig, ca *ifritcert.Ca) error {
	newCUs := 0
	for _, c := range configs {
		var cu *ifritcert.CryptoUnit

		// If the crypto unit directory exists, assume the cu to be consistent with the ca.
		if stat, err := os.Stat(c.Path); err == nil && stat.IsDir() {
			log.Infof("Loading crypto unit on path %s ...", c.Path)
			cu, err = ifritcert.LoadCu(c)
			if err != nil {
				return err
			}
		} else if _, err := os.Stat(c.Path); os.IsNotExist(err) {
			log.Infof("Creating crypto unit on path %s ...", c.Path)
			cu, err = ifritcert.NewCu(c, ca)
			if err != nil {
				return err
			}

			if err := cu.SavePrivateKey(); err != nil {
				return err
			}

			if err := cu.SaveCertificate(); err != nil {
				return err
			}

			newCUs++
		}
	}

	if newCUs == 0 {
		log.Infof("No additional crypto units were created")
	} else {
		log.Infof("%d new crypto units were created", newCUs)
	}

	return nil
}

func createCa(load bool, caDirectory string, numRings int, bootNodes int) (*ifritcert.Ca, error) {
	var ca *ifritcert.Ca
	var err error

	// TODO: promt user if resources already exist
	if load {
		ca, err = ifritcert.LoadCa(caDirectory, uint32(numRings), uint32(bootNodes))
		if err != nil {
			return nil, err
		}
	} else {
		ca, err = ifritcert.NewCa(caDirectory)
		if err != nil {
			return nil, err
		}

		if err = ca.NewGroup(uint32(numRings), uint32(bootNodes)); err != nil {
			return nil, err
		}
	}
	return ca, nil
}
