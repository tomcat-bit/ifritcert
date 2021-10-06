package main

import (
	"bufio"
	"strings"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/tomcat-bit/ifritcert"
	"os"
)

var DefaultPermission = os.FileMode(0750)
var deploymentFilePath = "deployment_files"

type App struct {
	ca          *ifritcert.Ca
	cryptoUnits []*ifritcert.CryptoUnit
}

type Build struct {
	hostname string
}

type Deployment struct {
	hostname string
}

func main() {
	var numRings int
	var bootNodes int
	var tcpPort int
	var udpPort int
	var load bool
	var caDirectory string
	var outputDirectory string
	var hostnameFile string
	var hostnames []string
	var genDeploymentSchema bool

	flag.BoolVar(&load, "load", false, "If true, create a new CA and cryptographic resources. Otherwise, use existing resources.")
	flag.IntVar(&tcpPort, "tcp", 0, "TCP port of the Ifrit client's X.509 certificate.")
	flag.IntVar(&udpPort, "udp", 0, "UDP port of the Ifrit client's X.509 certificate.")
	flag.IntVar(&numRings, "rings", 10, "Number of rings in the Ifrit network.")
	flag.IntVar(&bootNodes, "nodes", 10, "Number of boot nodes in the Ifrit network.")
	flag.StringVar(&hostnameFile, "f", "", "Line-separated file of hostnames. If this flag is set, it will ignore the positional arguments.")
	flag.StringVar(&outputDirectory, "o", ".", "Directory into which certificates and keys are stored.")
	flag.BoolVar(&genDeploymentSchema, "build", false, "If true, generate YAML schemas for each Azure Container Instance.")
	flag.Parse()
	args := flag.Args()

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

	// Don't use hostname file
	if hostnameFile == "" {
		if len(args) == 1 {
			log.Println("No hostname was found")
			log.Println("Usage: ifrit-ca-gen [OPTIONS...] CRYPTO-DIR HOSTNAME [HOSTNAME...]")
			flag.PrintDefaults()
			os.Exit(1)
		}
		hostnames = args[0:]
	} else {
		h, err := readHostnameFile(hostnameFile)
		if err != nil {
			log.Fatal(err.Error())
		}
		hostnames = h
	}

	if caDirectory == "" {
		log.Info("CRYPTO-DIR not set. Using default 'ca_dir' instead.")
		caDirectory = "ca_dir"
	}

	// Generate the ca
	ca, err := createCa(load, caDirectory, numRings, bootNodes)
	if err != nil {
		log.Fatal(err.Error())
	}

	cuConfigs := createCryptoUnitConfigs(outputDirectory, hostnames, tcpPort, udpPort)
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

	if genDeploymentSchema {
		if err := generateDeploymentSchema(deploymentFilePath, hostnames); err != nil {
			log.Fatal(err.Error())
		}
	}

	os.Exit(0)
}

func generateDeploymentSchema(outputDirectory string, hostnames []string) error {
	if _, err := os.Stat(outputDirectory); os.IsNotExist(err) {
		if err := os.Mkdir(outputDirectory, 0755); err != nil {
			return err
		}
	}

	for _, h := range hostnames {
		location := strings.Split(h, ".")[1]
		tag := strings.Split(h, ".")[0]
		fileContent := deploymentFile(location, tag)

		log.Println("location:", location)

		filename := fmt.Sprintf("%s/%s.yaml", outputDirectory, h)
		f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
    	if err != nil {
	        return err
	    }

		if _, err := f.Write([]byte(fileContent)); err != nil {
			f.Close() 
			return err
		}

    	if err := f.Close(); err != nil {
	        return err
	    }
	}
	return nil 
}

func readHostnameFile(filepath string) ([]string, error) {
	hostnames := make([]string, 0)
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hostnames = append(hostnames, scanner.Text())
	}

	return hostnames, scanner.Err()
}

func createCryptoUnitConfigs(outputDirectory string, hostnames []string, tcpPort int, udpPort int) []*ifritcert.CryptoUnitConfig {
	configs := make([]*ifritcert.CryptoUnitConfig, 0)
	for _, h := range hostnames {
		pk := pkix.Name{
			Locality: []string{
				fmt.Sprintf("%s:%d", h, tcpPort),
				fmt.Sprintf("%s:%d", h, udpPort),
			},
		}

		c := &ifritcert.CryptoUnitConfig{
			Identity: pk,
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

func deploymentFile(location string, tag string) string {
	return fmt.Sprintf(`
location: %s
name: %s
properties:
  containers:
  - name: %s
    properties:
      image: lohpi.azurecr.io/%s:latest
      resources:
        requests:
          cpu: 2
          memoryInGb: 1.5
      ports:
        - protocol: UDP
          port: 8000
        - protocol: TCP
          port: 5000
  osType: Linux
  ipAddress:
    type: Public
    ports:
      - protocol: UDP
        port: 8000
      - protocol: TCP
        port: 5000
    dnsnamelabel: %s
  imageRegistryCredentials:
    - server: lohpi.azurecr.io
      username: lohpi
      password: jQA8j+27P11I36IOJGf9lXWwKqqbo/Ym
tags: {exampleTag: tutorial}
type: Microsoft.ContainerInstance/containerGroups
`, location, tag, tag, tag, tag)
}

/*
location: norwayeast
name: ifrit-server
properties:
  containers:
  - name: ifrit-server
    properties:
      image: lohpi.azurecr.io/ifrit-server:latest
      resources:
        requests:
          cpu: 2
          memoryInGb: 1.5
      ports:
        - protocol: UDP
          port: 8000
        - protocol: TCP
          port: 5000
  osType: Linux
  ipAddress:
    type: Public
    ports:
      - protocol: UDP
        port: 8000
      - protocol: TCP
        port: 5000
    dnsnamelabel: "ifrit-server"
  imageRegistryCredentials:
    - server: lohpi.azurecr.io
      username: lohpi
      password: jQA8j+27P11I36IOJGf9lXWwKqqbo/Ym
tags: {exampleTag: tutorial}
type: Microsoft.ContainerInstance/containerGroups

*/