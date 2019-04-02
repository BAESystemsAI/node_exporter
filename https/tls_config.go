// Package https allows the implementation of tls
package https

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v2"
)

type Config struct {
	TLSCertPath string    `yaml:"tlsCertPath"`
	TLSKeyPath  string    `yaml:"tlsKeyPath"`
	TLSConfig   TLSStruct `yaml:"tlsConfig"`
}

type TLSStruct struct {
	RootCAs            string `yaml:"rootCAs"`
	ServerName         string `yaml:"serverName"`
	ClientAuth         string `yaml:"clientAuth"`
	ClientCAs          string `yaml:"clientCAs"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
}

func GetTLSConfig(configPath string) *tls.Config {
	config, err := loadConfigFromYaml(configPath)
	if err != nil {
		log.Fatal("Config failed to load from Yaml", err)
	}
	tlsc, err := LoadTLSConfig(config)
	if err != nil {
		log.Fatal("Failed to convert Config to tls.Config", err)
	}
	return tlsc
}

func loadConfigFromYaml(fileName string) (*TLSConfig, error) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	err = yaml.Unmarshal(content, c)
	if err != nil {
		return nil, err
	}
	return &c.TLSConfig, nil
}

func configToTLSConfig(c *TLSConfig) (*tls.Config, error) {
	cfg := &tls.Config{}
	if len(c.TLSCertPath) > 0 && len(c.TLSKeyPath) > 0 {

		loadCert := func() (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(c.TLSCertPath, c.TLSKeyPath)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		}

		//Errors if either the certpath or keypath is invalid
		if _, err := loadCert(); err != nil {
			return nil, err
		}

		cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return loadCert()
		}
	}

	if len(c.ClientCAs) > 0 {
		clientCAPool := x509.NewCertPool()
		clientCAFile, err := ioutil.ReadFile(c.ClientCAs)
		if err != nil {
			return cfg, err
		}
		clientCAPool.AppendCertsFromPEM(clientCAFile)
		cfg.ClientCAs = clientCAPool
	}
	if len(c.ClientAuth) > 0 {
		switch s := (c.ClientAuth); s {
		case "NoClientCert":
			cfg.ClientAuth = tls.NoClientCert
		case "RequestClientCert":
			cfg.ClientAuth = tls.RequestClientCert
		case "RequireClientCert":
			cfg.ClientAuth = tls.RequireAnyClientCert
		case "VerifyClientCertIfGiven":
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		case "RequireAndVerifyClientCert":
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		default:
			return nil, errors.New("Invalid string provided to ClientAuth: " + s)
		}
	}
	return cfg, nil
}

func Listen(server *http.Server) error {
	if server.TLSConfig != nil {
		return server.ListenAndServeTLS("", "")
	} else {
		return server.ListenAndServe()
	}
}
