// Copyright 2019 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package https allows the implementation of tls
package https

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sync"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Config struct {
	TLSConfig TLSConfig `yaml:"tlsConfig"`
}

type TLSConfig struct {
	TLSCertPath string `yaml:"tlsCertPath"`
	TLSKeyPath  string `yaml:"tlsKeyPath"`
	ClientAuth  string `yaml:"clientAuth"`
	ClientCAs   string `yaml:"clientCAs"`
}

func getTLSConfig(reader io.Reader) (*tls.Config, error) {
	config, err := loadConfigFromYaml(reader)
	if err != nil {
		return nil, err
	}
	tlsc, err := configToTLSConfig(config)
	if err != nil {
		return nil, err
	}
	return tlsc, nil
}

func loadConfigFromYaml(reader io.Reader) (*TLSConfig, error) {
	content, err := ioutil.ReadAll(reader)
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
			return nil, err
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

// When the listen function is called if the tlsConfigPath is an empty string an HTTP server is started
// If the tlsConfigPath is a valid config file then an HTTPS server will be started
// The listen function also sets the GetConfigForClient method of the HTTPS server so that the config and certs are reloaded on new connections
func Listen(server *http.Server, reader io.Reader) error {
	if reader != nil {
		tlsConfig, err := getTLSConfig(reader)
		server.TLSConfig = tlsConfig
		if err != nil {
			return err
		}
		server.TLSConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return getTLSConfig(reader)
		}
		return server.ListenAndServeTLS("", "")
	}
	return server.ListenAndServe()
}

func ConfigPath(s string) io.Reader {
	if s == "" {
		return nil
	}
	return &configFileReader{Path: s}
}

type configFileReader struct {
	Path   string
	mutex  sync.Mutex
	reader io.Reader
}

func (r *configFileReader) NewPath(path string) error {
	r.mutex.Lock()
	r.Path = path
	reader, err := os.Open(r.Path)
	r.reader = reader
	r.mutex.Unlock()
	return err
}

func (r *configFileReader) Read(b []byte) (n int, err error) {
	r.mutex.Lock()
	if r.reader == nil {
		r.reset()
	}
	n, err = r.reader.Read(b)
	if err == io.EOF {
		r.reset()
	}
	r.mutex.Unlock()
	return n, err
}

func (r *configFileReader) reset() error {
	reader, err := os.Open(r.Path)
	r.reader = reader
	return err
}
