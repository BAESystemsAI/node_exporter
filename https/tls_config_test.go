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

package https

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"sync"
	"testing"
	"time"
)

var (
	port = ":9100"

	ErrorMap = map[string]*regexp.Regexp{
		"HTTP Response to HTTPS": regexp.MustCompile(`server gave HTTP response to HTTPS client`),
		"Server Panic":           regexp.MustCompile(`Panic starting server`),
		"No such file":           regexp.MustCompile(`no such file`),
		"YAML error":             regexp.MustCompile(`yaml`),
		"Invalid ClientAuth":     regexp.MustCompile(`ClientAuth`),
		"TLS handshake":          regexp.MustCompile(`tls`),
		"Malformed response":     regexp.MustCompile(`malformed HTTP`),
	}
)

type TestInputs struct {
	Name           string
	Server         func() *http.Server
	UseNilServer   bool
	YAMLConfigPath string
	ExpectedError  *regexp.Regexp
	UseTLSClient   bool
}

func TestYAMLFiles(t *testing.T) {
	testTables := []*TestInputs{
		{
			Name:           `path to config yml invalid`,
			YAMLConfigPath: "somefile",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `empty config yml`,
			YAMLConfigPath: "testdata/tls_config_empty.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (invalid structure)`,
			YAMLConfigPath: "testdata/tls_config_junk.yml",
			ExpectedError:  ErrorMap["YAML error"],
		},
		{
			Name:           `invalid config yml (cert path empty)`,
			YAMLConfigPath: "testdata/tls_config_noAuth_certPath_empty.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (key path empty)`,
			YAMLConfigPath: "testdata/tls_config_noAuth_keyPath_empty.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (cert path and key path empty)`,
			YAMLConfigPath: "testdata/tls_config_noAuth_certPath_keyPath_empty.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (cert path invalid)`,
			YAMLConfigPath: "testdata/tls_config_noAuth_certPath_invalid.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (key path invalid)`,
			YAMLConfigPath: "testdata/tls_config_noAuth_keyPath_invalid.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (cert path and key path invalid)`,
			YAMLConfigPath: "testdata/tls_config_noAuth_certPath_keyPath_invalid.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (invalid ClientAuth)`,
			YAMLConfigPath: "testdata/tls_config_noAuth.bad.yml",
			ExpectedError:  ErrorMap["Invalid ClientAuth"],
		},
		{
			Name:           `invalid config yml (invalid ClientCAs filepath)`,
			YAMLConfigPath: "testdata/tls_config_auth_clientCAs_invalid.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
	}
	for _, testInputs := range testTables {
		t.Run(testInputs.Name, testInputs.Test)
	}
}

func TestServerBehaviour(t *testing.T) {
	testTables := []*TestInputs{
		{
			Name:           `nil Server and default client`,
			UseNilServer:   true,
			YAMLConfigPath: "",
			ExpectedError:  ErrorMap["Server Panic"],
		},
		{
			Name:           `empty string YAMLConfigPath and default client`,
			YAMLConfigPath: "",
			ExpectedError:  nil,
		},
		{
			Name:           `empty string YAMLConfigPath and TLS client`,
			YAMLConfigPath: "",
			UseTLSClient:   true,
			ExpectedError:  ErrorMap["HTTP Response to HTTPS"],
		},
		{
			Name:           `valid tls config yml and default client`,
			YAMLConfigPath: "testdata/tls_config_noAuth.good.yml",
			ExpectedError:  ErrorMap["Malformed response"],
		},
		{
			Name:           `valid tls config yml and tls client`,
			YAMLConfigPath: "testdata/tls_config_noAuth.good.yml",
			UseTLSClient:   true,
			ExpectedError:  nil,
		},
	}
	for _, testInputs := range testTables {
		t.Run(testInputs.Name, testInputs.Test)
	}
}

func (test *TestInputs) Test(t *testing.T) {
	errorChannel := make(chan error, 1)
	var once sync.Once
	recordConnectionError := func(err error) {
		once.Do(func() {
			errorChannel <- err
		})
	}
	defer func() {
		if recover() != nil {
			recordConnectionError(errors.New("Panic in test function"))
		}
	}()

	var server *http.Server
	if test.UseNilServer {
		server = nil
	} else {
		server = &http.Server{
			Addr: port,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hello World!"))
			}),
		}
		defer func() {
			server.Close()
		}()
	}
	go func() {
		defer func() {
			if recover() != nil {
				recordConnectionError(errors.New("Panic starting server"))
			}
		}()
		err := Listen(server, test.YAMLConfigPath)
		recordConnectionError(err)
	}()

	var ClientConnection func() (*http.Response, error)
	if test.UseTLSClient {
		ClientConnection = func() (*http.Response, error) {
			cert, err := ioutil.ReadFile("testdata/tls-ca-chain.pem")
			if err != nil {
				log.Fatal("Unable to start TLS client. Check cert path")
			}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: func() *x509.CertPool {
							caCertPool := x509.NewCertPool()
							caCertPool.AppendCertsFromPEM(cert)
							return caCertPool
						}(),
					},
				},
			}
			return client.Get("https://localhost" + port)
		}
	} else {
		ClientConnection = func() (*http.Response, error) {
			client := http.DefaultClient
			return client.Get("http://localhost" + port)
		}
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		r, err := ClientConnection()
		if err != nil {
			recordConnectionError(err)
			return
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			recordConnectionError(err)
			return
		}
		if string(body) != "Hello World!" {
			recordConnectionError(errors.New("Server result did not match"))
			return
		}
		recordConnectionError(nil)
	}()
	err := <-errorChannel
	if test.isCorrectError(err) == false {
		t.Errorf(" *** Failed test: %s *** Returned error: %v *** Expected error: %v", test.Name, err, test.ExpectedError)
	}
}

func (test *TestInputs) isCorrectError(returnedError error) bool {
	switch {
	case returnedError == nil && test.ExpectedError == nil:
	case returnedError != nil && test.ExpectedError != nil && test.ExpectedError.MatchString(returnedError.Error()):
	default:
		return false
	}
	return true
}
