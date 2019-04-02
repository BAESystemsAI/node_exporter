The `https` directory contains files and a template config for the implementation of tls.
When running a server with tls use the flag --web.tls-config=" /path to config/.yml "
Where the path is from where the exporter was run.

i.e. ./node_exporter --web.tls-config="https/tls-config"
If the config is kept within the https directory 

The config file should is written in YAML format.
The layout is outlined below, with optional parameters in brackets.

For more detail on the clientAuth option: [ClientAuthType](https://golang.org/pkg/crypto/tls/#ClientAuthType)

### TLS Config Layout

#TLS CONFIG YAML
  # Paths to Cert File & Key file from base directory
  # Both required for valid tls
  # Paths set as string values
  # These are reloaded on initial connection 
  tlsCertPath : <filename>
  tlsKeyPath : <filename>

  # ClientAuth declares the policy the server will follow for client authentication
  # Accepts the following string values and maps to ClientAuth Policies
  # NoClientCert                -
  # RequestClientCert           -
  # RequireAnyClientCert        -
  # VerifyClientCertIfGiven     -
  # RequireAndVerifyClientCert  -
  clientAuth : ~

  # Client Ca's accepts a string path to the set of CA's
  clientCAs : ~

  # Controls whether a client verifies the servers cert chain and hostname
  # Boolean value - TLS insecure if true so should only be set as true for testing
  insecureSkipVerify : ~
