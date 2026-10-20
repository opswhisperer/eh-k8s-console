// Package model describes every setting of the ExtraHop Kubernetes integration: where it lives,
// what a valid value looks like, and how it maps to the official Helm chart.
package model

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type Type string

const (
	TypeString   Type = "string"
	TypeHost     Type = "host"     // hostname or IPv4
	TypeHostPort Type = "hostport" // host:port
	TypeEnum     Type = "enum"
	TypeNSList   Type = "nslist" // comma-separated namespaces
	TypeHex64    Type = "hex64"  // 32-byte key, hex
	TypePEM      Type = "pem"
	TypeDNSName  Type = "dnsname"
)

// Setting is one ConfigMap key.
type Setting struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Group    string   `json:"group"`
	Doc      string   `json:"doc"`
	Type     Type     `json:"type"`
	Enum     []string `json:"enum,omitempty"`
	Required bool     `json:"required"`
	// Default is what the integration assumes when the key is absent.
	Default string `json:"default,omitempty"`
	// HelmPath is the values.yaml path in the official chart, "" when the chart has no such value.
	HelmPath string `json:"helmPath,omitempty"`
	// Restart: changing it needs the consuming pods restarted (all keys today: env and
	// file-mounted values are read at start-up).
	Restart bool `json:"restart"`
	// ReadOnly settings are shown but never changed by the console.
	ReadOnly bool `json:"readOnly,omitempty"`
}

// SecretSetting is one Secret key. Values are write-only in the UI.
type SecretSetting struct {
	// Suffix is appended to the integration prefix to form the Secret name.
	Suffix   string `json:"suffix"`
	Key      string `json:"key"`
	Label    string `json:"label"`
	Doc      string `json:"doc"`
	Type     Type   `json:"type"`
	HelmPath string `json:"helmPath,omitempty"`
	// PublicKey names the ConfigMap key holding the matching public key, if any.
	PublicKey string `json:"publicKey,omitempty"`
	// ReadOnly secrets are shown (length, pair check) but never changed by the console.
	ReadOnly bool `json:"readOnly,omitempty"`
}

// keyPairDoc explains why the exkpkt keys are read-only.
const keyPairDoc = " Read-only here: the public and private halves are generated together on the sensor's Kubernetes Integration page, and changing one without the other breaks coordinator-forwarder messages. To replace them, generate a new configuration on the sensor and apply it."

// LinkedArg is a command-line flag that must carry the same value as a ConfigMap key. The
// session-key-forwarder takes the sensor address as args rather than from the ConfigMap, so the
// editor updates both together and the validator flags drift.
type LinkedArg struct {
	Flag       string `json:"flag"`
	Setting    string `json:"setting"`
	Containers string `json:"container"` // container name that carries the flag
}

const (
	GroupSensor    = "Sensor"
	GroupFiltering = "Traffic filtering"
	GroupKeys      = "Forwarder keys"
	GroupCluster   = "Cluster"
)

var Settings = []Setting{
	{Key: "clusterName", Label: "Cluster name", Group: GroupCluster, Type: TypeString, Required: true, HelmPath: "clusterName", Restart: true,
		Doc: "Name shown for this cluster in the ExtraHop system. Usually the cluster's own name."},
	{Key: "mgmtTarget", Label: "Sensor management interface", Group: GroupSensor, Type: TypeHost, Required: true, HelmPath: "sensor.mgmtTarget", Restart: true,
		Doc: "Hostname or IPv4 address of the sensor's management interface. Metadata (443) and session keys (4873) are sent here."},
	{Key: "serverNameOverride", Label: "Sensor TLS name", Group: GroupSensor, Type: TypeDNSName, HelmPath: "sensor.serverNameOverride", Restart: true,
		Doc: "Name the forwarders expect on the sensor's TLS certificate. Must be one of the certificate's names."},
	{Key: "mirrorTarget", Label: "Traffic ingest interface", Group: GroupSensor, Type: TypeHostPort, Required: true, HelmPath: "exkpkt.mirrorTarget", Restart: true,
		Doc: "host:port of the sensor interface that receives mirrored traffic as Geneve (UDP 6081). Must be configured to receive Geneve."},
	{Key: "sensorCert", Label: "Sensor certificate bundle", Group: GroupSensor, Type: TypePEM, Required: true, HelmPath: "sensor.certificate", Restart: true,
		Doc: "PEM certificates the forwarders trust when connecting to the sensor. Any certificate here can anchor trust; for a public CA store the CA chain only."},
	{Key: "kubernetesBaseTrafficRule", Label: "Cluster-scoped traffic rule", Group: GroupFiltering, Type: TypeEnum, Enum: []string{"mirror", "skip"}, Default: "mirror", Restart: true,
		Doc: "mirror forwards traffic from resources that are not scoped to a namespace (for example nodes); skip omits it."},
	{Key: "kubernetesNamespacedTrafficRule", Label: "Namespace traffic rule", Group: GroupFiltering, Type: TypeEnum, Enum: []string{"mirror", "skip"}, Default: "mirror", Restart: true,
		Doc: "mirror forwards traffic from every namespace except Skip namespaces; skip forwards only Mirror namespaces. The extrahop.com/traffic-mirror-rule annotation on a resource overrides both."},
	{Key: "mirrorNamespaces", Label: "Mirror namespaces", Group: GroupFiltering, Type: TypeNSList, Restart: true,
		Doc: "Namespaces to forward when the namespace rule is skip. With the rule at mirror this list changes nothing."},
	{Key: "skipNamespaces", Label: "Skip namespaces", Group: GroupFiltering, Type: TypeNSList, Restart: true,
		Doc: "Namespaces to omit when the namespace rule is mirror."},
	{Key: "exkpktCoordinatorPublic", Label: "Coordinator public key", Group: GroupKeys, Type: TypeHex64, Required: true, HelmPath: "exkpkt.coordinatorPublic", Restart: true, ReadOnly: true,
		Doc: "Public half of the coordinator key pair that secures coordinator ↔ forwarder messages." + keyPairDoc},
	{Key: "exkpktForwarderPublic", Label: "Forwarder public key", Group: GroupKeys, Type: TypeHex64, Required: true, HelmPath: "exkpkt.forwarderPublic", Restart: true, ReadOnly: true,
		Doc: "Public half of the forwarder key pair." + keyPairDoc},
}

var Secrets = []SecretSetting{
	{Suffix: "sensor-api-credentials", Key: "apiKey", Label: "Sensor API key", Type: TypeString, HelmPath: "sensor.apiKey",
		Doc: "API key the metadata forwarder uses on the sensor. Generated on the sensor's Kubernetes Integration page."},
	{Suffix: "exkpkt-coordinator", Key: "secret", Label: "Coordinator private key", Type: TypeHex64, HelmPath: "exkpkt.coordinatorSecret", PublicKey: "exkpktCoordinatorPublic", ReadOnly: true,
		Doc: "Private half of the coordinator key pair." + keyPairDoc},
	{Suffix: "exkpkt-forwarder", Key: "secret", Label: "Forwarder private key", Type: TypeHex64, HelmPath: "exkpkt.forwarderSecret", PublicKey: "exkpktForwarderPublic", ReadOnly: true,
		Doc: "Private half of the forwarder key pair." + keyPairDoc},
}

var LinkedArgs = []LinkedArg{
	{Flag: "-server", Setting: "mgmtTarget", Containers: "session-key-forwarder"},
	{Flag: "-server-name-override", Setting: "serverNameOverride", Containers: "session-key-forwarder"},
}

// Groups lists setting groups in display order.
var Groups = []string{GroupSensor, GroupFiltering, GroupCluster, GroupKeys}

func Lookup(key string) *Setting {
	for i := range Settings {
		if Settings[i].Key == key {
			return &Settings[i]
		}
	}
	return nil
}

var (
	dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	nsName   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

func validHostname(h string) bool {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !dnsLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// CheckHost accepts an IPv4 address or a hostname. IPv6 is refused: the integration does not
// support it.
func CheckHost(v string) error {
	if ip := net.ParseIP(v); ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("%q is IPv6; the ExtraHop Kubernetes integration supports IPv4 only", v)
		}
		return nil
	}
	if !validHostname(v) {
		return fmt.Errorf("%q is not a valid hostname or IPv4 address", v)
	}
	return nil
}

// SplitList splits a namespace list on commas and/or whitespace. Which separator the traffic
// forwarder expects depends on its version, so parsing here is tolerant and the validator checks
// the configured separator separately.
func SplitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

// JoinList writes a namespace list with the given separator ("," or " ").
func JoinList(items []string, sep string) string {
	if sep == "" {
		sep = ","
	}
	return strings.Join(items, sep)
}

// Check validates a value's format. It does not check cross-setting rules.
func (s *Setting) Check(v string) error {
	if strings.TrimSpace(v) == "" {
		if s.Required {
			return fmt.Errorf("%s is required", s.Label)
		}
		return nil
	}
	switch s.Type {
	case TypeHost:
		return CheckHost(v)
	case TypeDNSName:
		if !validHostname(v) {
			return fmt.Errorf("%q is not a valid DNS name", v)
		}
	case TypeHostPort:
		h, p, err := net.SplitHostPort(v)
		if err != nil {
			return fmt.Errorf("%q must be host:port (for example 10.0.0.5:6081)", v)
		}
		if err := CheckHost(h); err != nil {
			return err
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("port %q is not a valid port number", p)
		}
	case TypeEnum:
		for _, e := range s.Enum {
			if v == e {
				return nil
			}
		}
		return fmt.Errorf("%q must be one of %s", v, strings.Join(s.Enum, ", "))
	case TypeNSList:
		for _, n := range SplitList(v) {
			if !nsName.MatchString(n) {
				return fmt.Errorf("%q is not a valid namespace name", n)
			}
		}
	case TypeHex64:
		if _, err := DecodeKey(v); err != nil {
			return err
		}
	case TypePEM:
		if !strings.Contains(v, "-----BEGIN CERTIFICATE-----") {
			return fmt.Errorf("must contain at least one PEM certificate")
		}
	}
	return nil
}

// DecodeKey decodes a 32-byte key written as 64 hex characters.
func DecodeKey(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("must be 64 hexadecimal characters (a 32-byte key)")
	}
	return b, nil
}

// LookupSecret finds the SecretSetting for a Secret name and key.
func LookupSecret(prefix, name, key string) *SecretSetting {
	for i := range Secrets {
		if Secrets[i].SecretName(prefix) == name && Secrets[i].Key == key {
			return &Secrets[i]
		}
	}
	return nil
}

// SecretName returns the full Secret name for a SecretSetting.
func (s SecretSetting) SecretName(prefix string) string { return prefix + s.Suffix }
