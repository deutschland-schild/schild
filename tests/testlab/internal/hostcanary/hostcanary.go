// Package hostcanary holds the canary values planted on the test lab's app VM
// (MVP-11). They are unique strings that only a host report can carry:
//
//   - Hostname and Package must show up in the app VM's host report at the
//     gateway (positive control: otherwise an absence check proves nothing)
//     and never in anything a lab received (host reports stay local).
//   - Secrets must never show up anywhere, not even in the stored host report
//     (kill criterion: "a report leaks a secret").
//
// The values are also written literally into the compose file and the app VM
// image (testlab/dockerfiles/app-vm); compose/agents_test.go keeps them in sync.
// None of them looks like an IP address, so the egress IP rule never
// confuses them with a visitor address.
package hostcanary

const (
	// Hostname of the enrolled app VM container (compose `hostname:`).
	Hostname = "app-vm-canary-k4p8z2"
	// Package is a dummy Debian package installed at 1.0 with 1.1 in a local
	// file repository, so it shows up as a pending update.
	Package = "schild-canary-pkg-q7m3x9"
	// SecretDB is the DB_PASSWORD in the app VM's wp-config.php.
	SecretDB = "schild-secret-canary-db-v2n8r4"
	// SecretEnv is an environment variable of every process in the app VM
	// container (including the agent).
	SecretEnv = "schild-secret-canary-env-t6w1y5"
	// SecretDotEnv is APP_KEY in /var/www/html/.env.
	SecretDotEnv = "schild-secret-canary-dotenv-h3j9c7"
)

// Local are the canaries a host report may carry (they stay in the operator
// network) and that no lab may ever receive.
func Local() []string { return []string{Hostname, Package} }

// Secrets are the canaries no report, gateway store or lab may ever contain.
func Secrets() []string { return []string{SecretDB, SecretEnv, SecretDotEnv} }

// All returns every canary.
func All() []string { return append(Local(), Secrets()...) }
