package util

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
)

// HasPolicyIdentifierOID checks if the given x509 certificate has the specified policy identifier OID.
func HasPolicyIdentifierOID(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, policy := range c.PolicyIdentifiers {
		if policy.Equal(oid) {
			return true
		}
	}
	return false
}
