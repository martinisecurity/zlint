package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/util"
)

// IsSTI returns true if the certificate is a STI certificate.
func IsSTI(c *x509.Certificate) bool {
	return IsSTIv1_3(c) || IsSTIv1_4(c)
}

// IsSTIv1_3 returns true if the certificate is a STI v1.3 certificate.
func IsSTIv1_3(c *x509.Certificate) bool {
	return util.SliceContainsOID(c.PolicyIdentifiers, util.ShakenUnitedStatesCPv1_3OID)
}

// IsSTIv1_4 returns true if the certificate is a STI v1.4 certificate.
func IsSTIv1_4(c *x509.Certificate) bool {
	return util.SliceContainsOID(c.PolicyIdentifiers, util.ShakenUnitedStatesCPv1_4OID)
}
