package shaken

import (
	"github.com/zmap/zcrypto/encoding/asn1"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

// CP v1.1
// CAs that generate STI certificates under this policy shall use the SHA-256 algorithm when generating digital
// signatures. ECDSA signatures on certificates shall use SHA-256.

// CP v1.4
// CAs that issue STI Certificates under this CP shall generate digital signatures with the Elliptic Curve Digital
// Signature Algorithm (ECDSA) with Curve P-256 and SHA-256 or ECDSA with Curve P-384 and SHA-384.

var (
	ecdsaWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	ecdsaWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
)

type keySize_1_1 struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name: "e_cp_1_1_key_size",
		Description: "CAs that generate STI certificates under this policy shall use the SHA-256 algorithm " +
			"when generating digital signatures. ECDSA signatures on certificates shall use SHA-256.",
		Citation:      United_States_SHAKEN_CPv1_1_Citation_6_1_5,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_1_Date,
		Lint:          NewKeySize_1_1,
	})
}

func NewKeySize_1_1() lint.LintInterface {
	return &keySize_1_1{}
}

// CheckApplies implements lint.LintInterface.
func (*keySize_1_1) CheckApplies(c *x509.Certificate) bool {
	return util.HasPolicyIdentifierOID(c, util.ShakenCPv1_1OID) ||
		util.HasPolicyIdentifierOID(c, util.ShakenCPv1_2OID) ||
		util.HasPolicyIdentifierOID(c, util.ShakenUnitedStatesCPv1_3OID)
}

// Execute implements lint.LintInterface.
func (*keySize_1_1) Execute(c *x509.Certificate) *lint.LintResult {
	if !c.SignatureAlgorithmOID.Equal(ecdsaWithSHA256) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "STI certificates shall use the ECDSA with SHA-256 algorithm when generating digital signatures",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}

type keySize_1_4 struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name: "e_cp_1_4_key_size",
		Description: "CAs that issue STI Certificates under this CP shall generate digital signatures with " +
			"the Elliptic Curve Digital Signature Algorithm (ECDSA) with Curve P-256 and SHA-256 or ECDSA with " +
			"Curve P-384 and SHA-384.",
		Citation:      United_States_SHAKEN_CPv1_4_Citation_6_1_5,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_4_Date,
		Lint:          NewKeySize_1_4,
	})
}

func NewKeySize_1_4() lint.LintInterface {
	return &keySize_1_4{}
}

// CheckApplies implements lint.LintInterface.
func (*keySize_1_4) CheckApplies(c *x509.Certificate) bool {
	return util.HasPolicyIdentifierOID(c, util.ShakenUnitedStatesCPv1_4OID)
}

// Execute implements lint.LintInterface.
func (*keySize_1_4) Execute(c *x509.Certificate) *lint.LintResult {
	// Check that the signature algorithm is ECDSA with SHA-256 or ECDSA with SHA-384.
	if !c.SignatureAlgorithmOID.Equal(ecdsaWithSHA256) && !c.SignatureAlgorithmOID.Equal(ecdsaWithSHA384) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "STI certificates shall use the ECDSA with SHA-256 or ECDSA with SHA-384 algorithm when generating digital signatures",
		}
	}

	// NOTE: This lint cannot check the curve used for the ECDSA key because the curve is not included in the
	// certificate. The curve is included in the Subject Public Key Info of the
	// CA certificate.

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
