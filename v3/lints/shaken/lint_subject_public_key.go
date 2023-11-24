package shaken

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
  SHAKEN certificates shall contain a Subject Public Key Info field specifying a Public
	Key Algorithm of "id.ecPublicKey` and containing a 256-bit public key.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
  STI certificates shall contain a Subject Public Key Info field specifying a Public Key
	Algorithm of "id-ecPublicKey" and containing a 256-bit public key.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
  STI certificates shall contain a Subject Public Key Info field. The AlgorithmIdentifier
	field shall contain an algorithm field containing the value "id-ecPublicKey` and a
	namedCurve field containing the value National Institute of Standards and Technology (NIST)
	`P-256`, as defined in RFC 5480, Elliptic Curve Cryptography Subject Public Key Information.
	The subjectPublicKey field shall contain a 256-bit public key.

CP v1.4: 6.1.5 Key Sizes
  CAs that issue STI Certificates under this CP shall generate digital signatures with
	the Elliptic Curve Digital Signature Algorithm (ECDSA) with Curve P-256 and SHA-256 or
	ECDSA with Curve P-384 and SHA-384. CAs that issue STI Certificates under this CP shall
	generate digital signatures with a NIST-approved hash function that offer the same
	security as the elliptic curve used by the CA. For example, the NIST P-256 curve and
	SHA-256 offer the same security.
************************************************/

type subjectPublicKey struct {
	ca bool
}

const subjectPublicKey_details = "STI certificates shall contain a Subject Public Key Info field specifying a Public Key Algorithm of \"id-ecPublicKey\" and containing a 256-bit public key"

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_subject_public_key",
			Description:   subjectPublicKey_details,
			Citation:      ATIS1000080v003_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		},
		Lint: NewSubjectPublicKeyLeaf,
	})
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_subject_public_key_ca",
			Description:   subjectPublicKey_details,
			Citation:      ATIS1000080v003_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v003_Date,
		},
		Lint: NewSubjectPublicKeyCA,
	})
}

func NewSubjectPublicKey(ca bool) lint.LintInterface {
	return &subjectPublicKey{ca}
}

func NewSubjectPublicKeyLeaf() lint.LintInterface {
	return NewSubjectPublicKey(false)
}

func NewSubjectPublicKeyCA() lint.LintInterface {
	return NewSubjectPublicKey(true)
}

// CheckApplies implements lint.LintInterface
func (l *subjectPublicKey) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA
}

// Execute implements lint.LintInterface
func (*subjectPublicKey) Execute(c *x509.Certificate) *lint.LintResult {
	if c.PublicKeyAlgorithmOID.String() != "1.2.840.10045.2.1" { // id-ecPublicKey
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("Subject Public Key Info field specifies a Public Key Algorithm of %s, but must be id-ecPublicKey", c.PublicKeyAlgorithmOID.String()),
		}
	}

	ecKey := c.PublicKey.(*x509.AugmentedECDSA)
	namedCurve := ecKey.Pub.Curve.Params()
	if namedCurve == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Subject Public Key Info field does not contain a namedCurve field",
		}
	}
	if ecKey == nil || namedCurve.Name != "P-256" {
		// CP v1.4 supports P-384, but ATIS-1000080v005 does not
		if IsSTIv1_4(c) && c.IsCA && namedCurve.Name == "P-384" {
			return &lint.LintResult{
				Status: lint.Pass,
				Details: fmt.Sprintf("Subject Public Key Info field contains a public key that is %d bits, which is allowed by CP v1.4",
					ecKey.Pub.Curve.Params().BitSize),
			}
		}

		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Subject Public Key Info field contains a public key that is not 256 bits",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
