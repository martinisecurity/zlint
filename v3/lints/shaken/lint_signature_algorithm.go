package shaken

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN certificates shall contain a Signature Algorithm field with the value "ecdsa-with-SHA256".

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
  STI certificates shall contain a Signature Algorithm field with the value "ecdsa-with-SHA256".

ATIS-1000080v005: 6.4.1.1 STI Certificate Fields
  STI certificates shall contain a Signature Algorithm field with the value "ecdsa-with-SHA256".

CP v1.4: 6.1.5 Key Sizes
  CAs that issue STI Certificates under this CP shall generate digital signatures with
	the Elliptic Curve Digital Signature Algorithm (ECDSA) with Curve P-256 and SHA-256 or
	ECDSA with Curve P-384 and SHA-384. CAs that issue STI Certificates under this CP shall
	generate digital signatures with a NIST-approved hash function that offer the same
	security as the elliptic curve used by the CA. For example, the NIST P-256 curve and
	SHA-256 offer the same security.
************************************************/

type signatureAlgorithm struct {
	ca bool
}

var signatureAlgorithm_details = "STI certificates shall contain a Signature Algorithm field with the value 'ecdsa-with-SHA256'"

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_signature_algorithm",
			Description:   signatureAlgorithm_details,
			Citation:      ATIS1000080v003_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		},
		Lint: NewSignatureAlgorithmLeaf,
	})

	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_signature_algorithm_ca",
			Description:   signatureAlgorithm_details,
			Citation:      ATIS1000080v003_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v003_Date,
		},
		Lint: NewSignatureAlgorithmCA,
	})
}

func NewSignatureAlgorithm(ca bool) lint.LintInterface {
	return &signatureAlgorithm{
		ca: ca,
	}
}

func NewSignatureAlgorithmLeaf() lint.LintInterface {
	return NewSignatureAlgorithm(false)
}

func NewSignatureAlgorithmCA() lint.LintInterface {
	return NewSignatureAlgorithm(true)
}

// CheckApplies implements lint.LintInterface
func (s *signatureAlgorithm) CheckApplies(c *x509.Certificate) bool {
	return s.ca == c.IsCA
}

// Execute implements lint.LintInterface
func (*signatureAlgorithm) Execute(c *x509.Certificate) *lint.LintResult {
	if c.SignatureAlgorithmOID.String() != "1.2.840.10045.4.3.2" {
		// CP v1.4 specification allows ECDSA with P-384. It conflicts with ATIS-1000080.
		if (IsSTIv1_4(c) || util.IsRootCA(c)) && c.SignatureAlgorithmOID.String() == "1.2.840.10045.4.3.3" {
			return &lint.LintResult{
				Status:  lint.Pass,
				Details: "SignatureAlgorithm field is 'ecdsa-with-SHA384' which is allowed by CP v1.4",
			}
		}
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("SignatureAlgorithm field is not 'ecdsa-with-SHA256', got %s", c.SignatureAlgorithmOID.String()),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
