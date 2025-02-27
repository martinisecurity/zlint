package shaken

import (
	"encoding/asn1"
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN certificates shall contain a Subject Key Identifier extension identifying the public key
	of the certificate.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
	STI certificates shall contain a Subject Key Identifier extension which is unique for each
	certificate. The value for the Subject Key Identifier is recommended to be derived from the public
	key of the certificate (e.g., a 160-bit SHA.1 hash of the public key, as described in RFC 5280
	[Ref 11]). The value for the Subject Key Identifier for a root or intermediate certificate shall
	be the value placed in the Key Identifier field of the Authority Key Identifier extension of
	certificates issued by the subject of the root or intermediate certificate.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
	STI certificates shall contain a Subject Key Identifier extension which is unique for each
	certificate. The value for the Subject Key Identifier shall contain the 160-bit SHA-1 hash of
	the public key, as described in RFC 5280 [Ref 13].
************************************************/

type subjectKeyIdentifierSize struct {
	ca bool
}

func init() {
	description := "The value for the Subject Key Identifier shall contain the 160-bit SHA-1 hash of the public key"

	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_subject_key_identifier_size",
			Description:   description,
			Citation:      ATIS1000080v004_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		},
		Lint: NewSubjectKeyIdentifierSizeLeaf,
	})

	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_subject_key_identifier_size_ca",
			Description:   description,
			Citation:      ATIS1000080v004_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v004_Date,
		},
		Lint: NewSubjectKeyIdentifierSizeCA,
	})
}

func NewSubjectKeyIdentifierSize(ca bool) lint.LintInterface {
	return &subjectKeyIdentifierSize{ca}
}

func NewSubjectKeyIdentifierSizeLeaf() lint.LintInterface {
	return NewSubjectKeyIdentifierSize(false)
}

func NewSubjectKeyIdentifierSizeCA() lint.LintInterface {
	return NewSubjectKeyIdentifierSize(true)
}

// CheckApplies implements lint.LintInterface
func (s *subjectKeyIdentifierSize) CheckApplies(c *x509.Certificate) bool {
	return s.ca == c.IsCA
}

// Execute implements lint.LintInterface
func (s *subjectKeyIdentifierSize) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.SubjectKeyIdentityOID)
	if ext == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Subject Key Identifier extension not found",
		}
	}

	var extValue asn1.RawValue
	_, err := asn1.Unmarshal(ext.Value, &extValue)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("Failed to parse Subject Key Identifier extension value: %s", err.Error()),
		}
	}

	if len(extValue.Bytes) != 20 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("Subject Key Identifier extension value is %d bytes, but must be 20 bytes", len(extValue.Bytes)),
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
