package shaken

import (
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

const subjectKeyIdentifier_details = "STI certificates shall contain a Subject Key Identifier extension identifying the public key of the certificate"

type subjectKeyIdentifier struct {
	ca bool
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_subject_key_identifier",
		Description:   subjectKeyIdentifier_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint:          NewSubjectKeyIdentifierLeaf,
	})

	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ca_subject_key_identifier",
		Description:   subjectKeyIdentifier_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewSubjectKeyIdentifierCA,
	})
}

func NewSubjectKeyIdentifier(ca bool) lint.LintInterface {
	return &subjectKeyIdentifier{ca}
}

func NewSubjectKeyIdentifierLeaf() lint.LintInterface {
	return NewSubjectKeyIdentifier(false)
}

func NewSubjectKeyIdentifierCA() lint.LintInterface {
	return NewSubjectKeyIdentifier(true)
}

// CheckApplies implements lint.LintInterface
func (l *subjectKeyIdentifier) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA
}

// Execute implements lint.LintInterface
func (*subjectKeyIdentifier) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.SubjectKeyIdentityOID)
	if ext == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Subject Key Identifier extension not found",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
