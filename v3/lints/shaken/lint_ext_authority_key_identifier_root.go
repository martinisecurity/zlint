package shaken

import (
	"bytes"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN intermediate and end entity certificates shall contain an Authority Key Identifier
	extension (this extension is optional for root certificates). For root certificates that
	contain an Authority Key Identifier extension, the Authority Key Identifier shall contain
	a keyIdentifier field with a value that matches the Subject Key Identifier value of the
	same root certificate. For intermediate and end entity certificates, the Authority Key
	Identifier extension shall contain a keyIdentifier field with a value that matches the
	Subject Key Identifier value of the parent certificate.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
	STI intermediate and End-Entity certificates shall contain an Authority Key Identifier
	extension (this extension is optional for root certificates). For root certificates that
	contain an Authority Key Identifier extension, the Authority Key Identifier shall contain
	a keyIdentifier field with a value that matches the Subject Key Identifier value of the
	same root certificate. For intermediate and End-Entity certificates, the Authority Key
	Identifier extension shall contain a keyIdentifier field with a value that matches the
	Subject Key Identifier value of the parent certificate.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
	STI intermediate and end-entity certificates shall contain an Authority Key Identifier
	extension (this extension is optional for root certificates). For root certificates that
	contain an Authority Key Identifier extension, the Authority Key Identifier shall contain
	a keyIdentifier field with a value that matches the Subject Key Identifier value of the
	same root certificate. For intermediate and end-entity certificates, the Authority Key
	Identifier extension shall contain a keyIdentifier field with a value that matches the
	Subject Key Identifier value of the issuing certificate.
************************************************/

type authorityKeyIdentifierRoot struct{}

func init() {
	description := "Root certificates containing an Authority Key Identifier extension must have a keyIdentifier field within the Authority Key Identifier that matches the Subject Key Identifier value of the same root certificate."
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_authority_key_identifier_root",
		Description:   description,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewAuthorityKeyIdentifierRoot,
	})
}

func NewAuthorityKeyIdentifierRoot() lint.LintInterface {
	return &authorityKeyIdentifierRoot{}
}

// CheckApplies implements lint.LintInterface
func (l *authorityKeyIdentifierRoot) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c) && util.IsExtInCert(c, util.AuthkeyOID)
}

// Execute implements lint.LintInterface
func (*authorityKeyIdentifierRoot) Execute(c *x509.Certificate) *lint.LintResult {
	subjectKeyIdentifier := c.SubjectKeyId
	authorityKeyIdentifier := c.AuthorityKeyId

	// compare the two values
	if !bytes.Equal(subjectKeyIdentifier, authorityKeyIdentifier) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The Authority Key Identifier doesn't match the Subject Key Identifier value",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
