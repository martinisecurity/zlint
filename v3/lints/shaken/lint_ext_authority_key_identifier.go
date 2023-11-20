package shaken

import (
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

type authorityKeyIdentifier struct {
	ca bool
}

func init() {
	description := "STI certificates shall contain an Authority Key Identifier extension"
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_authority_key_identifier",
		Description:   description,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint:          NewAuthorityKeyIdentifierLeaf,
	})

	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_authority_key_identifier_ca",
		Description:   description,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewAuthorityKeyIdentifierCA,
	})
}

func NewAuthorityKeyIdentifier(ca bool) lint.LintInterface {
	return &authorityKeyIdentifier{ca}
}

func NewAuthorityKeyIdentifierLeaf() lint.LintInterface {
	return NewAuthorityKeyIdentifier(false)
}

func NewAuthorityKeyIdentifierCA() lint.LintInterface {
	return NewAuthorityKeyIdentifier(true)
}

// CheckApplies implements lint.LintInterface
func (l *authorityKeyIdentifier) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA && !util.IsRootCA(c)
}

// Execute implements lint.LintInterface
func (*authorityKeyIdentifier) Execute(c *x509.Certificate) *lint.LintResult {
	if ext := util.GetExtFromCert(c, util.AuthkeyOID); ext == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "STI certificates shall contain an Authority Key Identifier extension",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
