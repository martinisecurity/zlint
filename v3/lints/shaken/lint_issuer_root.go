package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
  SHAKEN certificates shall include an Issuer field. For root certificates, the Issuer
	field shall match the certificate's Subject field. For intermediate and end entity
	certificates, the Issuer field shall match the Subject field of the parent certificate.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
  STI certificates shall include an Issuer field. For root certificates, the Issuer field
	shall match the certificate's Subject field. For intermediate and End-Entity certificates,
	the Issuer field shall match the Subject field of the parent certificate.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
  STI certificates shall include an Issuer field. For root certificates, the Issuer field
	shall match the certificate`s Subject field. For intermediate and end-entity certificates,
	the Issuer field shall match the Subject field of the issuing certificate.
************************************************/

type issuerRoot struct{}

func init() {
	description := "Issuer field of root certificate must match Subject field"
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_issuer_root",
			Description:   description,
			Citation:      ATIS1000080v003_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v003_Date,
		},
		Lint: NewIssuerRoot,
	})
}

func NewIssuerRoot() lint.LintInterface {
	return &issuerRoot{}
}

// CheckApplies implements LintInterface.
func (l *issuerRoot) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c)
}

// Execute implements LintInterface.
func (l *issuerRoot) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Issuer.String() != c.Subject.String() {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Issuer field of root certificate must match Subject field",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
