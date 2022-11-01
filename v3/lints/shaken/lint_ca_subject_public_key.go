package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caSubjectPublicKey struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ca_subject_public_key",
		Description:   subjectPublicKey_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewCaSubjectPublicKey,
	})
}

func NewCaSubjectPublicKey() lint.LintInterface {
	return &caSubjectPublicKey{}
}

// CheckApplies implements lint.LintInterface
func (*caSubjectPublicKey) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA
}

// Execute implements lint.LintInterface
func (*caSubjectPublicKey) Execute(c *x509.Certificate) *lint.LintResult {
	if err := assertSubjectPublicKey(c); err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
