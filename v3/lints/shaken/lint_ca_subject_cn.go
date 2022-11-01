package shaken

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caSubjectCN struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ca_subject_cn",
		Description:   "For non-End-Entity CA certificates, the Common Name attribute shall include the text string \"SHAKEN\" and also indicate whether the certificate is a root or intermediate certificate",
		Citation:      ATIS1000080v004_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
		Lint:          NewCaSubjectCN,
	})
}

func NewCaSubjectCN() lint.LintInterface {
	return &caSubjectCN{}
}

// CheckApplies implements lint.LintInterface
func (*caSubjectCN) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA
}

// Execute implements lint.LintInterface
func (*caSubjectCN) Execute(c *x509.Certificate) *lint.LintResult {
	if !strings.Contains(c.Subject.CommonName, "SHAKEN") {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The Common Name attribute shall include the text string \"SHAKEN\"",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
