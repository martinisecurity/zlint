package shaken

import (
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type subjectCN struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_subject_cn",
		Description:   "The Common Name attribute of an End-Entity certificate shall contain the text string “SHAKEN”, followed by a single space, followed by the SPC value identified in the TNAuthList of the End-Entity certificate",
		Citation:      ATIS1000080v004_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		Lint:          NewSubjectCN,
	})
}

func NewSubjectCN() lint.LintInterface {
	return &subjectCN{}
}

// CheckApplies implements lint.LintInterface
func (*subjectCN) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*subjectCN) Execute(c *x509.Certificate) *lint.LintResult {
	spc, err := GetTNEntrySPC(c)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("Cannot get SPC value from the TNAuthList extension, %s", err.Error()),
		}
	}

	match := fmt.Sprintf("SHAKEN %s", spc)
	if !strings.Contains(c.Subject.CommonName, match) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("Common name shall contain the text string '%s'", match),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
