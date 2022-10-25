package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type subjectSN struct{}

const (
	serialNumberShallBeIncluded = "STI certificate shall include a ‘serialNumber’ attribute along with the CN"
)

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_cp1_3_subject_sn",
		Description:   "The ‘serialNumber’ attribute shall be included along with the CN",
		Citation:      CPv1_3_Citation,
		Source:        lint.CPv1_3,
		EffectiveDate: util.CPv1_3_Leaf_Date,
		Lint:          NewSubjectSN,
	})
}

func NewSubjectSN() lint.LintInterface {
	return &subjectSN{}
}

// CheckApplies implements lint.LintInterface
func (*subjectSN) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*subjectSN) Execute(c *x509.Certificate) *lint.LintResult {
	values := make([]interface{}, 0)
	for _, v := range c.Subject.Names {
		if v.Type.Equal(util.SerialOID) { // SERIALNUMBER
			values = append(values, v.Value)
		}
	}

	if len(values) != 1 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: serialNumberShallBeIncluded,
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
