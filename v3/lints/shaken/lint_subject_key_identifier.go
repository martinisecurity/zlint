package shaken

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

const subjectKeyIdentifier_details = "STI certificates shall contain a Subject Key Identifier extension"

type subjectKeyIdentifier struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_subject_key_identifier",
		Description:   subjectKeyIdentifier_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint:          NewSubjectKeyIdentifier,
	})
}

func NewSubjectKeyIdentifier() lint.LintInterface {
	return &subjectKeyIdentifier{}
}

// CheckApplies implements lint.LintInterface
func (*subjectKeyIdentifier) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*subjectKeyIdentifier) Execute(c *x509.Certificate) *lint.LintResult {
	if err := assertSubjectKeyIdentifier(c); err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}

func assertSubjectKeyIdentifier(c *x509.Certificate) error {
	ext := util.GetExtFromCert(c, util.SubjectKeyIdentityOID)
	if ext == nil {
		return fmt.Errorf(subjectKeyIdentifier_details)
	}

	return nil
}
