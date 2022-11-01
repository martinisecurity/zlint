package shaken

import (
	"encoding/asn1"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type asnBasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

type basicConstraints struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_basic_constraints",
		Description:   "STI certificates shall contain a Basic Constraints extension marked critical",
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewBasicConstraints,
	})
}

func NewBasicConstraints() lint.LintInterface {
	return &basicConstraints{}
}

// CheckApplies implements lint.LintInterface
func (*basicConstraints) CheckApplies(c *x509.Certificate) bool {
	return true
}

// Execute implements lint.LintInterface
func (*basicConstraints) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.BasicConstOID)

	if ext != nil && ext.Critical {
		basicConstraints := asnBasicConstraints{}
		if _, err := asn1.Unmarshal(ext.Value, &basicConstraints); err != nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: err.Error(), // "bad BasicConstraints ASN.1 value",
			}
		}

		return &lint.LintResult{
			Status: lint.Pass,
		}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: "STI certificates shall contain a BasicConstraints extension marked critical",
	}
}
