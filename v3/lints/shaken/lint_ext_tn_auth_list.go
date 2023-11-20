package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN end entity certificates shall contain a TNAuthList extension as specified in RFC 8226
	[Ref 25]. The TNAuthList shall contain a single SPC value.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
	STI End-Entity certificates shall contain a TNAuthList extension as specified in RFC 8226
	[Ref 20]. The TNAuthList shall contain a single SPC value.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
	STI end-entity certificates shall contain a TNAuthList extension as specified in RFC 8226
	[Ref 20]. The TNAuthList shall contain a single SPC value. The SPC value shall contain only
	numbers and uppercase letters. The TNAuthList shall not contain any TNs or TN ranges. STI
	root and intermediate certificates shall not contain a TNAuthList extension.
************************************************/

type tnAuthList struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_tn_auth_list",
		Description:   "STI End-Entity certificates shall contain a TNAuthList extension as specified in RFC 8226. The TNAuthList shall contain a single SPC value",
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint:          NewTnAuthList,
	})
}

func NewTnAuthList() lint.LintInterface {
	return &tnAuthList{}
}

// CheckApplies implements lint.LintInterface
func (*tnAuthList) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*tnAuthList) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.TNAuthListOID)
	if ext == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "the TNAuthList extension is not present",
		}
	}

	if ext.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "the TNAuthList extension is marked as critical",
		}
	}

	_, err := GetTNEntrySPC(c)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
