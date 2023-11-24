package shaken

import (
	"fmt"
	"regexp"

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

type tnAuthListSpcFormat struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_tn_auth_list_spc_format",
			Description:   "The SPC value in the TNAuthList extension shall contain only numbers and uppercase letters",
			Citation:      ATIS1000080v005_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v005_Leaf_Date,
		},
		Lint: NewTnAuthListSpcFormat,
	})
}

func NewTnAuthListSpcFormat() lint.LintInterface {
	return &tnAuthListSpcFormat{}
}

// CheckApplies implements lint.LintInterface
func (*tnAuthListSpcFormat) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*tnAuthListSpcFormat) Execute(c *x509.Certificate) *lint.LintResult {
	spc, err := GetTNEntrySPC(c)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	matches := regexp.MustCompile(`^[A-Z0-9]+$`).MatchString(spc)
	if !matches {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("the SPC value '%s' contains characters other than uppercase letters and numbers", spc),
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
