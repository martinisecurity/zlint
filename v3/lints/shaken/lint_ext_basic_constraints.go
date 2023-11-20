package shaken

import (
	"encoding/asn1"
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN certificates shall contain a BasicConstraints extension marked critical. For root
	and intermediate certificates, the BasicConstraints CA boolean shall be set to TRUE, while
	for end entity certificates, the CA boolean shall be set to FALSE.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
	STI certificates shall contain a BasicConstraints extension marked critical. For root and
	intermediate certificates, the BasicConstraints CA boolean shall be set to TRUE, while for
	End-Entity certificates, the CA boolean shall be set to FALSE.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
	STI certificates shall contain a BasicConstraints extension marked critical. For root and
	intermediate certificates, the BasicConstraints CA boolean shall be set to TRUE. For end-entity
	certificates, the CA boolean shall be set to FALSE. For root and intermediate certificates,
	the BasicConstraints pathLen field may be set to limit the maximum path length, as described
	in RFC 5280 [Ref 13].
************************************************/

type asnBasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

type basicConstraints struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_basic_constraints",
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
				Details: fmt.Sprintf("unable to parse BasicConstraints extension: %s", err.Error()),
			}
		}

		return &lint.LintResult{
			Status: lint.Pass,
		}
	}

	if ext == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "BasicConstraints extension not found",
		}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: "BasicConstraints extension is not marked critical",
	}
}
