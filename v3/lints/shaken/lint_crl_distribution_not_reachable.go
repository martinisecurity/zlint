package shaken

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type crlDistributionNotReachable struct {
	ca bool
}

// stipaSpcValidateCDPRequest specifies request for CRL DP validation
type stipaSpcValidateCDPRequest struct {
	CrlURL string `json:"crl"`
}

const crlDistributionNotReachable_details = "HTTP URL from the CRL Distribution Point shall be reachable"

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_crl_distribution_not_reachable",
		Description:   crlDistributionNotReachable_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint: func() lint.LintInterface {
			return NewCrlDistributionNotReachable(false)
		},
	})
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ca_crl_distribution_not_reachable",
		Description:   crlDistributionNotReachable_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint: func() lint.LintInterface {
			return NewCrlDistributionNotReachable(true)
		},
	})
}

func NewCrlDistributionNotReachable(ca bool) lint.LintInterface {
	return &crlDistributionNotReachable{
		ca: ca,
	}
}

// CheckApplies implements lint.LintInterface
func (t *crlDistributionNotReachable) CheckApplies(c *x509.Certificate) bool {
	return ((t.ca && c.IsCA && !c.SelfSigned) || !t.ca && !c.IsCA) && len(c.CRLDistributionPoints) == 1 && strings.HasPrefix(c.CRLDistributionPoints[0], "http")
}

// Execute implements lint.LintInterface
func (*crlDistributionNotReachable) Execute(c *x509.Certificate) *lint.LintResult {
	// TODO Requires API for CRL validation
	return &lint.LintResult{
		Status: lint.NA,
	}
}
