package shaken

import (
	"fmt"
	"net/http"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type crlDistribution struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_crl_distribution",
		Description:   "STI End-Entity certificates shall contain a CRL Distribution Points extension containing a single DistributionPoint entry",
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		Lint:          NewCrlDistribution,
	})
}

func NewCrlDistribution() lint.LintInterface {
	return &crlDistribution{}
}

// CheckApplies implements lint.LintInterface
func (*crlDistribution) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*crlDistribution) Execute(c *x509.Certificate) *lint.LintResult {
	if ext := util.GetExtFromCert(c, util.CrlDistOID); ext != nil {
		if err := assertCrlDistributionPoint(c); err != nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: err.Error(),
			}
		}

		return &lint.LintResult{
			Status: lint.Pass,
		}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: "STI End-Entity certificates shall contain a CRL Distribution Points extension",
	}
}

func assertCrlDistributionPoint(c *x509.Certificate) error {
	if len(c.CRLDistributionPoints) != 1 {
		return fmt.Errorf("CRL Distribution Points extension should contain a single DistributionPoint entry")
	}
	if _, err := http.Get(c.CRLDistributionPoints[0]); err != nil {
		return fmt.Errorf("CRL Distribution Point shall be reachable if the requesting IP address within the program ACLs")
	}
	return nil
}
