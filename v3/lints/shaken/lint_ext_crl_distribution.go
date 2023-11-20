package shaken

import (
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN end entity certificates shall contain a CRL Distribution Point extension with a
	CRL Distribution Point Name identifying the HTTP URL reference to the file containing
	the SHAKEN CRL hosted by the STI-PA.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
	STI intermediate and End-Entity certificates shall contain a CRL Distribution Points
	extension containing a single DistributionPoint entry. The DistributionPoint entry shall
	contain a distributionPoint field identifying the HTTP URL reference to the file containing
	the SHAKEN CRL hosted by the STI-PA, and a cRLIssuer field that contains the DN of the
	issuer of the CRL.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
	STI intermediate and end-entity certificates shall contain a CRL Distribution Points
	extension containing a single DistributionPoint entry. The DistributionPoint entry shall
	contain a distributionPoint field identifying the HTTP URL reference to the file containing
	the SHAKEN CRL hosted by the STI-PA, and a CRLIssuer field that matches the DN of the issuer
	of the CRL. STI root certificates shall not contain a CRL Distribution Points extension.
************************************************/

type crlDistribution struct {
	ca bool
}

func init() {
	description := "STI End-Entity certificates shall contain a CRL Distribution Points extension containing a single DistributionPoint entry"

	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_crl_distribution",
		Description:   description,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint:          NewCrlDistributionLeaf,
	})

	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_crl_distribution_ca",
		Description:   description,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewCrlDistributionCA,
	})
}

func NewCrlDistribution(ca bool) lint.LintInterface {
	return &crlDistribution{ca}
}

func NewCrlDistributionLeaf() lint.LintInterface {
	return NewCrlDistribution(false)
}

func NewCrlDistributionCA() lint.LintInterface {
	return NewCrlDistribution(true)
}

// CheckApplies implements lint.LintInterface
func (l *crlDistribution) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA && !util.IsRootCA(c)
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

	if !strings.HasPrefix(c.CRLDistributionPoints[0], "http") {
		return fmt.Errorf("DistributionPoint filed shall contain the HTTP URL reference to the CRL")
	}

	return nil
}
