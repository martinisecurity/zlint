package shaken

import (
	"bytes"
	"encoding/json"
	"net/http"
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
		Name:          "e_sti_crl_distribution_not_reachable",
		Description:   crlDistributionNotReachable_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		Lint: func() lint.LintInterface {
			return NewCrlDistributionNotReachable(false)
		},
	})
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_ca_crl_distribution_not_reachable",
		Description:   crlDistributionNotReachable_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
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
	// GET
	isGetReachable := true
	if _, err := http.Get(c.CRLDistributionPoints[0]); err != nil {
		isGetReachable = false
	}

	// IP
	isIpReachable := true
	jsonValue, _ := json.Marshal(stipaSpcValidateCDPRequest{
		CrlURL: c.CRLDistributionPoints[0],
	})
	if resp, err := http.Post("https://wfe.prod.martinisecurity.com/v1/stipa/validate_cdp", "application/json", bytes.NewBuffer(jsonValue)); err != nil || resp.StatusCode != 204 {
		isIpReachable = false
	}

	if !isIpReachable || isGetReachable {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Unable to retrieve CRL specified in CRLdp from allow listed IP address",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
