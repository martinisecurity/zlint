package shaken

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type signatureAlgorithm struct{}

var signatureAlgorithm_details = "STI certificates shall contain a Signature Algorithm field with the value 'ecdsa-with-SHA256'"

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_signature_algorithm",
		Description:   signatureAlgorithm_details,
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		Lint:          NewSignatureAlgorithm,
	})
}

func NewSignatureAlgorithm() lint.LintInterface {
	return &signatureAlgorithm{}
}

// CheckApplies implements lint.LintInterface
func (*signatureAlgorithm) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*signatureAlgorithm) Execute(c *x509.Certificate) *lint.LintResult {
	if err := assertSignatureAlgorithm(c); err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}

func assertSignatureAlgorithm(c *x509.Certificate) error {
	if c.SignatureAlgorithmOID.String() != "1.2.840.10045.4.3.2" {
		return fmt.Errorf(signatureAlgorithm_details)
	}
	return nil
}
