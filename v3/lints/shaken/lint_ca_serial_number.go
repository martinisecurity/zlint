package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caSerialNumber struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_ca_serial_number",
		Description:   "STI certificates shall include a Serial Number field containing an integer greater than zero. The serial number shall contain at least 64 bits of output from a Cryptographically Secure PseudoRandom Number Generator (CSPRNG)",
		Citation:      ATIS1000080v004_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
		Lint:          NewCaSerialNumber,
	})
}

func NewCaSerialNumber() lint.LintInterface {
	return &caSerialNumber{}
}

// CheckApplies implements lint.LintInterface
func (*caSerialNumber) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA
}

// Execute implements lint.LintInterface
func (*caSerialNumber) Execute(c *x509.Certificate) *lint.LintResult {
	if err := assertSerialNumber(c); err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
