package shaken

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type serialNumber struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_serial_number",
		Description:   "STI certificates shall include a Serial Number field containing an integer greater than zero. The serial number shall contain at least 64 bits of output from a Cryptographically Secure PseudoRandom Number Generator (CSPRNG)",
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		Lint:          NewSerialNumber,
	})
}

func NewSerialNumber() lint.LintInterface {
	return &serialNumber{}
}

// CheckApplies implements lint.LintInterface
func (*serialNumber) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*serialNumber) Execute(c *x509.Certificate) *lint.LintResult {
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

func assertSerialNumber(c *x509.Certificate) error {
	if strings.HasPrefix(c.SerialNumber.String(), "-") || c.SerialNumber.Cmp(big.NewInt(0x0100000000000000)) == -1 {
		return fmt.Errorf("STI certificates shall include a Serial Number field containing an integer greater than zero. The serial number shall contain at least 64 bits of output from a Cryptographically Secure PseudoRandom Number Generator (CSPRNG)")
	}

	return nil
}
