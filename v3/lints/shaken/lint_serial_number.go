package shaken

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN certificates shall include a Serial Number field containing a serial number
	that is unique within the scope of the issuing STI-CA.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
  STI certificates shall include a Serial Number field containing a serial number that is
  unique within the scope of the issuing STI-CA.

ATIS-1000080v005: 6.4.1.1 STI Certificate Fields
  STI certificates shall include a Serial Number field containing an integer greater than
	zero. The serial number shall contain at least 64 bits of output from a Cryptographically
	Secure PseudoRandom Number Generator (CSPRNG). The serial number shall be unique within the
	scope of the issuing STI-CA.
************************************************/

type serialNumber struct {
	ca bool
}

func init() {
	description := "STI certificates shall include a Serial Number field containing an serial number"

	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_serial_number",
		Description:   description,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint:          NewSerialNumberLeaf,
	})
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_serial_number_ca",
		Description:   description,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewSerialNumberCA,
	})
}

func NewSerialNumber(ca bool) lint.LintInterface {
	return &serialNumber{
		ca: ca,
	}
}

func NewSerialNumberLeaf() lint.LintInterface {
	return NewSerialNumber(false)
}

func NewSerialNumberCA() lint.LintInterface {
	return NewSerialNumber(true)
}

// CheckApplies implements lint.LintInterface
func (s *serialNumber) CheckApplies(c *x509.Certificate) bool {
	return s.ca == c.IsCA
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
	if c.SerialNumber.Sign() != 1 {
		return fmt.Errorf("STI certificates shall include a Serial Number field containing an integer greater than zero")
	}

	return nil
}
