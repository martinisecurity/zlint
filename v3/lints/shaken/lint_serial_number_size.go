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

type serialNumberSize struct {
	ca bool
}

func init() {
	description := "STI certificates shall have a serial number that contains at least 64 bits."

	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_serial_number_size",
			Description:   description,
			Citation:      ATIS1000080v005_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v005_Leaf_Date,
		},
		Lint: NewSerialNumberSizeLeaf,
	})

	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_serial_number_size_ca",
			Description:   description,
			Citation:      "ATIS-1000080.v005",
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v005_Date,
		},
		Lint: NewSerialNumberSizeCA,
	})
}

func NewSerialNumberSize(ca bool) lint.LintInterface {
	return &serialNumberSize{
		ca: ca,
	}
}

func NewSerialNumberSizeLeaf() lint.LintInterface {
	return NewSerialNumberSize(false)
}

func NewSerialNumberSizeCA() lint.LintInterface {
	return NewSerialNumberSize(true)
}

// CheckApplies implements lint.LintInterface
func (s *serialNumberSize) CheckApplies(c *x509.Certificate) bool {
	return s.ca == c.IsCA
}

// Execute implements lint.LintInterface
func (*serialNumberSize) Execute(c *x509.Certificate) *lint.LintResult {
	if c.SerialNumber.BitLen() < 64 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("STI certificates shall have a serial number that contains at least 64 bits, got %d", c.SerialNumber.BitLen()),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
