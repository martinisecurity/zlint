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

type crlDistributionStruct struct {
	ca bool
}

func init() {
	description := "STI intermediate and end-entity certificates shall contain a CRL Distribution Points extension containing a single DistributionPoint entry. The DistributionPoint entry shall contain a distributionPoint field identifying the HTTP URL reference to the file containing the SHAKEN CRL hosted by the STI-PA, and a cRLIssuer field that contains the DN of the issuer of the CRL."
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_ext_crl_distribution_struct",
			Description:   description,
			Citation:      ATIS1000080v004_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		},
		Lint: NewCrlDistributionStructLeaf,
	})

	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_ext_crl_distribution_struct_ca",
			Description:   description,
			Citation:      ATIS1000080v004_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v004_Date,
		},
		Lint: NewCrlDistributionStructCA,
	})
}

func NewCrlDistributionStruct(ca bool) lint.LintInterface {
	return &crlDistributionStruct{ca}
}

func NewCrlDistributionStructLeaf() lint.LintInterface {
	return NewCrlDistributionStruct(false)
}

func NewCrlDistributionStructCA() lint.LintInterface {
	return NewCrlDistributionStruct(true)
}

// CheckApplies implements lint.LintInterface
func (l *crlDistributionStruct) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.CrlDistOID) && l.ca == c.IsCA && !util.IsRootCA(c)
}

// Execute implements lint.LintInterface
func (l *crlDistributionStruct) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.CrlDistOID)
	if err := assertCrlDistributionPointStruct(ext.Value); err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}

func assertCrlDistributionPointStruct(raw []byte) error {
	rawValue := asn1.RawValue{}
	_, err := asn1.Unmarshal(raw, &rawValue)
	if err != nil {
		return fmt.Errorf("failed to unmarshal CRL Distribution Points extension: %v", err)
	}
	if rawValue.Class != 0 || rawValue.Tag != 16 || !rawValue.IsCompound {
		return fmt.Errorf("invalid CRL Distribution Points extension")
	}

	_, err = asn1.Unmarshal(rawValue.Bytes, &rawValue)
	if err != nil {
		return fmt.Errorf("failed to unmarshal CRL Distribution Point: %v", err)
	}
	if rawValue.Class != 0 || rawValue.Tag != 16 || !rawValue.IsCompound {
		return fmt.Errorf("invalid CRL Distribution Point")
	}

	rest, err := asn1.Unmarshal(rawValue.Bytes, &rawValue)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Distribution Point Name: %v", err)
	}
	if rawValue.Class != 2 || rawValue.Tag != 0 || !rawValue.IsCompound {
		return fmt.Errorf("invalid Distribution Point Name")
	}

	if len(rest) == 0 {
		return fmt.Errorf("CRL Distribution Point shall contain a CRLIssuer field")
	}

	_, err = asn1.Unmarshal(rest, &rawValue)
	if err != nil {
		return fmt.Errorf("failed to unmarshal CRLIssuer: %v", err)
	}
	if rawValue.Class != 2 || rawValue.Tag != 2 || !rawValue.IsCompound {
		return fmt.Errorf("invalid CRLIssuer")
	}

	return nil
}
