package shaken

import (
	"encoding/asn1"
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/util"
)

/*
ASN.1 schema:

id-pe-TNAuthList OBJECT IDENTIFIER ::= { id-pe 26 }

TNAuthorizationList ::= SEQUENCE SIZE (1..MAX) OF TNEntry

TNEntry ::= CHOICE {
  spc   [0] ServiceProviderCode,
  range [1] TelephoneNumberRange,
  one   [2] TelephoneNumber
  }

ServiceProviderCode ::= IA5String

-- SPCs may be OCNs, various SPIDs, or other SP identifiers
-- from the telephone network.

TelephoneNumberRange ::= SEQUENCE {
  start TelephoneNumber,
  count INTEGER (2..MAX),
  ...
  }

TelephoneNumber ::= IA5String (SIZE (1..15)) (FROM ("0123456789#*"))
*/

// TNAuthorizationList represents the ASN.1 structure of the same name. See RFC 8226
type TNAuthorizationList = []TNEntry

// TNEntry represents the ASN.1 structure of the same name. See RFC 8226
type TNEntry struct {
	SPC string
	// Range TelephoneNumberRange `asn1:"tag:1,optional,explicit"`
	// One   TelephoneNumber      `asn1:"tag:2,optional,explicit"`
}

// type ServiceProviderCode = string `asn1:"ia5string"`

func ParseTNAuthorizationList(raw []byte) (TNAuthorizationList, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return nil, fmt.Errorf("bad TNAuthorizationList ASN.1 raw, %w", err)
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return nil, asn1.StructuralError{Msg: "bad TNAuthorizationList sequence"}
	}

	res := make(TNAuthorizationList, 0)

	rest := seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return nil, fmt.Errorf("bad TNEntry ASN.1 raw, %w", err)
		}
		switch v.Tag {
		case 0:
			var spc string
			if _, err := asn1.UnmarshalWithParams(v.Bytes, &spc, "ia5"); err != nil {
				return nil, fmt.Errorf("bad spc ASN.1 raw, %w", err)
			}
			res = append(res, TNEntry{
				SPC: spc,
			})
		}
	}

	return res, nil
}

func GetTNEntrySPC(c *x509.Certificate) (string, error) {
	ext := util.GetExtFromCert(c, util.TNAuthListOID)
	if ext != nil {
		tnList, err := ParseTNAuthorizationList(ext.Value)
		if err != nil {
			return "", fmt.Errorf("bad TNAuthorizationList, %w", err)
		}

		if len(tnList) != 1 {
			return "", fmt.Errorf("TNAuthorizationList shall have only one TN Entry")
		}

		spc := tnList[0].SPC
		if len(spc) == 0 {
			return "", fmt.Errorf("TN Entry shall contain a SPC value")
		}

		return spc, nil
	}

	return "", fmt.Errorf("STI certificate shall contain TNAuthorizationList extension")
}
