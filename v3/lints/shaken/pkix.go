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

// CRLDistributionPoints represents the ASN.1 structure of the same name. See RFC 5280
//
//	CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
type CRLDistributionPoints = []DistributionPoint

// DistributionPoint represents the ASN.1 structure of the same name. See RFC 5280
//
//	DistributionPoint ::= SEQUENCE {
//	  distributionPoint       [0]     DistributionPointName OPTIONAL,
//	  reasons                 [1]     ReasonFlags OPTIONAL,
//	  cRLIssuer               [2]     GeneralNames OPTIONAL }
type DistributionPoint struct {
	DistributionPointName asn1.RawValue  `asn1:"optional,tag:0"`
	Reasons               asn1.BitString `asn1:"optional,tag:1"`
	CRLIssuer             asn1.RawValue  `asn1:"optional,tag:2"`
}

// DistributionPointName represents the ASN.1 structure of the same name. See RFC 5280
//
//	DistributionPointName ::= CHOICE {
//	  fullName                [0]  GeneralNames,
//	  nameRelativeToCRLIssuer [1]  RelativeDistinguishedName }
type DistributionPointName struct {
	FullName                GeneralNames              `asn1:"optional,tag:0"`
	NameRelativeToCRLIssuer RelativeDistinguishedName `asn1:"optional,tag:1"`
}

// GeneralNames represents the ASN.1 structure of the same name. See RFC 5280
//
//	GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
type GeneralNames = []GeneralName

// GeneralName represents the ASN.1 structure of the same name. See RFC 5280
//
//	GeneralName ::= CHOICE {
//	  otherName                 [0]  AnotherName,
//	  rfc822Name                [1]  IA5String,
//	  dNSName                   [2]  IA5String,
//	  x400Address               [3]  ORAddress,
//	  directoryName             [4]  Name,
//	  ediPartyName              [5]  EDIPartyName,
//	  uniformResourceIdentifier [6]  IA5String,
//	  iPAddress                 [7]  OCTET STRING,
//	  registeredID              [8]  OBJECT IDENTIFIER }
type GeneralName struct {
	OtherName    asn1.RawValue         `asn1:"optional,tag:0"`
	RFC822       string                `asn1:"optional,tag:1"`
	DNS          string                `asn1:"optional,tag:2"`
	X400         asn1.RawValue         `asn1:"optional,tag:3"`
	DirName      asn1.RawValue         `asn1:"optional,tag:4"`
	EDIParty     asn1.RawValue         `asn1:"optional,tag:5"`
	URI          string                `asn1:"optional,tag:6"`
	IP           asn1.RawValue         `asn1:"optional,tag:7"`
	RegisteredID asn1.ObjectIdentifier `asn1:"optional,tag:8"`
}

// RelativeDistinguishedName represents the ASN.1 structure of the same name. See RFC 5280
//
//	RelativeDistinguishedName ::=
//		SET SIZE (1..MAX) OF AttributeTypeAndValue
type RelativeDistinguishedName = []AttributeTypeAndValue

// AttributeTypeAndValue represents the ASN.1 structure of the same name. See RFC 5280
//
//	AttributeTypeAndValue ::= SEQUENCE {
//	  type     AttributeType,
//	  value    AttributeValue }
type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

func ParseCRLDistributionPoints(raw []byte) (CRLDistributionPoints, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return nil, fmt.Errorf("bad CRLDistributionPoints ASN.1 raw, %w", err)
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return nil, asn1.StructuralError{Msg: "bad CRLDistributionPoints sequence"}
	}

	res := make(CRLDistributionPoints, 0)

	rest := seq.Bytes
	for len(rest) > 0 {
		var dp DistributionPoint
		var err error
		rest, err = asn1.Unmarshal(rest, &dp)
		if err != nil {
			return nil, fmt.Errorf("bad DistributionPoint ASN.1 raw, %w", err)
		}
		res = append(res, dp)
	}

	return res, nil
}
