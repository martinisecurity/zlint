package shaken

import (
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_SubjectSnShall(t *testing.T) {
	type args struct {
		lintName string
		cert     *x509.Certificate
		config   lint.Configuration
	}

	tests := []struct {
		name string
		args args
		want *lint.LintResult
	}{
		{
			name: "e_us_cp_subject_sn_shall correct",
			args: args{
				lintName: "e_us_cp_subject_sn_shall",
				cert: &x509.Certificate{
					NotBefore: util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
					NotAfter:  util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
					Subject: pkix.Name{
						SerialNumber: "123456789",
					},
					IsCA: false,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
					},
					ExtensionsMap: map[string]pkix.Extension{
						util.TNAuthListOID.String(): {
							Id:       util.TNAuthListOID,
							Critical: false,
							Value:    []byte{0x30, 0x08, 0xA0, 0x06, 0x16, 0x04, 0x37, 0x30, 0x39, 0x4A},
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_us_cp_subject_sn_shall serialNumber missing",
			args: args{
				lintName: "e_us_cp_subject_sn_shall",
				cert: &x509.Certificate{
					NotBefore: util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
					NotAfter:  util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
					Subject:   pkix.Name{},
					IsCA:      false,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
					},
					ExtensionsMap: map[string]pkix.Extension{
						util.TNAuthListOID.String(): {
							Id:       util.TNAuthListOID,
							Critical: false,
							Value:    []byte{0x30, 0x08, 0xA0, 0x06, 0x16, 0x04, 0x37, 0x30, 0x39, 0x4A},
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN does not contain a serialNumber attribute.",
			},
		},
		{
			name: "e_us_cp_subject_sn_shall_ca correct",
			args: args{
				lintName: "e_us_cp_subject_sn_shall_ca",
				cert: &x509.Certificate{
					NotBefore: util.UnitedStatesSHAKENCPv1_3_Date,
					NotAfter:  util.UnitedStatesSHAKENCPv1_3_Date,
					Subject: pkix.Name{
						SerialNumber: "123456789",
					},
					IsCA: true,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
					},
					ExtensionsMap: map[string]pkix.Extension{
						util.TNAuthListOID.String(): {
							Id:       util.TNAuthListOID,
							Critical: false,
							Value:    []byte{0x30, 0x08, 0xA0, 0x06, 0x16, 0x04, 0x37, 0x30, 0x39, 0x4A},
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_us_cp_subject_sn_shall_ca serialNumber missing",
			args: args{
				lintName: "e_us_cp_subject_sn_shall_ca",
				cert: &x509.Certificate{
					NotBefore: util.UnitedStatesSHAKENCPv1_3_Date,
					NotAfter:  util.UnitedStatesSHAKENCPv1_3_Date,
					Subject:   pkix.Name{},
					IsCA:      true,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
					},
					ExtensionsMap: map[string]pkix.Extension{
						util.TNAuthListOID.String(): {
							Id:       util.TNAuthListOID,
							Critical: false,
							Value:    []byte{0x30, 0x08, 0xA0, 0x06, 0x16, 0x04, 0x37, 0x30, 0x39, 0x4A},
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN does not contain a serialNumber attribute.",
			},
		},
		{
			name: "e_us_cp_subject_sn_shall_ca without TNAuthList",
			args: args{
				lintName: "e_us_cp_subject_sn_shall_ca",
				cert: &x509.Certificate{
					NotBefore: util.UnitedStatesSHAKENCPv1_3_Date,
					NotAfter:  util.UnitedStatesSHAKENCPv1_3_Date,
					Subject:   pkix.Name{},
					IsCA:      true,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
					},
					ExtensionsMap: map[string]pkix.Extension{},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := test.TestLintCert(tt.args.lintName, tt.args.cert, tt.args.config); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TestLintCert() = %v, want %v", got, tt.want)
			}
		})
	}
}
