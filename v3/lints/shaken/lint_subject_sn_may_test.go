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

func Test_SubjectSnMay(t *testing.T) {
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
			name: "e_us_cp_subject_sn_may leaf with serialNumber",
			args: args{
				lintName: "e_us_cp_subject_sn_may",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						SerialNumber: "123456789",
					},
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_us_cp_subject_sn_may leaf without serialNumber",
			args: args{
				lintName: "e_us_cp_subject_sn_may",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject:    pkix.Name{},
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_us_cp_subject_sn_may leaf CPv1.3",
			args: args{
				lintName: "e_us_cp_subject_sn_may",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject:    pkix.Name{},
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
		},
		{
			name: "e_us_cp_subject_sn_may_ca intermediate",
			args: args{
				lintName: "e_us_cp_subject_sn_may_ca",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:       true,
					SelfSigned: false,
					Subject: pkix.Name{
						SerialNumber: "123456789",
					},
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_us_cp_subject_sn_may_ca root",
			args: args{
				lintName: "e_us_cp_subject_sn_may_ca",
				cert: &x509.Certificate{
					NotBefore:         util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:              true,
					SelfSigned:        false,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						// The Root CA shall not include the policy identifier
					},
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
