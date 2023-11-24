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

func Test_SubjectCUs(t *testing.T) {
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
			name: "e_atis_subject_c_us leaf",
			args: args{
				lintName: "e_atis_subject_c_us",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						Country: []string{"US"},
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
			name: "e_atis_subject_c_us incorrect",
			args: args{
				lintName: "e_atis_subject_c_us",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						Country: []string{"CA"},
					},
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject MUST contain a Country (C=) of \"US\".",
			},
		},
		{
			name: "e_atis_subject_c_us no country",
			args: args{
				lintName: "e_atis_subject_c_us",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject MUST be present and MUST contain exactly one value for Country (C=).",
			},
		},
		{
			name: "e_atis_subject_c_us multiple countries",
			args: args{
				lintName: "e_atis_subject_c_us",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						Country: []string{"US", "CA"},
					},
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject MUST be present and MUST contain exactly one value for Country (C=).",
			},
		},
		{
			name: "e_atis_subject_c_us_ca intermediate",
			args: args{
				lintName: "e_atis_subject_c_us_ca",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:       true,
					SelfSigned: false,
					Subject: pkix.Name{
						Country: []string{"US"},
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
			name: "e_atis_subject_c_us_ca root",
			args: args{
				lintName: "e_atis_subject_c_us_ca",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:       true,
					SelfSigned: true,
					Subject: pkix.Name{
						Country: []string{"US"},
					},
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
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
