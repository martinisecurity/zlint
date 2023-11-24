package shaken

import (
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_SubjectCIso(t *testing.T) {
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
			name: "e_atis_subject_c_iso leaf",
			args: args{
				lintName: "e_atis_subject_c_iso",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						Country: []string{"US"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_c_iso missing",
			args: args{
				lintName: "e_atis_subject_c_iso",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject:    pkix.Name{},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject MUST be present and MUST contain exactly one value for Country (C=).",
			},
		},
		{
			name: "e_atis_subject_c_iso multiple",
			args: args{
				lintName: "e_atis_subject_c_iso",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						Country: []string{"US", "US"},
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
			name: "e_atis_subject_c_iso incorrect format",
			args: args{
				lintName: "e_atis_subject_c_iso",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						Country: []string{"us"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Country (C=) attribute 'us' does not contain an ISO 3166-1 alpha-2 country code.",
			},
		},
		{
			name: "e_atis_subject_c_iso_ca intermediate",
			args: args{
				lintName: "e_atis_subject_c_iso_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       true,
					SelfSigned: false,
					Subject: pkix.Name{
						Country: []string{"US"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_c_iso_ca root",
			args: args{
				lintName: "e_atis_subject_c_iso_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       true,
					SelfSigned: true,
					Subject: pkix.Name{
						Country: []string{"US"},
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
