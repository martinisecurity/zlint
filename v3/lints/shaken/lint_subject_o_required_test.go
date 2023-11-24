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

func Test_SubjectORequired(t *testing.T) {
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
			name: "e_atis_subject_o_required leaf",
			args: args{
				lintName: "e_atis_subject_o_required",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						Organization: []string{"Organization"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_o_required missing",
			args: args{
				lintName: "e_atis_subject_o_required",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN does not contain exactly one Organization (O=) attribute.",
			},
		},
		{
			name: "e_atis_subject_o_required multiple",
			args: args{
				lintName: "e_atis_subject_o_required",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						Organization: []string{"Organization", "Organization"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN does not contain exactly one Organization (O=) attribute.",
			},
		},
		{
			name: "e_atis_subject_o_required_ca intermediate",
			args: args{
				lintName: "e_atis_subject_o_required_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Date,
					IsCA:       true,
					SelfSigned: false,
					Subject: pkix.Name{
						Organization: []string{"Organization"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_o_required_ca root",
			args: args{
				lintName: "e_atis_subject_o_required_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Date,
					IsCA:       true,
					SelfSigned: true,
					Subject: pkix.Name{
						Organization: []string{"Organization"},
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
