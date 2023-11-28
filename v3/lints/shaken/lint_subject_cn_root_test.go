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

func Test_SubjectCnRoot(t *testing.T) {
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
			name: "e_atis_subject_cn_root in uppercase",
			args: args{
				lintName: "e_atis_subject_cn_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       true,
					SelfSigned: true,
					Subject: pkix.Name{
						CommonName: "SHAKEN ROOT CA",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_cn_root in lowercase",
			args: args{
				lintName: "e_atis_subject_cn_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       true,
					SelfSigned: true,
					Subject: pkix.Name{
						CommonName: "SHAKEN root ca",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			name: "e_atis_subject_cn_root in camelcase",
			args: args{
				lintName: "e_atis_subject_cn_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       true,
					SelfSigned: true,
					Subject: pkix.Name{
						CommonName: "SHAKEN Root CA",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			name: "e_atis_subject_cn_root incorrect",
			args: args{
				lintName: "e_atis_subject_cn_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       true,
					SelfSigned: true,
					Subject: pkix.Name{
						CommonName: "SHAKEN Roots CA",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Common Name attribute 'SHAKEN Roots CA' does not include the text string 'ROOT' (case insensitive).",
			},
		},
		{
			name: "e_atis_subject_cn_root intermediate",
			args: args{
				lintName: "e_atis_subject_cn_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       true,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "SHAKEN intermediate",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.NA,
			},
		},
		{
			name: "e_atis_subject_cn_root leaf",
			args: args{
				lintName: "e_atis_subject_cn_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "SHAKEN intermediate",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.NA,
			},
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
