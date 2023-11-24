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

func Test_SubjectCn(t *testing.T) {
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
			name: "e_atis_subject_cn correct",
			args: args{
				lintName: "e_atis_subject_cn",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "1 SHAKEN 2",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_cn case sensitive",
			args: args{
				lintName: "e_atis_subject_cn",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "shaken",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Common Name attribute 'shaken' does not contain 'SHAKEN'",
			},
		},
		{
			name: "e_atis_subject_cn extra characters",
			args: args{
				lintName: "e_atis_subject_cn",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "sSHAKEN",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Common Name attribute 'sSHAKEN' does not contain 'SHAKEN'",
			},
		},
		{
			name: "e_atis_subject_cn_ca intermediate",
			args: args{
				lintName: "e_atis_subject_cn_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "SHAKEN intermediate",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_cn_ca root",
			args: args{
				lintName: "e_atis_subject_cn_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: true,
					Subject: pkix.Name{
						CommonName: "SHAKEN ROOT",
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
