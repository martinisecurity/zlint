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

func Test_SubjectDn(t *testing.T) {
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
			name: "e_atis_subject_dn correct",
			args: args{
				lintName: "e_atis_subject_dn",
				cert: &x509.Certificate{
					NotBefore: util.ATIS1000080_v003_Leaf_Date,
					IsCA:      false,
					Subject: pkix.Name{
						Country:      []string{"US"},
						CommonNames:  []string{"SHAKEN 1234"},
						SerialNumber: "1234", // other fields are optional
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_dn multiple countries",
			args: args{
				lintName: "e_atis_subject_dn",
				cert: &x509.Certificate{
					NotBefore: util.ATIS1000080_v003_Leaf_Date,
					IsCA:      false,
					Subject: pkix.Name{
						Country:     []string{"US", "CA"},
						CommonNames: []string{"SHAKEN 1234"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject DN contains multiple Country (C=) attributes",
			},
		},
		{
			name: "e_atis_subject_dn multiple common names",
			args: args{
				lintName: "e_atis_subject_dn",
				cert: &x509.Certificate{
					NotBefore: util.ATIS1000080_v003_Leaf_Date,
					IsCA:      false,
					Subject: pkix.Name{
						Country:     []string{"US"},
						CommonNames: []string{"SHAKEN 1234", "SHAKEN 5678"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject DN contains multiple Common Name (CN=) attributes",
			},
		},
		{
			name: "e_atis_subject_dn country missing",
			args: args{
				lintName: "e_atis_subject_dn",
				cert: &x509.Certificate{
					NotBefore: util.ATIS1000080_v003_Leaf_Date,
					IsCA:      false,
					Subject: pkix.Name{
						CommonNames: []string{"SHAKEN 1234"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject DN does not contain a Country (C=) attribute",
			},
		},
		{
			name: "e_atis_subject_dn common name missing",
			args: args{
				lintName: "e_atis_subject_dn",
				cert: &x509.Certificate{
					NotBefore: util.ATIS1000080_v003_Leaf_Date,
					IsCA:      false,
					Subject: pkix.Name{
						Country: []string{"US"},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject DN does not contain a Common Name (CN=) attribute",
			},
		},
		{
			name: "e_atis_subject_dn_ca intermediate",
			args: args{
				lintName: "e_atis_subject_dn_ca",
				cert: &x509.Certificate{
					NotBefore: util.ATIS1000080_v003_Date,
					IsCA:      true,
					Subject: pkix.Name{
						Country:      []string{"US"},
						CommonNames:  []string{"SHAKEN Intermediate"},
						SerialNumber: "1234", // other fields are optional
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_dn_ca root",
			args: args{
				lintName: "e_atis_subject_dn_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: true,
					Subject: pkix.Name{
						Country:      []string{"US"},
						CommonNames:  []string{"SHAKEN Intermediate"},
						SerialNumber: "1234", // other fields are optional
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
