package shaken

import (
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_Version(t *testing.T) {
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
			name: "e_atis_version correct",
			args: args{
				lintName: "e_atis_version",
				cert: &x509.Certificate{
					Version:   3,
					NotBefore: util.ATIS1000080_v003_Leaf_Date,
					NotAfter:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:      false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_version wrong",
			args: args{
				lintName: "e_atis_version",
				cert: &x509.Certificate{
					Version:   2,
					NotBefore: util.ATIS1000080_v003_Leaf_Date,
					NotAfter:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:      false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain Version field specifying version 3",
			},
		},
		{
			name: "e_atis_version_ca correct",
			args: args{
				lintName: "e_atis_version_ca",
				cert: &x509.Certificate{
					Version:   3,
					NotBefore: util.ATIS1000080_v003_Date,
					NotAfter:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:      true,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_version_ca wrong",
			args: args{
				lintName: "e_atis_version_ca",
				cert: &x509.Certificate{
					Version:   2,
					NotBefore: util.ATIS1000080_v003_Date,
					NotAfter:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:      true,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain Version field specifying version 3",
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
