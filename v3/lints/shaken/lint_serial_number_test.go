package shaken

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_SerialNumber(t *testing.T) {
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
			name: "e_atis_serial_number leaf",
			args: args{
				lintName: "e_atis_serial_number",
				cert: &x509.Certificate{
					NotBefore:    util.ATIS1000080_v003_Leaf_Date,
					IsCA:         false,
					SelfSigned:   false,
					SerialNumber: big.NewInt(1),
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_serial_number leaf negative",
			args: args{
				lintName: "e_atis_serial_number",
				cert: &x509.Certificate{
					NotBefore:    util.ATIS1000080_v003_Leaf_Date,
					IsCA:         false,
					SelfSigned:   false,
					SerialNumber: big.NewInt(-1),
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall include a Serial Number field containing an integer greater than zero",
			},
		},
		{
			name: "e_atis_serial_number leaf empty",
			args: args{
				lintName: "e_atis_serial_number",
				cert: &x509.Certificate{
					NotBefore:    util.ATIS1000080_v003_Leaf_Date,
					IsCA:         false,
					SelfSigned:   false,
					SerialNumber: big.NewInt(0),
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall include a Serial Number field containing an integer greater than zero",
			},
		},
		{
			name: "e_atis_serial_number_ca intermediate",
			args: args{
				lintName: "e_atis_serial_number_ca",
				cert: &x509.Certificate{
					NotBefore:    util.ATIS1000080_v003_Date,
					IsCA:         true,
					SelfSigned:   false,
					SerialNumber: big.NewInt(1),
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_serial_number_ca root",
			args: args{
				lintName: "e_atis_serial_number_ca",
				cert: &x509.Certificate{
					NotBefore:    util.ATIS1000080_v003_Date,
					IsCA:         true,
					SelfSigned:   true,
					SerialNumber: big.NewInt(1),
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
