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

func Test_SerialNumberSize(t *testing.T) {
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
			name: "e_atis_serial_number_size leaf",
			args: args{
				lintName: "e_atis_serial_number_size",
				cert: &x509.Certificate{
					NotBefore:    util.ATIS1000080_v005_Leaf_Date,
					IsCA:         false,
					SelfSigned:   false,
					SerialNumber: big.NewInt(0).SetBytes([]byte{0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_serial_number_size leaf less than 64 bits",
			args: args{
				lintName: "e_atis_serial_number_size",
				cert: &x509.Certificate{
					NotBefore:    util.ATIS1000080_v005_Leaf_Date,
					IsCA:         false,
					SelfSigned:   false,
					SerialNumber: big.NewInt(0).SetBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall have a serial number that contains at least 64 bits, got 57",
			},
		},
		{
			name: "e_atis_serial_number_size_ca intermediate",
			args: args{
				lintName: "e_atis_serial_number_size_ca",
				cert: &x509.Certificate{
					NotBefore:    util.ATIS1000080_v005_Date,
					IsCA:         true,
					SelfSigned:   false,
					SerialNumber: big.NewInt(0).SetBytes([]byte{0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_serial_number_size_ca root",
			args: args{
				lintName: "e_atis_serial_number_size_ca",
				cert: &x509.Certificate{
					NotBefore:    util.ATIS1000080_v005_Date,
					IsCA:         true,
					SelfSigned:   true,
					SerialNumber: big.NewInt(0).SetBytes([]byte{0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
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
