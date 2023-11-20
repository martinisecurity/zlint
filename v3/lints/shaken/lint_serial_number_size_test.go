package shaken

import (
	"math/big"
	"testing"

	"github.com/zmap/zcrypto/x509"
)

func Test_assertSerialNumberSize(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "serial number is 64 bits",
			args: args{
				c: &x509.Certificate{
					SerialNumber: new(big.Int).SetBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
				},
			},
			wantErr: false,
		},
		{
			name: "serial number is less than 64 bits",
			args: args{
				c: &x509.Certificate{
					SerialNumber: big.NewInt(1),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := assertSerialNumberSize(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("assertSerialNumberSize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
