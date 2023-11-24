package util

import (
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
)

func TestHasPolicyIdentifierOID(t *testing.T) {
	type args struct {
		c   *x509.Certificate
		oid asn1.ObjectIdentifier
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "has policy identifier",
			args: args{
				c: &x509.Certificate{
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						{1, 2, 3},
						{4, 5, 6},
					},
				},
				oid: asn1.ObjectIdentifier{4, 5, 6},
			},
			want: true,
		},
		{
			name: "does not have policy identifier",
			args: args{
				c: &x509.Certificate{
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						{1, 2, 3},
						{4, 5, 6},
					},
				},
				oid: asn1.ObjectIdentifier{7, 8, 9},
			},
			want: false,
		},
		{
			name: "empty policy identifiers",
			args: args{
				c:   &x509.Certificate{},
				oid: asn1.ObjectIdentifier{7, 8, 9},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasPolicyIdentifierOID(tt.args.c, tt.args.oid); got != tt.want {
				t.Errorf("HasPolicyIdentifierOID() = %v, want %v", got, tt.want)
			}
		})
	}
}
