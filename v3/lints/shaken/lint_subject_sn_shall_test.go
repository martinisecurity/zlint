package shaken

import (
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
)

func Test_subjectSnShall_Execute(t *testing.T) {
	type fields struct {
		ca bool
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *lint.LintResult
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &subjectSnShall{
				ca: tt.fields.ca,
			}
			if got := l.Execute(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("subjectSnShall.Execute() = %v, want %v", got, tt.want)
			}
		})
	}
}
