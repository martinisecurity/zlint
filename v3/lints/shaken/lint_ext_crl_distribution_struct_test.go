package shaken

import (
	"encoding/hex"
	"testing"
)

func Test_assertCrlDistributionPointStruct(t *testing.T) {
	raw1, err := hex.DecodeString("30819F30819CA03EA03C863A68747470733A2F2F61757468656E7469636174652D6170692D7374672E69636F6E65637469762E636F6D2F646F776E6C6F61642F76312F63726CA25AA4583056311430120603550407130B4272696467657761746572310B3009060355040813024E4A311330110603550403130A5354492D50412043524C310B3009060355040613025553310F300D060355040A13065354492D5041")
	if err != nil {
		t.Fatal(err.Error())
	}
	raw2, err := hex.DecodeString("30333031A02FA02D862B687474703A2F2F63726C2E6964656E74727573742E636F6D2F445354524F4F544341583343524C2E63726C")
	if err != nil {
		t.Fatal(err.Error())
	}

	type args struct {
		raw []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "CRLDistributionPoints correct",
			args: args{
				raw: raw1,
			},
			wantErr: false,
		},
		{
			name: "CRLDistributionPoints without CRLIssuer",
			args: args{
				raw: raw2,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := assertCrlDistributionPointStruct(tt.args.raw); (err != nil) != tt.wantErr {
				t.Errorf("assertCrlDistributionPointStruct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
