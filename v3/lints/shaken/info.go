package shaken

import "fmt"

var (
	ATIS1000080v003_STI_Citation             = "ATIS-1000080.v003 / 6.4.1 SHAKEN Certificate Requirements"
	ATIS1000080v004_STI_Citation             = "ATIS-1000080.v004 / 6.4.1 STI Certificate Requirements"
	United_States_SHAKEN_CP_Citation         = "United States SHAKEN Certificate Policy"
	United_States_SHAKEN_CPv1_1_Citation_3_1 = fmt.Sprintf("%s / %s", United_States_SHAKEN_CP_Citation, "3.1 Naming")
	United_States_SHAKEN_CPv1_1_Citation_3_2 = fmt.Sprintf("%s / %s", United_States_SHAKEN_CP_Citation, "3.2 Initial Identity Validation")
	United_States_SHAKEN_CPv1_1_Citation_4_9 = fmt.Sprintf("%s / %s", United_States_SHAKEN_CP_Citation, "4.9 Certificate Revocation and Suspension")
	PKI_Citation                             = "SHAKEN PKI Best Practice"
)
