package internal

import (
	"fmt"

	"golang.org/x/crypto/ocsp"
)

func PrintOCSPResponse(certFileName string, resp *ocsp.Response) {
	fmt.Printf("%v: %v\n", certFileName, StatusString(resp.Status))
	fmt.Printf("\tThis Update: %v\n", resp.ThisUpdate)
	if !resp.NextUpdate.IsZero() {
		fmt.Printf("\tNext Update: %v\n", resp.NextUpdate)
	}
	if resp.Status == ocsp.Revoked {
		fmt.Printf("\tReason: %v\n", RevocationReasonString(resp.RevocationReason))
		fmt.Printf("\tRevocation Time: %v\n", resp.RevokedAt)
	}
}
