package jwetpm

import (
	"io"
	"net"
	"slices"

	"github.com/google/go-tpm/tpmutil"
)

// Base configuration for seal and unseal functions

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}
