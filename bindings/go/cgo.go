package wired

// libwired_ffi.a is found in lib/<goos>_<goarch>/ (scripts/build.sh or scripts/fetch.sh put it
// there), or in a directory given with CGO_LDFLAGS=-L<dir>, which is searched first. The latter
// is how a module that depends on this one links a lib from a release.

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64 -lwired_ffi -lm -ldl -lpthread
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux_arm64 -lwired_ffi -lm -ldl -lpthread
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64 -lwired_ffi -framework Security -framework CoreFoundation -framework SystemConfiguration
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64 -lwired_ffi -framework Security -framework CoreFoundation -framework SystemConfiguration
#include <stdlib.h>
#include "wired.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// cstr converts s to a C string; empty becomes NULL. Free with freeC.
func cstr(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

func freeC(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

// goString copies and frees a string returned by the library.
func goString(p *C.char) string {
	if p == nil {
		return ""
	}
	s := C.GoString(p)
	C.wired_string_free(p)
	return s
}

func takeErr(p *C.char) error {
	return errors.New("wired: " + goString(p))
}

func cbool(b bool) C.int {
	if b {
		return 1
	}
	return 0
}
