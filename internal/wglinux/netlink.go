//go:build linux
// +build linux

package wglinux

import (
	"bytes"
	"errors"
)

type AttrType int

const (
	MNL_TYPE_UNSPEC AttrType = iota
	MNL_TYPE_U8
	MNL_TYPE_U16
	MNL_TYPE_U32
	MNL_TYPE_U64
	MNL_TYPE_STRING
	MNL_TYPE_FLAG
	MNL_TYPE_MSECS
	MNL_TYPE_NESTED
	MNL_TYPE_NESTED_COMPAT
	MNL_TYPE_NUL_STRING
	MNL_TYPE_NUL_BINARY
	MNL_TYPE_MAX
)

func MnlDataValidate(d []byte, typ AttrType) error {
	switch typ {
	case MNL_TYPE_U8:
		if len(d) != 1 {
			return errors.New("attribute is not u8")
		}
	case MNL_TYPE_U16:
		if len(d) != 2 {
			return errors.New("attribute is not u16")
		}
	case MNL_TYPE_U32:
		if len(d) != 4 {
			return errors.New("attribute is not u32")
		}
	case MNL_TYPE_U64:
		if len(d) != 8 {
			return errors.New("attribute is not u64")
		}
	case MNL_TYPE_NUL_STRING:
		if len(d) == 0 || d[len(d)-1] != 0 {
			return errors.New("attribute is not a NUL-terminated string")
		}

		if bytes.IndexByte(d[:len(d)-1], 0) >= 0 {
			return errors.New("attribute contains embedded NUL")
		}
	default:
		return errors.New("unknown attribute type")
	}

	return nil
}
