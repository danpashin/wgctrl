package wgtypes

import (
	"fmt"
	"strconv"
	"strings"
)

func parseRange(s string, bitsize int) (uint64, uint64, bool) {
	if s == "" {
		return 0, 0, false
	}

	lo, err := strconv.ParseUint(s, 10, bitsize)
	if err != nil {
		return 0, 0, false
	}

	hi := lo

	if before, after, ok := strings.Cut(s, "-"); ok {
		if before == "" || after == "" {
			return 0, 0, false
		}

		lo, err = strconv.ParseUint(before, 10, bitsize)
		if err != nil {
			return 0, 0, false
		}

		hi, err = strconv.ParseUint(after, 10, bitsize)
		if err != nil || hi < lo {
			return 0, 0, false
		}
	}

	return lo, hi, true
}

type Range32 struct {
	r uint64
}

func Range32FromParts(lo uint32, hi uint32) *Range32 {
	return &Range32{r: uint64(hi)<<32 | uint64(lo)}
}

func Range32FromSingle(r uint64) *Range32 {
	return &Range32{r}
}

func Range32FromString(s string) *Range32 {
	lo, hi, success := parseRange(s, 32)
	if !success {
		return nil
	}

	return Range32FromParts(uint32(lo), uint32(hi))
}

func (r Range32) Uint32() uint32 {
	return uint32(r.r)
}

func (r Range32) String() string {
	lo := uint32(r.r)
	hi := uint32(r.r >> 32)

	if lo == hi {
		return fmt.Sprintf("%d", lo)
	}

	return fmt.Sprintf("%d-%d", lo, hi)
}

func (r Range32) Uint64() uint64 {
	return r.r
}

func (r Range32) IsZero() bool {
	return r.r == 0
}

type Range16 struct {
	r uint32
}

func Range16FromParts(lo uint16, hi uint16) *Range16 {
	return &Range16{r: uint32(hi)<<16 | uint32(lo)}
}

func Range16FromSingle(r uint32) *Range16 {
	return &Range16{r}
}

func Range16FromString(s string) *Range16 {
	lo, hi, success := parseRange(s, 16)
	if !success {
		return nil
	}

	return Range16FromParts(uint16(lo), uint16(hi))
}

func (r Range16) Uint16() uint16 {
	return uint16(r.r)
}

func (r Range16) String() string {
	lo := uint16(r.r)
	hi := uint16(r.r >> 16)

	if lo == hi {
		return fmt.Sprintf("%d", lo)
	}

	return fmt.Sprintf("%d-%d", lo, hi)
}

func (r Range16) Uint32() uint32 {
	return r.r
}

func (r Range16) IsZero() bool {
	return r.r == 0
}
