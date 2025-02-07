package byteutil_test

import (
	"bytes"
	"testing"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"github.com/stretchr/testify/require"
)

func TestCCharSliceToStr(t *testing.T) {
	byteArray := []int8{104, 101, 108, 108, 111, 0}

	ret := byteutil.CCharSliceToStr(byteArray)
	require.Equal(t, ret, "hello\x00")
}

func TestReadNullTerminatedString(t *testing.T) {
	// fits within buffer and has a null terminator
	b := []byte{'a', '\x00', 'b'}
	arr := make([]int8, 2)

	require.NoError(t, byteutil.ReadNullTerminatedString(bytes.NewBuffer(b), arr))
	require.Equal(t, arr, []int8{97, 0})

	// fits, but no null terminatior
	b2 := []byte{'a'}
	arr2 := make([]int8, 2)
	err := byteutil.ReadNullTerminatedString(bytes.NewBuffer(b2), arr2)
	require.Equal(t, err, byteutil.ErrNoNullTerminator)

	// doesn't fit, no null terminator

	b3 := []byte{'a', 'b', 'c'}
	arr3 := make([]int8, 3)
	err = byteutil.ReadNullTerminatedString(bytes.NewBuffer(b3), arr3)
	require.Equal(t, err, byteutil.ErrNoNullTerminator)

}
