package byteutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

var (
	ErrNoNullTerminator = errors.New("null terminator not found before array end")
)

func Ipv4Str(ip uint32) string {
	bytes := make([]byte, 4)
	binary.NativeEndian.PutUint32(bytes, ip)
	return net.IP(bytes).String()
}

func Ipv6Str(ipv6 [16]uint8) string {
	return net.IP(ipv6[:]).String()
}

func EmptyIpv6(ipv6 string) bool {
	return ipv6 == "::"
}

// excludes null terminators from output string
func CCharSliceToStr(arr []int8) string {
	byteSlice := make([]byte, len(arr))
	retLen := 0
	for i, b := range arr {
		if b == 0 {
			return string(byteSlice[:retLen])
		}
		byteSlice[i] = byte(b)
		retLen++
	}
	return string(byteSlice)

}

// ReadNullTerminatedString reads a null-terminated string into the provided array
func ReadNullTerminatedString(buf *bytes.Buffer, arr []int8) error {
	var last int8
	for i := 0; i < len(arr); i++ {
		b, err := buf.ReadByte()
		if err != nil {
			if err.Error() == "EOF" && last != 0 {
				return ErrNoNullTerminator
			} else if last == 0 {
				return nil
			}
			return err
		}
		last = int8(b)
		arr[i] = last

		if b == 0 { // null terminator for C char *
			return nil
		}
	}
	return ErrNoNullTerminator
}
