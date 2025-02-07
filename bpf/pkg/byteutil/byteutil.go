package byteutil

import (
	"bytes"
	"errors"
)

var (
	ErrNoNullTerminator = errors.New("null terminator not found before array end")
)

func CCharSliceToStr(arr []int8) string {
	byteSlice := make([]byte, len(arr))
	for i, b := range arr {
		if b == 0 {
			return string(byteSlice)
		}
		byteSlice[i] = byte(b)
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
