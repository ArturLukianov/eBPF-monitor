package helpers

func NullTermStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func OpenFlagsToOp(flags uint32) string {
	const (
		O_WRONLY = 0x1
		O_RDWR   = 0x2
		O_CREAT  = 0x40
	)
	if flags&(O_WRONLY|O_RDWR|O_CREAT) != 0 {
		return "write"
	}
	return "read"
}
