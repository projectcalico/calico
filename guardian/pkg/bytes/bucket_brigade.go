package bytes

type BucketBrigade struct {
	length  int
	buckets [][]byte
}

func (bm *BucketBrigade) Append(bytes []byte) {
	bm.length += len(bytes)
	bm.buckets = append(bm.buckets, bytes)
}

// flatten combines all the byte slices in buckets into one byte array
func (bm *BucketBrigade) Flatten() []byte {
	// Create an array with a capacity of "length"
	bytes := make([]byte, 0, bm.length)
	for _, bucket := range bm.buckets {
		// Since the capacity of bytes is the sum of the lengths of all the byte slices append will never create a new
		// slice
		bytes = append(bytes, bucket...)
	}

	return bytes
}
