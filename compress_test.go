package pkcs7

import (
	"testing"
)

func TestCompress(t *testing.T) {

	tests := []struct {
		name string
		data []byte
		want []byte
	}{
		{
			name: "1",
			data: []byte("1"),
			want: []byte("1"),
		},
		{
			name: "2",
			data: []byte("2"),
			want: []byte("2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := Compress(tt.data)
			if err != nil {
				t.Fatalf("Compress failed: %v", err)
			}
			p7, err := Parse(compressed)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			got, err := p7.Decompress()
			if err != nil {
				t.Fatalf("Decompress failed: %v", err)
			}
			if string(got) != string(tt.want) {
				t.Fatalf("Decompress failed: got %q, want %q", got, tt.want)
			}
		})
	}
}
