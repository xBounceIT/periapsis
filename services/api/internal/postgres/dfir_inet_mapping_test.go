package postgres

import "testing"

func TestDFIRInetHostProjection(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ input, want string }{
		{"198.51.100.42/32", "198.51.100.42"},
		{"198.51.100.42", "198.51.100.42"},
		{"2001:0db8::42/128", "2001:db8::42"},
		{"2001:db8::42", "2001:db8::42"},
		{"198.51.100.42/24", ""},
		{"2001:db8::42/64", ""},
		{"invalid", ""},
	} {
		t.Run(test.input, func(t *testing.T) {
			if got := dfirInetHost(test.input); got != test.want {
				t.Fatalf("host = %q; want %q", got, test.want)
			}
		})
	}
}
