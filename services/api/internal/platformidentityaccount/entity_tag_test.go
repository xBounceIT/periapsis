package platformidentityaccount

import "testing"

func TestAccountEntityTagIsCanonicalAndStrong(t *testing.T) {
	for _, versions := range [][2]int64{
		{1, 1}, {17, 23}, {maximumAccountVersion, maximumAccountVersion},
	} {
		tag, err := EntityTag(versions[0], versions[1])
		if err != nil {
			t.Fatalf("EntityTag(%d, %d) error = %v", versions[0], versions[1], err)
		}
		resourceVersion, userVersion, err := ParseEntityTag(tag)
		if err != nil || resourceVersion != versions[0] || userVersion != versions[1] {
			t.Fatalf(
				"ParseEntityTag(%q) = %d, %d, %v",
				tag, resourceVersion, userVersion, err,
			)
		}
	}
	for _, value := range []string{
		"", "v1-u1", "*", `W/"v1-u1"`, `"v0-u1"`, `"v1-u0"`,
		`"v01-u1"`, `"v1-u01"`, `"V1-u1"`, `"v1-U1"`, `"v1-u1 "`,
		` "v1-u1"`, `"v1-u1","v2-u1"`, `"v1-u1"\t`, `"v1"`,
		`"v1-u1-u2"`, `"v2147483648-u1"`, `"v1-u2147483648"`,
	} {
		if _, _, err := ParseEntityTag(value); err == nil {
			t.Fatalf("ParseEntityTag(%q) succeeded", value)
		}
	}
}
