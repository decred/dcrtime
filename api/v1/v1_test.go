package v1

import (
	"testing"
)

var sha256tests = []struct {
	in       string
	expected bool
}{
	{"360f84035942243c6a36537ae2f8673485e6c04455a0a85a0db19690f2541480", true},
	{"27042f4e6eca7d0b2a7ee4026df2ecfa51d3339e6d122aa099118ecd8563bad9", true},
	{"b0b3e798e388f85158a9eb6c5053b81e76aa77e7a780d21cebb8e127517227dc", true},
	// Spaces
	{" 360f84035942243c6a36537ae2f8673485e6c04455a0a85a0db19690f2541480", false},
	{"27042f4e6eca7d0b2a7ee4026df2ecfa51d3339e6d122aa099118ecd8563bad9 ", false},
	// Too short
	{"0b3e798e388f85158a9eb6c5053b81e76aa77e7a780d21cebb8e127517227dc", false},
	{"b0b3e798e388f85158a9eb6c5053b81e76aa77e7a780d21cebb8e127517227d", false},
	// Too long
	{"b0b3e798e388f85158a9eb6c5053b81e76aa77e7a780d21cebb8e127517227dcaaa", false},
	{"aaab0b3e798e388f85158a9eb6c5053b81e76aa77e7a780d21cebb8e127517227dc", false},
	// Too long invalid char
	{"b0b3e798e388f85158a9eb6c5053b81e76aa77e7a780d21cebb8e127517227dcZ", false},
	{"Zb0b3e798e388f85158a9eb6c5053b81e76aa77e7a780d21cebb8e127517227dc", false},
	// Invalid char
	{"b0b3e798e388f85158a9eb6c5053b81e76aa77e7a780d21cebb8e127517227dZ", false},
	{"Zb0b3e798e388f85158a9eb6c5053b81e76aa77e7a780d21cebb8e127517227d", false},
}

var timestampTests = []struct {
	in       string
	expected bool
}{
	{"1523296148", true},
	// Spaces
	{" 1523296148", false},
	{"1523296148 ", false},
	// Too short
	{"523296148", false},
	{"152329614", false},
	// Too long
	{"15232961489", false},
	{"91523296148", false},
	// Too long invalid char
	{"1523296148a", false},
	{"a1523296148", false},
	// Invalid char
	{"152329614a", false},
	{"a523296148", false},
}

func TestSha256Regex(t *testing.T) {
	for _, v := range sha256tests {
		t.Logf("testing %v %v", v.in, v.expected)
		if RegexpSHA256.MatchString(v.in) != v.expected {
			t.Errorf("testing %v %v got %v %v",
				v.in, v.expected, v.in, !v.expected)
		}
	}
}

func TestTimestampRegex(t *testing.T) {
	for _, v := range timestampTests {
		t.Logf("testing %v %v", v.in, v.expected)
		if RegexpTimestamp.MatchString(v.in) != v.expected {
			t.Errorf("testing %v %v got %v %v",
				v.in, v.expected, v.in, !v.expected)
		}
	}
}
