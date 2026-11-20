package events

import "testing"

func TestBlockLadder(t *testing.T) {
	for _, c := range []struct {
		nc          string
		level, want int
	}{
		{"hosting", 1, 900}, {"hosting", 3, 86400}, {"hosting", 4, 604800}, {"hosting", 9, 604800},
		{"residential", 3, 14400}, {"residential", 4, 86400}, {"vpn", 6, 86400}, {"unknown", 0, 900},
	} {
		if got := BlockDurationS(c.nc, c.level); got != c.want {
			t.Errorf("%s level %d: %d, want %d", c.nc, c.level, got, c.want)
		}
	}
	if LadderHosting[len(LadderHosting)-1] != MaxBlockHostingS || LadderDefault[len(LadderDefault)-1] != MaxBlockDefaultS {
		t.Error("caps differ from the last ladder steps")
	}
}
