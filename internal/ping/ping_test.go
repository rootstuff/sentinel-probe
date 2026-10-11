package ping

import "testing"

const linuxOut = `PING example.com (93.184.216.34) 56(84) bytes of data.
64 bytes from 93.184.216.34: icmp_seq=1 ttl=56 time=11.2 ms
64 bytes from 93.184.216.34: icmp_seq=2 ttl=56 time=10.8 ms
64 bytes from 93.184.216.34: icmp_seq=3 ttl=56 time=12.0 ms

--- example.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 10.800/11.333/12.000/0.498 ms
`

func TestParseLinuxOutput(t *testing.T) {
	if avg := parseAvg(linuxOut); avg == nil || *avg != 11 {
		t.Fatalf("avg %v", avg)
	}
	if parseLoss(linuxOut) != 0 {
		t.Fatal("loss")
	}
	partial := "3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms\nrtt min/avg/max/mdev = 1/2.6/4/0 ms"
	if parseLoss(partial) != 33 || *parseAvg(partial) != 3 {
		t.Fatalf("partial: loss=%d avg=%d", parseLoss(partial), *parseAvg(partial))
	}
	if parseLoss("garbage") != 100 || parseAvg("garbage") != nil {
		t.Fatal("garbage")
	}
}

func TestFailureReasonPrefersStderr(t *testing.T) {
	if got := failureReason("3 packets transmitted, 0 received", "ping: unknown host nope.invalid\n"); got != "ping: unknown host nope.invalid" {
		t.Fatalf("got %q", got)
	}
	if got := failureReason("\n\nfirst\nsecond", ""); got != "first" {
		t.Fatalf("got %q", got)
	}
}

func TestInvalidAndPrivateTargets(t *testing.T) {
	ctx := t.Context()
	if r := Run(ctx, "http://"); r.Status != "offline" || *r.Error != "Invalid host in monitor URL" {
		t.Fatalf("invalid: %+v", r)
	}
	if r := Run(ctx, "10.0.0.1"); r.Status != "offline" || *r.Error != "Target host is not publicly routable" {
		t.Fatalf("private: %+v", r)
	}
	// As PingService: "localhost" fails the hostname rule before the
	// public-address rule gets a say.
	if r := Run(ctx, "https://localhost/x"); r.Status != "offline" || *r.Error != "Invalid host in monitor URL" {
		t.Fatalf("localhost: %+v", r)
	}
	if r := Run(ctx, "127.0.0.1"); r.Status != "offline" || *r.Error != "Target host is not publicly routable" {
		t.Fatalf("loopback literal: %+v", r)
	}
}
