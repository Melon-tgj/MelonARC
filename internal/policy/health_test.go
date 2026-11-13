package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedProber answers from a table the test can change between rounds.
type scriptedProber struct {
	mu      sync.Mutex
	failing map[string]error
	latency map[string]time.Duration
}

func newScriptedProber() *scriptedProber {
	return &scriptedProber{
		failing: make(map[string]error),
		latency: make(map[string]time.Duration),
	}
}

// fail makes every probe of a member fail with err.
func (p *scriptedProber) fail(member string, err error) {
	p.mu.Lock()
	p.failing[member] = err
	p.mu.Unlock()
}

// recover makes a member answer healthily again.
func (p *scriptedProber) recoverMember(member string, latency time.Duration) {
	p.mu.Lock()
	delete(p.failing, member)
	p.latency[member] = latency
	p.mu.Unlock()
}

// Probe implements Prober.
func (p *scriptedProber) Probe(_ context.Context, member string) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err, ok := p.failing[member]; ok {
		return 0, err
	}
	return p.latency[member], nil
}

// memberOf returns the status of one member.
func memberOf(t *testing.T, st Status, name string) MemberStatus {
	t.Helper()
	for _, m := range st.Members {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("group %q has no member %q", st.Name, name)
	return MemberStatus{}
}

// TestConsecutiveFailuresAccumulateAndReset walks a member through three probe
// rounds: two failures then a success. The count has to climb and then clear,
// and the error text has to appear and disappear with it.
func TestConsecutiveFailuresAccumulateAndReset(t *testing.T) {
	prober := newScriptedProber()
	prober.fail("a", errors.New("probe a: dial tcp: connection refused"))
	group, err := NewURLTest("auto", []string{"a", "b"}, prober, time.Hour, time.Second, 0)
	if err != nil {
		t.Fatalf("NewURLTest: %v", err)
	}
	prober.recoverMember("b", 10*time.Millisecond)

	ctx := context.Background()
	group.Check(ctx)
	first := memberOf(t, group.Status(), "a")
	if first.Failures != 1 || first.Healthy || !first.Checked {
		t.Fatalf("after one round: %+v, want one failure and unhealthy", first)
	}
	if first.CheckedAt.IsZero() {
		t.Error("a probed member carries no timestamp")
	}
	if !strings.Contains(first.Error, "connection refused") {
		t.Fatalf("error = %q, want the probe failure", first.Error)
	}
	if st := group.Status(); st.AllUnhealthy {
		// b is healthy, so the group is not all-unhealthy.
		t.Fatalf("group reports all-unhealthy with a healthy member: %+v", st.Members)
	}

	group.Check(ctx)
	second := memberOf(t, group.Status(), "a")
	if second.Failures != 2 {
		t.Fatalf("failures = %d after two rounds, want 2", second.Failures)
	}

	prober.recoverMember("a", 5*time.Millisecond)
	group.Check(ctx)
	third := memberOf(t, group.Status(), "a")
	if !third.Healthy || third.Failures != 0 {
		t.Fatalf("after recovery: %+v, want healthy with no failures", third)
	}
	if third.Error != "" {
		t.Fatalf("error = %q, want it cleared by a healthy probe", third.Error)
	}
	if group.Status().AllUnhealthy {
		t.Fatal("the group still reports all-unhealthy after a healthy round")
	}
}

// TestAllUnhealthyNeedsEveryMemberDown pins the flag that makes a misconfigured
// probe URL visible: it is only true when nothing is left to route to.
func TestAllUnhealthyNeedsEveryMemberDown(t *testing.T) {
	prober := newScriptedProber()
	prober.fail("a", errors.New("down"))
	prober.fail("b", errors.New("down"))
	group, err := NewFallback("backup", []string{"a", "b"}, prober, time.Hour, time.Second)
	if err != nil {
		t.Fatalf("NewFallback: %v", err)
	}
	if group.Status().AllUnhealthy {
		t.Fatal("a group that was never probed reports itself dead")
	}

	group.Check(context.Background())
	st := group.Status()
	if !st.AllUnhealthy {
		t.Fatalf("all-unhealthy = false with both members down: %+v", st.Members)
	}
	for _, m := range st.Members {
		if m.Failures != 1 {
			t.Errorf("%s failures = %d, want 1", m.Name, m.Failures)
		}
	}

	prober.recoverMember("b", 20*time.Millisecond)
	group.Check(context.Background())
	if group.Status().AllUnhealthy {
		t.Fatal("all-unhealthy stayed true after one member recovered")
	}
}

// TestInUseFailureCounts checks that a member reported as failed in use adds to
// the same counter a failed probe uses, without waiting for a probe round.
func TestInUseFailureCounts(t *testing.T) {
	group, err := NewFallback("backup", []string{"a", "b"}, newScriptedProber(), time.Hour, time.Second)
	if err != nil {
		t.Fatalf("NewFallback: %v", err)
	}
	group.NotifyFailure("a")
	st := group.Status()
	a := memberOf(t, st, "a")
	if a.Failures != 1 || a.Healthy {
		t.Fatalf("after an in-use failure: %+v", a)
	}
	if a.CheckedAt.IsZero() {
		t.Error("an in-use failure carries no timestamp")
	}
	if st.Active != "b" {
		t.Fatalf("active = %q, want the group to have moved on", st.Active)
	}
	group.NotifyFailure("a")
	if got := memberOf(t, group.Status(), "a").Failures; got != 2 {
		t.Fatalf("failures = %d after two in-use failures, want 2", got)
	}
}

// TestSelectRecordsFailuresWithoutSwitching checks the manual group: the
// selection is the user's and never moves, but the failures are visible.
func TestSelectRecordsFailuresWithoutSwitching(t *testing.T) {
	group, err := NewSelect("manual", []string{"a", "b"}, "")
	if err != nil {
		t.Fatalf("NewSelect: %v", err)
	}
	group.NotifyFailure("a")
	group.NotifyFailure("a")

	st := group.Status()
	if st.Active != "a" {
		t.Fatalf("active = %q, want the manual selection to stay", st.Active)
	}
	a := memberOf(t, st, "a")
	if a.Failures != 2 {
		t.Fatalf("failures = %d, want 2", a.Failures)
	}
	// Nothing probes a manual group, so the member is not "down": it is simply
	// unprobed, and reporting it down would leave it down forever.
	if !a.Healthy || a.Checked {
		t.Fatalf("member = %+v, want healthy and unprobed", a)
	}
	if a.CheckedAt.IsZero() {
		t.Error("the in-use failure carries no timestamp")
	}
	if st.AllUnhealthy {
		t.Fatal("a manual group can never be all-unhealthy: nothing probes it")
	}
}

// TestMemberErrorIsShortened keeps a snapshot small even when a probe error
// repeats a long URL or a remote message.
func TestMemberErrorIsShortened(t *testing.T) {
	prober := newScriptedProber()
	prober.fail("a", errors.New(strings.Repeat("x", 4096)))
	group, err := NewURLTest("auto", []string{"a"}, prober, time.Hour, time.Second, 0)
	if err != nil {
		t.Fatalf("NewURLTest: %v", err)
	}
	group.Check(context.Background())
	got := memberOf(t, group.Status(), "a").Error
	if len(got) > maxErrorLen+3 {
		t.Fatalf("error is %d bytes, want it bounded near %d", len(got), maxErrorLen)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("error = %q, want a truncation marker", got)
	}
}

// TestShortErrorKeepsValidText cuts a multi-byte message at a rune boundary so
// the snapshot stays valid text.
func TestShortErrorKeepsValidText(t *testing.T) {
	err := errors.New(strings.Repeat("连接失败", 100))
	got := shortError(err)
	if len(got) > maxErrorLen+3 {
		t.Fatalf("error is %d bytes, want it bounded", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("error = %q, want a truncation marker", got)
	}
	if shortError(nil) != "" {
		t.Fatal("a nil error must render as an empty string")
	}
}
