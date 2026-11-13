package policy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// fakeProber returns the latency configured per member and fails the members
// listed as down.
type fakeProber struct {
	latency map[string]time.Duration
	down    map[string]bool
	calls   atomic.Int64
}

func (f *fakeProber) Probe(ctx context.Context, member string) (time.Duration, error) {
	f.calls.Add(1)
	if f.down[member] {
		return 0, errors.New("probe failed")
	}
	d, ok := f.latency[member]
	if !ok {
		return 20 * time.Millisecond, nil
	}
	return d, nil
}

func TestNewSelect(t *testing.T) {
	g, err := NewSelect("Proxy", []string{"a", "b", "c"}, "")
	if err != nil {
		t.Fatalf("NewSelect: %v", err)
	}
	if got := g.Active(); got != "a" {
		t.Fatalf("default active = %q, want a", got)
	}
	if g.Kind() != KindSelect || g.Name() != "Proxy" {
		t.Fatalf("group = %s/%s", g.Name(), g.Kind())
	}
	if _, err := NewSelect("G", []string{"a"}, "z"); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("initial member error = %v", err)
	}
	if _, err := NewSelect("G", nil, ""); err == nil {
		t.Fatal("a group without members must be rejected")
	}
	if _, err := NewSelect("G", []string{"a", "a"}, ""); err == nil {
		t.Fatal("duplicate members must be rejected")
	}
	if _, err := NewSelect("", []string{"a"}, ""); err == nil {
		t.Fatal("a group without a name must be rejected")
	}
}

func TestSelectSwitchTakesEffectImmediately(t *testing.T) {
	g, err := NewSelect("Proxy", []string{"a", "b"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Select("b"); err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got := g.Active(); got != "b" {
		t.Fatalf("active = %q, want b", got)
	}
	if err := g.Select("nope"); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("error = %v, want ErrUnknownMember", err)
	}
	if got := g.Active(); got != "b" {
		t.Fatalf("a failed selection changed the active member to %q", got)
	}
	g.NotifyFailure("b")
	if got := g.Active(); got != "b" {
		t.Fatalf("a manual group must ignore failures, active = %q", got)
	}
}

func TestSelectStatus(t *testing.T) {
	g, _ := NewSelect("Proxy", []string{"a", "b"}, "b")
	st := g.Status()
	if st.Name != "Proxy" || st.Kind != KindSelect || st.Active != "b" {
		t.Fatalf("status = %+v", st)
	}
	if len(st.Members) != 2 || st.Members[0].Name != "a" {
		t.Fatalf("members = %+v", st.Members)
	}
	if st.Members[0].Healthy != true || st.Members[0].Checked {
		t.Fatalf("a manual group must not claim probe results: %+v", st.Members[0])
	}
}

func TestURLTestPicksFastest(t *testing.T) {
	p := &fakeProber{latency: map[string]time.Duration{
		"slow": 200 * time.Millisecond,
		"fast": 10 * time.Millisecond,
		"mid":  60 * time.Millisecond,
	}}
	g, err := NewURLTest("Auto", []string{"slow", "fast", "mid"}, p, time.Minute, time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if got := g.Active(); got != "slow" {
		t.Fatalf("initial active = %q, want the first member", got)
	}
	g.Check(context.Background())
	if got := g.Active(); got != "fast" {
		t.Fatalf("active = %q, want fast", got)
	}
	st := g.Status()
	if st.Active != "fast" || st.Checked.IsZero() {
		t.Fatalf("status = %+v", st)
	}
	var fast MemberStatus
	for _, m := range st.Members {
		if m.Name == "fast" {
			fast = m
		}
	}
	if !fast.Healthy || fast.Latency != 10*time.Millisecond || !fast.Checked {
		t.Fatalf("fast member status = %+v", fast)
	}
}

func TestURLTestTolerancePreventsFlapping(t *testing.T) {
	p := &fakeProber{latency: map[string]time.Duration{
		"a": 100 * time.Millisecond,
		"b": 90 * time.Millisecond,
	}}
	g, err := NewURLTest("Auto", []string{"a", "b"}, p, time.Minute, time.Second, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Check(context.Background())
	if got := g.Active(); got != "a" {
		t.Fatalf("active = %q, a 10ms gain is inside the 50ms tolerance", got)
	}

	// A gain beyond the tolerance does switch.
	p.latency["b"] = 10 * time.Millisecond
	g.Check(context.Background())
	if got := g.Active(); got != "b" {
		t.Fatalf("active = %q, want b once it is clearly faster", got)
	}
}

func TestURLTestSkipsUnhealthy(t *testing.T) {
	p := &fakeProber{
		latency: map[string]time.Duration{"a": time.Millisecond, "b": 5 * time.Millisecond},
		down:    map[string]bool{"a": true},
	}
	g, err := NewURLTest("Auto", []string{"a", "b"}, p, time.Minute, time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Check(context.Background())
	if got := g.Active(); got != "b" {
		t.Fatalf("active = %q, want the healthy member", got)
	}
	st := g.Status()
	if st.Members[0].Healthy {
		t.Fatalf("failed member reported as healthy: %+v", st.Members[0])
	}
}

func TestURLTestKeepsActiveWhenAllFail(t *testing.T) {
	p := &fakeProber{down: map[string]bool{"a": true, "b": true}}
	g, err := NewURLTest("Auto", []string{"a", "b"}, p, time.Minute, time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Check(context.Background())
	if got := g.Active(); got != "a" {
		t.Fatalf("active = %q, want the previous member", got)
	}
	if err := g.Select("b"); !errors.Is(err, ErrNotManual) {
		t.Fatalf("Select error = %v, want ErrNotManual", err)
	}
}

func TestURLTestNotifyFailureSwitchesImmediately(t *testing.T) {
	p := &fakeProber{latency: map[string]time.Duration{
		"a": 10 * time.Millisecond,
		"b": 80 * time.Millisecond,
	}}
	g, err := NewURLTest("Auto", []string{"a", "b"}, p, time.Minute, time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Check(context.Background())
	if got := g.Active(); got != "a" {
		t.Fatalf("active = %q", got)
	}
	g.NotifyFailure("a")
	if got := g.Active(); got != "b" {
		t.Fatalf("active = %q, want b after a failed", got)
	}
}

func TestURLTestRunsOnInterval(t *testing.T) {
	var calls atomic.Int64
	p := ProbeFunc(func(ctx context.Context, member string) (time.Duration, error) {
		calls.Add(1)
		return 5 * time.Millisecond, nil
	})
	g, err := NewURLTest("Auto", []string{"a", "b"}, p, 10*time.Millisecond, time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	g.Start(context.Background())
	defer g.Close()
	waitFor(t, 2*time.Second, func() bool { return calls.Load() >= 4 })
}

func TestFallbackOrderAndFailover(t *testing.T) {
	p := &fakeProber{latency: map[string]time.Duration{
		"a": 300 * time.Millisecond,
		"b": 10 * time.Millisecond,
		"c": 20 * time.Millisecond,
	}}
	g, err := NewFallback("Backup", []string{"a", "b", "c"}, p, time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	// Priority, not latency, decides.
	g.Check(context.Background())
	if got := g.Active(); got != "a" {
		t.Fatalf("active = %q, want a", got)
	}

	p.down = map[string]bool{"a": true}
	g.Check(context.Background())
	if got := g.Active(); got != "b" {
		t.Fatalf("active = %q, want b after a failed", got)
	}

	// Recovery restores the priority order.
	p.down = nil
	g.Check(context.Background())
	if got := g.Active(); got != "a" {
		t.Fatalf("active = %q, want a after recovery", got)
	}
}

func TestFallbackNotifyFailure(t *testing.T) {
	p := &fakeProber{}
	g, err := NewFallback("Backup", []string{"a", "b"}, p, time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.NotifyFailure("a")
	if got := g.Active(); got != "b" {
		t.Fatalf("active = %q, want b", got)
	}
	g.NotifyFailure("b")
	if got := g.Active(); got != "a" {
		t.Fatalf("active = %q, with everything down the group keeps a target", got)
	}
	if _, err := NewFallback("B", nil, p, 0, 0); err == nil {
		t.Fatal("a group without members must be rejected")
	}
	if _, err := NewFallback("B", []string{"a"}, nil, 0, 0); err == nil {
		t.Fatal("a probing group without a prober must be rejected")
	}
}

func TestRegistryResolve(t *testing.T) {
	r := NewRegistry()
	for _, leaf := range []string{"DIRECT", "REJECT", "node-a", "node-b"} {
		if err := r.AddLeaf(leaf); err != nil {
			t.Fatalf("AddLeaf(%s): %v", leaf, err)
		}
	}
	inner, err := NewSelect("Inner", []string{"node-a", "node-b"}, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	outer, err := NewSelect("Outer", []string{"Inner", "DIRECT"}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []Group{inner, outer} {
		if err := r.AddGroup(g); err != nil {
			t.Fatalf("AddGroup(%s): %v", g.Name(), err)
		}
	}

	res, err := r.Resolve("Outer")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Leaf != "node-b" || res.String() != "Outer -> Inner -> node-b" {
		t.Fatalf("resolution = %+v (%s)", res, res)
	}
	if res, err := r.Resolve("DIRECT"); err != nil || res.Leaf != "DIRECT" {
		t.Fatalf("leaf resolution = %+v, %v", res, err)
	}
	if _, err := r.Resolve("missing"); !errors.Is(err, ErrUnknownTarget) {
		t.Fatalf("error = %v, want ErrUnknownTarget", err)
	}
	if err := r.AddLeaf("DIRECT"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate leaf error = %v", err)
	}
	if err := r.AddLeaf("Outer"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("a leaf must not shadow a group, error = %v", err)
	}
	if got := r.Names(); len(got) != 6 {
		t.Fatalf("Names = %v", got)
	}
	if got := r.Groups(); len(got) != 2 || got[0].Name() != "Inner" {
		t.Fatalf("Groups = %v", got)
	}
	if g, ok := r.Group("Inner"); !ok || g.Active() != "node-b" {
		t.Fatalf("Group = %v, %v", g, ok)
	}
	r.Close()
}

func TestRegistryDetectsCycle(t *testing.T) {
	r := NewRegistry()
	a, _ := NewSelect("A", []string{"B"}, "")
	b, _ := NewSelect("B", []string{"A"}, "")
	if err := r.AddGroup(a); err != nil {
		t.Fatal(err)
	}
	if err := r.AddGroup(b); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("A"); !errors.Is(err, ErrCycle) {
		t.Fatalf("error = %v, want ErrCycle", err)
	}
}

func TestRegistryRejectsDuplicateGroup(t *testing.T) {
	r := NewRegistry()
	g, _ := NewSelect("G", []string{"a"}, "")
	if err := r.AddGroup(g); err != nil {
		t.Fatal(err)
	}
	if err := r.AddGroup(g); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("error = %v", err)
	}
	if err := r.AddGroup(nil); err == nil {
		t.Fatal("a nil group must be rejected")
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before the deadline")
}
