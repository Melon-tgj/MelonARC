package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeTool is a settings tool that records what it was asked to do and answers
// from a table. A call can be made to fail, which is how the rollback path is
// exercised without a desktop.
type fakeTool struct {
	// answers is the standard output per "name arg1 arg2 …" command line.
	answers map[string]string
	// failAt makes the nth mutating call fail, counted from 1. Zero fails
	// nothing.
	failAt int
	// failFrom makes every mutating call fail from the nth one on, which is the
	// case where the rollback cannot run either. Zero disables it.
	failFrom int
	// mutations counts the mutating calls, for failFrom.
	mutations int
	// calls is every command line, in order.
	calls []string
}

// run is the runner the backends take.
//
// A successful write updates the answers table, so a later read sees what the
// desktop would report after that write. Restore tests need this: they are
// about the values currently in force, not about the initial fixture.
func (f *fakeTool) run(_ context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	mutation := isMutation(args)
	if mutation {
		f.mutations++
		if f.failFrom > 0 && f.mutations >= f.failFrom {
			return "", errors.New("the settings tool refused")
		}
	}
	if f.failAt > 0 && mutation {
		f.failAt--
		if f.failAt == 0 {
			return "", errors.New("the settings tool refused")
		}
	}
	if answer, ok := f.answers[line]; ok {
		return answer, nil
	}
	if !mutation {
		return "", errors.New("no answer for " + line)
	}
	f.applyMutation(name, args)
	return "", nil
}

// applyMutation mirrors one write in the answers table, including the way
// reg.exe spells a DWORD when it is read back.
func (f *fakeTool) applyMutation(name string, args []string) {
	if f.answers == nil {
		f.answers = map[string]string{}
	}
	if name == "gsettings" && len(args) == 4 && args[0] == "set" {
		f.answers["gsettings get "+args[1]+" "+args[2]] = args[3] + "\n"
		return
	}
	if name != "reg" || len(args) < 2 {
		return
	}
	key := args[1]
	switch args[0] {
	case "add":
		valueName := flagArg(args, "/v")
		kind := flagArg(args, "/t")
		data := dataArg(args)
		if strings.EqualFold(kind, "REG_DWORD") {
			if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(data), "0x"), 16, 32); err == nil {
				data = "0x" + strconv.FormatUint(n, 16)
			}
		}
		f.answers["reg query "+key+" /v "+valueName] =
			"HKEY_CURRENT_USER\\...\n    " + valueName + "    " + kind + "    " + data + "\n"
	case "delete":
		delete(f.answers, "reg query "+key+" /v "+flagArg(args, "/v"))
	}
}

// flagArg returns the argument after a flag such as /v or /t.
func flagArg(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// dataArg joins everything between /d and /f, because a value may contain
// spaces even though the command line joins arguments with single spaces.
func dataArg(args []string) string {
	start := -1
	for i, arg := range args {
		if arg == "/d" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return ""
	}
	for i := start; i < len(args); i++ {
		if args[i] == "/f" {
			return strings.Join(args[start:i], " ")
		}
	}
	return strings.Join(args[start:], " ")
}

// isMutation reports whether a call changes a setting rather than reading one.
func isMutation(args []string) bool {
	for _, arg := range args {
		if arg == "set" || arg == "add" || arg == "delete" {
			return true
		}
	}
	return false
}

// countMutations counts the calls that change something.
func countMutations(calls []string) int {
	n := 0
	for _, call := range calls {
		if isMutation(strings.Fields(call)[1:]) {
			n++
		}
	}
	return n
}

// gsettingsAnswers is the state a desktop reports before anything is written.
func gsettingsAnswers() map[string]string {
	return map[string]string{
		"gsettings get org.gnome.system.proxy mode":                     "'none'\n",
		"gsettings get org.gnome.system.proxy.http host":                "''\n",
		"gsettings get org.gnome.system.proxy.http port":                "0\n",
		"gsettings get org.gnome.system.proxy.https host":               "''\n",
		"gsettings get org.gnome.system.proxy.https port":               "0\n",
		"gsettings get org.gnome.system.proxy.socks host":               "''\n",
		"gsettings get org.gnome.system.proxy.socks port":               "0\n",
		"gsettings get org.gnome.system.proxy ignore-hosts":             "['localhost', '127.0.0.1', '::1']\n",
		"gsettings get org.gnome.system.proxy.http use-authentication":  "false\n",
		"gsettings get org.gnome.system.proxy.https use-authentication": "false\n",
	}
}

func TestGSettingsApplyWritesEveryField(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers()}
	backend := newGSettings(tool.run)

	err := backend.Apply(context.Background(), Settings{
		HTTP:   "127.0.0.1:7890",
		SOCKS5: "127.0.0.1:7891",
		Bypass: []string{"*.internal"},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	want := []string{
		"gsettings set org.gnome.system.proxy mode 'manual'",
		"gsettings set org.gnome.system.proxy.http host '127.0.0.1'",
		"gsettings set org.gnome.system.proxy.http port 7890",
		"gsettings set org.gnome.system.proxy.https host '127.0.0.1'",
		"gsettings set org.gnome.system.proxy.https port 7890",
		"gsettings set org.gnome.system.proxy.socks host '127.0.0.1'",
		"gsettings set org.gnome.system.proxy.socks port 7891",
		"gsettings set org.gnome.system.proxy ignore-hosts ['localhost', '127.0.0.1', '::1', '*.internal']",
	}
	for _, line := range want {
		if !containsCall(tool.calls, line) {
			t.Errorf("the setting was not written: %q\ncalls:\n%s", line, strings.Join(tool.calls, "\n"))
		}
	}
	// The https proxy is the HTTP listener, because that is the one that
	// answers CONNECT.
	if !containsCall(tool.calls, "gsettings set org.gnome.system.proxy.https port 7890") {
		t.Error("the https proxy does not point at the HTTP inbound")
	}
}

// TestGSettingsApplyClearsAProxyThatIsNotConfigured checks the case of a daemon
// with only one listener: the other kind of proxy is switched off rather than
// left pointing at whatever an earlier run put there.
func TestGSettingsApplyClearsAProxyThatIsNotConfigured(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers()}
	if err := newGSettings(tool.run).Apply(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, line := range []string{
		"gsettings set org.gnome.system.proxy.socks host ''",
		"gsettings set org.gnome.system.proxy.socks port 0",
	} {
		if !containsCall(tool.calls, line) {
			t.Errorf("the socks proxy was left as it was: %q is missing", line)
		}
	}
}

// TestGSettingsApplyRollsBack is the property the whole package exists for: a
// write that fails in the middle leaves the desktop exactly as it was.
func TestGSettingsApplyRollsBack(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers(), failAt: 4}
	backend := newGSettings(tool.run)

	err := backend.Apply(context.Background(), Settings{HTTP: "127.0.0.1:7890", SOCKS5: "127.0.0.1:7891"})
	if err == nil {
		t.Fatal("Apply succeeded although a write failed")
	}
	if !strings.Contains(err.Error(), "previous settings were restored") {
		t.Errorf("the error does not say the setting was put back: %v", err)
	}
	// The three writes before the failure are undone, so the desktop is back on
	// the values it reported.
	for _, line := range []string{
		"gsettings set org.gnome.system.proxy mode 'none'",
		"gsettings set org.gnome.system.proxy.http host ''",
		"gsettings set org.gnome.system.proxy.http port 0",
	} {
		if !containsCall(tool.calls, line) {
			t.Errorf("the value was not restored: %q\ncalls:\n%s", line, strings.Join(tool.calls, "\n"))
		}
	}
}

// TestGSettingsApplyReportsAnUnreadableSetting checks that a desktop which does
// not answer at all produces an error naming the tool, not a panic.
func TestGSettingsApplyReportsAnUnreadableSetting(t *testing.T) {
	tool := &fakeTool{answers: map[string]string{}}
	err := newGSettings(tool.run).Apply(context.Background(), Settings{HTTP: "127.0.0.1:7890"})
	if err == nil {
		t.Fatal("Apply succeeded without answers")
	}
	if !strings.Contains(err.Error(), "gsettings") {
		t.Errorf("the error does not name the tool: %v", err)
	}
}

func TestGSettingsClearTurnsTheModeOff(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers()}
	if err := newGSettings(tool.run).Clear(context.Background()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if !containsCall(tool.calls, "gsettings set org.gnome.system.proxy mode 'none'") {
		t.Errorf("Clear did not switch the mode off:\n%s", strings.Join(tool.calls, "\n"))
	}
	// Nothing else is touched: the addresses stay, so a later Apply does not
	// have to guess what the desktop used to say.
	if n := countMutations(tool.calls); n != 1 {
		t.Errorf("Clear wrote %d settings, want 1:\n%s", n, strings.Join(tool.calls, "\n"))
	}
}

func TestGSettingsEnabled(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{mode: "'none'\n", want: false},
		{mode: "'manual'\n", want: true},
		{mode: "'auto'\n", want: true},
	} {
		answers := gsettingsAnswers()
		answers["gsettings get org.gnome.system.proxy mode"] = tc.mode
		got, err := newGSettings((&fakeTool{answers: answers}).run).Enabled(context.Background())
		if err != nil {
			t.Fatalf("Enabled: %v", err)
		}
		if got != tc.want {
			t.Errorf("mode %q reported enabled=%v", strings.TrimSpace(tc.mode), got)
		}
	}
}

// TestRegistryApplyWritesTheAddressList checks the shape Windows reads: one
// entry per protocol, and the enable flag written last.
func TestRegistryApplyWritesTheAddressList(t *testing.T) {
	tool := &fakeTool{answers: map[string]string{}}
	if err := newRegistry(tool.run).Apply(context.Background(), Settings{
		HTTP:   "127.0.0.1:7890",
		SOCKS5: "127.0.0.1:7891",
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	server := findWrite(tool.calls, "ProxyServer")
	if !strings.Contains(server, "http=127.0.0.1:7890") ||
		!strings.Contains(server, "https=127.0.0.1:7890") ||
		!strings.Contains(server, "socks=127.0.0.1:7891") {
		t.Errorf("ProxyServer = %q", server)
	}
	override := findWrite(tool.calls, "ProxyOverride")
	for _, want := range []string{"localhost", "127.0.0.1", "::1"} {
		if !strings.Contains(override, want) {
			t.Errorf("ProxyOverride = %q, want it to contain %q", override, want)
		}
	}
	// The enable flag comes last, so nothing is ever proxied to a half written
	// address.
	last := tool.calls[len(tool.calls)-1]
	if !strings.Contains(last, "ProxyEnable") || !strings.Contains(last, "/d 1") {
		t.Errorf("the last write was %q, want the enable flag", last)
	}
}

// TestRegistryClearDisablesFirst checks that clearing only turns the proxy off:
// a stale address with the proxy disabled is harmless, the other order is not.
func TestRegistryClearDisablesFirst(t *testing.T) {
	tool := &fakeTool{answers: map[string]string{}}
	if err := newRegistry(tool.run).Clear(context.Background()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if len(tool.calls) != 1 || !strings.Contains(tool.calls[0], "ProxyEnable") || !strings.Contains(tool.calls[0], "/d 0") {
		t.Errorf("Clear wrote %v, want one write that disables the proxy", tool.calls)
	}
}

// TestRegistryApplyRollsBack checks that a failure while writing restores the
// values that were there, including deleting the ones that did not exist.
func TestRegistryApplyRollsBack(t *testing.T) {
	answers := map[string]string{
		"reg query " + internetSettingsKey + " /v ProxyEnable":   "HKEY_CURRENT_USER\\...\n    ProxyEnable    REG_DWORD    0x0\n",
		"reg query " + internetSettingsKey + " /v ProxyServer":   "HKEY_CURRENT_USER\\...\n    ProxyServer    REG_SZ    proxy.corp:8080\n",
		"reg query " + internetSettingsKey + " /v ProxyOverride": "HKEY_CURRENT_USER\\...\n    ProxyOverride    REG_SZ    corp.local\n",
	}
	tool := &fakeTool{answers: answers, failAt: 2}
	err := newRegistry(tool.run).Apply(context.Background(), Settings{HTTP: "127.0.0.1:7890"})
	if err == nil {
		t.Fatal("Apply succeeded although a write failed")
	}
	if !strings.Contains(err.Error(), "restored") {
		t.Errorf("the error does not say the setting was put back: %v", err)
	}
	if !containsCall(tool.calls, "reg add "+internetSettingsKey+" /v ProxyServer /t REG_SZ /d proxy.corp:8080 /f") {
		t.Errorf("the previous ProxyServer was not restored:\n%s", strings.Join(tool.calls, "\n"))
	}
}

// TestRegistryEnabled reads the flag the desktop keeps.
func TestRegistryEnabled(t *testing.T) {
	for _, tc := range []struct {
		answer string
		want   bool
	}{
		{answer: "HKEY_CURRENT_USER\\...\n    ProxyEnable    REG_DWORD    0x1\n", want: true},
		{answer: "HKEY_CURRENT_USER\\...\n    ProxyEnable    REG_DWORD    0x0\n", want: false},
	} {
		tool := &fakeTool{answers: map[string]string{
			"reg query " + internetSettingsKey + " /v ProxyEnable": tc.answer,
		}}
		got, err := newRegistry(tool.run).Enabled(context.Background())
		if err != nil {
			t.Fatalf("Enabled: %v", err)
		}
		if got != tc.want {
			t.Errorf("answer %q reported enabled=%v", strings.TrimSpace(tc.answer), got)
		}
	}

	// A value that is not there is the state of a machine that never had a
	// proxy, not a failure.
	tool := &fakeTool{answers: map[string]string{}}
	got, err := newRegistry(tool.run).Enabled(context.Background())
	if err != nil || got {
		t.Errorf("a missing ProxyEnable reported %v, %v", got, err)
	}
}

// TestControllerReportsTheReason checks the wrapping: the message has to name
// the setting and the reason, because the user cannot see either otherwise.
func TestControllerReportsTheReason(t *testing.T) {
	c := WithBackend(newGSettings((&fakeTool{answers: gsettingsAnswers(), failAt: 1}).run), nil, "")
	err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"})
	if err == nil {
		t.Fatal("Enable succeeded although the write failed")
	}
	if !strings.Contains(err.Error(), "gsettings") {
		t.Errorf("the error does not name the backend: %v", err)
	}
	if c.Applied() {
		t.Error("the controller reports a setting it could not write")
	}
}

// TestControllerReleaseOnlyRestoresItsOwnSetting keeps a stopped daemon from
// switching off a proxy it never turned on.
func TestControllerReleaseOnlyRestoresItsOwnSetting(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers()}
	c := WithBackend(newGSettings(tool.run), nil, "")

	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if len(tool.calls) != 0 {
		t.Errorf("Release wrote %v without having applied anything", tool.calls)
	}

	if err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !containsCall(tool.calls, "gsettings set org.gnome.system.proxy mode 'none'") {
		t.Error("Release did not put the original mode back")
	}
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("a second Release: %v", err)
	}
}

// TestEnablePersistsTheSnapshotBeforeItWrites is the hard-kill guarantee: the
// record is on disk before the first field of the machine is changed.
func TestEnablePersistsTheSnapshotBeforeItWrites(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers()}
	path := filepath.Join(t.TempDir(), "state", SnapshotFile)
	c := WithBackend(newGSettings(tool.run), nil, path)

	if err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the takeover was not persisted: %v", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("decode the snapshot: %v", err)
	}
	if snap.Backend != "gsettings" || len(snap.Fields) == 0 || snap.TakenAt.IsZero() {
		t.Fatalf("snapshot = %+v, want a dated gsettings takeover", snap)
	}
	for _, f := range snap.Fields {
		if f.Written == "" || f.Key == "" {
			t.Errorf("field %+v has no written value", f)
		}
	}
	// The plan was taken before any write: mode records the user's value and
	// the value this program replaced it with, not one and the same thing.
	mode := snap.Fields[0]
	if mode.Key != "mode" || mode.Before != "'none'" || mode.Written != "'manual'" {
		t.Errorf("mode field = %+v, want 'none' replaced by 'manual'", mode)
	}
}

// TestReleaseRestoresEveryField checks a normal shutdown: the machine ends up
// with the values it had before the takeover, and the record is removed.
func TestReleaseRestoresEveryField(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers()}
	path := filepath.Join(t.TempDir(), SnapshotFile)
	c := WithBackend(newGSettings(tool.run), nil, path)
	if err := c.Enable(context.Background(), Settings{
		HTTP: "127.0.0.1:7890", SOCKS5: "127.0.0.1:7891", Bypass: []string{"*.internal"},
	}); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	tool.calls = nil
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	for _, line := range []string{
		"gsettings set org.gnome.system.proxy mode 'none'",
		"gsettings set org.gnome.system.proxy.http host ''",
		"gsettings set org.gnome.system.proxy.http port 0",
		"gsettings set org.gnome.system.proxy.https host ''",
		"gsettings set org.gnome.system.proxy.https port 0",
		"gsettings set org.gnome.system.proxy.socks host ''",
		"gsettings set org.gnome.system.proxy.socks port 0",
		"gsettings set org.gnome.system.proxy ignore-hosts ['localhost', '127.0.0.1', '::1']",
	} {
		if !containsCall(tool.calls, line) {
			t.Errorf("the previous value was not put back: %q\ncalls:\n%s", line, strings.Join(tool.calls, "\n"))
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the takeover record survived a successful release: %v", err)
	}
	if c.Applied() {
		t.Error("the controller still reports a setting it released")
	}
}

// TestReleaseKeepsFieldsTheUserChanged is the ownership rule: a restore may
// not overwrite a value the user edited while the daemon was running.
func TestReleaseKeepsFieldsTheUserChanged(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers()}
	c := WithBackend(newGSettings(tool.run), nil, "")
	if err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	// The user changes the mode and the HTTP host by hand.
	tool.answers["gsettings get org.gnome.system.proxy mode"] = "'auto'\n"
	tool.answers["gsettings get org.gnome.system.proxy.http host"] = "'user.proxy'\n"
	tool.calls = nil
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	for _, line := range []string{
		"gsettings set org.gnome.system.proxy mode 'none'",
		"gsettings set org.gnome.system.proxy.http host ''",
	} {
		if containsCall(tool.calls, line) {
			t.Errorf("a field the user changed was overwritten: %q", line)
		}
	}
	if !containsCall(tool.calls, "gsettings set org.gnome.system.proxy.http port 0") {
		t.Errorf("a field the user did not change was left behind:\n%s", strings.Join(tool.calls, "\n"))
	}
}

// TestSnapshotSurvivesAProcessRestart is the hard-kill case. The first
// controller never releases; the next start recovers from the file on disk.
func TestSnapshotSurvivesAProcessRestart(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers()}
	path := filepath.Join(t.TempDir(), SnapshotFile)
	first := WithBackend(newGSettings(tool.run), nil, path)
	if err := first.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	// No Release: the process is killed outright.

	tool.calls = nil
	second := WithBackend(newGSettings(tool.run), nil, path)
	if err := second.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	for _, line := range []string{
		"gsettings set org.gnome.system.proxy mode 'none'",
		"gsettings set org.gnome.system.proxy.http host ''",
		"gsettings set org.gnome.system.proxy.http port 0",
	} {
		if !containsCall(tool.calls, line) {
			t.Errorf("the next start did not restore %q:\n%s", line, strings.Join(tool.calls, "\n"))
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the recovered record was not removed: %v", err)
	}
	// A second recovery is a no-op, so startup can be retried safely.
	tool.calls = nil
	if err := second.Recover(context.Background()); err != nil {
		t.Fatalf("a second Recover: %v", err)
	}
	if len(tool.calls) != 0 {
		t.Errorf("a second Recover wrote %v", tool.calls)
	}
}

// TestRecoverRejectsAForeignRecord keeps a snapshot from another desktop from
// being applied to this one, and keeps the record for an operator to inspect.
func TestRecoverRejectsAForeignRecord(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers()}
	path := filepath.Join(t.TempDir(), SnapshotFile)
	snap := Snapshot{Backend: "another-desktop", Fields: []Field{{Key: "mode", Written: "'manual'"}}}
	if err := saveSnapshot(path, snap); err != nil {
		t.Fatalf("saveSnapshot: %v", err)
	}
	c := WithBackend(newGSettings(tool.run), nil, path)
	if err := c.Recover(context.Background()); err == nil {
		t.Fatal("a foreign takeover record was accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the foreign record was discarded: %v", err)
	}
}

// TestGSettingsRollbackReportsAnIncompleteRestore checks that a rollback which
// cannot put a value back says so. The controller keeps the takeover record on
// that answer, because the next start is then the only thing that can still
// restore the machine.
func TestGSettingsRollbackReportsAnIncompleteRestore(t *testing.T) {
	tool := &fakeTool{answers: gsettingsAnswers(), failFrom: 3}
	err := newGSettings(tool.run).Apply(context.Background(), Settings{HTTP: "127.0.0.1:7890"})
	if err == nil {
		t.Fatal("Apply succeeded although every write from the third one on failed")
	}
	if !errors.Is(err, ErrRollbackIncomplete) {
		t.Errorf("a failed rollback was not reported as incomplete: %v", err)
	}
}

// stubBackend is a backend a controller test drives directly: it hands out a
// fixed plan and fails Commit the way the test asks.
type stubBackend struct {
	name      string
	commitErr error
	calls     []string
}

func (s *stubBackend) Name() string {
	if s.name != "" {
		return s.name
	}
	return "stub"
}

func (s *stubBackend) Enabled(context.Context) (bool, error) { return false, nil }

func (s *stubBackend) Plan(context.Context, Settings) (Snapshot, error) {
	return Snapshot{Fields: []Field{{Key: "mode", Before: "off", Written: "on", Present: true}}}, nil
}

func (s *stubBackend) Commit(context.Context, Snapshot) error {
	s.calls = append(s.calls, "commit")
	return s.commitErr
}

func (s *stubBackend) Restore(context.Context, Snapshot) (RestoreResult, error) {
	s.calls = append(s.calls, "restore")
	return RestoreResult{Restored: 1}, nil
}

func (s *stubBackend) Clear(context.Context) error { return nil }

// TestEnableKeepsTheRecordWhenTheRollbackFailed is the case the stage exists
// for: the write failed, the undo failed too, and the machine is therefore still
// carrying values this program wrote. Deleting the record would throw away the
// only description of them, so it has to stay for the next start.
func TestEnableKeepsTheRecordWhenTheRollbackFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), SnapshotFile)
	backend := &stubBackend{commitErr: fmt.Errorf("%w: the tool stopped answering", ErrRollbackIncomplete)}
	c := WithBackend(backend, nil, path)

	err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"})
	if !errors.Is(err, ErrRollbackIncomplete) {
		t.Fatalf("Enable = %v, want it to report the incomplete rollback", err)
	}
	if !strings.Contains(err.Error(), "record is kept") {
		t.Errorf("the error does not say the record was kept: %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("the takeover record was removed after a rollback that failed: %v", statErr)
	}
	if !c.Applied() {
		t.Error("the controller does not report the values that are still in force")
	}

	// A shutdown that still happens gets a chance to put the machine back, and
	// the record goes away with it.
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the record survived a successful release: %v", statErr)
	}
}

// TestTheKeptRecordIsWhatTheNextStartRestores is the acceptance criterion of the
// stage, stated as a test: after a takeover that failed and could not be undone,
// a *new* controller reading the same file puts the machine back. Without the
// record it would have nothing to work from.
func TestTheKeptRecordIsWhatTheNextStartRestores(t *testing.T) {
	path := filepath.Join(t.TempDir(), SnapshotFile)
	backend := &stubBackend{commitErr: fmt.Errorf("%w: the tool stopped answering", ErrRollbackIncomplete)}
	first := WithBackend(backend, nil, path)
	if err := first.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err == nil {
		t.Fatal("Enable succeeded although the write failed")
	}

	// The process dies here. The next start has the backend back and only the
	// file to go on.
	next := WithBackend(backend, nil, path)
	if err := next.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !containsCall(backend.calls, "restore") {
		t.Errorf("the next start did not restore anything: %v", backend.calls)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the record survived the recovery it was kept for: %v", statErr)
	}
}

// TestEnableRemovesTheRecordWhenTheRollbackSucceeded keeps the other half of the
// rule: a failure that undid everything leaves nothing to restore, so the record
// must not make the next start restore values that are no longer there.
func TestEnableRemovesTheRecordWhenTheRollbackSucceeded(t *testing.T) {
	path := filepath.Join(t.TempDir(), SnapshotFile)
	c := WithBackend(&stubBackend{commitErr: errors.New("the tool refused")}, nil, path)

	if err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err == nil {
		t.Fatal("Enable succeeded although the write failed")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a record survived a failure that was fully rolled back: %v", statErr)
	}
	if c.Applied() {
		t.Error("the controller reports a setting it did not write")
	}
}

// TestRegistryRestoreDeletesValuesThatWereMissing is the registry half of the
// ownership rule: a value the user never had must be absent again, not present
// with a zero or a stale address in it.
func TestRegistryRestoreDeletesValuesThatWereMissing(t *testing.T) {
	tool := &fakeTool{answers: map[string]string{}}
	c := WithBackend(newRegistry(tool.run), nil, "")
	if err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	tool.calls = nil
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	for _, name := range registryNames {
		want := "reg delete " + internetSettingsKey + " /v " + name + " /f"
		if !containsCall(tool.calls, want) {
			t.Errorf("the value that did not exist was not deleted: %q\ncalls:\n%s", want, strings.Join(tool.calls, "\n"))
		}
	}
}

// TestRegistryRestorePutsBackExistingValues checks both halves together: an
// existing value is restored to its old data, a value the user changed since
// the takeover is kept, and the absence of a third value is restored as absence.
func TestRegistryRestorePutsBackExistingValues(t *testing.T) {
	answers := map[string]string{
		"reg query " + internetSettingsKey + " /v ProxyEnable": "HKEY_CURRENT_USER\\...\n    ProxyEnable    REG_DWORD    0x0\n",
		"reg query " + internetSettingsKey + " /v ProxyServer": "HKEY_CURRENT_USER\\...\n    ProxyServer    REG_SZ    proxy.corp:8080\n",
	}
	tool := &fakeTool{answers: answers}
	c := WithBackend(newRegistry(tool.run), nil, "")
	if err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	// The user edits ProxyServer while the daemon runs.
	tool.answers["reg query "+internetSettingsKey+" /v ProxyServer"] =
		"HKEY_CURRENT_USER\\...\n    ProxyServer    REG_SZ    user.proxy:3128\n"
	tool.calls = nil
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !containsCall(tool.calls, "reg add "+internetSettingsKey+" /v ProxyEnable /t REG_DWORD /d 0 /f") {
		t.Errorf("the previous enable flag was not restored:\n%s", strings.Join(tool.calls, "\n"))
	}
	if !containsCall(tool.calls, "reg delete "+internetSettingsKey+" /v ProxyOverride /f") {
		t.Errorf("the value that was absent was not deleted:\n%s", strings.Join(tool.calls, "\n"))
	}
	if containsCall(tool.calls, "reg add "+internetSettingsKey+" /v ProxyServer /t REG_SZ /d proxy.corp:8080 /f") ||
		containsCall(tool.calls, "reg delete "+internetSettingsKey+" /v ProxyServer /f") {
		t.Errorf("the value the user changed was overwritten:\n%s", strings.Join(tool.calls, "\n"))
	}
}

// TestValueComparisonsIgnoreTheDesktopsFormatting pins the two normalisations
// a restore depends on: a reformatted list and a DWORD printed as hex.
func TestValueComparisonsIgnoreTheDesktopsFormatting(t *testing.T) {
	if !sameGVariant("['localhost', '127.0.0.1', '::1']", "['localhost','127.0.0.1','::1']") {
		t.Error("a reformatted list was read as a user change")
	}
	if sameGVariant("'auto'", "'manual'") {
		t.Error("a changed mode was read as unchanged")
	}
	if !sameRegistryData("0x1", "1", "REG_DWORD") {
		t.Error("a DWORD printed as hex was read as a user change")
	}
	if sameRegistryData("0x0", "1", "REG_DWORD") {
		t.Error("a changed DWORD was read as unchanged")
	}
}

func TestSettingsValidate(t *testing.T) {
	tests := []struct {
		name string
		s    Settings
		want string
	}{
		{name: "nothing to point at", s: Settings{}, want: "no inbound listener"},
		{name: "no port", s: Settings{HTTP: "127.0.0.1"}, want: "not a host:port"},
		{name: "a port that is not a number", s: Settings{HTTP: "127.0.0.1:proxy"}, want: "invalid port"},
		{name: "a port out of range", s: Settings{HTTP: "127.0.0.1:70000"}, want: "invalid port"},
		{name: "no host", s: Settings{HTTP: ":7890"}, want: "no host"},
		{name: "http only", s: Settings{HTTP: "127.0.0.1:7890"}},
		{name: "socks only", s: Settings{SOCKS5: "127.0.0.1:7891"}},
		{name: "an address literal", s: Settings{HTTP: "[::1]:7890"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestBypassListKeepsTheDefaultsAndTheOrder checks the list that is written: the
// loopback names are always there, a configured entry comes after them and a
// duplicate is dropped.
func TestBypassListKeepsTheDefaultsAndTheOrder(t *testing.T) {
	got := Settings{Bypass: []string{" *.internal ", "127.0.0.1", "intranet", ""}}.BypassList()
	want := []string{"localhost", "127.0.0.1", "::1", "*.internal", "intranet"}
	if len(got) != len(want) {
		t.Fatalf("bypass = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bypass = %v, want %v", got, want)
		}
	}
}

// containsCall reports whether the tool ran this command line.
func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

// findWrite returns the first write that mentions value, which is how the tests
// look at what was stored rather than at what was read.
func findWrite(calls []string, value string) string {
	for _, call := range calls {
		if strings.Contains(call, " add ") && strings.Contains(call, value) {
			return call
		}
	}
	return ""
}
