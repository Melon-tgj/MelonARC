package outbound

// Validate runs every static check New performs on a spec, without keeping the
// dialer it would build.
//
// It exists for importers. A share link becomes exactly the [Proxy] entry a
// configuration line describes, so this package — the code that will eventually
// build the dialer — is the only place that can say whether the cipher, the
// account identifier, the flow, the TLS options or the credentials are usable.
// Running those checks when the link is parsed reports a bad node while the
// importer still has the link in hand, instead of leaving it for startup to
// refuse with a line number.
//
// Validate is deliberately implemented by calling New: copying the checks into
// a second function would give the importer and the daemon two lists of rules
// that can drift apart. The name is cleared so an error quotes the option and
// not a display name the importer may not have decided yet. Construction opens
// no socket and starts no goroutine; every constructor here only reads options,
// and a dialer that holds a lazily dialled session is retired before returning.
//
// A type this build does not implement is not an error here, exactly as it is
// not an error in New: that case yields an Unsupported dialer. The caller
// decides what an unsupported type means for its own input.
func Validate(spec Spec) error {
	spec.Name = ""
	dialer, err := New(spec)
	if err != nil {
		return err
	}
	if retired, ok := dialer.(disownable); ok {
		retired.Disown()
	}
	return nil
}
