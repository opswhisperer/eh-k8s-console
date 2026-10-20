package logs

import (
	"testing"
	"time"

	"github.com/opswhisperer/eh-k8s-console/internal/ignore"
)

var md = Target{Pod: "md-1", Container: "metadata-forwarder", Component: "metadata-forwarder"}
var skf = Target{Pod: "skf-1", Container: "session-key-forwarder", Component: "session-key-forwarder"}

const jsonErr = `2026-10-20T13:11:21.177249782Z {"time":"2026-10-20T13:11:21.177Z","level":"ERROR","msg":"SensorClient: SendDeviceProperties returned Bad Request","host":"192.0.2.10","status":400,"count":2,"body":"{\"error\": \"all_updates_invalid\", \"warnings\": [{\"index\": 0, \"key\": \"device_id\", \"value\": \"k8s-e7e36cf259674deb8d78fd4d66061e5d\", \"warnings\": [{\"type\": \"device_not_found\"}]}]}"}`

func TestParseJSON(t *testing.T) {
	l := Parse(md, jsonErr)
	if l.Level != "error" || l.Message != "SensorClient: SendDeviceProperties returned Bad Request" || l.Fields["status"] != "400" {
		t.Fatalf("parsed %+v", l)
	}
	if l.Time.IsZero() {
		t.Fatal("no timestamp")
	}
	if got := Signature(l); got != "SensorClient: SendDeviceProperties returned Bad Request [all_updates_invalid, device_not_found]" {
		t.Fatalf("signature = %q", got)
	}
}

func TestParsePlainGoLog(t *testing.T) {
	l := Parse(skf, "2026-10-20T13:04:00.1Z 2026/10/20 13:04:00 containerd: new container 7401a44f12607c9afac939c2e4c94d4c58dd011814300458589c65656a2a97cc")
	if l.Level != "info" || l.Message != "containerd: new container 7401a44f12607c9afac939c2e4c94d4c58dd011814300458589c65656a2a97cc" {
		t.Fatalf("parsed %+v", l)
	}
	e := Parse(skf, "2026-10-20T13:04:00.1Z 2026/10/20 13:04:00 failed to dial 192.0.2.10:4873: connection refused")
	if e.Level != "error" || Signature(e) != "failed to dial <addr>: connection refused" {
		t.Fatalf("parsed %+v sig %q", e, Signature(e))
	}
}

func TestSignaturesGroupRepeats(t *testing.T) {
	var lines []Line
	for i := 0; i < 5; i++ {
		lines = append(lines, Parse(md, jsonErr))
	}
	lines = append(lines, Parse(skf, "2026-10-20T13:04:00.1Z 2026/10/20 13:04:00 containerd: new container abc"))
	st := Signatures(lines, time.Hour)
	if len(st) != 1 || st[0].Count != 5 || st[0].Component != "metadata-forwarder" {
		t.Fatalf("stats = %+v", st)
	}
}

func TestSignatureStripsInterfaceIDs(t *testing.T) {
	a := Parse(skf, "2026-10-20T13:04:00.1Z stopped reading packets on cali53e670eb917: packet poll failed")
	b := Parse(skf, "2026-10-20T13:04:00.1Z stopped reading packets on cali7eea3dc8673: packet poll failed")
	if Signature(a) != Signature(b) || Signature(a) != "stopped reading packets on cali<id>: packet poll failed" {
		t.Fatalf("%q vs %q", Signature(a), Signature(b))
	}
	if got := Signature(Parse(skf, "2026-10-20T13:04:00.1Z failed to reach coordinator")); got != "failed to reach coordinator" {
		t.Fatalf("plain words must survive: %q", got)
	}
}

func TestSignatureHexLetterAfterPrefix(t *testing.T) {
	for _, ifc := range []string{"calib7f46b4fb47", "calicdee7b186b2", "caliea4653ea0b2", "cali53e670eb917"} {
		if got := Signature(Parse(skf, "2026-10-20T13:04:00.1Z stopped reading packets on "+ifc+": packet poll failed")); got != "stopped reading packets on cali<id>: packet poll failed" {
			t.Errorf("%s -> %q", ifc, got)
		}
	}
}

func TestReaderTagsIgnoredLines(t *testing.T) {
	r := &Reader{Ignore: ignore.NewStore(nil, "", "", []string{`device_not_found\]$`}, true)}
	l := r.tag(Parse(md, jsonErr))
	if l.Signature == "" || l.IgnoredBy != `device_not_found\]$` {
		t.Fatalf("tagged %+v", l)
	}
	info := r.tag(Parse(skf, "2026-10-20T13:04:00.1Z 2026/10/20 13:04:00 containerd: new container abc"))
	if info.Signature != "" || info.IgnoredBy != "" {
		t.Fatal("info lines are not tagged")
	}
}
