package app

import "testing"

func TestUnknownCommandHasUsageExit(t *testing.T) {
	if got := Run([]string{"not-a-command"}); got != 2 {
		t.Fatalf("got %d want 2", got)
	}
}
func TestHelpDoesNotNeedSourceScripts(t *testing.T) {
	t.Setenv("CPROXY_SOURCE_DIR", "/nonexistent")
	if got := Run([]string{"--help"}); got != 0 {
		t.Fatalf("help failed: %d", got)
	}
}
func TestServeRequiresStateDirectory(t *testing.T) {
	if got := Run([]string{"--serve"}); got != 2 {
		t.Fatalf("got %d want 2", got)
	}
}
