package main

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestEngineArchiveMustMatchPinnedHash(t *testing.T) {
	if verify([]byte("tampered"), "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee") == nil {
		t.Fatal("tampered engine accepted")
	}
}
func TestZipExtractionIgnoresTraversalAndRequiresLicense(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create("../../sing-box.exe")
	f.Write([]byte("malicious"))
	f, _ = w.Create("official/LICENSE")
	f.Write([]byte("license"))
	w.Close()
	if _, e := unpack(b.Bytes(), "windows", "amd64"); e == nil {
		t.Fatal("accepted unexpected archive path")
	}
}
