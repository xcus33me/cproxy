// bundle creates reproducible, self-contained release archives. It is not a runtime dependency.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const version = "1.14.3"

var hashes = map[string]string{
	"linux-amd64":   "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
	"linux-arm64":   "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
	"windows-amd64": "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518",
	"windows-arm64": "195b35424c6e3f5913954c7f08c5d8ba2d2199f6d18eb27a3972a5a29cdaa78c",
}

type entry struct {
	name string
	data []byte
	mode os.FileMode
}

func verify(data []byte, expected string) error {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != expected {
		return errors.New("SHA256 официального архива sing-box не совпадает")
	}
	return nil
}
func unpack(data []byte, target, arch string) ([]entry, error) {
	binary := "sing-box"
	if target == "windows" {
		binary += ".exe"
	}
	prefix := "sing-box-" + version + "-" + target + "-" + arch + "/"
	found := map[string][]byte{}
	consume := func(name string, size int64, r io.Reader) error {
		if name != prefix+binary && name != prefix+"LICENSE" {
			return nil
		}
		if _, ok := found[name]; ok {
			return errors.New("Повторяющийся файл в архиве")
		}
		if size < 0 || size > 128*1024*1024 {
			return errors.New("Слишком большой файл в архиве")
		}
		b, e := io.ReadAll(io.LimitReader(r, size+1))
		if e != nil {
			return e
		}
		if int64(len(b)) != size {
			return errors.New("Размер файла не совпадает")
		}
		found[name] = b
		return nil
	}
	if target == "windows" {
		r, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if e != nil {
			return nil, e
		}
		for _, f := range r.File {
			if f.UncompressedSize64 > 128*1024*1024 {
				return nil, errors.New("Слишком большой ZIP entry")
			}
			rc, e := f.Open()
			if e != nil {
				return nil, e
			}
			e = consume(f.Name, int64(f.UncompressedSize64), rc)
			rc.Close()
			if e != nil {
				return nil, e
			}
		}
	} else {
		g, e := gzip.NewReader(bytes.NewReader(data))
		if e != nil {
			return nil, e
		}
		defer g.Close()
		r := tar.NewReader(g)
		for {
			h, e := r.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, e
			}
			if h.Typeflag != tar.TypeReg {
				continue
			}
			if e = consume(h.Name, h.Size, r); e != nil {
				return nil, e
			}
		}
	}
	if len(found[prefix+binary]) == 0 || len(found[prefix+"LICENSE"]) == 0 {
		return nil, errors.New("В архиве нет ожидаемого sing-box и его LICENSE")
	}
	return []entry{{binary, found[prefix+binary], 0755}, {"licenses/sing-box.txt", found[prefix+"LICENSE"], 0644}}, nil
}
func download(address string) ([]byte, error) {
	client := &http.Client{Timeout: 3 * time.Minute}
	r, e := client.Get(address)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("Download HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 128*1024*1024+1))
	if len(b) > 128*1024*1024 {
		return nil, errors.New("Слишком большой архив")
	}
	return b, e
}
func notices(target, arch string) ([]entry, error) {
	cmd := exec.Command("go", "list", "-deps", "-json=Module", "./cmd/cproxy")
	cmd.Env = append(os.Environ(), "GOOS="+target, "GOARCH="+arch, "CGO_ENABLED=0")
	b, e := cmd.CombinedOutput()
	if e != nil {
		return nil, fmt.Errorf("Не удалось собрать лицензии зависимостей: %w: %s", e, b)
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	var result []entry
	seen := map[string]bool{}
	for {
		var p struct {
			Module *struct {
				Path, Dir string
				Main      bool
			}
		}
		e = decoder.Decode(&p)
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		m := p.Module
		if m == nil || m.Main || m.Dir == "" || seen[m.Path] {
			continue
		}
		seen[m.Path] = true
		for _, name := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"} {
			if b, e := os.ReadFile(filepath.Join(m.Dir, name)); e == nil {
				result = append(result, entry{"licenses/" + strings.ReplaceAll(m.Path, "/", "-") + ".txt", b, 0644})
				break
			}
		}
	}
	if b, e := os.ReadFile(filepath.Join(runtime.GOROOT(), "LICENSE")); e == nil {
		result = append(result, entry{"licenses/go.txt", b, 0644})
	}
	return result, nil
}
func writeArchive(path, root string, entries []entry, target string) error {
	f, e := os.Create(path)
	if e != nil {
		return e
	}
	defer f.Close()
	if target == "windows" {
		w := zip.NewWriter(f)
		for _, item := range entries {
			h := &zip.FileHeader{Name: root + "/" + item.name, Method: zip.Deflate}
			h.SetMode(item.mode)
			out, e := w.CreateHeader(h)
			if e != nil {
				return e
			}
			if _, e = out.Write(item.data); e != nil {
				return e
			}
		}
		return w.Close()
	}
	g := gzip.NewWriter(f)
	w := tar.NewWriter(g)
	for _, item := range entries {
		h := &tar.Header{Name: root + "/" + item.name, Mode: int64(item.mode), Size: int64(len(item.data)), ModTime: time.Unix(0, 0)}
		if e = w.WriteHeader(h); e != nil {
			return e
		}
		if _, e = w.Write(item.data); e != nil {
			return e
		}
	}
	if e = w.Close(); e != nil {
		return e
	}
	return g.Close()
}
func run() error {
	target := flag.String("os", runtime.GOOS, "linux or windows")
	arch := flag.String("arch", runtime.GOARCH, "amd64 or arm64")
	out := flag.String("out", "dist", "output directory")
	cached := flag.String("engine-archive", "", "already downloaded official archive (SHA256 still checked)")
	only := flag.Bool("engine-only", false, "download and verify sing-box only (CI integration tests)")
	flag.Parse()
	hash, ok := hashes[*target+"-"+*arch]
	if !ok {
		return errors.New("Поддерживаются только linux/windows amd64/arm64")
	}
	if e := os.MkdirAll(*out, 0755); e != nil {
		return e
	}
	ext := ".tar.gz"
	if *target == "windows" {
		ext = ".zip"
	}
	asset := "sing-box-" + version + "-" + *target + "-" + *arch + ext
	var data []byte
	var e error
	if *cached != "" {
		data, e = os.ReadFile(*cached)
	} else {
		fmt.Println("Downloading", asset)
		data, e = download("https://github.com/SagerNet/sing-box/releases/download/v" + version + "/" + asset)
	}
	if e != nil {
		return e
	}
	if e = verify(data, hash); e != nil {
		return e
	}
	entries, e := unpack(data, *target, *arch)
	if e != nil {
		return e
	}
	if *only {
		for _, item := range entries {
			p := filepath.Join(*out, filepath.FromSlash(item.name))
			if e = os.MkdirAll(filepath.Dir(p), 0755); e != nil {
				return e
			}
			if e = os.WriteFile(p, item.data, item.mode); e != nil {
				return e
			}
		}
		fmt.Println(filepath.Join(*out, entries[0].name))
		return nil
	}
	stage, e := os.MkdirTemp(*out, ".cproxy-bundle-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	name := "cproxy"
	if *target == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(stage, name)
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", binary, "./cmd/cproxy")
	cmd.Env = append(os.Environ(), "GOOS="+*target, "GOARCH="+*arch, "CGO_ENABLED=0")
	if b, e := cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("Build: %w: %s", e, b)
	}
	data, e = os.ReadFile(binary)
	if e != nil {
		return e
	}
	entries = append(entries, entry{name, data, 0755})
	for _, p := range []string{"README.md", "LICENSE", "docs/architecture.md", "docs/troubleshooting.md"} {
		data, e = os.ReadFile(p)
		if e != nil {
			return e
		}
		entries = append(entries, entry{p, data, 0644})
	}
	licenses, e := notices(*target, *arch)
	if e != nil {
		return e
	}
	entries = append(entries, licenses...)
	root := "cproxy-" + *target + "-" + *arch
	path := filepath.Join(*out, root+ext)
	if e = writeArchive(path, root, entries, *target); e != nil {
		return e
	}
	fmt.Println(path)
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
