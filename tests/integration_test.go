// Package tests runs the built rbacgap binary on the examples, on a fixture
// written against the real controller-runtime and client-go modules, and on
// damaged copies of each input, which must never pass as clean.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

var tool string

const cleanLine = "Every call rbacgap found is granted."

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rbacgap-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	tool = filepath.Join(dir, "rbacgap"+exe)
	cmd := exec.Command("go", "build", "-o", tool, "../plugin/scripts")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building rbacgap:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	stdout, stderr string
	code           int
}

func runIn(t *testing.T, env []string, args ...string) result {
	t.Helper()
	cmd := exec.Command(tool, args...)
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running rbacgap: %v", err)
	}
	return result{out.String(), errb.String(), code}
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	return runIn(t, nil, args...)
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// examplesCopy copies the stub modules and one example so the example's
// relative replace directives still work.
func examplesCopy(t *testing.T, example string) string {
	t.Helper()
	root := t.TempDir()
	copyTree(t, filepath.Join("..", "examples", "stubs"), filepath.Join(root, "stubs"))
	copyTree(t, filepath.Join("..", "examples", example), filepath.Join(root, example))
	return filepath.Join(root, example)
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

const buildFailure = `# example.com/bakery/internal/controller
internal/controller/bakery_controller.go:42:9: undefined: bakeryv1.Bakeryy
internal/controller/bakery_controller.go:57:3: cannot use ovens (variable of type *v1.Deployment) as client.Object value
`

const testFailure = `--- FAIL: TestReconcile (0.01s)
    bakery_controller_test.go:31: expected 3 ovens, got 0
FAIL
exit status 1
FAIL	example.com/bakery/internal/controller	0.112s
`

func damaged(orig string) map[string]string {
	return map[string]string{
		"empty":         "",
		"garbage":       "\x7fELF\x02\x01\x01\x00garbage }}}{{ ::: \n",
		"cut off":       orig[:len(orig)/2],
		"build failure": buildFailure,
		"test failure":  testFailure,
	}
}

// assertNotClean fails if a damaged input produced a clean result.
func assertNotClean(t *testing.T, name string, r result, allowFindings bool) {
	t.Helper()
	if strings.Contains(r.stdout, cleanLine) {
		t.Errorf("%s: printed a clean result:\n%s", name, r.stdout)
	}
	if r.code == 0 {
		t.Errorf("%s: exit 0\nstdout: %s\nstderr: %s", name, r.stdout, r.stderr)
	}
	if r.code == 1 && !allowFindings {
		t.Errorf("%s: exit 1, want 2\nstdout: %s", name, r.stdout)
	}
}

func TestBakeryBroken(t *testing.T) {
	r := run(t, "--dir", filepath.Join("..", "examples", "bakery"))
	if r.code != 1 {
		t.Fatalf("exit %d, want 1\n%s%s", r.code, r.stdout, r.stderr)
	}
	for _, want := range []string{
		"MISSING  core secrets: list, watch",
		"MISSING  apps deployments: update",
		"MISSING  core configmaps: get, list, watch, create, update",
		"MISSING  core pods: list",
		"MISSING  core events: create, patch",
		`verb "List" isn't lowercase`,
		"internal/controller/bakery_controller.go:35 +kubebuilder:rbac:groups=core,resources=configmaps",
		"attached to a declaration (its doc comment",
		"UNCHECKED internal/controller/bakery_controller.go:81 r.Update: the object has interface type client.Object",
		"5 resources have calls that nothing checked grants.",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q\n%s", want, r.stdout)
		}
	}
	for _, unwanted := range []string{"bakeries", cleanLine, "MAYBE"} {
		if strings.Contains(r.stdout, unwanted) {
			t.Errorf("output has %q\n%s", unwanted, r.stdout)
		}
	}
}

func TestBakeryFixedIsQuiet(t *testing.T) {
	r := run(t, "--dir", filepath.Join("..", "examples", "bakery-fixed"))
	want := "Checked 10 API calls in 2 packages against 8 +kubebuilder:rbac markers.\n" + cleanLine + "\n"
	if r.code != 0 || r.stdout != want || r.stderr != "" {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s\nwant:\n%s", r.code, r.stdout, r.stderr, want)
	}
	for _, failOn := range []string{"missing", "unchecked", "none"} {
		if r := run(t, "--dir", filepath.Join("..", "examples", "bakery-fixed"), "--fail-on", failOn); r.code != 0 {
			t.Errorf("--fail-on %s: exit %d", failOn, r.code)
		}
	}
}

type jsonReport struct {
	Calls    int `json:"calls"`
	Findings []struct {
		Level    string   `json:"level"`
		Group    string   `json:"group"`
		Resource string   `json:"resource"`
		Verbs    []string `json:"verbs"`
	} `json:"findings"`
	MarkerIssues []struct {
		Line int `json:"line"`
	} `json:"markerIssues"`
	Unresolved []struct {
		Line int `json:"line"`
	} `json:"unresolved"`
	Needs   []json.RawMessage `json:"needs"`
	Guessed []string          `json:"guessedPlurals"`
}

func missingSet(rep jsonReport, level string) []string {
	var out []string
	for _, f := range rep.Findings {
		if f.Level == level {
			g := f.Group
			if g == "" {
				g = "core"
			}
			out = append(out, g+" "+f.Resource+": "+strings.Join(f.Verbs, ","))
		}
	}
	sort.Strings(out)
	return out
}

func TestBakeryJSON(t *testing.T) {
	r := run(t, "--dir", filepath.Join("..", "examples", "bakery"), "--format", "json")
	if r.code != 1 {
		t.Fatalf("exit %d", r.code)
	}
	var rep jsonReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, r.stdout)
	}
	want := []string{
		"apps deployments: update",
		"core configmaps: get,list,watch,create,update",
		"core events: create,patch",
		"core pods: list",
		"core secrets: list,watch",
	}
	if got := missingSet(rep, "missing"); !reflect.DeepEqual(got, want) {
		t.Errorf("missing = %v\nwant %v", got, want)
	}
	if len(rep.MarkerIssues) != 2 || len(rep.Unresolved) != 1 || rep.Calls != 10 || len(rep.Needs) == 0 {
		t.Errorf("markerIssues=%d unresolved=%d calls=%d needs=%d", len(rep.MarkerIssues), len(rep.Unresolved), rep.Calls, len(rep.Needs))
	}
}

func TestFailOn(t *testing.T) {
	dir := filepath.Join("..", "examples", "bakery")
	r := run(t, "--dir", dir, "--fail-on", "none")
	if r.code != 0 || !strings.Contains(r.stdout, "MISSING") || strings.Contains(r.stdout, cleanLine) {
		t.Errorf("--fail-on none: exit %d\n%s", r.code, r.stdout)
	}
	if r := run(t, "--dir", dir, "--fail-on", "unchecked"); r.code != 1 {
		t.Errorf("--fail-on unchecked: exit %d", r.code)
	}
	// Only the unchecked helper left: exit 0 by default, 1 with unchecked.
	d := examplesCopy(t, "bakery-fixed")
	ctl := filepath.Join(d, "internal", "controller", "bakery_controller.go")
	src := read(t, ctl)
	src = strings.Replace(src, "return ctrl.Result{}, r.Update(ctx, &bakery)", "return ctrl.Result{}, r.save(ctx, &bakery)", 1)
	src += "\nfunc (r *BakeryReconciler) save(ctx context.Context, obj client.Object) error {\n\treturn r.Update(ctx, obj)\n}\n"
	write(t, ctl, src)
	if r := run(t, "--dir", d); r.code != 0 || strings.Contains(r.stdout, cleanLine) || !strings.Contains(r.stdout, "UNCHECKED") {
		t.Errorf("unchecked call, default: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if r := run(t, "--dir", d, "--fail-on", "unchecked"); r.code != 1 {
		t.Errorf("unchecked call, --fail-on unchecked: exit %d", r.code)
	}
}

func TestPackagePatternScopesToBinary(t *testing.T) {
	d := examplesCopy(t, "bakery")
	// A second binary in the module whose calls belong to another role.
	if err := os.MkdirAll(filepath.Join(d, "cmd", "other"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(d, "cmd", "other", "main.go"), `package main

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get

func main() {
	var c client.Client
	_ = c.Delete(context.Background(), &corev1.Pod{})
}
`)
	if r := run(t, "--dir", d); !strings.Contains(r.stdout, "MISSING  core pods: list, delete") || !strings.Contains(r.stdout, "core secrets") {
		t.Errorf("./... should include cmd/other:\n%s", r.stdout)
	}
	r := run(t, "--dir", d, "./cmd/other")
	if !strings.Contains(r.stdout, "MISSING  core pods: delete") || strings.Contains(r.stdout, "secrets") {
		t.Errorf("./cmd/other should only check what it imports:\n%s%s", r.stdout, r.stderr)
	}
}

// Every Go input and go.mod, damaged five ways, must exit 2 under every
// --fail-on value and print no clean line.
func TestDamagedGoInputs(t *testing.T) {
	files := []string{
		"internal/controller/bakery_controller.go",
		"api/v1/bakery_types.go",
		"api/v1/groupversion_info.go",
		"go.mod",
		"../stubs/api/core/v1/doc.go",
		"../stubs/controller-runtime/pkg/client/interfaces.go",
	}
	for _, f := range files {
		for kind, content := range damaged(read(t, filepath.Join("..", "examples", "bakery-fixed", filepath.FromSlash(f)))) {
			d := examplesCopy(t, "bakery-fixed")
			write(t, filepath.Join(d, filepath.FromSlash(f)), content)
			for _, failOn := range []string{"missing", "unchecked", "none"} {
				r := run(t, "--dir", d, "--fail-on", failOn)
				name := fmt.Sprintf("%s %s --fail-on %s", f, kind, failOn)
				assertNotClean(t, name, r, false)
				if r.code == 2 && !strings.Contains(r.stderr, "can't trust this result") {
					t.Errorf("%s: stderr doesn't say the result can't be trusted: %s", name, r.stderr)
				}
			}
		}
	}
}

// A new damaged Go file next to healthy ones must also stop the run.
func TestDamagedExtraGoFile(t *testing.T) {
	for kind, content := range damaged(read(t, filepath.Join("..", "examples", "bakery-fixed", "internal", "controller", "bakery_controller.go"))) {
		d := examplesCopy(t, "bakery-fixed")
		write(t, filepath.Join(d, "internal", "controller", "extra.go"), content)
		assertNotClean(t, "extra.go "+kind, run(t, "--dir", d, "--fail-on", "unchecked"), false)
	}
}

// The CRD file only supplies plural names. Damaged, it either stops the run
// or leaves the plural guessed, which is never reported as clean and fails
// under --fail-on unchecked.
func TestDamagedCRDFile(t *testing.T) {
	crd := filepath.Join("config", "crd", "bases", "bakery.example.com_bakeries.yaml")
	for kind, content := range damaged(read(t, filepath.Join("..", "examples", "bakery-fixed", crd))) {
		d := examplesCopy(t, "bakery-fixed")
		write(t, filepath.Join(d, crd), content)
		r := run(t, "--dir", d)
		if strings.Contains(r.stdout, cleanLine) {
			t.Errorf("%s: printed a clean result:\n%s", kind, r.stdout)
		}
		if r.code == 0 && !strings.Contains(r.stdout, "GUESSED  bakery.example.com bakeries") {
			t.Errorf("%s: exit 0 without the guessed note:\n%s", kind, r.stdout)
		}
		assertNotClean(t, "crd "+kind+" --fail-on unchecked", run(t, "--dir", d, "--fail-on", "unchecked"), true)
	}
}

const bakeryRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: manager-role
rules:
- apiGroups:
  - bakery.example.com
  resources:
  - bakeries
  verbs:
  - get
  - list
  - watch
  - update
- apiGroups:
  - bakery.example.com
  resources:
  - bakeries/status
  verbs:
  - update
- apiGroups:
  - apps
  resources:
  - deployments
  verbs:
  - get
  - list
  - watch
  - create
  - update
- apiGroups:
  - ""
  resources:
  - secrets
  - pods
  - configmaps
  verbs:
  - get
  - list
  - watch
  - create
  - update
- apiGroups:
  - ""
  resources:
  - events
  verbs:
  - create
  - patch
`

// roleCopy is bakery-fixed with its markers moved to role.yaml.
func roleCopy(t *testing.T) (string, string) {
	t.Helper()
	d := examplesCopy(t, "bakery-fixed")
	ctl := filepath.Join(d, "internal", "controller", "bakery_controller.go")
	var kept []string
	for _, line := range strings.Split(read(t, ctl), "\n") {
		if !strings.HasPrefix(line, "// +kubebuilder:rbac:") {
			kept = append(kept, line)
		}
	}
	write(t, ctl, strings.Join(kept, "\n"))
	role := filepath.Join(d, "role.yaml")
	write(t, role, bakeryRole)
	return d, role
}

func TestRoleFile(t *testing.T) {
	d, role := roleCopy(t)
	r := run(t, "--dir", d, "--role", role)
	if r.code != 0 || !strings.Contains(r.stdout, "against 0 +kubebuilder:rbac markers and 5 role file rules") || !strings.Contains(r.stdout, cleanLine) {
		t.Fatalf("healthy role file: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	// Without --role there is nothing to compare with.
	if r := run(t, "--dir", d); r.code != 2 || !strings.Contains(r.stderr, "no +kubebuilder:rbac markers") {
		t.Errorf("no markers, no role: exit %d %s", r.code, r.stderr)
	}
	// Same rules as kubectl JSON.
	js := filepath.Join(d, "role.json")
	write(t, js, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"m"},"rules":[`+
		`{"apiGroups":["bakery.example.com"],"resources":["bakeries"],"verbs":["get","list","watch","update"]},`+
		`{"apiGroups":["bakery.example.com"],"resources":["bakeries/status"],"verbs":["update"]},`+
		`{"apiGroups":["apps"],"resources":["deployments"],"verbs":["get","list","watch","create","update"]},`+
		`{"apiGroups":[""],"resources":["secrets","pods","configmaps"],"verbs":["get","list","watch","create","update"]},`+
		`{"apiGroups":[""],"resources":["events"],"verbs":["create","patch"]}]}`+"\n")
	if r := run(t, "--dir", d, "--role", js); r.code != 0 || !strings.Contains(r.stdout, cleanLine) {
		t.Errorf("healthy JSON role: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	// A rule removed: the gap is reported with a role-style fix.
	write(t, role, strings.Replace(bakeryRole, "  - events\n  verbs:\n  - create\n  - patch\n", "  - events\n  verbs:\n  - create\n", 1))
	r = run(t, "--dir", d, "--role", role)
	if r.code != 1 || !strings.Contains(r.stdout, "MISSING  core events: patch") || !strings.Contains(r.stdout, "fix:  add a rule with apiGroups") {
		t.Errorf("removed verb: exit %d\n%s", r.code, r.stdout)
	}
}

func TestDamagedRoleFile(t *testing.T) {
	lines := strings.SplitAfter(bakeryRole, "\n")
	variants := damaged(bakeryRole)
	variants["first half of the lines"] = strings.Join(lines[:len(lines)/2], "")
	variants["verb cut mid-word"] = strings.Replace(bakeryRole, "  - patch\n", "  - pat\n", 1)
	variants["json cut off"] = `{"kind":"ClusterRole","rules":[{"apiGroups":[""],"resources":["pods"],` + "\n"
	for kind, content := range variants {
		d, role := roleCopy(t)
		write(t, role, content)
		for _, failOn := range []string{"missing", "unchecked"} {
			assertNotClean(t, "role "+kind+" --fail-on "+failOn, run(t, "--dir", d, "--role", role, "--fail-on", failOn), true)
		}
		if r := run(t, "--dir", d, "--role", role, "--fail-on", "none"); strings.Contains(r.stdout, cleanLine) {
			t.Errorf("role %s --fail-on none: printed a clean result", kind)
		}
	}
	d, _ := roleCopy(t)
	if r := run(t, "--dir", d, "--role", filepath.Join(d, "nope.yaml")); r.code != 2 {
		t.Errorf("missing role file: exit %d", r.code)
	}
}

// A fake go command damages the output of go list -export.
func TestDamagedGoList(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake go command is a shell script")
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	d := examplesCopy(t, "bakery-fixed")
	cmd := exec.Command(realGo, "list", "-e", "-export", "-compiled", "-deps", "-json", "./...")
	cmd.Dir = d
	good, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	// Offsets of each top-level JSON object.
	var ends []int64
	dec := json.NewDecoder(bytes.NewReader(good))
	for {
		var v json.RawMessage
		if err := dec.Decode(&v); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		ends = append(ends, dec.InputOffset())
	}
	if len(ends) < 3 {
		t.Fatalf("only %d packages", len(ends))
	}
	noExport := strings.ReplaceAll(string(good), `"Export":`, `"Exported":`)
	variants := map[string]struct {
		out  string
		exit int
	}{
		"empty":                 {"", 0},
		"garbage":               {"\x00\x01 not json {{{", 0},
		"cut mid-object":        {string(good[:len(good)/2]), 0},
		"cut between packages":  {string(good[:ends[len(ends)-2]]), 0},
		"first package only":    {string(good[:ends[0]]), 0},
		"build failure":         {buildFailure, 1},
		"test failure":          {testFailure, 1},
		"no export data":        {noExport, 0},
		"good output, exit one": {string(good), 1},
	}
	bin := t.TempDir()
	script := "#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = \"-export\" ]; then cat \"$FAKE_OUT\"; exit \"$FAKE_EXIT\"; fi\ndone\nexec \"$REAL_GO\" \"$@\"\n"
	write(t, filepath.Join(bin, "go"), script)
	if err := os.Chmod(filepath.Join(bin, "go"), 0o755); err != nil {
		t.Fatal(err)
	}
	for kind, v := range variants {
		out := filepath.Join(t.TempDir(), "out")
		write(t, out, v.out)
		env := []string{
			"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
			"REAL_GO=" + realGo, "FAKE_OUT=" + out, fmt.Sprintf("FAKE_EXIT=%d", v.exit),
		}
		for _, failOn := range []string{"missing", "none"} {
			assertNotClean(t, "go list "+kind+" --fail-on "+failOn, runIn(t, env, "--dir", d, "--fail-on", failOn), false)
		}
	}
	// The fake passes good output through unchanged: still clean.
	out := filepath.Join(t.TempDir(), "out")
	write(t, out, string(good))
	env := []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "REAL_GO=" + realGo, "FAKE_OUT=" + out, "FAKE_EXIT=0"}
	if r := runIn(t, env, "--dir", d); r.code != 0 || !strings.Contains(r.stdout, cleanLine) {
		t.Errorf("fake go with good output: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestNotAnOperator(t *testing.T) {
	// This repository has no Kubernetes calls or markers.
	r := run(t, "--dir", "..")
	if r.code != 2 || strings.Contains(r.stdout, cleanLine) {
		t.Errorf("own repo: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	// Markers but no calls.
	d := t.TempDir()
	write(t, filepath.Join(d, "go.mod"), "module example.com/x\n\ngo 1.22\n")
	write(t, filepath.Join(d, "x.go"), "package x\n\n// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get\n\nvar X = 1\n")
	if r := run(t, "--dir", d); r.code != 2 || !strings.Contains(r.stderr, "found no controller-runtime or client-go API calls") {
		t.Errorf("markers without calls: exit %d %s", r.code, r.stderr)
	}
	// A broken live marker stops the run, as it stops controller-gen.
	write(t, filepath.Join(d, "x.go"), "package x\n\n// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;create,update\n\nvar X = 1\n")
	if r := run(t, "--dir", d); r.code != 2 {
		t.Errorf("broken marker: exit %d", r.code)
	}
}

// realOperator checks a module written against the real controller-runtime
// v0.18 and client-go v0.30 APIs. It needs the modules, so it skips when
// they can't be downloaded.
func realOperator(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("downloads modules")
	}
	src := filepath.Join("testdata", "realop")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "mod", "download")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("can't download the real modules, skipping: %v\n%s", err, out)
	}
	d := filepath.Join(t.TempDir(), "realop")
	copyTree(t, src, d)
	return d
}

func TestRealOperator(t *testing.T) {
	d := realOperator(t)
	for _, pattern := range []string{"./...", "./cmd/manager"} {
		r := run(t, "--dir", d, "--format", "json", pattern)
		if r.code != 1 {
			t.Fatalf("%s: exit %d\n%s%s", pattern, r.code, r.stdout, r.stderr)
		}
		var rep jsonReport
		if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
			t.Fatal(err)
		}
		want := []string{
			"core events: create,patch",
			"core nodes/status: update",
			"core pods/eviction: create",
			"core pods: deletecollection",
			"core secrets: list,watch",
			"core services: list,watch",
			"widgets.example.com widgetries/status: patch",
		}
		if got := missingSet(rep, "missing"); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: missing = %v\nwant %v", pattern, got, want)
		}
		if got := missingSet(rep, "soft"); !reflect.DeepEqual(got, []string{"widgets.example.com widgetries/finalizers: update"}) {
			t.Errorf("%s: soft = %v", pattern, got)
		}
		if len(rep.Unresolved) != 0 || len(rep.MarkerIssues) != 0 || len(rep.Guessed) != 0 {
			t.Errorf("%s: unresolved %v, marker issues %v, guessed %v", pattern, rep.Unresolved, rep.MarkerIssues, rep.Guessed)
		}
	}
}

func TestRealOperatorFixedIsQuiet(t *testing.T) {
	d := realOperator(t)
	ctl := filepath.Join(d, "internal", "controller", "widget_controller.go")
	src := read(t, ctl)
	start := strings.Index(src, "// +kubebuilder:rbac:")
	end := strings.Index(src, "// WidgetReconciler reconciles")
	fixed := `// +kubebuilder:rbac:groups=widgets.example.com,resources=widgetries,verbs=get;list;watch
// +kubebuilder:rbac:groups=widgets.example.com,resources=widgetries/status,verbs=patch
// +kubebuilder:rbac:groups=widgets.example.com,resources=widgetries/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get
// +kubebuilder:rbac:groups=core,resources=pods,verbs=deletecollection
// +kubebuilder:rbac:groups=core,resources=pods/eviction,verbs=create
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get
// +kubebuilder:rbac:groups=core,resources=nodes/status,verbs=update
// +kubebuilder:rbac:groups=core,resources=services,verbs=list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

`
	write(t, ctl, src[:start]+fixed+src[end:])
	r := run(t, "--dir", d, "--unused")
	if r.code != 0 || strings.Count(r.stdout, "\n") != 2 || !strings.Contains(r.stdout, cleanLine) {
		t.Errorf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

// Cases an independent review found that once passed as clean. Each now
// reports a finding, an UNCHECKED line or exit 2.
func TestReviewCases(t *testing.T) {
	type tc struct {
		name, file, src string
		want            string // substring of stdout or stderr
		code            int
	}
	imports := "package controller\n\nimport (\n\t\"context\"\n\n\tcorev1 \"k8s.io/api/core/v1\"\n\t\"sigs.k8s.io/controller-runtime/pkg/client\"\n)\n\nvar _ client.Client\n\n"
	cases := []tc{
		{"method value", "mv.go", imports + "func (r *BakeryReconciler) cleanup(ctx context.Context) error {\n\tdel := r.Delete\n\treturn del(ctx, &corev1.Secret{})\n}\n",
			"UNCHECKED internal/controller/mv.go:13 r.Delete: method value", 0},
		{"wrapper interface", "wrap.go", imports + "type creator interface {\n\tCreate(ctx context.Context, obj client.Object, opts ...client.CreateOption) error\n}\n\nfunc cleanup2(ctx context.Context, c client.Client) error {\n\tvar w creator = c\n\treturn w.Create(ctx, &corev1.Secret{})\n}\n",
			"MISSING  core secrets: create", 1},
		{"trailing marker on a var", "m.go", imports + "var x = 1 // +kubebuilder:rbac:groups=core,resources=secrets,verbs=delete\n\nfunc (r *BakeryReconciler) del(ctx context.Context) error {\n\treturn r.Delete(ctx, &corev1.Secret{})\n}\n",
			"MARKER   internal/controller/m.go:12", 1},
		{"trailing marker on a struct", "m.go", imports + "type T struct {\n\tA int\n} // +kubebuilder:rbac:groups=core,resources=secrets,verbs=delete\n\nfunc (r *BakeryReconciler) del(ctx context.Context) error {\n\treturn r.Delete(ctx, &corev1.Secret{})\n}\n",
			"MISSING  core secrets: delete", 1},
		{"hand-written generated header", "zz_extra.go", "// Code generated by hand-scaffolder. DO NOT EDIT.\n\n" + imports + "func (r *BakeryReconciler) extra(ctx context.Context) error {\n\treturn r.Delete(ctx, &corev1.Secret{})\n}\n",
			"MISSING  core secrets: delete", 1},
		{"namespaced grant for nodes", "node.go", "// +kubebuilder:rbac:groups=core,namespace=bakery-system,resources=nodes,verbs=get\n\n" + imports + "func (r *BakeryReconciler) node(ctx context.Context, c client.Reader) error {\n\treturn c.Get(ctx, client.ObjectKey{Name: \"n1\"}, &corev1.Node{})\n}\n",
			"MISSING  core nodes: get", 1},
		{"self-referential list", "p.go", imports + "type OvenList struct {\n\tcorev1.PodList\n\tItems []OvenList\n}\n\nfunc (r *BakeryReconciler) ovens(ctx context.Context) error {\n\tvar l OvenList\n\treturn r.List(ctx, &l)\n}\n",
			"nest too deeply", 0},
	}
	for _, c := range cases {
		d := examplesCopy(t, "bakery-fixed")
		write(t, filepath.Join(d, "internal", "controller", c.file), c.src)
		r := run(t, "--dir", d)
		if r.code != c.code || !strings.Contains(r.stdout+r.stderr, c.want) || strings.Contains(r.stdout, cleanLine) {
			t.Errorf("%s: exit %d, want %d with %q\n%s%s", c.name, r.code, c.code, c.want, r.stdout, r.stderr)
		}
		if r := run(t, "--dir", d, "--fail-on", "unchecked"); r.code != 1 {
			t.Errorf("%s --fail-on unchecked: exit %d", c.name, r.code)
		}
	}
	// A real client-gen file is skipped: its callers are checked instead.
	d := examplesCopy(t, "bakery-fixed")
	write(t, filepath.Join(d, "internal", "controller", "zz_client.go"), "// Code generated by client-gen. DO NOT EDIT.\n\n"+imports+"func (r *BakeryReconciler) gen(ctx context.Context) error {\n\treturn r.Delete(ctx, &corev1.Secret{})\n}\n")
	if r := run(t, "--dir", d); r.code != 0 || !strings.Contains(r.stdout, cleanLine) {
		t.Errorf("client-gen file: exit %d\n%s", r.code, r.stdout)
	}
	// Two CRD files that disagree on a plural stop the run.
	d = examplesCopy(t, "bakery-fixed")
	if err := os.MkdirAll(filepath.Join(d, "hack", "old"), 0o755); err != nil {
		t.Fatal(err)
	}
	crd := read(t, filepath.Join(d, "config", "crd", "bases", "bakery.example.com_bakeries.yaml"))
	write(t, filepath.Join(d, "hack", "old", "crd.yaml"), strings.Replace(crd, "plural: bakeries", "plural: bakerys", 1))
	if r := run(t, "--dir", d); r.code != 2 || !strings.Contains(r.stderr, "disagree on the plural") {
		t.Errorf("conflicting CRDs: exit %d %s", r.code, r.stderr)
	}
}

// A cgo file in the operator is checked like any other.
func TestCgoFileIsChecked(t *testing.T) {
	out, err := exec.Command("go", "env", "CGO_ENABLED", "CC").Output()
	lines := strings.Fields(string(out))
	if err != nil || len(lines) < 2 || lines[0] != "1" {
		t.Skip("cgo is off")
	}
	if _, err := exec.LookPath(lines[1]); err != nil {
		t.Skip("no C compiler")
	}
	d := examplesCopy(t, "bakery-fixed")
	write(t, filepath.Join(d, "internal", "controller", "cgo.go"), "package controller\n\n// int one(void) { return 1; }\nimport \"C\"\n\nimport (\n\t\"context\"\n\n\tcorev1 \"k8s.io/api/core/v1\"\n)\n\nfunc (r *BakeryReconciler) cgo(ctx context.Context) error {\n\t_ = C.one()\n\treturn r.Delete(ctx, &corev1.Secret{})\n}\n")
	r := run(t, "--dir", d)
	if r.code != 1 || !strings.Contains(r.stdout, "internal/controller/cgo.go:14 r.Delete") {
		t.Errorf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

// client-go APIs whose resource is chosen at runtime are UNCHECKED.
func TestRuntimeChosenResources(t *testing.T) {
	d := realOperator(t)
	write(t, filepath.Join(d, "internal", "controller", "extra.go"), extraGo)
	r := runIn(t, []string{"GOFLAGS=-mod=mod"}, "--dir", d, "--format", "json")
	var rep jsonReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("exit %d: %v\n%s", r.code, err, r.stderr)
	}
	lines := map[int]bool{}
	for _, u := range rep.Unresolved {
		lines[u.Line] = true
	}
	for _, l := range []int{22, 23, 25, 27, 28, 29, 30, 31} {
		if !lines[l] {
			t.Errorf("extra.go:%d not UNCHECKED: %+v", l, rep.Unresolved)
		}
	}
}

const extraGo = `package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var secretsGVR = corev1.SchemeGroupVersion.WithResource("secrets")

func Extra(ctx context.Context, mc metadata.Interface, dc dynamic.Interface, cs kubernetes.Interface, mgr ctrl.Manager) {
	_, _ = mc.Resource(secretsGVR).Namespace("x").List(ctx, metav1.ListOptions{})
	_ = mc.Resource(secretsGVR).Namespace("x").Delete(ctx, "n", metav1.DeleteOptions{})
	f := informers.NewSharedInformerFactory(cs, 0)
	gi, _ := f.ForResource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"})
	_ = gi.Informer()
	_ = dynamicinformer.NewDynamicSharedInformerFactory(dc, 0).ForResource(secretsGVR).Informer()
	_ = metadatainformer.NewSharedInformerFactory(mc, 0).ForResource(secretsGVR).Informer()
	_ = cs.CoreV1().RESTClient().Delete().Resource("secrets").Namespace("x").Name("n").Do(ctx)
	_, _ = mgr.GetCache().GetInformerForKind(ctx, corev1.SchemeGroupVersion.WithKind("Secret"))
	_ = f.InformerFor(&corev1.Secret{}, nil)
	var c client.Client = mgr.GetClient()
	_ = c
}
`
