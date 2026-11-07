// Command rbacgap finds Kubernetes API calls in a Go operator or controller
// that its +kubebuilder:rbac markers don't grant, before the pod logs
// "forbidden" in a cluster.
//
// It type-checks the module's packages with export data from
// `go list -export`, finds calls made through controller-runtime and client-go,
// works out the API group, resource and verb each one needs, and compares them
// with the RBAC markers in the same module. It never runs the code it checks.
//
// Standard library only, so `go run rbacgap.go` needs no setup.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const version = "0.1.0"

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1
	exitUnknown  = 2
)

const (
	crRoot        = "sigs.k8s.io/controller-runtime"
	crClient      = "sigs.k8s.io/controller-runtime/pkg/client"
	crBuilder     = "sigs.k8s.io/controller-runtime/pkg/builder"
	crSource      = "sigs.k8s.io/controller-runtime/pkg/source"
	crUtil        = "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	crManager     = "sigs.k8s.io/controller-runtime/pkg/manager"
	crCluster     = "sigs.k8s.io/controller-runtime/pkg/cluster"
	crCache       = "sigs.k8s.io/controller-runtime/pkg/cache"
	cgDynamic     = "k8s.io/client-go/dynamic"
	cgMetadata    = "k8s.io/client-go/metadata"
	cgRest        = "k8s.io/client-go/rest"
	unstructured  = "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	metav1        = "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sAPIPrefix  = "k8s.io/api/"
	applyCfgPkg   = "k8s.io/client-go/applyconfigurations/"
	markerPrefix  = "+kubebuilder:rbac:"
	groupNameMark = "+groupName="
)

// listedPackage is the part of `go list -json` output rbacgap uses.
type listedPackage struct {
	ImportPath      string
	Name            string
	Dir             string
	GoFiles         []string
	CompiledGoFiles []string
	Export          string
	Standard        bool
	DepOnly         bool
	Incomplete      bool
	ImportMap       map[string]string
	Module          *struct {
		Path string
		Main bool
		Dir  string
	}
	Error *struct {
		Err string
	}
	DepsErrors []*struct {
		Err string
	}
}

// Need is one permission a call site requires.
type Need struct {
	Group    string `json:"group"`
	Resource string `json:"resource"`
	Verb     string `json:"verb"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Call     string `json:"call"`
	Why      string `json:"why"`
	// Cache is true when the verb is needed because the read goes through
	// controller-runtime's informer cache, not because the call itself uses it.
	Cache bool `json:"cache,omitempty"`
	// Soft needs depend on cluster settings or runtime data. They are reported
	// but never fail the check.
	Soft bool `json:"soft,omitempty"`
	// Guessed is set when the plural resource name came from English rules
	// rather than a marker or a CRD file.
	Guessed bool `json:"guessedPlural,omitempty"`
	// Cluster is set for resources that aren't namespaced, which a Role or
	// a namespace= marker can never grant.
	Cluster bool `json:"clusterScoped,omitempty"`
}

// Unresolved is a call rbacgap saw but couldn't map to a permission.
type Unresolved struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Call   string `json:"call"`
	Reason string `json:"reason"`
}

// Grant is one +kubebuilder:rbac marker.
type Grant struct {
	Groups        []string `json:"groups"`
	Resources     []string `json:"resources"`
	Verbs         []string `json:"verbs"`
	ResourceNames []string `json:"resourceNames,omitempty"`
	URLs          []string `json:"urls,omitempty"`
	Namespace     string   `json:"namespace,omitempty"`
	File          string   `json:"file"`
	Line          int      `json:"line"`
}

// Finding is a missing or partly granted permission.
type Finding struct {
	Level    string   `json:"level"` // missing, soft, partial
	Group    string   `json:"group"`
	Resource string   `json:"resource"`
	Verbs    []string `json:"verbs"`
	Needs    []Need   `json:"needs"`
	Note     string   `json:"note,omitempty"`
}

// MarkerIssue is a marker that doesn't grant what it says.
type MarkerIssue struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Marker  string `json:"marker"`
	Problem string `json:"problem"`
}

// Unused is a granted verb with no call found that needs it.
type Unused struct {
	Group    string `json:"group"`
	Resource string `json:"resource"`
	Verb     string `json:"verb"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// Report is the full result, also printed with --format json.
type Report struct {
	Version      string        `json:"version"`
	Dir          string        `json:"dir"`
	Packages     int           `json:"packages"`
	Calls        int           `json:"calls"`
	Markers      int           `json:"markers"`
	RoleRules    int           `json:"roleRules"`
	Findings     []Finding     `json:"findings"`
	MarkerIssues []MarkerIssue `json:"markerIssues"`
	Unresolved   []Unresolved  `json:"unresolved"`
	Unused       []Unused      `json:"unused"`
	Needs        []Need        `json:"needs"`
	// Guessed lists resources whose plural came from English rules, because
	// no marker or CRD file named it.
	Guessed []string `json:"guessedPlurals"`
}

// multiFlag collects a repeated string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// inputError means the input can't be trusted. It always exits 2.
type inputError struct{ msgs []string }

func (e *inputError) Error() string { return strings.Join(e.msgs, "\n") }

func untrusted(format string, args ...any) error {
	return &inputError{msgs: []string{fmt.Sprintf(format, args...)}}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rbacgap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "Go module directory of the operator")
	format := fs.String("format", "text", "output format: text or json")
	showUnused := fs.Bool("unused", false, "also list granted verbs that no call needs")
	showCalls := fs.Bool("calls", false, "also list every call site and the permissions it needs")
	showVersion := fs.Bool("version", false, "print the version and exit")
	failOn := fs.String("fail-on", "missing", "what exits 1: missing (missing permissions and broken markers), unchecked (also calls rbacgap couldn't resolve), or none")
	var roles multiFlag
	fs.Var(&roles, "role", "a Role or ClusterRole file (YAML or JSON) whose rules also count as granted; repeat for more")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: rbacgap [--dir DIR] [--role FILE]... [--format text|json] [--fail-on missing|unchecked|none]\n")
		fmt.Fprintf(stderr, "               [--calls] [--unused] [packages]\n\n")
		fmt.Fprintf(stderr, "Finds Kubernetes API calls that the module's +kubebuilder:rbac markers don't grant.\n")
		fmt.Fprintf(stderr, "Packages default to ./... and are passed to go list. Packages of the module that they\n")
		fmt.Fprintf(stderr, "import are checked too, so give a manager's main package to check only what that binary runs.\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 every resolved call is granted, 1 findings (see --fail-on), 2 bad usage or input that can't be trusted.\n")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUnknown
	}
	if *showVersion {
		fmt.Fprintln(stdout, "rbacgap", version)
		return exitOK
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "rbacgap: --format must be text or json, not %q\n", *format)
		return exitUnknown
	}
	if *failOn != "missing" && *failOn != "unchecked" && *failOn != "none" {
		fmt.Fprintf(stderr, "rbacgap: --fail-on must be missing, unchecked or none, not %q\n", *failOn)
		return exitUnknown
	}
	patterns := fs.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	rep, err := analyze(*dir, patterns, roles)
	if err != nil {
		var ie *inputError
		if errors.As(err, &ie) {
			fmt.Fprintf(stderr, "rbacgap: can't trust this result, nothing was checked:\n")
			for _, m := range ie.msgs {
				fmt.Fprintf(stderr, "  %s\n", m)
			}
		} else {
			fmt.Fprintf(stderr, "rbacgap: %v\n", err)
		}
		return exitUnknown
	}
	if !*showUnused && *format == "text" {
		rep.Unused = nil
	}
	if !*showCalls && *format == "text" {
		rep.Needs = nil
	}
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(stderr, "rbacgap: %v\n", err)
			return exitUnknown
		}
	} else {
		printText(stdout, rep)
	}
	return exitCode(rep, *failOn)
}

// exitCode applies --fail-on. Untrusted input never reaches here: it always
// exits 2.
func exitCode(rep *Report, failOn string) int {
	if failOn == "none" {
		return exitOK
	}
	if len(rep.MarkerIssues) > 0 {
		return exitFindings
	}
	for _, f := range rep.Findings {
		if f.Level == "missing" {
			return exitFindings
		}
	}
	if failOn == "unchecked" && (len(rep.Unresolved) > 0 || len(rep.Guessed) > 0) {
		return exitFindings
	}
	return exitOK
}

// analyze loads, type-checks and compares. Any error is an inputError or an
// environment failure; both exit 2.
func analyze(dir string, patterns []string, roleFiles []string) (*Report, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, untrusted("%v", err)
	}
	if !st.IsDir() {
		return nil, untrusted("%s is not a directory", dir)
	}
	pkgs, err := goList(abs, patterns)
	if err != nil {
		return nil, err
	}
	var listErrs []string
	for _, p := range pkgs {
		if !p.DepOnly && p.Error != nil && (p.Module == nil || !p.Module.Main) {
			listErrs = append(listErrs, fmt.Sprintf("%s: %s", p.ImportPath, strings.TrimSpace(p.Error.Err)))
		}
	}
	if len(listErrs) > 0 {
		return nil, &inputError{msgs: limit(listErrs, 10)}
	}
	a := newAnalyzer(abs, pkgs)
	if err := a.crossCheck(patterns); err != nil {
		return nil, err
	}
	if err := a.typeCheck(); err != nil {
		return nil, err
	}
	grants, issues, err := a.markers()
	if err != nil {
		return nil, err
	}
	var roleGrants []Grant
	for _, rf := range roleFiles {
		gs, err := readRoleFile(rf, filepath.ToSlash(rf))
		if err != nil {
			return nil, untrusted("--role: %v", err)
		}
		for _, g := range gs {
			for _, v := range g.Verbs {
				if p := verbProblem(v); p != "" {
					issues = append(issues, MarkerIssue{File: g.File, Line: g.Line, Marker: "role rule", Problem: p})
				}
			}
			for _, r := range g.Resources {
				if r != strings.ToLower(r) {
					issues = append(issues, MarkerIssue{File: g.File, Line: g.Line, Marker: "role rule", Problem: fmt.Sprintf("resource %q isn't lowercase; RBAC compares resource names exactly, so it grants nothing", r)})
				}
			}
		}
		roleGrants = append(roleGrants, gs...)
	}
	markerCount := len(grants)
	grants = append(grants, roleGrants...)
	if err := a.findCRDNames(); err != nil {
		return nil, err
	}
	for _, p := range a.targets {
		a.walk(p)
	}
	if len(grants) == 0 && len(issues) == 0 {
		if len(roleFiles) > 0 {
			return nil, untrusted("the --role files have no rules and the code has no +kubebuilder:rbac markers, so there is nothing to compare the calls with")
		}
		return nil, untrusted("no +kubebuilder:rbac markers found in %d packages under %s, so there is nothing to compare the calls with; pass --role if the RBAC is in a YAML file", len(a.targets), dir)
	}
	if a.calls == 0 {
		return nil, untrusted("found no controller-runtime or client-go API calls in %d packages under %s; is this the operator's module?", len(a.targets), dir)
	}
	rep := &Report{
		Version:      version,
		Dir:          dir,
		Packages:     len(a.targets),
		Calls:        a.calls,
		Markers:      markerCount,
		RoleRules:    len(roleGrants),
		Unresolved:   a.unresolved,
		MarkerIssues: issues,
	}
	if rep.MarkerIssues == nil {
		rep.MarkerIssues = []MarkerIssue{}
	}
	a.markClusterScoped()
	rep.Findings, rep.Unused = compare(a.needs, grants)
	rep.Needs = a.needs
	seenGuess := map[string]bool{}
	rep.Guessed = []string{}
	for _, n := range a.needs {
		base, _, _ := strings.Cut(n.Resource, "/")
		k := groupLabel(n.Group) + " " + base
		if n.Guessed && !seenGuess[k] {
			seenGuess[k] = true
			rep.Guessed = append(rep.Guessed, k)
		}
	}
	sort.SliceStable(rep.Unresolved, func(i, j int) bool {
		if rep.Unresolved[i].File != rep.Unresolved[j].File {
			return rep.Unresolved[i].File < rep.Unresolved[j].File
		}
		return rep.Unresolved[i].Line < rep.Unresolved[j].Line
	})
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	if rep.Unresolved == nil {
		rep.Unresolved = []Unresolved{}
	}
	if rep.Unused == nil {
		rep.Unused = []Unused{}
	}
	if rep.Needs == nil {
		rep.Needs = []Need{}
	}
	return rep, nil
}

// goList runs go list with export data and decodes every package.
func goList(dir string, patterns []string) ([]*listedPackage, error) {
	args := append([]string{"list", "-e", "-export", "-compiled", "-deps", "-json"}, patterns...)
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := cmd.Run()
	var pkgs []*listedPackage
	dec := json.NewDecoder(&out)
	for {
		p := new(listedPackage)
		err := dec.Decode(p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, untrusted("go list printed output that isn't valid JSON: %v", err)
		}
		if p.ImportPath == "" {
			return nil, untrusted("go list printed a package with no import path")
		}
		pkgs = append(pkgs, p)
	}
	if runErr != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = runErr.Error()
		}
		return nil, untrusted("go list failed in %s: %s", dir, firstLines(msg, 8))
	}
	if len(pkgs) == 0 {
		return nil, untrusted("go list found no packages in %s", dir)
	}
	return pkgs, nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = append(lines[:n], fmt.Sprintf("... and %d more lines", len(lines)-n))
	}
	return strings.Join(lines, "\n  ")
}

type checkedPackage struct {
	listed *listedPackage
	files  []*ast.File
	info   *types.Info
	pkg    *types.Package
}

type analyzer struct {
	dir        string
	fset       *token.FileSet
	byPath     map[string]*listedPackage
	targets    []*checkedPackage
	needs      []Need
	unresolved []Unresolved
	calls      int
	// skippedGenerated counts generated files whose calls weren't read.
	skippedGenerated int
	groups           map[string]groupInfo
	plurals          map[string]string // "group/Kind" -> plural from a marker or CRD file
	crdPlurals       map[string]string // "group/Kind" -> plural from CRD YAML
	clusterScoped    map[string]bool   // "group/Kind" of custom resources that aren't namespaced
}

type groupInfo struct {
	group string
	ok    bool
}

func newAnalyzer(dir string, pkgs []*listedPackage) *analyzer {
	a := &analyzer{
		dir:           dir,
		fset:          token.NewFileSet(),
		byPath:        map[string]*listedPackage{},
		groups:        map[string]groupInfo{},
		plurals:       map[string]string{},
		crdPlurals:    map[string]string{},
		clusterScoped: map[string]bool{},
	}
	for _, p := range pkgs {
		a.byPath[p.ImportPath] = p
		// Packages of the main module that the patterns import count too,
		// so `rbacgap ./cmd/manager` checks exactly what that binary links.
		if p.Module != nil && p.Module.Main && !p.Standard {
			a.targets = append(a.targets, &checkedPackage{listed: p})
		}
	}
	return a
}

// crossCheck lists the matched packages a second time, without export data,
// and makes sure each one came back from the first go list run. Output that
// was cut off between two packages is still valid JSON, so this is how a
// short list is caught.
func (a *analyzer) crossCheck(patterns []string) error {
	args := append([]string{"list", "-e", "-f", "{{.ImportPath}}"}, patterns...)
	cmd := exec.Command("go", args...)
	cmd.Dir = a.dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return untrusted("go list failed in %s: %s", a.dir, firstLines(msg, 8))
	}
	have := map[string]bool{}
	for _, cp := range a.targets {
		have[cp.listed.ImportPath] = true
	}
	var missing []string
	n := 0
	for _, line := range strings.Split(out.String(), "\n") {
		path := strings.TrimSpace(line)
		if path == "" {
			continue
		}
		n++
		if !have[path] {
			missing = append(missing, path)
		}
	}
	if n == 0 {
		return untrusted("go list matched no packages in %s", a.dir)
	}
	if len(missing) > 0 {
		return untrusted("go list -export left out %d matched packages, such as %s; its output may be cut off", len(missing), missing[0])
	}
	return nil
}

// typeCheck parses and type-checks every target package from source, using
// export data for imports. Any error makes the result untrusted.
func (a *analyzer) typeCheck() error {
	if len(a.targets) == 0 {
		return untrusted("go list matched no packages of the main module in %s", a.dir)
	}
	var problems []string
	for _, cp := range a.targets {
		p := cp.listed
		if p.Error != nil {
			problems = append(problems, fmt.Sprintf("%s: %s", p.ImportPath, strings.TrimSpace(p.Error.Err)))
		}
		for _, de := range p.DepsErrors {
			problems = append(problems, fmt.Sprintf("%s: dependency error: %s", p.ImportPath, strings.TrimSpace(de.Err)))
		}
	}
	if len(problems) > 0 {
		return &inputError{msgs: limit(problems, 10)}
	}
	exports := map[string]string{}
	for path, p := range a.byPath {
		if p.Export != "" {
			exports[path] = p.Export
		}
	}
	gc := importer.ForCompiler(a.fset, "gc", func(path string) (io.ReadCloser, error) {
		f, ok := exports[path]
		if !ok {
			return nil, fmt.Errorf("go list gave no export data for %s", path)
		}
		return os.Open(f)
	})
	sizes := types.SizesFor("gc", build.Default.GOARCH)
	for _, cp := range a.targets {
		p := cp.listed
		files := p.CompiledGoFiles
		if len(files) == 0 {
			files = p.GoFiles
		}
		if len(files) == 0 {
			continue
		}
		for _, name := range files {
			path := name
			if !filepath.IsAbs(path) {
				path = filepath.Join(p.Dir, name)
			}
			f, err := parser.ParseFile(a.fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", rel(a.dir, path), err))
				continue
			}
			cp.files = append(cp.files, f)
		}
		cp.info = &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Uses:       map[*ast.Ident]types.Object{},
			Defs:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		}
		var typeErrs []string
		conf := types.Config{
			Importer: mappedImporter{base: gc, m: p.ImportMap},
			Sizes:    sizes,
			Error: func(err error) {
				typeErrs = append(typeErrs, err.Error())
			},
		}
		pkg, _ := conf.Check(p.ImportPath, a.fset, cp.files, cp.info)
		cp.pkg = pkg
		if len(typeErrs) > 0 {
			problems = append(problems, fmt.Sprintf("%s does not type-check: %s", p.ImportPath, relAll(a.dir, typeErrs[0])))
			if len(typeErrs) > 1 {
				problems = append(problems, fmt.Sprintf("%s: %d more type errors", p.ImportPath, len(typeErrs)-1))
			}
		}
	}
	if len(problems) > 0 {
		return &inputError{msgs: limit(problems, 10)}
	}
	return nil
}

type mappedImporter struct {
	base types.Importer
	m    map[string]string
}

func (mi mappedImporter) Import(path string) (*types.Package, error) {
	if to, ok := mi.m[path]; ok {
		path = to
	}
	return mi.base.Import(path)
}

func limit(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("... and %d more", len(s)-n))
	}
	return s
}

func rel(base, path string) string {
	if r, err := filepath.Rel(base, path); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return path
}

func relAll(base, msg string) string {
	return strings.ReplaceAll(msg, base+string(filepath.Separator), "")
}

// ---------------------------------------------------------------------------
// Markers

// markers reads +kubebuilder:rbac markers from every comment in the target
// packages' files. controller-gen only reads markers that stand alone: one in
// a declaration's doc comment or inside a declaration is ignored, so it's
// reported as inert and grants nothing. A live marker rbacgap can't parse
// makes the result untrusted, because controller-gen would fail on it too.
func (a *analyzer) markers() ([]Grant, []MarkerIssue, error) {
	var grants []Grant
	var issues []MarkerIssue
	var problems []string
	seen := map[string]bool{}
	for _, cp := range a.targets {
		for _, f := range cp.files {
			attached := attachedComments(f)
			for _, cg := range f.Comments {
				for _, c := range cg.List {
					text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
					if !strings.HasPrefix(text, markerPrefix) {
						continue
					}
					pos := a.fset.Position(c.Pos())
					file := rel(a.dir, pos.Filename)
					key := fmt.Sprintf("%s:%d", file, pos.Line)
					if seen[key] {
						continue
					}
					seen[key] = true
					if attached[cg] {
						issues = append(issues, MarkerIssue{File: file, Line: pos.Line, Marker: text, Problem: "attached to a declaration (its doc comment, a comment inside it, or the end of its line), so controller-gen ignores it; give it its own comment with a blank line after"})
						continue
					}
					g, err := parseMarker(strings.TrimPrefix(text, markerPrefix))
					if err != nil {
						problems = append(problems, fmt.Sprintf("%s:%d: %v: %s", file, pos.Line, err, text))
						continue
					}
					for _, v := range g.Verbs {
						if p := verbProblem(v); p != "" {
							issues = append(issues, MarkerIssue{File: file, Line: pos.Line, Marker: text, Problem: p})
						}
					}
					for _, r := range g.Resources {
						if r != strings.ToLower(r) {
							issues = append(issues, MarkerIssue{File: file, Line: pos.Line, Marker: text, Problem: fmt.Sprintf("resource %q isn't lowercase; RBAC compares resource names exactly, so it grants nothing", r)})
						}
					}
					g.File, g.Line = file, pos.Line
					grants = append(grants, g)
				}
			}
		}
	}
	if len(problems) > 0 {
		return nil, nil, &inputError{msgs: limit(problems, 10)}
	}
	return grants, issues, nil
}

// knownVerbs are the verbs Kubernetes RBAC checks for built-in APIs.
var knownVerbs = map[string]bool{
	"get": true, "list": true, "watch": true, "create": true, "update": true, "patch": true,
	"delete": true, "deletecollection": true, "*": true,
	"use": true, "bind": true, "escalate": true, "impersonate": true, "approve": true, "sign": true, "attest": true,
}

// verbProblem explains why a verb grants nothing, or returns "".
func verbProblem(v string) string {
	if knownVerbs[v] {
		return ""
	}
	if knownVerbs[strings.ToLower(v)] {
		return fmt.Sprintf("verb %q isn't lowercase; RBAC compares verbs exactly, so it grants nothing", v)
	}
	return fmt.Sprintf("verb %q isn't a Kubernetes verb, so it grants nothing; is it a typo?", v)
}

// attachedComments returns the comment groups controller-gen treats as
// belonging to a declaration: doc comments of declarations, specs and fields,
// and any comment inside a declaration. The package doc comment is not one.
func attachedComments(f *ast.File) map[*ast.CommentGroup]bool {
	out := map[*ast.CommentGroup]bool{}
	type span struct{ from, to token.Pos }
	var spans []span
	for _, d := range f.Decls {
		spans = append(spans, span{d.Pos(), d.End()})
		ast.Inspect(d, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				if n.Doc != nil {
					out[n.Doc] = true
				}
			case *ast.GenDecl:
				if n.Doc != nil {
					out[n.Doc] = true
				}
			case *ast.TypeSpec:
				markAttached(out, n.Doc, n.Comment)
			case *ast.ValueSpec:
				markAttached(out, n.Doc, n.Comment)
			case *ast.ImportSpec:
				markAttached(out, n.Doc, n.Comment)
			case *ast.Field:
				markAttached(out, n.Doc, n.Comment)
			}
			return true
		})
	}
	for _, cg := range f.Comments {
		if cg == f.Doc {
			delete(out, cg)
			continue
		}
		for _, sp := range spans {
			if cg.Pos() > sp.from && cg.End() < sp.to {
				out[cg] = true
			}
		}
	}
	return out
}

// markAttached marks a spec's or field's doc and trailing line comment. Both
// belong to the declaration, so controller-gen doesn't read markers there.
func markAttached(out map[*ast.CommentGroup]bool, groups ...*ast.CommentGroup) {
	for _, cg := range groups {
		if cg != nil {
			out[cg] = true
		}
	}
}

// parseMarker parses the arguments of a +kubebuilder:rbac marker, such as
// groups=apps,resources=deployments,verbs=get;list;watch.
func parseMarker(body string) (Grant, error) {
	var g Grant
	body = strings.TrimSpace(body)
	if body == "" {
		return g, errors.New("empty rbac marker")
	}
	parts, err := splitTop(body)
	if err != nil {
		return g, err
	}
	seen := map[string]bool{}
	for _, part := range parts {
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok {
			return g, fmt.Errorf("argument %q has no value", part)
		}
		if seen[k] {
			return g, fmt.Errorf("argument %q appears twice", k)
		}
		seen[k] = true
		vals, err := splitValues(v)
		if err != nil {
			return g, err
		}
		switch k {
		case "groups":
			for i, gr := range vals {
				if gr == "core" {
					vals[i] = ""
				}
			}
			g.Groups = vals
		case "resources":
			g.Resources = vals
		case "verbs":
			g.Verbs = vals
		case "resourceNames":
			g.ResourceNames = vals
		case "urls":
			g.URLs = vals
		case "namespace":
			if len(vals) != 1 {
				return g, errors.New("namespace takes one value")
			}
			g.Namespace = vals[0]
		default:
			return g, fmt.Errorf("unknown argument %q", k)
		}
	}
	if len(g.Verbs) == 0 {
		return g, errors.New("rbac marker has no verbs")
	}
	if len(g.URLs) == 0 && len(g.Resources) == 0 {
		return g, errors.New("rbac marker has no resources")
	}
	if len(g.URLs) == 0 && g.Groups == nil {
		return g, errors.New("rbac marker has no groups")
	}
	return g, nil
}

// splitTop splits on commas that aren't inside braces or quotes.
func splitTop(s string) ([]string, error) {
	var parts []string
	depth, start := 0, 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth < 0 {
				return nil, errors.New("unbalanced braces")
			}
		case c == ',' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if depth != 0 || inQuote {
		return nil, errors.New("unbalanced braces or quotes")
	}
	parts = append(parts, s[start:])
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			return nil, errors.New("empty argument")
		}
	}
	return parts, nil
}

// splitValues splits a marker value: a;b;c, {a,b,c} or a quoted string.
func splitValues(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	var raw []string
	if strings.HasPrefix(v, "{") {
		if !strings.HasSuffix(v, "}") {
			return nil, fmt.Errorf("value %q is missing its closing brace", v)
		}
		raw = strings.Split(v[1:len(v)-1], ",")
	} else {
		raw = strings.Split(v, ";")
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, `"`) {
			u, err := strconv.Unquote(r)
			if err != nil {
				return nil, fmt.Errorf("bad quoted value %s", r)
			}
			r = u
		} else if r == "" {
			return nil, fmt.Errorf("empty value in %q", v)
		}
		out = append(out, r)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// CRD plural names

// findCRDNames reads plural names from CustomResourceDefinition YAML files in
// the module, as controller-gen writes them. Lines are matched one at a time,
// so only the generated layout is understood. A CRD document without a group,
// kind and plural is an error, because it may be cut off.
func (a *analyzer) findCRDNames() error {
	var problems []string
	_ = filepath.WalkDir(a.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != a.dir && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Contains(data, []byte("kind: CustomResourceDefinition")) {
			return nil
		}
		for _, doc := range strings.Split(string(data), "\n---") {
			if !isCRDDoc(doc) {
				continue
			}
			var group, kind, plural string
			for _, line := range strings.Split(doc, "\n") {
				t := strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(t, "group:") && group == "":
					group = unquoteYAML(strings.TrimPrefix(t, "group:"))
				case strings.HasPrefix(t, "kind:") && kind == "" && !strings.Contains(t, "CustomResourceDefinition"):
					kind = unquoteYAML(strings.TrimPrefix(t, "kind:"))
				case strings.HasPrefix(t, "plural:") && plural == "":
					plural = unquoteYAML(strings.TrimPrefix(t, "plural:"))
				}
			}
			if group == "" && !strings.Contains(doc, "\n  names:") {
				// A kustomize patch for a CRD, with no names to read.
				continue
			}
			if group == "" || kind == "" || plural == "" {
				problems = append(problems, fmt.Sprintf("%s: a CustomResourceDefinition has no spec.group, names.kind or names.plural; it may be cut off", rel(a.dir, path)))
				continue
			}
			key := group + "/" + kind
			if prev, ok := a.crdPlurals[key]; ok && prev != plural {
				problems = append(problems, fmt.Sprintf("%s: CRD files disagree on the plural of %s: %s and %s; remove the stale copy", rel(a.dir, path), key, prev, plural))
				continue
			}
			a.crdPlurals[key] = plural
			if strings.Contains(doc, "\n  scope: Cluster") {
				a.clusterScoped[key] = true
			}
		}
		return nil
	})
	if len(problems) > 0 {
		return &inputError{msgs: limit(problems, 10)}
	}
	return nil
}

// isCRDDoc reports whether a YAML document is a CustomResourceDefinition:
// both apiVersion and kind are top-level keys with CRD values.
func isCRDDoc(doc string) bool {
	api, kind := false, false
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimRight(line, " \r")
		if strings.HasPrefix(line, "apiVersion:") && strings.HasPrefix(unquoteYAML(strings.TrimPrefix(line, "apiVersion:")), "apiextensions.k8s.io/") {
			api = true
		}
		if strings.HasPrefix(line, "kind:") && unquoteYAML(strings.TrimPrefix(line, "kind:")) == "CustomResourceDefinition" {
			kind = true
		}
	}
	return api && kind
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return strings.Trim(s, `"'`)
}

// ---------------------------------------------------------------------------
// Call sites

// kindRef is the API kind an object argument refers to.
type kindRef struct {
	kind    string
	pkgPath string
}

func (a *analyzer) walk(cp *checkedPackage) {
	for _, f := range cp.files {
		if isGenerated(f) {
			// Generated clientsets and informers call the API on behalf of
			// their callers. Those calls are counted where the callers are.
			a.skippedGenerated++
			continue
		}
		called := map[*ast.SelectorExpr]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				fun := ast.Unparen(c.Fun)
				switch x := fun.(type) {
				case *ast.IndexExpr:
					fun = x.X
				case *ast.IndexListExpr:
					fun = x.X
				}
				if sel, ok := ast.Unparen(fun).(*ast.SelectorExpr); ok {
					called[sel] = true
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				a.call(cp, n)
			case *ast.CompositeLit:
				a.compositeLit(cp, n)
			case *ast.SelectorExpr:
				if !called[n] {
					a.methodValue(cp, n)
				}
			}
			return true
		})
	}
}

// clientGenerators are the code-generator tools whose output calls the API on
// behalf of its callers.
var clientGenerators = []string{"client-gen", "informer-gen", "lister-gen", "applyconfiguration-gen"}

// methodValue reports an API method taken as a value, such as
// del := r.Delete, which is called later where rbacgap can't follow it.
func (a *analyzer) methodValue(cp *checkedPackage, sel *ast.SelectorExpr) {
	s, ok := cp.info.Selections[sel]
	if !ok || s.Kind() != types.MethodVal {
		return
	}
	fn, ok := s.Obj().(*types.Func)
	if !ok || fn.Pkg() == nil || !isAPIMethod(fn.Origin()) {
		return
	}
	a.calls++
	file, line := a.pos(sel)
	a.unresolvedAt(file, line, exprText(sel), "method value; the call it's used for can't be followed, check by hand")
}

// isAPIMethod reports whether a method sends a request to the API server.
func isAPIMethod(fn *types.Func) bool {
	path := fn.Pkg().Path()
	recv := recvName(fn)
	if recv == "" {
		return false
	}
	switch {
	case path == crClient || strings.HasPrefix(path, crCache):
		return isVerbMethod(fn.Name()) || fn.Name() == "DeleteAllOf"
	case strings.Contains(path, "/typed/"), path == cgDynamic, path == cgMetadata:
		return isVerbMethod(fn.Name())
	}
	return false
}

// clientMethodShape reports whether a method on some other interface has the
// signature of a controller-runtime client method, so a wrapper interface
// that a client.Client is assigned to is still checked.
func clientMethodShape(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	if _, ok := sig.Recv().Type().Underlying().(*types.Interface); !ok {
		return false
	}
	want := map[string]int{"Get": 2, "List": 1, "Create": 1, "Update": 1, "Patch": 1, "Delete": 1, "DeleteAllOf": 1, "Apply": 1}
	idx, ok := want[fn.Name()]
	if !ok || sig.Params().Len() <= idx {
		return false
	}
	t := types.Unalias(sig.Params().At(idx).Type())
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return false
	}
	p := n.Obj().Pkg().Path()
	return (p == crClient || strings.HasPrefix(p, crCache) || p == "k8s.io/apimachinery/pkg/runtime") &&
		(n.Obj().Name() == "Object" || n.Obj().Name() == "ObjectList" || n.Obj().Name() == "ApplyConfiguration")
}

// isGenerated reports whether a file is a generated clientset, informer,
// lister or apply configuration: a "Code generated by X. DO NOT EDIT."
// header before the package clause, where X is one of Kubernetes' client
// generators. Other generated files, including cgo output, are checked.
func isGenerated(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			return false
		}
		for _, c := range cg.List {
			if !strings.HasPrefix(c.Text, "// Code generated by ") || !strings.HasSuffix(c.Text, " DO NOT EDIT.") {
				continue
			}
			gen := strings.TrimSuffix(strings.Fields(strings.TrimPrefix(c.Text, "// Code generated by "))[0], ".")
			for _, g := range clientGenerators {
				if gen == g {
					return true
				}
			}
		}
	}
	return false
}

// pos returns where a call is. For a method call it's the method name, so
// each call in a builder chain gets its own line.
func (a *analyzer) pos(n ast.Node) (string, int) {
	at := n.Pos()
	if c, ok := n.(*ast.CallExpr); ok {
		if sel, ok := ast.Unparen(c.Fun).(*ast.SelectorExpr); ok {
			at = sel.Sel.Pos()
		}
	}
	p := a.fset.Position(at)
	return rel(a.dir, p.Filename), p.Line
}

// exprText prints a call's function for messages, shortening long chains to
// their last two steps.
func exprText(e ast.Expr) string {
	s := types.ExprString(e)
	if len(s) <= 50 {
		return s
	}
	if sel, ok := ast.Unparen(e).(*ast.SelectorExpr); ok {
		x := types.ExprString(sel.X)
		if inner, ok := ast.Unparen(sel.X).(*ast.CallExpr); ok {
			if isel, ok := ast.Unparen(inner.Fun).(*ast.SelectorExpr); ok {
				x = isel.Sel.Name + "(...)"
			}
		}
		if len(x) > 30 {
			x = x[:27] + "..."
		}
		return "..." + x + "." + sel.Sel.Name
	}
	return s[:47] + "..."
}

// callee returns the function or method a call invokes, if it's static.
func callee(info *types.Info, fun ast.Expr) *types.Func {
	fun = ast.Unparen(fun)
	switch f := fun.(type) {
	case *ast.IndexExpr:
		fun = f.X
	case *ast.IndexListExpr:
		fun = f.X
	}
	switch f := ast.Unparen(fun).(type) {
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[f]; ok {
			fn, _ := sel.Obj().(*types.Func)
			return fn
		}
		switch obj := info.Uses[f.Sel].(type) {
		case *types.Func:
			return obj
		case *types.Var:
			return rootAlias(obj)
		}
		return nil
	case *ast.Ident:
		fn, _ := info.Uses[f].(*types.Func)
		return fn
	}
	return nil
}

// rootAlias returns a stand-in function for the variables in
// controller-runtime's root package that alias controllerutil functions.
func rootAlias(v *types.Var) *types.Func {
	if v.Pkg() == nil || v.Pkg().Path() != crRoot {
		return nil
	}
	switch v.Name() {
	case "CreateOrUpdate", "CreateOrPatch", "SetControllerReference":
		return types.NewFunc(v.Pos(), v.Pkg(), v.Name(), types.NewSignatureType(nil, nil, nil, nil, nil, false))
	}
	return nil
}

// recvName returns the receiver type name of a method, or "" for a function.
func recvName(fn *types.Func) string {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return ""
	}
	t := sig.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	t = types.Unalias(t)
	if n, ok := t.(*types.Named); ok {
		return n.Origin().Obj().Name()
	}
	return ""
}

func (a *analyzer) call(cp *checkedPackage, call *ast.CallExpr) {
	fn := callee(cp.info, call.Fun)
	if fn == nil || fn.Pkg() == nil {
		return
	}
	fn = fn.Origin()
	path := fn.Pkg().Path()
	name := fn.Name()
	recv := recvName(fn)
	if path == crRoot && recv == "" {
		// ctrl.CreateOrUpdate and friends are variables in the root
		// package that hold controllerutil's functions.
		path = crUtil
	}
	if path != crClient && !strings.HasPrefix(path, "sigs.k8s.io/controller-runtime") && clientMethodShape(fn) {
		// A user interface that a client.Client is assigned to.
		a.crClientCall(cp, call, "Client", name)
		return
	}
	switch {
	case path == crClient:
		a.crClientCall(cp, call, recv, name)
	case path == crBuilder && (name == "For" || name == "Owns" || name == "Watches" || name == "WatchesMetadata") && recv != "":
		if len(call.Args) == 0 {
			return
		}
		// Before controller-runtime 0.15, Watches took a source.Source.
		// That source is handled where it's built.
		if name == "Watches" && !isObjectArg(cp.info, call.Args[0]) {
			return
		}
		a.objectNeeds(cp, call, call.Args[0], needOpts{verbs: []string{"list", "watch"}, why: "the controller watches it (" + name + ")", count: true})
	case path == crSource && recv == "" && (name == "Kind" || name == "TypedKind"):
		if len(call.Args) >= 2 {
			a.objectNeeds(cp, call, call.Args[1], needOpts{verbs: []string{"list", "watch"}, why: "source." + name + " watches it", count: true})
		}
	case path == crUtil && recv == "" && (name == "CreateOrUpdate" || name == "CreateOrPatch"):
		if len(call.Args) < 3 {
			return
		}
		a.calls++
		obj := call.Args[2]
		why := "controllerutil." + name
		a.objectNeeds(cp, call, obj, needOpts{verbs: []string{"get"}, why: why + " reads first"})
		a.cacheNeeds(cp, call, obj, call.Args[1], why)
		last := "update"
		if name == "CreateOrPatch" {
			last = "patch"
		}
		a.objectNeeds(cp, call, obj, needOpts{verbs: []string{"create", last}, why: why})
		if name == "CreateOrPatch" {
			a.objectNeeds(cp, call, obj, needOpts{sub: "status", verbs: []string{"patch"}, why: why + " patches status if the mutate function changes it", soft: true})
		}
	case path == crUtil && recv == "" && name == "SetControllerReference":
		if len(call.Args) < 1 {
			return
		}
		a.objectNeeds(cp, call, call.Args[0], needOpts{sub: "finalizers", verbs: []string{"update"}, why: "SetControllerReference sets blockOwnerDeletion; needed when the OwnerReferencesPermissionEnforcement admission plugin is on", soft: true})
	case (path == crManager || path == crCluster) && recv != "" && (name == "GetEventRecorderFor" || name == "GetEventRecorder"):
		a.calls++
		file, line := a.pos(call)
		group := ""
		why := "GetEventRecorderFor writes core/v1 Events"
		if name == "GetEventRecorder" {
			group = "events.k8s.io"
			why = "GetEventRecorder writes events.k8s.io/v1 Events"
		}
		for _, v := range []string{"create", "patch"} {
			a.needs = append(a.needs, Need{Group: group, Resource: "events", Verb: v, File: file, Line: line, Call: exprText(call.Fun), Why: why})
		}
	case strings.HasPrefix(path, crCache) && recv != "" && name == "IndexField":
		// controller-runtime 0.25 moved FieldIndexer to pkg/cache/cacheapi.
		if len(call.Args) >= 2 {
			a.objectNeeds(cp, call, call.Args[1], needOpts{verbs: []string{"list", "watch"}, why: "IndexField starts an informer", count: true})
		}
	case strings.HasPrefix(path, crCache) && recv != "" && name == "GetInformer":
		if len(call.Args) >= 2 {
			a.objectNeeds(cp, call, call.Args[1], needOpts{verbs: []string{"list", "watch"}, why: "GetInformer starts an informer", count: true})
		}
	case (path == cgDynamic || path == cgMetadata) && recv != "" && isVerbMethod(name):
		a.calls++
		a.unresolve(call, "dynamic or metadata client call; the resource is chosen at runtime, check its RBAC by hand")
	case (strings.Contains(path, "/informers") || strings.HasSuffix(path, "informer")) && recv != "" && (name == "ForResource" || name == "InformerFor"):
		a.calls++
		a.unresolve(call, "informer for a resource chosen at runtime; it lists and watches, check its RBAC by hand")
	case path == cgRest && recv == "Request" && (name == "Do" || name == "DoRaw" || name == "Stream" || name == "Watch"):
		a.calls++
		a.unresolve(call, "raw REST client request; check its RBAC by hand")
	case strings.HasPrefix(path, crCache) && recv != "" && name == "GetInformerForKind":
		a.calls++
		a.unresolve(call, "informer for a kind chosen at runtime; it lists and watches, check its RBAC by hand")
	case strings.Contains(path, "/typed/") && (strings.HasSuffix(recv, "Interface") || strings.HasSuffix(recv, "Expansion")):
		a.typedClientCall(cp, call, fn, recv, name)
	case strings.Contains(path, "/informers/") && strings.HasSuffix(recv, "Informer") && (name == "Informer" || name == "Lister"):
		a.informerCall(cp, call, fn, recv)
	}
}

func isVerbMethod(name string) bool {
	switch name {
	case "Get", "List", "Watch", "Create", "Update", "UpdateStatus", "Delete", "DeleteCollection", "Patch", "Apply", "ApplyStatus":
		return true
	}
	return false
}

// compositeLit handles &source.Kind{Type: &T{}} from controller-runtime
// before 0.15.
func (a *analyzer) compositeLit(cp *checkedPackage, lit *ast.CompositeLit) {
	t := cp.info.TypeOf(lit)
	if t == nil {
		return
	}
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil || n.Obj().Pkg().Path() != crSource || n.Obj().Name() != "Kind" {
		return
	}
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Type" {
			a.objectNeeds(cp, lit, kv.Value, needOpts{verbs: []string{"list", "watch"}, why: "source.Kind watches it", count: true})
		}
	}
}

func (a *analyzer) crClientCall(cp *checkedPackage, call *ast.CallExpr, recv, name string) {
	sel, _ := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	switch recv {
	case "Reader", "Client", "WithWatch":
		switch name {
		case "Get":
			if len(call.Args) < 3 {
				return
			}
			a.objectNeeds(cp, call, call.Args[2], needOpts{verbs: []string{"get"}, why: "Get", count: true})
			if sel != nil {
				a.cacheNeeds(cp, call, call.Args[2], sel.X, "Get")
			}
			return
		case "List":
			if len(call.Args) < 2 {
				return
			}
			a.objectNeeds(cp, call, call.Args[1], needOpts{verbs: []string{"list"}, why: "List", count: true})
			if sel != nil && cachedReceiver(cp.info, sel.X) {
				a.objectNeeds(cp, call, call.Args[1], needOpts{verbs: []string{"watch"}, why: "cached client: its informer also watches", cache: true})
			}
			return
		case "Watch":
			if len(call.Args) >= 2 {
				a.objectNeeds(cp, call, call.Args[1], needOpts{verbs: []string{"watch"}, why: "Watch", count: true})
			}
			return
		}
		fallthrough
	case "Writer":
		verb := map[string]string{"Create": "create", "Delete": "delete", "Update": "update", "Patch": "patch", "DeleteAllOf": "deletecollection", "Apply": "patch"}[name]
		if verb == "" || len(call.Args) < 2 {
			return
		}
		a.objectNeeds(cp, call, call.Args[1], needOpts{verbs: []string{verb}, why: name, count: true})
	case "StatusWriter", "SubResourceWriter", "SubResourceClient", "SubResourceReader":
		verb := map[string]string{"Create": "create", "Update": "update", "Patch": "patch", "Apply": "patch", "Get": "get"}[name]
		if verb == "" || len(call.Args) < 2 || sel == nil {
			return
		}
		sub, ok := subresourceOf(cp.info, sel.X)
		if !ok {
			a.calls++
			a.unresolve(call, "subresource "+name+" on a writer held in a variable; rbacgap can't tell which subresource")
			return
		}
		a.objectNeeds(cp, call, call.Args[1], needOpts{sub: sub, verbs: []string{verb}, why: sub + " " + name, count: true})
	case "FieldIndexer":
		if name == "IndexField" && len(call.Args) >= 2 {
			a.objectNeeds(cp, call, call.Args[1], needOpts{verbs: []string{"list", "watch"}, why: "IndexField starts an informer", count: true})
		}
	}
}

// cacheNeeds adds list and watch for a Get that goes through the cache.
func (a *analyzer) cacheNeeds(cp *checkedPackage, call *ast.CallExpr, obj, recvExpr ast.Expr, what string) {
	if !cachedReceiver(cp.info, recvExpr) {
		return
	}
	a.objectNeeds(cp, call, obj, needOpts{verbs: []string{"list", "watch"}, why: "cached client: its informer lists and watches", cache: true})
}

// cachedReceiver reports whether reads through this expression probably go
// through controller-runtime's cache. The manager's client does by default.
// A reader from GetAPIReader, or a field or variable whose name says it's the
// API reader or uncached, doesn't.
func cachedReceiver(info *types.Info, x ast.Expr) bool {
	x = ast.Unparen(x)
	if c, ok := x.(*ast.CallExpr); ok {
		if fn := callee(info, c.Fun); fn != nil && fn.Name() == "GetAPIReader" {
			return false
		}
	}
	var name string
	switch e := x.(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	}
	l := strings.ToLower(name)
	if strings.Contains(l, "apireader") || strings.Contains(l, "uncached") || strings.Contains(l, "noncached") || strings.Contains(l, "nocache") || strings.Contains(l, "direct") {
		return false
	}
	return true
}

// subresourceOf finds the subresource of X in X.Status().Update or
// X.SubResource("scale").Update.
func subresourceOf(info *types.Info, x ast.Expr) (string, bool) {
	c, ok := ast.Unparen(x).(*ast.CallExpr)
	if !ok {
		return "", false
	}
	fn := callee(info, c.Fun)
	if fn == nil {
		return "", false
	}
	switch fn.Name() {
	case "Status":
		return "status", true
	case "SubResource":
		if len(c.Args) == 1 {
			if tv, ok := info.Types[c.Args[0]]; ok && tv.Value != nil {
				if s, err := strconv.Unquote(tv.Value.ExactString()); err == nil && s != "" {
					return s, true
				}
			}
		}
	}
	return "", false
}

// isObjectArg reports whether e looks like a Kubernetes object: it has a
// GetObjectKind method.
func isObjectArg(info *types.Info, e ast.Expr) bool {
	t := info.TypeOf(e)
	if t == nil {
		return false
	}
	ms := types.NewMethodSet(t)
	for i := 0; i < ms.Len(); i++ {
		if ms.At(i).Obj().Name() == "GetObjectKind" {
			return true
		}
	}
	return false
}

// needOpts describes the permissions one call site needs on its object.
type needOpts struct {
	sub   string   // subresource, such as status
	verbs []string // verbs needed
	why   string   // shown next to each need
	soft  bool     // depends on cluster settings; never fails the check
	cache bool     // needed because the read goes through the informer cache
	count bool     // a new call site for the count
}

// objectNeeds resolves the object argument and records one need per verb.
func (a *analyzer) objectNeeds(cp *checkedPackage, at ast.Node, obj ast.Expr, o needOpts) {
	if o.count {
		a.calls++
	}
	file, line := a.pos(at)
	text := ""
	if c, ok := at.(*ast.CallExpr); ok {
		text = exprText(c.Fun)
	} else if e, ok := at.(ast.Expr); ok {
		text = exprText(e)
	}
	ref, reason := resolveKind(cp.info, obj)
	if reason != "" {
		// A soft need, such as the owner's finalizers, is only a hint, so
		// an unknown kind there isn't worth an UNCHECKED line.
		if !o.soft {
			a.unresolvedAt(file, line, text, reason)
		}
		return
	}
	group, ok := a.groupOf(ref.pkgPath)
	if !ok {
		a.unresolvedAt(file, line, text, fmt.Sprintf("can't find the API group of package %s (no +groupName and no GroupVersion literal)", ref.pkgPath))
		return
	}
	resource, guessed := a.pluralOf(group, ref)
	if o.sub != "" {
		resource += "/" + o.sub
	}
	for _, v := range o.verbs {
		a.needs = append(a.needs, Need{Group: group, Resource: resource, Verb: v, File: file, Line: line, Call: text, Why: o.why, Soft: o.soft, Cache: o.cache, Guessed: guessed})
	}
}

func (a *analyzer) unresolve(call *ast.CallExpr, reason string) {
	file, line := a.pos(call)
	a.unresolvedAt(file, line, exprText(call.Fun), reason)
}

func (a *analyzer) unresolvedAt(file string, line int, text, reason string) {
	for _, u := range a.unresolved {
		if u.File == file && u.Line == line && u.Reason == reason {
			return
		}
	}
	a.unresolved = append(a.unresolved, Unresolved{File: file, Line: line, Call: text, Reason: reason})
}

// resolveKind finds the named API type behind an object or list argument.
func resolveKind(info *types.Info, e ast.Expr) (kindRef, string) {
	t := info.TypeOf(e)
	if t == nil {
		return kindRef{}, "no type information for the object argument"
	}
	return kindOfType(t)
}

func kindOfType(t types.Type) (kindRef, string) {
	return kindOfTypeDepth(t, 0)
}

func kindOfTypeDepth(t types.Type, depth int) (kindRef, string) {
	if depth > 3 {
		return kindRef{}, "list type whose Items nest too deeply to resolve"
	}
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	if _, ok := t.Underlying().(*types.Interface); ok {
		return kindRef{}, fmt.Sprintf("the object has interface type %s, so its kind is only known at runtime", types.TypeString(t, shortQualifier))
	}
	if tp, ok := t.(*types.TypeParam); ok {
		return kindRef{}, fmt.Sprintf("the object has type parameter %s, so its kind is only known at runtime", tp.Obj().Name())
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return kindRef{}, fmt.Sprintf("the object has unnamed type %s", types.TypeString(t, shortQualifier))
	}
	name := n.Obj().Name()
	path := n.Obj().Pkg().Path()
	if path == unstructured || (path == metav1 && strings.HasPrefix(name, "PartialObjectMetadata")) {
		return kindRef{}, fmt.Sprintf("%s object; its group and kind are set at runtime, check its RBAC by hand", name)
	}
	if strings.HasSuffix(name, "ApplyConfiguration") {
		kind := strings.TrimSuffix(name, "ApplyConfiguration")
		if strings.HasPrefix(path, applyCfgPkg) {
			return kindRef{kind: kind, pkgPath: k8sAPIPrefix + strings.TrimPrefix(path, applyCfgPkg)}, ""
		}
		return kindRef{}, fmt.Sprintf("apply configuration %s from %s; rbacgap only maps client-go's own apply configurations", name, path)
	}
	// A list type: use the element type of its Items field.
	if st, ok := n.Underlying().(*types.Struct); ok && strings.HasSuffix(name, "List") {
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f.Name() != "Items" {
				continue
			}
			if sl, ok := types.Unalias(f.Type()).(*types.Slice); ok {
				return kindOfTypeDepth(sl.Elem(), depth+1)
			}
		}
		return kindRef{kind: strings.TrimSuffix(name, "List"), pkgPath: path}, ""
	}
	return kindRef{kind: name, pkgPath: path}, ""
}

func shortQualifier(p *types.Package) string { return p.Name() }

// groupOf finds the API group of a package from its +groupName marker or its
// GroupVersion / SchemeGroupVersion literal.
func (a *analyzer) groupOf(pkgPath string) (string, bool) {
	if gi, ok := a.groups[pkgPath]; ok {
		return gi.group, gi.ok
	}
	gi := a.findGroup(pkgPath)
	a.groups[pkgPath] = gi
	return gi.group, gi.ok
}

func (a *analyzer) pkgFiles(pkgPath string) []*ast.File {
	for _, cp := range a.targets {
		if cp.listed.ImportPath == pkgPath {
			return cp.files
		}
	}
	p, ok := a.byPath[pkgPath]
	if !ok {
		return nil
	}
	var files []*ast.File
	fset := token.NewFileSet()
	for _, name := range p.GoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, parser.ParseComments|parser.SkipObjectResolution)
		if err == nil {
			files = append(files, f)
		}
	}
	return files
}

func (a *analyzer) findGroup(pkgPath string) groupInfo {
	files := a.pkgFiles(pkgPath)
	for _, f := range files {
		for _, cg := range f.Comments {
			if cg.Pos() > f.Package {
				continue
			}
			for _, c := range cg.List {
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				if strings.HasPrefix(text, groupNameMark) {
					return groupInfo{group: strings.TrimSpace(strings.TrimPrefix(text, groupNameMark)), ok: true}
				}
			}
		}
	}
	consts := map[string]ast.Expr{}
	for _, f := range files {
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, s := range gd.Specs {
					vs := s.(*ast.ValueSpec)
					for i, id := range vs.Names {
						if i < len(vs.Values) {
							consts[id.Name] = vs.Values[i]
						}
					}
				}
			}
		}
	}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, id := range vs.Names {
					if (id.Name != "GroupVersion" && id.Name != "SchemeGroupVersion") || i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.CompositeLit); ok {
						for _, el := range lit.Elts {
							kv, ok := el.(*ast.KeyValueExpr)
							if !ok {
								continue
							}
							if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Group" {
								if s, ok := stringValue(kv.Value, consts); ok {
									return groupInfo{group: s, ok: true}
								}
							}
						}
					}
				}
			}
		}
	}
	return groupInfo{}
}

// stringValue evaluates a string literal, or a package constant that is one.
func stringValue(e ast.Expr, consts map[string]ast.Expr) (string, bool) {
	for depth := 0; depth < 4; depth++ {
		switch v := e.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(v.Value)
			return s, err == nil
		case *ast.Ident:
			next, ok := consts[v.Name]
			if !ok {
				return "", false
			}
			e = next
		default:
			return "", false
		}
	}
	return "", false
}

// pluralOf finds the resource name for a kind: a +kubebuilder:resource:path
// marker on the type, then a CRD YAML file in the module, then English rules.
func (a *analyzer) pluralOf(group string, ref kindRef) (string, bool) {
	key := group + "/" + ref.kind
	if p, ok := a.plurals[key]; ok {
		return p, false
	}
	if !strings.HasPrefix(ref.pkgPath, k8sAPIPrefix) {
		p, scope := a.resourceMarker(ref)
		if scope == "Cluster" {
			a.clusterScoped[key] = true
		}
		if p != "" {
			a.plurals[key] = p
			return p, false
		}
		if p, ok := a.crdPlurals[key]; ok {
			a.plurals[key] = p
			return p, false
		}
		return guessPlural(ref.kind), true
	}
	return guessPlural(ref.kind), false
}

// resourceMarker reads path= and scope= from a +kubebuilder:resource marker
// on the kind's type.
func (a *analyzer) resourceMarker(ref kindRef) (path, scope string) {
	for _, f := range a.pkgFiles(ref.pkgPath) {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, s := range gd.Specs {
				ts := s.(*ast.TypeSpec)
				if ts.Name.Name != ref.kind {
					continue
				}
				for _, cg := range []*ast.CommentGroup{gd.Doc, ts.Doc} {
					if cg == nil {
						continue
					}
					for _, c := range cg.List {
						text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
						if !strings.HasPrefix(text, "+kubebuilder:resource:") {
							continue
						}
						for _, part := range strings.Split(strings.TrimPrefix(text, "+kubebuilder:resource:"), ",") {
							k, v, ok := strings.Cut(part, "=")
							if !ok {
								continue
							}
							v = strings.Trim(strings.TrimSpace(v), `"`)
							switch strings.TrimSpace(k) {
							case "path":
								path = v
							case "scope":
								scope = v
							}
						}
					}
				}
			}
		}
	}
	return path, scope
}

// builtinClusterScoped lists built-in resources that aren't namespaced.
var builtinClusterScoped = map[string]bool{
	"/nodes": true, "/namespaces": true, "/persistentvolumes": true, "/componentstatuses": true,
	"rbac.authorization.k8s.io/clusterroles": true, "rbac.authorization.k8s.io/clusterrolebindings": true,
	"apiextensions.k8s.io/customresourcedefinitions": true, "apiregistration.k8s.io/apiservices": true,
	"storage.k8s.io/storageclasses": true, "storage.k8s.io/csidrivers": true, "storage.k8s.io/csinodes": true,
	"storage.k8s.io/volumeattachments": true, "scheduling.k8s.io/priorityclasses": true,
	"node.k8s.io/runtimeclasses": true, "networking.k8s.io/ingressclasses": true,
	"admissionregistration.k8s.io/mutatingwebhookconfigurations":     true,
	"admissionregistration.k8s.io/validatingwebhookconfigurations":   true,
	"admissionregistration.k8s.io/validatingadmissionpolicies":       true,
	"admissionregistration.k8s.io/validatingadmissionpolicybindings": true,
	"certificates.k8s.io/certificatesigningrequests":                 true, "flowcontrol.apiserver.k8s.io/flowschemas": true,
	"flowcontrol.apiserver.k8s.io/prioritylevelconfigurations": true,
	"authentication.k8s.io/tokenreviews":                       true, "authorization.k8s.io/subjectaccessreviews": true,
	"authorization.k8s.io/selfsubjectaccessreviews": true, "authorization.k8s.io/selfsubjectrulesreviews": true,
}

// markClusterScoped sets Cluster on needs for resources that aren't
// namespaced, from the built-in list, CRD files and resource markers.
func (a *analyzer) markClusterScoped() {
	byPlural := map[string]bool{}
	for key, cluster := range a.clusterScoped {
		if !cluster {
			continue
		}
		group, kind, _ := strings.Cut(key, "/")
		if p, ok := a.plurals[key]; ok {
			byPlural[group+"/"+p] = true
		} else if p, ok := a.crdPlurals[key]; ok {
			byPlural[group+"/"+p] = true
		} else {
			byPlural[group+"/"+guessPlural(kind)] = true
		}
	}
	for i := range a.needs {
		base, _, _ := strings.Cut(a.needs[i].Resource, "/")
		k := a.needs[i].Group + "/" + base
		if builtinClusterScoped[k] || byPlural[k] {
			a.needs[i].Cluster = true
		}
	}
}

// guessPlural lowercases a kind and pluralizes it the way Kubernetes names
// its built-in resources.
func guessPlural(kind string) string {
	l := strings.ToLower(kind)
	switch l {
	case "endpoints":
		return l
	}
	switch {
	case strings.HasSuffix(l, "s"), strings.HasSuffix(l, "x"), strings.HasSuffix(l, "z"), strings.HasSuffix(l, "ch"), strings.HasSuffix(l, "sh"):
		return l + "es"
	case strings.HasSuffix(l, "y") && len(l) > 1 && !strings.ContainsRune("aeiou", rune(l[len(l)-2])):
		return l[:len(l)-1] + "ies"
	}
	return l + "s"
}

// typedClientCall handles client-go clientsets, including generated ones:
// clientset.CoreV1().Pods(ns).Get(...).
func (a *analyzer) typedClientCall(cp *checkedPackage, call *ast.CallExpr, fn *types.Func, recv, name string) {
	base := strings.TrimSuffix(strings.TrimSuffix(recv, "Interface"), "Expansion")
	ref, ok := typedKind(fn.Pkg(), base)
	if !ok {
		// Not a resource client, such as CoreV1Interface.
		return
	}
	verb, sub := "", ""
	switch name {
	case "Get":
		verb = "get"
	case "List":
		verb = "list"
	case "Watch":
		verb = "watch"
	case "Create":
		verb = "create"
	case "Update":
		verb = "update"
	case "UpdateStatus":
		verb, sub = "update", "status"
	case "Delete":
		verb = "delete"
	case "DeleteCollection":
		verb = "deletecollection"
	case "Apply":
		verb = "patch"
	case "ApplyStatus":
		verb, sub = "patch", "status"
	case "GetScale":
		verb, sub = "get", "scale"
	case "UpdateScale":
		verb, sub = "update", "scale"
	case "ApplyScale":
		verb, sub = "patch", "scale"
	case "Evict", "EvictV1", "EvictV1beta1":
		verb, sub = "create", "eviction"
	case "GetLogs":
		verb, sub = "get", "log"
	case "Bind":
		verb, sub = "create", "binding"
	case "ProxyGet":
		verb, sub = "get", "proxy"
	case "UpdateEphemeralContainers":
		verb, sub = "update", "ephemeralcontainers"
	case "UpdateResize":
		verb, sub = "update", "resize"
	case "CreateToken":
		verb, sub = "create", "token"
	case "UpdateApproval":
		verb, sub = "update", "approval"
	case "Patch":
		verb = "patch"
		// Patch(ctx, name, pt, data, opts, subresources ...string)
		if len(call.Args) > 5 {
			if len(call.Args) > 6 || call.Ellipsis.IsValid() {
				a.calls++
				a.unresolve(call, "Patch with several or variable subresources; check by hand")
				return
			}
			tv, ok := cp.info.Types[call.Args[5]]
			if !ok || tv.Value == nil {
				a.calls++
				a.unresolve(call, "Patch with a subresource that isn't a constant")
				return
			}
			s, err := strconv.Unquote(tv.Value.ExactString())
			if err != nil {
				a.calls++
				a.unresolve(call, "Patch with a subresource that isn't a string")
				return
			}
			sub = s
		}
	default:
		a.calls++
		a.unresolve(call, fmt.Sprintf("client-go method %s.%s isn't in rbacgap's verb table", recv, name))
		return
	}
	a.calls++
	file, line := a.pos(call)
	group, gok := a.groupOf(ref.pkgPath)
	if !gok {
		a.unresolvedAt(file, line, exprText(call.Fun), fmt.Sprintf("can't find the API group of package %s", ref.pkgPath))
		return
	}
	resource, guessed := a.pluralOf(group, ref)
	if sub != "" {
		resource += "/" + sub
	}
	a.needs = append(a.needs, Need{Group: group, Resource: resource, Verb: verb, File: file, Line: line, Call: exprText(call.Fun), Why: "client-go " + name, Guessed: guessed})
}

// typedKind finds the kind a typed client interface serves, from the result
// type of one of its methods: PodInterface.Get returns *corev1.Pod.
func typedKind(pkg *types.Package, base string) (kindRef, bool) {
	obj := pkg.Scope().Lookup(base + "Interface")
	if obj == nil {
		return kindRef{}, false
	}
	iface, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		return kindRef{}, false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		sig := iface.Method(i).Type().(*types.Signature)
		for j := 0; j < sig.Results().Len(); j++ {
			t := types.Unalias(sig.Results().At(j).Type())
			if p, ok := t.(*types.Pointer); ok {
				t = types.Unalias(p.Elem())
			}
			if n, ok := t.(*types.Named); ok && n.Obj().Name() == base && n.Obj().Pkg() != nil {
				return kindRef{kind: base, pkgPath: n.Obj().Pkg().Path()}, true
			}
		}
	}
	return kindRef{}, false
}

// informerCall handles shared informers: factory.Core().V1().Pods().Informer().
func (a *analyzer) informerCall(cp *checkedPackage, call *ast.CallExpr, fn *types.Func, recv string) {
	base := strings.TrimSuffix(recv, "Informer")
	obj := fn.Pkg().Scope().Lookup(recv)
	if obj == nil {
		return
	}
	iface, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		return
	}
	var ref kindRef
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m.Name() != "Lister" {
			continue
		}
		sig := m.Type().(*types.Signature)
		if sig.Results().Len() != 1 {
			continue
		}
		lister, ok := sig.Results().At(0).Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}
		for k := 0; k < lister.NumMethods(); k++ {
			lm := lister.Method(k)
			if lm.Name() != "List" {
				continue
			}
			ls := lm.Type().(*types.Signature)
			if ls.Results().Len() == 0 {
				continue
			}
			if sl, ok := types.Unalias(ls.Results().At(0).Type()).(*types.Slice); ok {
				if r, reason := kindOfType(sl.Elem()); reason == "" && r.kind == base {
					ref = r
				}
			}
		}
	}
	if ref.kind == "" {
		return
	}
	a.calls++
	file, line := a.pos(call)
	group, gok := a.groupOf(ref.pkgPath)
	if !gok {
		a.unresolvedAt(file, line, exprText(call.Fun), fmt.Sprintf("can't find the API group of package %s", ref.pkgPath))
		return
	}
	resource, guessed := a.pluralOf(group, ref)
	for _, v := range []string{"list", "watch"} {
		a.needs = append(a.needs, Need{Group: group, Resource: resource, Verb: v, File: file, Line: line, Call: exprText(call.Fun), Why: "shared informer", Guessed: guessed})
	}
}

// ---------------------------------------------------------------------------
// Comparison

// match reports whether a grant allows the need, and a note when it only
// allows part of it.
func match(g Grant, n Need) (bool, string) {
	if len(g.URLs) > 0 && len(g.Resources) == 0 {
		return false, ""
	}
	if !containsOrStar(g.Verbs, n.Verb) || !containsOrStar(g.Groups, n.Group) {
		return false, ""
	}
	_, sub, _ := strings.Cut(n.Resource, "/")
	ok := false
	for _, r := range g.Resources {
		if r == "*" || r == n.Resource || (sub != "" && r == "*/"+sub) {
			ok = true
			break
		}
	}
	if !ok {
		return false, ""
	}
	if g.Namespace != "" && n.Cluster {
		// A Role can't grant a resource that isn't namespaced.
		return false, ""
	}
	note := ""
	if len(g.ResourceNames) > 0 {
		switch n.Verb {
		case "list", "watch", "create", "deletecollection":
			return false, ""
		}
		note = fmt.Sprintf("granted only for the named objects %s (%s:%d)", strings.Join(g.ResourceNames, ", "), g.File, g.Line)
	}
	if g.Namespace != "" {
		if note != "" {
			note += "; "
		}
		note += fmt.Sprintf("granted only in namespace %s (%s:%d)", g.Namespace, g.File, g.Line)
	}
	return true, note
}

func containsOrStar(list []string, s string) bool {
	for _, v := range list {
		if v == s || v == "*" {
			return true
		}
	}
	return false
}

type resKey struct{ group, resource string }

func compare(needs []Need, grants []Grant) ([]Finding, []Unused) {
	type agg struct {
		verbs map[string]bool
		needs []Need
		note  string
	}
	missing := map[resKey]*agg{}
	soft := map[resKey]*agg{}
	partial := map[resKey]*agg{}
	var order []resKey
	seenKey := map[resKey]bool{}
	used := map[string]bool{} // grant index + group + resource + verb
	add := func(m map[resKey]*agg, k resKey, n Need, note string) {
		if !seenKey[k] {
			seenKey[k] = true
			order = append(order, k)
		}
		x := m[k]
		if x == nil {
			x = &agg{verbs: map[string]bool{}}
			m[k] = x
		}
		x.verbs[n.Verb] = true
		for _, e := range x.needs {
			if e.File == n.File && e.Line == n.Line && e.Verb == n.Verb {
				return
			}
		}
		x.needs = append(x.needs, n)
		if note != "" && x.note == "" {
			x.note = note
		}
	}
	for _, n := range needs {
		granted := false
		fullNote := ""
		for gi, g := range grants {
			ok, note := match(g, n)
			if !ok {
				continue
			}
			used[usedKey(gi, n.Group, n.Resource, n.Verb)] = true
			if note == "" {
				granted = true
				fullNote = ""
				break
			}
			if !granted {
				fullNote = note
			}
		}
		k := resKey{n.Group, n.Resource}
		switch {
		case granted:
		case fullNote != "":
			add(partial, k, n, fullNote)
		case n.Soft:
			add(soft, k, n, "")
		default:
			add(missing, k, n, "")
		}
	}
	var findings []Finding
	emit := func(level string, m map[resKey]*agg) {
		for _, k := range order {
			x, ok := m[k]
			if !ok {
				continue
			}
			f := Finding{Level: level, Group: k.group, Resource: k.resource, Needs: x.needs, Note: x.note}
			for _, v := range verbOrder {
				if x.verbs[v] {
					f.Verbs = append(f.Verbs, v)
				}
			}
			for v := range x.verbs {
				if !containsStr(verbOrder, v) {
					f.Verbs = append(f.Verbs, v)
				}
			}
			for _, n := range x.needs {
				if n.Guessed {
					f.Note = strings.TrimPrefix(f.Note+"; resource name "+k.resource+" is guessed from the kind, so check the CRD's plural", "; ")
					break
				}
			}
			findings = append(findings, f)
		}
	}
	emit("missing", missing)
	emit("partial", partial)
	emit("soft", soft)
	sort.SliceStable(findings, func(i, j int) bool {
		return levelRank(findings[i].Level) < levelRank(findings[j].Level)
	})
	var unused []Unused
	for gi, g := range grants {
		if len(g.Resources) == 0 {
			continue
		}
		for _, gr := range g.Groups {
			for _, r := range g.Resources {
				for _, v := range g.Verbs {
					if gr == "*" || r == "*" || v == "*" || strings.HasPrefix(r, "*/") {
						continue
					}
					if !used[usedKey(gi, gr, r, v)] {
						unused = append(unused, Unused{Group: gr, Resource: r, Verb: v, File: g.File, Line: g.Line})
					}
				}
			}
		}
	}
	return findings, unused
}

func usedKey(gi int, group, resource, verb string) string {
	return fmt.Sprintf("%d\x00%s\x00%s\x00%s", gi, group, resource, verb)
}

var verbOrder = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}

func levelRank(l string) int {
	switch l {
	case "missing":
		return 0
	case "partial":
		return 1
	}
	return 2
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Output

func groupLabel(g string) string {
	if g == "" {
		return "core"
	}
	return g
}

func markerFor(f Finding) string {
	g := f.Group
	if g == "" {
		g = "core"
	}
	return fmt.Sprintf("// +kubebuilder:rbac:groups=%s,resources=%s,verbs=%s", g, f.Resource, strings.Join(f.Verbs, ";"))
}

// groupSites prints each call site once, with its verbs grouped by reason:
// "x.go:12 r.Get: get (Get); list, watch (cached client: ...)".
func groupSites(needs []Need) []string {
	type site struct {
		key   string
		whys  []string
		verbs map[string][]string
	}
	var order []*site
	byKey := map[string]*site{}
	for _, n := range needs {
		k := fmt.Sprintf("%s:%d %s", n.File, n.Line, n.Call)
		st := byKey[k]
		if st == nil {
			st = &site{key: k, verbs: map[string][]string{}}
			byKey[k] = st
			order = append(order, st)
		}
		if _, ok := st.verbs[n.Why]; !ok {
			st.whys = append(st.whys, n.Why)
		}
		if !containsStr(st.verbs[n.Why], n.Verb) {
			st.verbs[n.Why] = append(st.verbs[n.Why], n.Verb)
		}
	}
	var out []string
	for _, st := range order {
		var parts []string
		for _, why := range st.whys {
			parts = append(parts, fmt.Sprintf("%s (%s)", strings.Join(st.verbs[why], ", "), why))
		}
		out = append(out, st.key+": "+strings.Join(parts, "; "))
	}
	return out
}

func printText(w io.Writer, rep *Report) {
	var missing, partial, soft int
	for _, f := range rep.Findings {
		switch f.Level {
		case "missing":
			missing++
		case "partial":
			partial++
		default:
			soft++
		}
	}
	for _, f := range rep.Findings {
		label := map[string]string{"missing": "MISSING", "partial": "PARTIAL", "soft": "MAYBE"}[f.Level]
		fmt.Fprintf(w, "%-8s %s %s: %s\n", label, groupLabel(f.Group), f.Resource, strings.Join(f.Verbs, ", "))
		sites := groupSites(f.Needs)
		for i, site := range sites {
			if i == 4 {
				fmt.Fprintf(w, "         ... and %d more call sites\n", len(sites)-i)
				break
			}
			fmt.Fprintf(w, "         %s\n", site)
		}
		if f.Note != "" {
			fmt.Fprintf(w, "         note: %s\n", f.Note)
		}
		if f.Level == "missing" {
			if rep.Markers > 0 || len(rep.MarkerIssues) > 0 || rep.RoleRules == 0 {
				fmt.Fprintf(w, "         fix:  %s\n", markerFor(f))
			} else {
				fmt.Fprintf(w, "         fix:  add a rule with apiGroups [%q], resources [%s], verbs [%s]\n", f.Group, f.Resource, strings.Join(f.Verbs, ", "))
			}
		}
		fmt.Fprintln(w)
	}
	for _, m := range rep.MarkerIssues {
		label, where := "MARKER", fmt.Sprintf("%s:%d", m.File, m.Line)
		if m.Marker == "role rule" {
			label = "ROLE"
		}
		if m.Line == 0 {
			where = m.File
		}
		fmt.Fprintf(w, "%-8s %s %s\n         %s\n\n", label, where, m.Marker, m.Problem)
	}
	for _, g := range rep.Guessed {
		fmt.Fprintf(w, "GUESSED  %s: no +kubebuilder:resource:path marker or CRD file names this plural, so it was guessed from the kind\n", g)
	}
	if len(rep.Guessed) > 0 {
		fmt.Fprintln(w)
	}
	for _, u := range rep.Unresolved {
		fmt.Fprintf(w, "UNCHECKED %s:%d %s: %s\n", u.File, u.Line, u.Call, u.Reason)
	}
	if len(rep.Unresolved) > 0 {
		fmt.Fprintln(w)
	}
	for _, n := range rep.Needs {
		fmt.Fprintf(w, "CALL     %s:%d %s needs %s %s: %s (%s)\n", n.File, n.Line, n.Call, groupLabel(n.Group), n.Resource, n.Verb, n.Why)
	}
	if len(rep.Needs) > 0 {
		fmt.Fprintln(w)
	}
	for _, u := range rep.Unused {
		fmt.Fprintf(w, "UNUSED   %s %s: %s granted at %s:%d, no call found that needs it\n", groupLabel(u.Group), u.Resource, u.Verb, u.File, u.Line)
	}
	if len(rep.Unused) > 0 {
		fmt.Fprintln(w)
	}
	if rep.RoleRules > 0 {
		fmt.Fprintf(w, "Checked %d API calls in %d packages against %d +kubebuilder:rbac markers and %d role file rules.\n", rep.Calls, rep.Packages, rep.Markers, rep.RoleRules)
	} else {
		fmt.Fprintf(w, "Checked %d API calls in %d packages against %d +kubebuilder:rbac markers.\n", rep.Calls, rep.Packages, rep.Markers)
	}
	if len(rep.MarkerIssues) > 0 {
		fmt.Fprintf(w, "%d markers or role rules don't grant what they say (MARKER or ROLE above).\n", len(rep.MarkerIssues))
	}
	switch {
	case missing > 0:
		fmt.Fprintf(w, "%d resources have calls that nothing checked grants. The pod will get \"forbidden\" errors for them.\n", missing)
	case len(rep.Unresolved) > 0:
		fmt.Fprintf(w, "Every resolved call is granted, but %d calls could not be checked (UNCHECKED above).\n", len(rep.Unresolved))
	case len(rep.Guessed) > 0:
		fmt.Fprintf(w, "Every resolved call is granted, but some resource names were guessed (GUESSED above).\n")
	default:
		fmt.Fprintf(w, "Every call rbacgap found is granted.\n")
	}
	if partial > 0 {
		fmt.Fprintf(w, "%d resources are granted only for some names or one namespace (PARTIAL above).\n", partial)
	}
	if soft > 0 {
		fmt.Fprintf(w, "%d resources may need more depending on cluster settings (MAYBE above).\n", soft)
	}
}

// ---------------------------------------------------------------------------
// Role files

// readRoleFile reads the rules of every Role and ClusterRole in a YAML or
// JSON file, such as config/rbac/role.yaml or `kubectl get clusterrole -o
// yaml`. Only the plain layout kubectl and controller-gen write is
// understood. Anything else is an error, never an empty grant list.
func readRoleFile(path, display string) ([]Grant, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(data)
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("%s is empty", display)
	}
	if !strings.HasSuffix(text, "\n") {
		return nil, fmt.Errorf("%s doesn't end with a newline, so it may be cut off; add one if the file is complete", display)
	}
	var grants []Grant
	var roles int
	if t := strings.TrimSpace(text); strings.HasPrefix(t, "{") {
		grants, roles, err = roleJSON([]byte(t), display)
	} else {
		grants, roles, err = roleYAML(text, display)
	}
	if err != nil {
		return nil, err
	}
	if roles == 0 {
		return nil, fmt.Errorf("%s has no Role or ClusterRole", display)
	}
	return grants, nil
}

type jsonRule struct {
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	Verbs           []string `json:"verbs"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

type jsonRole struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Rules []jsonRule  `json:"rules"`
	Items []*jsonRole `json:"items"`
}

func roleJSON(data []byte, display string) ([]Grant, int, error) {
	var top jsonRole
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, 0, fmt.Errorf("%s is not valid JSON: %v", display, err)
	}
	all := []*jsonRole{&top}
	if top.Kind == "List" || strings.HasSuffix(top.Kind, "List") {
		all = top.Items
	}
	var grants []Grant
	roles := 0
	for _, r := range all {
		if r == nil || (r.Kind != "Role" && r.Kind != "ClusterRole") {
			continue
		}
		roles++
		for _, rule := range r.Rules {
			g := Grant{Groups: rule.APIGroups, Resources: rule.Resources, Verbs: rule.Verbs, ResourceNames: rule.ResourceNames, URLs: rule.NonResourceURLs, File: display}
			if r.Kind == "Role" {
				g.Namespace = r.Metadata.Namespace
				if g.Namespace == "" {
					g.Namespace = "(the Role's namespace)"
				}
			}
			if len(g.Verbs) == 0 {
				return nil, 0, fmt.Errorf("%s: a rule has no verbs", display)
			}
			grants = append(grants, g)
		}
	}
	return grants, roles, nil
}

type yamlLine struct {
	n      int // 1-based line number
	indent int
	text   string // without indent and comments
}

// expandYAMLRoleListDocuments replaces a top-level Kubernetes List document
// with its Role and ClusterRole member documents, matching `kubectl get
// clusterroles -o yaml`. Items are deduplicated? It only understands simple
// items: any unrecognized List shape is rejected, so an unknown construct
// never silently disappears.
func expandYAMLRoleListDocuments(docs [][]yamlLine, display string) ([][]yamlLine, error) {
	expanded := make([][]yamlLine, 0, len(docs))
	for _, doc := range docs {
		kind := ""
		for _, l := range doc {
			if l.indent != 0 {
				continue
			}
			k, v, ok := strings.Cut(l.text, ":")
			if ok && strings.TrimSpace(k) == "kind" {
				kind = unquoteYAML(v)
			}
		}
		if kind != "List" {
			expanded = append(expanded, doc)
			continue
		}

		itemsAt := -1
		for i, l := range doc {
			if l.indent == 0 && strings.HasPrefix(l.text, "items:") {
				itemsAt = i
				_, v, _ := strings.Cut(l.text, ":")
				v = strings.TrimSpace(v)
				if v != "" && v != "[]" {
					return nil, fmt.Errorf("%s:%d: items must be a block list", display, l.n)
				}
				break
			}
		}
		if itemsAt < 0 {
			return nil, fmt.Errorf("%s: kind List has no items block list", display)
		}

		var items [][]yamlLine
		var item []yamlLine
		flush := func() {
			if len(item) > 0 {
				items = append(items, item)
				item = nil
			}
		}
		for _, l := range doc[itemsAt+1:] {
			if l.indent == 0 && (strings.HasPrefix(l.text, "- ") || l.text == "-") {
				flush()
				first := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
				item = []yamlLine{{n: l.n, indent: 0, text: first}}
				continue
			}
			if len(item) == 0 {
				return nil, fmt.Errorf("%s:%d: content before the first List item", display, l.n)
			}
			if l.indent == 0 {
				return nil, fmt.Errorf("%s:%d: unexpected top-level key after List items", display, l.n)
			}
			if l.indent < 2 {
				return nil, fmt.Errorf("%s:%d: List item continued at an unexpected indentation", display, l.n)
			}
			item = append(item, yamlLine{n: l.n, indent: l.indent - 2, text: l.text})
		}
		flush()
		if len(items) == 0 {
			return nil, fmt.Errorf("%s: kind List has no items", display)
		}
		expanded = append(expanded, items...)
	}
	return expanded, nil
}

// roleYAML parses documents separated by --- and reads kind,
// metadata.namespace and rules from each.
func roleYAML(text, display string) ([]Grant, int, error) {
	var docs [][]yamlLine
	var cur []yamlLine
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.ContainsRune(raw, '\t') {
			return nil, 0, fmt.Errorf("%s:%d: has a tab; rbacgap only reads role files indented with spaces", display, i+1)
		}
		t := stripComment(raw)
		trimmed := strings.TrimSpace(t)
		if trimmed == "---" || strings.HasPrefix(trimmed, "--- ") {
			docs = append(docs, cur)
			cur = nil
			continue
		}
		if trimmed == "" || trimmed == "..." {
			continue
		}
		cur = append(cur, yamlLine{n: i + 1, indent: len(t) - len(strings.TrimLeft(t, " ")), text: trimmed})
	}
	docs = append(docs, cur)
	expanded, err := expandYAMLRoleListDocuments(docs, display)
	if err != nil {
		return nil, 0, err
	}
	docs = expanded
	var grants []Grant
	roles := 0
	for _, doc := range docs {
		if len(doc) == 0 {
			continue
		}
		kind, ns := "", ""
		rulesAt := -1
		inMeta := false
		for i, l := range doc {
			if l.indent == 0 {
				inMeta = false
				k, v, ok := strings.Cut(l.text, ":")
				if !ok && !strings.HasPrefix(l.text, "- ") {
					return nil, 0, fmt.Errorf("%s:%d: expected a key, got %q", display, l.n, l.text)
				}
				switch strings.TrimSpace(k) {
				case "kind":
					kind = unquoteYAML(v)
				case "metadata":
					inMeta = true
				case "rules":
					rulesAt = i
				}
				continue
			}
			if inMeta && strings.HasPrefix(l.text, "namespace:") {
				ns = unquoteYAML(strings.TrimPrefix(l.text, "namespace:"))
			}
		}
		if kind != "Role" && kind != "ClusterRole" {
			continue
		}
		roles++
		if rulesAt < 0 {
			continue
		}
		_, v, _ := strings.Cut(doc[rulesAt].text, ":")
		v = strings.TrimSpace(v)
		if v == "[]" {
			continue
		}
		if v != "" {
			return nil, 0, fmt.Errorf("%s:%d: rules must be a block list", display, doc[rulesAt].n)
		}
		var body []yamlLine
		for _, l := range doc[rulesAt+1:] {
			if l.indent == 0 && !strings.HasPrefix(l.text, "- ") {
				break
			}
			body = append(body, l)
		}
		if len(body) == 0 {
			return nil, 0, fmt.Errorf("%s:%d: rules has no items; write rules: [] for an empty role", display, doc[rulesAt].n)
		}
		gs, err := parseRules(body, display)
		if err != nil {
			return nil, 0, err
		}
		for i := range gs {
			if kind == "Role" {
				gs[i].Namespace = ns
				if ns == "" {
					gs[i].Namespace = "(the Role's namespace)"
				}
			}
		}
		grants = append(grants, gs...)
	}
	return grants, roles, nil
}

func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && (i == 0 || s[i-1] == ' ') {
				return strings.TrimRight(s[:i], " ")
			}
		}
	}
	return strings.TrimRight(s, " ")
}

// parseRules parses a block list of rule maps.
func parseRules(lines []yamlLine, display string) ([]Grant, error) {
	if len(lines) == 0 {
		return nil, nil
	}
	seqIndent := lines[0].indent
	if !strings.HasPrefix(lines[0].text, "- ") && lines[0].text != "-" {
		return nil, fmt.Errorf("%s:%d: rules must be a list", display, lines[0].n)
	}
	var grants []Grant
	var g *Grant
	var key string
	keyIndent, itemIndent := -1, -1
	finish := func() error {
		if g == nil {
			return nil
		}
		if len(g.Verbs) == 0 {
			return fmt.Errorf("%s:%d: a rule has no verbs", display, g.Line)
		}
		grants = append(grants, *g)
		return nil
	}
	setKey := func(l yamlLine, kv string, indent int) error {
		k, v, ok := strings.Cut(kv, ":")
		if !ok {
			return fmt.Errorf("%s:%d: expected a rule key, got %q", display, l.n, kv)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		target := ruleField(g, k)
		if target == nil {
			return fmt.Errorf("%s:%d: unknown rule key %q", display, l.n, k)
		}
		key, keyIndent, itemIndent = k, indent, -1
		switch {
		case v == "":
			*target = []string{}
		case strings.HasPrefix(v, "["):
			if !strings.HasSuffix(v, "]") {
				return fmt.Errorf("%s:%d: flow list for %s isn't closed on its line", display, l.n, k)
			}
			inner := strings.TrimSpace(v[1 : len(v)-1])
			vals := []string{}
			if inner != "" {
				items, err := splitFlow(inner)
				if err != nil {
					return fmt.Errorf("%s:%d: %v", display, l.n, err)
				}
				vals = items
			}
			*target = vals
			key = ""
		default:
			return fmt.Errorf("%s:%d: %s must be a list", display, l.n, k)
		}
		return nil
	}
	for _, l := range lines {
		switch {
		case l.indent == seqIndent && (strings.HasPrefix(l.text, "- ") || l.text == "-"):
			if err := finish(); err != nil {
				return nil, err
			}
			g = &Grant{File: display, Line: l.n}
			key = ""
			rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
			if rest != "" {
				if err := setKey(l, rest, seqIndent+2); err != nil {
					return nil, err
				}
			}
		case l.indent < seqIndent:
			return nil, fmt.Errorf("%s:%d: unexpected indentation", display, l.n)
		case strings.HasPrefix(l.text, "- ") || l.text == "-":
			if key == "" || l.indent < keyIndent {
				return nil, fmt.Errorf("%s:%d: list item outside a rule key", display, l.n)
			}
			if itemIndent < 0 {
				itemIndent = l.indent
			} else if l.indent != itemIndent {
				return nil, fmt.Errorf("%s:%d: list item indented differently from the one above; rbacgap can't tell how YAML reads it", display, l.n)
			}
			item := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
			if item == "" || strings.HasPrefix(item, "- ") || strings.ContainsAny(item[:1], "[{&*!|>") {
				return nil, fmt.Errorf("%s:%d: list item %q isn't a plain string", display, l.n, item)
			}
			target := ruleField(g, key)
			*target = append(*target, unquoteYAML(strings.TrimPrefix(l.text, "-")))
		default:
			if err := setKey(l, l.text, l.indent); err != nil {
				return nil, err
			}
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	return grants, nil
}

// splitFlow splits the inside of a one-line flow list, keeping commas inside
// quotes: ["get", 'list'] or [get, list].
func splitFlow(inner string) ([]string, error) {
	var out []string
	var cur strings.Builder
	quote := byte(0)
	flush := func() error {
		v := strings.TrimSpace(cur.String())
		cur.Reset()
		if v == "" {
			return errors.New("empty item in a flow list")
		}
		if strings.ContainsAny(v[:1], "[{&*!|>") {
			return fmt.Errorf("flow list item %q isn't a plain string", v)
		}
		out = append(out, unquoteYAML(v))
		return nil
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quote = c
			cur.WriteByte(c)
		case c == ',':
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			cur.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, errors.New("unclosed quote in a flow list")
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

func ruleField(g *Grant, key string) *[]string {
	if g == nil {
		return nil
	}
	switch key {
	case "apiGroups":
		return &g.Groups
	case "resources":
		return &g.Resources
	case "verbs":
		return &g.Verbs
	case "resourceNames":
		return &g.ResourceNames
	case "nonResourceURLs":
		return &g.URLs
	}
	return nil
}
