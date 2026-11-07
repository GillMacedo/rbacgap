package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseMarker(t *testing.T) {
	cases := []struct {
		in   string
		want Grant
	}{
		{"groups=apps,resources=deployments,verbs=get;list;watch",
			Grant{Groups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}}},
		{"groups=core,resources=pods,verbs=get",
			Grant{Groups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
		{`groups="",resources=secrets,verbs=get`,
			Grant{Groups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
		{`groups="networking.k8s.io",resources=ingresses,verbs=get`,
			Grant{Groups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"get"}}},
		{"groups=apps,resources={deployments,statefulsets},verbs={get,list}",
			Grant{Groups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}}},
		{"groups=batch,namespace=foo,resources=jobs,verbs=get",
			Grant{Groups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"get"}, Namespace: "foo"}},
		{"groups=x.io,resources=things,resourceNames=a;b,verbs=get",
			Grant{Groups: []string{"x.io"}, Resources: []string{"things"}, Verbs: []string{"get"}, ResourceNames: []string{"a", "b"}}},
		{"urls=/metrics,verbs=get",
			Grant{URLs: []string{"/metrics"}, Verbs: []string{"get"}}},
		// Case is kept: RBAC compares verbs exactly.
		{"groups=batch,resources=jobs,verbs=GET",
			Grant{Groups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"GET"}}},
	}
	for _, c := range cases {
		got, err := parseMarker(c.in)
		if err != nil {
			t.Errorf("parseMarker(%q): %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseMarker(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseMarkerRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"groups=apps,resources=deployments",
		"groups=apps,verbs=get",
		"resources=pods,verbs=get",
		"groups=apps,resources=deployments,verbs=get,colour=blue",
		"groups=apps,groups=batch,resources=jobs,verbs=get",
		// controller-gen fails on this one: a comma inside a verb list.
		"groups=rbac.authorization.k8s.io,resources=roles,verbs=get;create,update;list",
		"groups=apps,resources={deployments,verbs=get",
		`groups="apps,resources=x,verbs=get`,
		"groups=apps,,resources=x,verbs=get",
		"groups=apps;;batch,resources=x,verbs=get",
		"cannot use r (variable of type *Reconciler) as client.Client value",
	} {
		if g, err := parseMarker(in); err == nil {
			t.Errorf("parseMarker(%q) = %+v, want an error", in, g)
		}
	}
}

func TestVerbProblem(t *testing.T) {
	for _, v := range []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "*", "use", "bind", "escalate", "impersonate", "approve"} {
		if p := verbProblem(v); p != "" {
			t.Errorf("verbProblem(%q) = %q, want none", v, p)
		}
	}
	if p := verbProblem("List"); !strings.Contains(p, "lowercase") {
		t.Errorf("verbProblem(List) = %q", p)
	}
	if p := verbProblem("wacth"); !strings.Contains(p, "typo") {
		t.Errorf("verbProblem(wacth) = %q", p)
	}
}

func TestGuessPlural(t *testing.T) {
	cases := map[string]string{
		"Pod": "pods", "Secret": "secrets", "Ingress": "ingresses", "NetworkPolicy": "networkpolicies",
		"Endpoints": "endpoints", "EndpointSlice": "endpointslices", "Gateway": "gateways",
		"Box": "boxes", "Batch": "batches", "StorageClass": "storageclasses",
	}
	for kind, want := range cases {
		if got := guessPlural(kind); got != want {
			t.Errorf("guessPlural(%s) = %s, want %s", kind, got, want)
		}
	}
}

func TestMatch(t *testing.T) {
	n := func(group, resource, verb string) Need { return Need{Group: group, Resource: resource, Verb: verb} }
	g := func(groups, resources, verbs []string) Grant {
		return Grant{Groups: groups, Resources: resources, Verbs: verbs}
	}
	s := func(v ...string) []string { return v }
	cases := []struct {
		g    Grant
		n    Need
		want bool
	}{
		{g(s("apps"), s("deployments"), s("get")), n("apps", "deployments", "get"), true},
		{g(s("apps"), s("deployments"), s("get")), n("apps", "deployments", "list"), false},
		{g(s("apps"), s("deployments"), s("get")), n("", "deployments", "get"), false},
		{g(s("*"), s("*"), s("*")), n("x.io", "things/status", "patch"), true},
		{g(s("apps"), s("*/scale"), s("update")), n("apps", "deployments/scale", "update"), true},
		{g(s("apps"), s("*/scale"), s("update")), n("apps", "deployments", "update"), false},
		{g(s("apps"), s("deployments"), s("update")), n("apps", "deployments/status", "update"), false},
		{g(s("apps"), s("deployments/*"), s("update")), n("apps", "deployments/status", "update"), false},
		{g(s(""), s("pods"), s("GET")), n("", "pods", "get"), false},
		{Grant{URLs: s("/metrics"), Verbs: s("get")}, n("", "metrics", "get"), false},
	}
	for i, c := range cases {
		got, _ := match(c.g, c.n)
		if got != c.want {
			t.Errorf("case %d: match(%+v, %+v) = %v, want %v", i, c.g, c.n, got, c.want)
		}
	}
	named := Grant{Groups: s(""), Resources: s("configmaps"), Verbs: s("get", "list", "update"), ResourceNames: s("lock")}
	if ok, note := match(named, n("", "configmaps", "get")); !ok || !strings.Contains(note, "named objects") {
		t.Errorf("resourceNames get: %v %q", ok, note)
	}
	if ok, _ := match(named, n("", "configmaps", "list")); ok {
		t.Errorf("resourceNames must not grant list")
	}
	ns := Grant{Groups: s(""), Resources: s("pods"), Verbs: s("get"), Namespace: "system"}
	if ok, note := match(ns, n("", "pods", "get")); !ok || !strings.Contains(note, "namespace system") {
		t.Errorf("namespaced grant: %v %q", ok, note)
	}
}

func TestCompare(t *testing.T) {
	needs := []Need{
		{Group: "apps", Resource: "deployments", Verb: "get", File: "a.go", Line: 1},
		{Group: "apps", Resource: "deployments", Verb: "update", File: "a.go", Line: 2},
		{Group: "", Resource: "secrets", Verb: "list", File: "a.go", Line: 3, Cache: true},
		{Group: "x.io", Resource: "things/finalizers", Verb: "update", File: "a.go", Line: 4, Soft: true},
		{Group: "", Resource: "configmaps", Verb: "get", File: "a.go", Line: 5},
	}
	grants := []Grant{
		{Groups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}, File: "m.go", Line: 10},
		{Groups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}, Namespace: "system", File: "m.go", Line: 11},
	}
	findings, unused := compare(needs, grants)
	got := map[string]string{}
	for _, f := range findings {
		got[f.Level+" "+f.Group+"/"+f.Resource] = strings.Join(f.Verbs, ",")
	}
	want := map[string]string{
		"missing apps/deployments":    "update",
		"missing /secrets":            "list",
		"soft x.io/things/finalizers": "update",
		"partial /configmaps":         "get",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
	if findings[0].Level != "missing" || findings[len(findings)-1].Level != "soft" {
		t.Errorf("findings not ordered missing, partial, soft: %+v", findings)
	}
	var uv []string
	for _, u := range unused {
		uv = append(uv, u.Resource+":"+u.Verb)
	}
	sort.Strings(uv)
	if !reflect.DeepEqual(uv, []string{"deployments:list", "deployments:watch"}) {
		t.Errorf("unused = %v", uv)
	}
}

// The live and inert cases match what controller-gen v0.17.0, v0.20.0 and
// v0.23.0 generated for the same file: only markers that stand alone, or that
// are the package doc comment, end up in the role.
func TestAttachedComments(t *testing.T) {
	src := `// +kubebuilder:rbac:groups=apps,resources=onpackage,verbs=get
package p

// +kubebuilder:rbac:groups=apps,resources=detachedtop,verbs=get

// +kubebuilder:rbac:groups=apps,resources=onfunc,verbs=get
func Reconcile() {}

// +kubebuilder:rbac:groups=apps,resources=ontype,verbs=get
type Reconciler struct{}

// Reconciler2 does things.
// +kubebuilder:rbac:groups=apps,resources=ontypewithdoc,verbs=get
type Reconciler2 struct{}

// +kubebuilder:rbac:groups=apps,resources=onvar,verbs=get
var X = 1

// +kubebuilder:rbac:groups=apps,resources=onmethod,verbs=get
func (r *Reconciler) Do() {}

type Y struct {
	// +kubebuilder:rbac:groups=apps,resources=onfield,verbs=get
	F int
}

func f() {
	// +kubebuilder:rbac:groups=apps,resources=infuncbody,verbs=get
	_ = 1
}

var (
	a = 1

	// +kubebuilder:rbac:groups=apps,resources=invargroup,verbs=get

	b = 2
)

// Some text about the reconciler.

// +kubebuilder:rbac:groups=apps,resources=aftertext,verbs=get

// Reconcile3 does it.
func Reconcile3() {} // +kubebuilder:rbac:groups=apps,resources=trailing,verbs=get
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	attached := attachedComments(f)
	var live, inert []string
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if i := strings.Index(c.Text, "resources="); i >= 0 {
				name := strings.SplitN(c.Text[i+len("resources="):], ",", 2)[0]
				if attached[cg] {
					inert = append(inert, name)
				} else {
					live = append(live, name)
				}
			}
		}
	}
	sort.Strings(live)
	sort.Strings(inert)
	if want := []string{"aftertext", "detachedtop", "onpackage", "trailing"}; !reflect.DeepEqual(live, want) {
		t.Errorf("live = %v, want %v", live, want)
	}
	if want := []string{"infuncbody", "invargroup", "onfield", "onfunc", "onmethod", "ontype", "ontypewithdoc", "onvar"}; !reflect.DeepEqual(inert, want) {
		t.Errorf("inert = %v, want %v", inert, want)
	}
}

func TestIsGenerated(t *testing.T) {
	for src, want := range map[string]bool{
		"// Code generated by informer-gen. DO NOT EDIT.\n\npackage v1\n":               true,
		"// Copyright\n\n// Code generated by client-gen. DO NOT EDIT.\n\npackage v1\n": true,
		"package v1\n\n// Code generated by hand. DO NOT EDIT.\nvar x = 1\n":            false,
		"// Code generated is a phrase in this comment.\npackage v1\n":                  false,
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		if got := isGenerated(f); got != want {
			t.Errorf("isGenerated(%q) = %v, want %v", src, got, want)
		}
	}
}

func TestExprText(t *testing.T) {
	e, err := parser.ParseExpr(`ctrl.NewControllerManagedBy(mgr).For(&batchv1.CronJob{}).Owns(&kbatch.Job{}).Named("cronjob")`)
	if err != nil {
		t.Fatal(err)
	}
	fun := e.(*ast.CallExpr).Fun
	if got := exprText(fun); got != "...Owns(...).Named" {
		t.Errorf("exprText = %q", got)
	}
	short, _ := parser.ParseExpr(`r.Status().Update`)
	if got := exprText(short); got != "r.Status().Update" {
		t.Errorf("exprText = %q", got)
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const roleYAMLFixture = `---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: manager-role
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - secrets # read only
  verbs:
  - get
  - list
- apiGroups: ["apps"]
  resources: ["deployments", 'statefulsets']
  verbs: ["*"]
  resourceNames:
    - web
- nonResourceURLs:
  - /metrics
  verbs:
  - get
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: leader-election
  namespace: system
rules:
  - apiGroups:
      - coordination.k8s.io
    resources:
      - leases
    verbs:
      - get
      - create
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: manager
`

func TestReadRoleFileYAML(t *testing.T) {
	p := writeFile(t, "role.yaml", roleYAMLFixture)
	gs, err := readRoleFile(p, "role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 4 {
		t.Fatalf("got %d grants, want 4: %+v", len(gs), gs)
	}
	want := []Grant{
		{Groups: []string{""}, Resources: []string{"pods", "secrets"}, Verbs: []string{"get", "list"}, File: "role.yaml", Line: 7},
		{Groups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"*"}, ResourceNames: []string{"web"}, File: "role.yaml", Line: 15},
		{URLs: []string{"/metrics"}, Verbs: []string{"get"}, File: "role.yaml", Line: 20},
		{Groups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"get", "create"}, Namespace: "system", File: "role.yaml", Line: 31},
	}
	if !reflect.DeepEqual(gs, want) {
		t.Errorf("got  %+v\nwant %+v", gs, want)
	}
}

func TestReadRoleFileJSON(t *testing.T) {
	js := `{"apiVersion":"v1","kind":"List","items":[{"kind":"ClusterRole","metadata":{"name":"x"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]},{"kind":"Role","metadata":{"name":"y","namespace":"ns"},"rules":[{"apiGroups":["apps"],"resources":["deployments"],"verbs":["list"]}]}]}` + "\n"
	gs, err := readRoleFile(writeFile(t, "role.json", js), "role.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 2 || gs[1].Namespace != "ns" || gs[0].Resources[0] != "pods" {
		t.Errorf("got %+v", gs)
	}
}

func TestReadRoleFileRejects(t *testing.T) {
	full := roleYAMLFixture
	cases := map[string]string{
		"empty":            "",
		"blank":            "\n\n  \n",
		"garbage":          "\x00\x01\x02 not yaml at all {{{\n",
		"cut off":          full[:len(full)/2],
		"no newline":       strings.TrimSuffix(full, "\n"),
		"build failure":    "# example.com/op/internal/controller\ninternal/controller/x.go:12:2: undefined: foo\n",
		"test failure":     "--- FAIL: TestX (0.00s)\n    x_test.go:9: boom\nFAIL\nexit status 1\nFAIL\texample.com/op\t0.01s\n",
		"service only":     "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: x\n",
		"no verbs":         "kind: ClusterRole\nrules:\n- apiGroups: [\"\"]\n  resources: [pods]\n",
		"unknown key":      "kind: ClusterRole\nrules:\n- apiGroups: [\"\"]\n  colour: [red]\n  verbs: [get]\n",
		"scalar verbs":     "kind: ClusterRole\nrules:\n- apiGroups: [\"\"]\n  resources: [pods]\n  verbs: get\n",
		"tabs":             "kind: ClusterRole\nrules:\n-\tapiGroups: [\"\"]\n",
		"yaml list":        "apiVersion: v1\nkind: List\nitems:\n- kind: ClusterRole\n",
		"bad json":         "{\"kind\": \"ClusterRole\", \"rules\": [\n",
		"unclosed flow":    "kind: ClusterRole\nrules:\n- apiGroups: [\"\"\n  verbs: [get]\n",
		"rules not list":   "kind: ClusterRole\nrules:\n  apiGroups: [\"\"]\n",
		"deeper list item": "kind: ClusterRole\nrules:\n- apiGroups: [\"\"]\n  resources: [pods]\n  verbs:\n  - get\n    - delete\n",
		"empty rules":      "kind: ClusterRole\nrules:\nmetadata:\n  name: x\n",
		"anchor item":      "kind: ClusterRole\nrules:\n- apiGroups: [\"\"]\n  resources: [pods]\n  verbs:\n  - *all\n",
	}
	for name, content := range cases {
		gs, err := readRoleFile(writeFile(t, "role.yaml", content), "role.yaml")
		if err == nil {
			t.Errorf("%s: got %d grants and no error", name, len(gs))
		}
	}
}

func TestExitCode(t *testing.T) {
	clean := &Report{}
	missing := &Report{Findings: []Finding{{Level: "missing"}}}
	soft := &Report{Findings: []Finding{{Level: "soft"}, {Level: "partial"}}}
	marker := &Report{MarkerIssues: []MarkerIssue{{}}}
	unchecked := &Report{Unresolved: []Unresolved{{}}}
	guessed := &Report{Guessed: []string{"x.io things"}}
	cases := []struct {
		r      *Report
		failOn string
		want   int
	}{
		{clean, "missing", 0}, {clean, "unchecked", 0}, {clean, "none", 0},
		{missing, "missing", 1}, {missing, "unchecked", 1}, {missing, "none", 0},
		{soft, "missing", 0}, {soft, "unchecked", 0},
		{marker, "missing", 1}, {marker, "none", 0},
		{unchecked, "missing", 0}, {unchecked, "unchecked", 1},
		{guessed, "missing", 0}, {guessed, "unchecked", 1},
	}
	for i, c := range cases {
		if got := exitCode(c.r, c.failOn); got != c.want {
			t.Errorf("case %d (%s): exit %d, want %d", i, c.failOn, got, c.want)
		}
	}
}

func TestBadUsage(t *testing.T) {
	var out, errb strings.Builder
	for _, args := range [][]string{
		{"--format", "xml"},
		{"--fail-on", "sometimes"},
		{"--dir", filepath.Join(t.TempDir(), "missing")},
		{"--no-such-flag"},
	} {
		if code := run(args, &out, &errb); code != exitUnknown {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
	}
	f := writeFile(t, "file.txt", "x")
	if code := run([]string{"--dir", f}, &out, &errb); code != exitUnknown {
		t.Errorf("--dir on a file = %d, want 2", code)
	}
	if strings.Contains(out.String(), "granted") {
		t.Errorf("bad usage printed a result: %s", out.String())
	}
}

func TestFlowListKeepsQuotedCommas(t *testing.T) {
	gs, err := readRoleFile(writeFile(t, "role.yaml", "kind: ClusterRole\nrules:\n- apiGroups: [\"\"]\n  resources: [pods]\n  verbs: [\"get,delete\", 'list']\n"), "role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"get,delete", "list"}; !reflect.DeepEqual(gs[0].Verbs, want) {
		t.Errorf("verbs = %q, want %q", gs[0].Verbs, want)
	}
	if verbProblem("get,delete") == "" {
		t.Error("get,delete should be flagged as not a verb")
	}
}
