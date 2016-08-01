package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	// TODO: use html/template
	"text/template"

	heapdump "github.com/tombergan/goheapdump"
)

var (
	serverPort   = flag.Int("port", 8080, "Port to run HTTP server")
	verboseDebug = flag.Bool("debug", false, "Print verbose debugging info")
)

// dump is the loaded heap dump.
var dump *heapdump.Dump

// lookupParam looks up an integer value in r.URL's query.
func lookupParam(q url.Values, param string, base int) (uint64, error) {
	v := q[param]
	if len(v) != 1 {
		return 0, fmt.Errorf("parameter %s not found", param)
	}
	x, err := strconv.ParseUint(v[0], base, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse parameter %s (%d): %v", param, v[0], err.Error())
	}
	return x, nil
}

// linkObj creates a link to the /obj page for the given address.
func linkObj(addr uint64) string {
	return fmt.Sprintf("<a href=obj?addr=%x>0x%x</a>", addr, addr)
}

// linkFrame creates a link to the /frame page for the given StackFrame, using name as the link text.
func linkFrame(sf *heapdump.StackFrame, name string) string {
	return fmt.Sprintf("<a href=frame?id=%x&depth=%d>%s</a>", sf.Addr(), sf.Depth(), name)
}

// limitedWriter returns EOF after writing N bytes.
type limitedWriter struct {
	io.Writer
	N int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.N <= 0 {
		return 0, io.EOF
	}
	// Always write the entire chunk as it may include HTML.
	n, err := w.Writer.Write(p)
	w.N -= n
	if err == nil && w.N < 0 {
		err = io.EOF
	}
	return n, err
}

type varInfo struct {
	Name  string
	Addr  string
	Type  string
	Value string
}

func makeVarInfo(name string, v *heapdump.Value) varInfo {
	info := varInfo{
		Name: name,
		Addr: linkObj(v.Addr()),
		Type: v.Type.String(),
	}

	// Format the value.
	var buf bytes.Buffer
	err := v.Fmt(&limitedWriter{&buf, 1000}, &heapdump.FmtOptions{
		CustomScalarFormatter: func(w io.Writer, v *heapdump.Value) error {
			if _, ok := v.Type.(*heapdump.PtrType); ok {
				if addr, err := v.ReadUint(); err == nil {
					_, err := w.Write([]byte(linkObj(addr)))
					return err
				}
			}
			return heapdump.ErrUseDefaultFormatter
		},
		FieldMode: heapdump.FmtLongFieldNames,
	})
	if err != nil {
		buf.WriteString(" ...")
	}
	info.Value = buf.String()
	return info
}

type mainInfo struct {
	HasTypeInfo                                         bool
	ByteOrder                                           string
	Params                                              *heapdump.RawParams
	HeapSize, HeapObjects, HeapRoots                    uint64
	Goroutines, StackFrames                             uint64
	GlobalRoots, LocalRoots, FinalizerRoots, OtherRoots uint64
	MemStats                                            runtime.MemStats
	AvgTotalPauseNs, AvgRecentPauseNs                   uint64
}

var mainTemplate = template.Must(template.New("main").Parse(`
<html>
	<head>
		<style>
		table {
			border-collapse: collapse;
			margin-left: 4em;
		}
		table, td, th {
			border: 0px;
			padding: 0px;
		}
		.right {
			text-align: right;
			padding-right: 20px;
		}
		</style>
		<title>Heapdump Viewer</title>
		</head>
	<body>
	<code>
		<h2>Heapdump Viewer</h2>
		<a href="histograms">Histograms</a>
		<a href="globals">Globals</a>
		<a href="goroutines?sort=status">Goroutines</a>
		<a href="otherRoots">Finalizers and Other Roots</a>
		{{if not .HasTypeInfo}}<br><br>Type information not available!{{end}}
		<br><br>
		Machine parameters:
		<table>
			<tr><td colspan="2">&nbsp;</td></tr>
			<tr><td>ByteOrder = {{.ByteOrder}}</td></tr>
			<tr><td>PointerSize = {{.Params.PtrSize}} bytes</td></tr>
			<tr><td>NCPU = {{.Params.NCPU}}</td></tr>
			<tr><td>GOARCH = '{{.Params.GoArch}}'</td></tr>
			<tr><td>GOEXPERIMENT = '{{.Params.GoExperiment}}'</td></tr>
		</table>
		<br><br>
		Heapdump stats:
		<table>
			<tr><td colspan="2">&nbsp;</td></tr>
			<tr>
				<td class="right">0x{{printf "%x" .Params.HeapStart}}</td>
				<td>Address of the first byte of the heap region</td>
			</tr>
			<tr>
				<td class="right">0x{{printf "%x" .Params.HeapEnd}}</td>
				<td>Address of the end the heap region (just after the last byte)</td>
			</tr>
			<tr>
				<td class="right">{{.HeapSize}}</td>
				<td>Size of the heap region in bytes</td>
			</tr>
			<tr>
				<td class="right">{{.HeapObjects}}</td>
				<td>Number of heap objects</td>
			</tr>
			<tr>
				<td class="right">{{.HeapRoots}}</td>
				<td>Number of GC roots
					({{.GlobalRoots}} globals,
					{{.LocalRoots}} locals,
					{{.FinalizerRoots}} from finalizers,
					{{.OtherRoots}} other)
				</td>
			</tr>
			<tr>
				<td class="right">{{.Goroutines}}</td>
				<td>Number of goroutines</td>
			</tr>
			<tr>
				<td class="right">{{.StackFrames}}</td>
				<td>Number of stack frames</td>
			</tr>
		</table>
		<br>
		<br>Full runtime.MemStats:
		<table>
			<!-- Main stats -->
			<tr><td colspan="2">&nbsp;</td></tr>
			<tr>
				<td class="right">{{.MemStats.TotalAlloc}}</td>
				<td>Bytes allocated over the program's lifetime (MemStats.TotalAlloc; includes freed)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.Alloc}}</td>
				<td>Bytes allocated and not yet freed (MemStats.Alloc)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.HeapAlloc}}</td>
				<td>Heap bytes allocated and not yet freed (MemStats.HeapAlloc; should match the above line)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.HeapIdle}}</td>
				<td>Heap bytes in idle spans (MemStats.HeapIdle)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.HeapInuse}}</td>
				<td>Heap bytes in non-idle spans (MemStats.HeapInuse)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.HeapReleased}}</td>
				<td>Heap bytes released to the system (MemStats.HeapReleased)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.HeapObjects}}</td>
				<td>Total number of allocated heap objects (MemStats.HeapObjects)</td>
			</tr>
			<tr><td colspan="2">&nbsp;</td></tr>
			<tr>
				<td class="right">{{.MemStats.StackInuse}}</td>
				<td>Stack bytes in use (MemStats.StackInuse)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.MSpanInuse}}</td>
				<td>MSpan bytes in use (MemStats.MSpanInuse)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.MCacheInuse}}</td>
				<td>MCache bytes in use (MemStats.MCacheInuse)</td>
			</tr>

			<!-- Sys breakdown -->
			<tr><td colspan="2">&nbsp;</td></tr>
			<tr>
				<td class="right">{{.MemStats.Sys}}</td>
				<td>Bytes obtained from the system (MemStats.Sys; sum of values below)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.HeapSys}}</td>
				<td>... for the heap (MemStats.HeapSys)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.StackSys}}</td>
				<td>... for stack (MemStats.StackSys)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.MSpanSys}}</td>
				<td>... for mspan (MemStats.MSpanSys)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.MCacheSys}}</td>
				<td>... for mcache (MemStats.MCacheSys)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.BuckHashSys}}</td>
				<td>... for the profiling bucket hash table (MemStats.BuckHashSys)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.GCSys}}</td>
				<td>... for GC metadata (MemStats.GCSys)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.OtherSys}}</td>
				<td>... for other system allocations (MemStats.OtherSys)</td>
			</tr>

			<!-- GC -->
			<tr><td colspan="2">&nbsp;</td></tr>
			<tr>
				<td class="right">{{.MemStats.Lookups}}</td>
				<td>Number of pointer lookups (MemStats.Lookups)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.Mallocs}}</td>
				<td>Number of mallocs (MemStats.Mallocs)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.Frees}}</td>
				<td>Number of frees (MemStats.Frees)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.NumGC}}</td>
				<td>Number of GCs (MemStats.NumGC)</td>
			</tr>
			<tr>
				<td class="right">{{.AvgTotalPauseNs}}</td>
				<td>Average pause time (ns) over all GCs (MemStats.PauseTotalNs/MemStats.NumGC)</td>
			</tr>
			<tr>
				<td class="right">{{.AvgRecentPauseNs}}</td>
				<td>Average pause time (ns) over the last 256 GCs (from MemStats.PauseNs)</td>
			</tr>
			<tr>
				<td class="right">{{.MemStats.NextGC}}</td>
				<td>Next collection will happen when there are this many bytes allocated on the heap (MemStats.NextGC)</td>
			</tr>
		</table>
	</code>
	</body>
</html>
`))

func mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "URL not found", 404)
		return
	}

	info := mainInfo{
		HasTypeInfo: dump.HasTypeInfo(),
		Params:      dump.Raw.Params,
		HeapSize:    dump.Raw.Params.HeapEnd - dump.Raw.Params.HeapStart,
		HeapObjects: uint64(len(dump.HeapObjects)),
	}
	switch dump.Raw.Params.ByteOrder {
	case binary.BigEndian:
		info.ByteOrder = "big endian"
	case binary.LittleEndian:
		info.ByteOrder = "little endian"
	default:
		panic(fmt.Errorf("unknown byte order %#v", dump.Raw.Params.ByteOrder))
	}
	for _, g := range dump.Goroutines {
		info.Goroutines++
		for sf := g.Stack; sf != nil; sf = sf.Caller {
			info.StackFrames++
		}
	}
	dump.ForeachRootVar(func(v *heapdump.RootVar) {
		info.HeapRoots++
		switch v.Kind {
		case heapdump.RootVarGlobal:
			info.GlobalRoots++
		case heapdump.RootVarLocal, heapdump.RootVarFuncParameter:
			info.LocalRoots++
		case heapdump.RootVarFinalizer:
			info.FinalizerRoots++
		default:
			info.OtherRoots++
		}
	})
	if ms := dump.Raw.MemStats; ms != nil {
		var total, count uint64
		for k := uint32(0); k < 256 && k < ms.NumGC; k++ {
			total += ms.PauseNs[(ms.NumGC-k)%256]
			count++
		}
		info.MemStats = *ms
		if count > 0 {
			info.AvgRecentPauseNs = total / count
			info.AvgTotalPauseNs = ms.PauseTotalNs / uint64(ms.NumGC)
		}
	}
	if err := mainTemplate.Execute(w, info); err != nil {
		log.Print(err)
	}
}

var globalsTemplate = template.Must(template.New("globals").Parse(`
<html>
	<head>
		<style>
		table {
			border-collapse:collapse;
		}
		table, td, th {
			border:1px solid grey;
		}
		</style>
		<title>Global Roots</title>
	</head>
	<body>
	<code>
		<h2>Global Roots</h2>
		<table>
		<tr>
			<td>Name</td>
			<td>Address</td>
			<td>Type</td>
			<td>Value</td>
		</tr>
		{{range .}}
		<tr>
			<td>{{.Name}}</td>
			<td>{{.Addr}}</td>
			<td>{{.Type}}</td>
			<td>{{.Value}}</td>
		</tr>
		{{end}}
		</table>
	</code>
	</body>
</html>
`))

func globalsHandler(w http.ResponseWriter, r *http.Request) {
	var infos []varInfo
	for _, gv := range dump.GlobalVars.List {
		infos = append(infos, makeVarInfo(gv.Name, gv.Value))
	}
	if err := globalsTemplate.Execute(w, infos); err != nil {
		log.Print(err)
	}
}

var otherRootsTemplate = template.Must(template.New("otherRoots").Parse(`
<html>
	<head>
		<style>
		table {
			border-collapse:collapse;
		}
		table, td, th {
			border:1px solid grey;
		}
		</style>
		<title>Other Roots</title>
	</head>
	<body>
	<code>
		<h2>Other Roots</h2>
		<table>
		<tr>
			<td>Name</td>
			<td>Type</td>
			<td>Value</td>
		</tr>
		{{range .}}
		<tr>
			<td>{{.Name}}</td>
			<td>{{.Type}}</td>
			<td>{{.Value}}</td>
		</tr>
		{{end}}
		</table>
	</code>
	</body>
</html>
`))

func otherRootsHandler(w http.ResponseWriter, r *http.Request) {
	var infos []varInfo
	dump.ForeachRootVar(func(rv *heapdump.RootVar) {
		switch rv.Kind {
		case heapdump.RootVarGlobal, heapdump.RootVarLocal, heapdump.RootVarFuncParameter:
		default:
			infos = append(infos, makeVarInfo(rv.Name, rv.Value))
		}
	})
	if err := otherRootsTemplate.Execute(w, infos); err != nil {
		log.Print(err)
	}
}

// TODO: lookup frame PC in dwarf and show current line info
// TODO: show summary counts per state?
// TODO: show summary counts per stack trace?
// TODO: show info for PC that created the goroutine?
// TODO: group by stack trace?
type goroutineListInfo struct {
	Goroutines []*goroutineInfo
}

type goroutineInfo struct {
	G      string
	Status string
	Frames []*frameInfo
}

type goroutineByStatus []*goroutineInfo

func (a goroutineByStatus) Len() int           { return len(a) }
func (a goroutineByStatus) Swap(i, k int)      { a[i], a[k] = a[k], a[i] }
func (a goroutineByStatus) Less(i, k int) bool { return a[i].Status < a[k].Status }

func makeGoroutineInfo(g *heapdump.Goroutine) *goroutineInfo {
	info := &goroutineInfo{
		G:      linkObj(g.Raw.GAddr),
		Status: g.Status(),
	}
	for sf := g.Stack; sf != nil; sf = sf.Caller {
		info.Frames = append(info.Frames, makeFrameInfo(sf))
	}
	return info
}

var goroutinesTemplate = template.Must(template.New("goroutines").Parse(`
<html>
	<head>
		<style>
		table {
			border-collapse:collapse;
		}
		table, td, th {
			border: 0px;
			padding: 0px;
			padding-right: 20px;
		}
		</style>
		<title>Goroutines</title>
	</head>
	<body>
	<code>
		<h2>Goroutines</h2>
		{{range .Goroutines}}
		<p>goroutine @{{.G}} status: {{.Status}} <br>
			<table>
			{{range .Frames}}
			<tr>
				<td>...</td>
				<td align="right">0x{{.PC}}</td>
				<td align="left">
					{{if .HavePos}}
						{{.LinkedName}}+0x{{printf "%x" .PCOffset}}
					{{else}}
						{{.LinkedName}}
					{{end}}
				</td>
				<td align="left">
					{{if .HavePos}}
						{{.PCPos.File}}:{{.PCPos.Line}}
					{{end}}
				</td>
			</tr>
			{{end}}
			</table>
		{{end}}
	</code>
	</body>
</html>
`))

func goroutinesHandler(w http.ResponseWriter, r *http.Request) {
	var info goroutineListInfo
	for _, g := range dump.Goroutines {
		info.Goroutines = append(info.Goroutines, makeGoroutineInfo(g))
	}
	sort.Sort(goroutineByStatus(info.Goroutines))
	if err := goroutinesTemplate.Execute(w, info); err != nil {
		log.Print(err)
	}
}

// TODO: more frame-specific information
// TODO: links to frame objects are broken? links to a very large type?
//  (might be linking to a heap object that the frame resides in, perhaps?)
type frameInfo struct {
	Addr             string               // address of the stack frame (as an obj link)
	Size             uint64               // size of the stack frame
	Depth            uint64               // depth in the goroutine (0 is the current stack)
	PC, PCOffset     uint64               // current PC and PC-FuncEntry.Offset
	Name, LinkedName string               // name of the function (linked name links to the frame's page)
	HavePos          bool                 // true if PCPos != nil
	PCPos            *heapdump.SymTabLine // if known
	Caller, Callee   string               // links to caller/callee, if any
	Vars             []varInfo
	Self             *frameInfo
}

func makeFrameInfo(sf *heapdump.StackFrame) *frameInfo {
	info := frameInfo{
		Size:  sf.Size(),
		Depth: sf.Depth(),
		PC:    sf.PC(),
	}
	if sf.Size() == 0 {
		info.Addr = fmt.Sprintf("0x%x", sf.Addr()) // frame is empty so there is no object to link to
	} else {
		info.Addr = linkObj(sf.Addr())
	}

	// Use symbol info to get the name and line info, if known.
	if dump.HasTypeInfo() {
		if pos := dump.LookupPC(sf.PC()); pos != nil {
			info.Name = pos.Func.Name
			info.PCOffset = sf.PC() - pos.Func.Entry
			info.PCPos = pos
			info.HavePos = true
		}
	}
	if info.Name == "" {
		info.Name = sf.Raw.Name
	}
	info.LinkedName = linkFrame(sf, info.Name)

	if sf.Caller != nil {
		info.Caller = linkFrame(sf.Caller, "Caller")
	} else {
		info.Caller = "(No caller)"
	}
	if sf.Callee != nil {
		info.Callee = linkFrame(sf.Callee, "Callee")
	} else {
		info.Callee = "(No callee)"
	}

	for _, lv := range sf.LocalVars.List {
		info.Vars = append(info.Vars, makeVarInfo(lv.Name, lv.Value))
	}

	return &info
}

type frameAndGoroutineInfo struct {
	Goroutine *goroutineInfo
	Self      *frameInfo
}

var frameTemplate = template.Must(template.New("frame").Parse(`
<html>
	<head>
		<style>
		table {
			border-collapse:collapse;
		}
		table, td, th {
			border:1px solid grey;
		}
		table.noborder, td.noborder, th.noborder {
			border: 0px;
			padding: 0px;
			padding-right: 20px;
		}
		</style>
		<title>Frame {{.Self.Name}}</title>
	</head>
	<body>
	<code>
		<h2>Frame #{{.Self.Depth}}: {{.Self.Name}}</h2>
		Frame is {{.Self.Size}} bytes starting from {{.Self.Addr}}.
		{{.Self.Caller}} {{.Self.Callee}} <br>

		<h3>Variables</h3>
		<table>
		<tr>
			<td>Name</td>
			<td>Address</td>
			<td>Type</td>
			<td>Value</td>
		</tr>
		{{range .Self.Vars}}
		<tr>
			<td>{{.Name}}</td>
			<td>{{.Addr}}</td>
			<td>{{.Type}}</td>
			<td>{{.Value}}</td>
		</tr>
		{{end}}
		</table>

		<h3>Parent Goroutine</h3>
		<p>goroutine @{{.Goroutine.G}} status: {{.Goroutine.Status}}
		<table class="noborder">
		{{range .Goroutine.Frames}}
		{{if eq .Depth $.Self.Depth}}
			<tr class="noborder" style="font-weight:bold">
		{{else}}
			<tr class="noborder">
		{{end}}
			<td class="noborder">
				{{if eq .Depth $.Self.Depth}}***{{else}}&middot;&middot;&middot;{{end}}
			</td>
			<td class="noborder" align="right">
				0x{{.PC}}
			</td>
			<td class="noborder" align="left">
				{{if .HavePos}}
					{{.LinkedName}}+0x{{printf "%x" .PCOffset}}
				{{else}}
					{{.LinkedName}}
				{{end}}
			</td>
			<td class="noborder" align="left">
				{{if .HavePos}}
					{{.PCPos.File}}:{{.PCPos.Line}}
				{{end}}
			</td>
		</tr>
		{{end}}
		</table>
	</code>
</body>
</html>
`))

func frameHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	addr, err := lookupParam(q, "id", 16)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	depth, err := lookupParam(q, "depth", 10)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	findStackFrame := func() *heapdump.StackFrame {
		for _, g := range dump.Goroutines {
			for sf := g.Stack; sf != nil; sf = sf.Caller {
				if sf.Addr() == addr && sf.Depth() == depth {
					return sf
				}
			}
		}
		return nil
	}
	sf := findStackFrame()
	if sf == nil {
		http.Error(w, "stack frame not found", 404)
		return
	}
	ginfo := makeGoroutineInfo(sf.Goroutine)
	info := &frameAndGoroutineInfo{
		Goroutine: ginfo,
		Self:      ginfo.Frames[depth],
	}

	if err := frameTemplate.Execute(w, info); err != nil {
		log.Print(err)
	}
}

// TODO: for local vars, link to the stack frame
// TODO: for local/global vars, show the name
// TODO: for offsets at a known location, give the name of the field
// TODO: show object value
// TODO: stats
//  - object size
//  - offset heap dominated by this object
// TODO: when we have dwarf info, some ptrs (e.g., in stacks?) are PCs
type objInfo struct {
	Addr            string
	Type            string
	Offset          uint64
	Size            uint64 // or estimate if unknown
	BaseObj         string
	BaseObjSize     uint64 // also the sizeof(obj) if Offset=0
	ExtraInfo       string
	IsUnknownType   bool
	Fields          []varInfo
	FieldsOverflow  string
	InEdges         []varInfo
	InEdgesOverflow string
}

var objTemplate = template.Must(template.New("obj").Parse(`
<html>
	<head>
		<style>
		table {
			border-collapse:collapse;
		}
		table, td, th {
			border:1px solid grey;
		}
		</style>
		<title>Object {{.Addr}}</title>
	</head>
	<body>
	<code>
		<h2>Object {{.Addr}} : {{.Type}}</h2>
		{{if ne .Offset 0}}
			Address {{.Addr}} is at offset {{.Offset}} of object {{.BaseObj}}, which is {{.BaseObjSize}} bytes.
			{{if .IsUnknownType}}
				Field size is not known, but it as most {{.Size}} bytes.
			{{else}}
				Field is {{.Size}} bytes.
			{{end}}
		{{else}}
			Object is {{.Size}} bytes.
		{{end}}
		{{.ExtraInfo}}

		<h3>Fields</h3>
		{{if .IsUnknownType}}
			Object type is not known. Showing pointer fields from the GC signature.<br><br>
		{{end}}
		<table>
			<tr>
				<td>Field</td>
				<td>Address</td>
				<td>Type</td>
				<td>Value</td>
			</tr>
			{{range .Fields}}
			<tr>
				<td>{{.Name}}</td>
				<td>{{.Addr}}</td>
				<td>{{.Type}}</td>
				<td>{{.Value}}</td>
			</tr>
			{{end}}
		</table>
		{{.FieldsOverflow}}

		<h3>Pointers to this object</h3>
		{{range .InEdges}}
		{{.Addr}}<br>
		{{end}}
		{{.InEdgesOverflow}}
	</code>
	</body>
</html>
`))

func objHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	addr, err := lookupParam(q, "addr", 16)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	const defaultMaxFields = 1024
	maxFields, err := lookupParam(q, "maxfields", 10)
	if err != nil {
		maxFields = defaultMaxFields
	}
	overflowText := fmt.Sprintf("... truncated to %d fields (click %s to show all; may be slow)",
		maxFields,
		fmt.Sprintf("<a href=obj?addr=%x,maxfields=%d>here</a>", addr, uint64(math.MaxUint64)))

	// Lookup the object.
	// For global/lock vars, rv will give extra info.
	var v *heapdump.Value
	rv := dump.FindStackOrGlobalObject(addr)
	if rv != nil {
		v = rv.Value
	} else {
		v = dump.FindHeapObject(addr)
	}
	if v == nil {
		http.Error(w, "object not found", 404)
		return
	}

	// Basic info about the object.
	info := objInfo{
		Addr:   fmt.Sprintf("0x%x", addr),
		Offset: addr - v.Addr(),
	}
	if info.Offset != 0 {
		info.BaseObj = linkObj(v.Addr())
		info.BaseObjSize = v.Size()
		v, err = v.RawOffset(info.Offset)
		if err != nil {
			// NB: Should not fail since FindObject returns a value that contains addr..
			panic(fmt.Errorf("RawOffset: %#v err=%v", info, err))
		}
		info.Size = v.Size()
	} else {
		info.Size = v.Size()
	}
	if rv != nil {
		info.ExtraInfo = fmt.Sprintf("Object is a %s variable named \"%s\".", strings.ToLower(string(rv.Kind)), rv.Name)
	}

	// Type info.
	info.Type = v.Type.String()
	_, info.IsUnknownType = v.Type.(*heapdump.UnknownType)

	// Enumerate all fields.
	// TODO: high-level instead?
	all := true
	v.ForeachField(heapdump.LowLevelScalarTypes, func(name string, field *heapdump.Value) {
		if uint64(len(info.Fields)) >= maxFields {
			all = false
			return
		}
		info.Fields = append(info.Fields, makeVarInfo(name, field))
	})
	if !all {
		info.FieldsOverflow = overflowText
	}

	// For heap objects, enumerate all in edges.
	if rv == nil {
		all := true
		obj, err := v.ContainingObject()
		if err != nil {
			panic(err) // shouldn't happen since v should be in the heap
		}
		for _, ptr := range dump.InEdges(obj) {
			info.InEdges = append(info.InEdges, makeVarInfo("", ptr))
		}
		if !all {
			info.InEdgesOverflow = overflowText
		}
	} else {
		info.InEdgesOverflow = fmt.Sprintf("Not tracked for stack/global variables.")
	}

	if err := objTemplate.Execute(w, info); err != nil {
		log.Print(err)
	}
}

type histogramInfo struct {
	Title                                string
	NameColumn, BytesColumn, CountColumn string
	Entries                              []*histogramEntry
}

type histogramEntry struct {
	Name  string
	Bytes uint64
	Count uint64
}

var histogramTemplate = template.Must(template.New("histogram").Parse(`
<html>
	<head>
		<style>
		table {
			border-collapse:collapse;
		}
		table, td, th {
			border:1px solid grey;
		}
		</style>
		<title>{{.Title}}</title>
		</head>
	<body>
	<code>
		<h2>{{.Title}}</h2>
		<table>
			<tr>
				<td align="right">{{.BytesColumn}}</td>
				<td align="right">{{.CountColumn}}</td>
				<td>{{.NameColumn}}</td>
			</tr>
			{{range .Entries}}
			<tr>
				<td align="right">{{.Bytes}}</td>
				<td align="right">{{.Count}}</td>
				<td>{{.Name}}</td>
			</tr>
			{{end}}
		</table>
	</code>
	</body>
</html>
`))

// TODO: build histograms of other properties?
// TODO: option to sort-by-count?
func histogramsHandler(w http.ResponseWriter, r *http.Request) {
	info := histogramInfo{
		Title:       "Types Histogram",
		NameColumn:  "Type",
		BytesColumn: "Total Bytes",
		CountColumn: "Objects",
	}
	types := map[heapdump.Type]*histogramEntry{}

	for k := range dump.HeapObjects {
		v := &dump.HeapObjects[k]
		if e := types[v.Type]; e != nil {
			e.Bytes += v.Size()
			e.Count++
			continue
		}
		e := &histogramEntry{
			Name:  v.Type.String(),
			Bytes: v.Size(),
			Count: 1,
		}
		info.Entries = append(info.Entries, e)
		types[v.Type] = e
	}

	sort.Sort(sortEntryByBytes(info.Entries))
	if err := histogramTemplate.Execute(w, info); err != nil {
		log.Print(err)
	}
}

type sortEntryByBytes []*histogramEntry

func (a sortEntryByBytes) Len() int           { return len(a) }
func (a sortEntryByBytes) Swap(i, k int)      { a[i], a[k] = a[k], a[i] }
func (a sortEntryByBytes) Less(i, k int) bool { return a[i].Bytes > a[k].Bytes }

func usage() {
	fmt.Fprintf(os.Stderr, "usage: heapview heapdump [executable]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

// TODO: Heap objects info
// - list of referrers for each object

// TODO: Dominator tree
// - save dominated bytes for each object
// - show as a dot/svg graph, perhaps with pruning
// - allow groupBy, e.g., group by type

// TODO: Expression evaluators
// - evaluate arbitrary Go exprs?
// - $pathsTo(obj) to compute paths from GC roots to obj
// - $paths(src, obj) to compute paths from src to obj

func main() {
	flag.Usage = usage
	flag.Parse()

	if *verboseDebug {
		heapdump.LogPrintf = log.Printf
	}

	var dumpname, execname string
	args := flag.Args()
	switch len(args) {
	case 1:
		dumpname = args[0]
		execname = ""
	case 2:
		dumpname = args[0]
		execname = args[1]
	default:
		usage()
	}

	fmt.Println("Loading...")
	var err error
	dump, err = heapdump.Read(dumpname, execname, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Analyzing...")
	dump.PrecomputeInEdges()

	fmt.Printf("Ready. Point your browser to localhost:%d\n", *serverPort)
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/globals", globalsHandler)
	http.HandleFunc("/goroutines", goroutinesHandler)
	http.HandleFunc("/frame", frameHandler)
	http.HandleFunc("/obj", objHandler)
	http.HandleFunc("/otherRoots", otherRootsHandler)
	http.HandleFunc("/histograms", histogramsHandler)
	//http.HandleFunc("/heapdump", heapdumpHandler) // XXX take heapdump of self
	//http.HandleFunc("/type", typeHandler)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *serverPort), nil); err != nil {
		log.Fatal(err)
	}
}
