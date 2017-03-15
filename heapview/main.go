package main

import (
	"bytes"
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
	// TODO: use html/template
	"text/template"

	"github.com/tombergan/goheapdump/corefile"
)

var (
	serverPort = flag.Int("port", 8092, "Port to run HTTP server")
	debugLevel = flag.Int("debuglevel", 0, "debug verbosity level")
)

var (
	program    *corefile.Program
	typeToID   = map[corefile.Type]int{}
	typeFromID = map[int]corefile.Type{}
)

func getTypeID(t corefile.Type) int {
	if id, have := typeToID[t]; have {
		return id
	}
	id := len(typeToID) + 1
	typeToID[t] = id
	typeFromID[id] = t
	return id
}

func getGoroutineID(g *corefile.Goroutine) int {
	for k := 0; k < len(program.Goroutines); k++ {
		if program.Goroutines[k] == g {
			return k
		}
	}
	panic(fmt.Sprintf("unknown goroutine %p %#v", g, g))
}

func getFrameDepth(sf *corefile.StackFrame) int {
	var d int
	for ; sf.Callee != nil; sf = sf.Callee {
		d++
	}
	return d
}

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

// linkObj creates a link to the /obj page for the given address and type.
func linkObj(addr uint64, t corefile.Type) string {
	return fmt.Sprintf("<a href=obj?addr=%x&type=%d>0x%x</a>", addr, getTypeID(t), addr)
}

func linkValue(v corefile.Value) string {
	return linkObj(v.Addr, v.Type)
}

// linkFrame creates a link to the /frame page for the given StackFrame, using name as the link text.
func linkFrame(sf *corefile.StackFrame, name string) string {
	gid := getGoroutineID(sf.Goroutine)
	return fmt.Sprintf("<a href=frame?goroutine=%d&depth=%d>%s</a>", gid, getFrameDepth(sf), name)
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

func makeVarInfo(v corefile.Var) varInfo {
	var buf bytes.Buffer
	w := &limitedWriter{&buf, 1000}
	isFirst := true
	writeField := func(_ corefile.Value, name, value string) error {
		var err error
		if !isFirst {
			_, err = fmt.Fprintf(w, "<br/>%s=%s", name, value)
		} else {
			_, err = fmt.Fprintf(w, "%s=%s", name, value)
			isFirst = false
		}
		return err
	}
	if err := fmtValue(v.Value, "", writeField); err != nil {
		buf.WriteString(" ...")
	}
	return varInfo{
		Name:  v.Name,
		Addr:  linkValue(v.Value),
		Type:  v.Value.Type.String(),
		Value: buf.String(),
	}
}

func fmtValue(v corefile.Value, fieldName string, writeField func(v corefile.Value, name, value string) error) error {
	switch v.Type.(type) {
	case *corefile.SliceType, *corefile.ChanType:
		if v.IsZero() {
			return writeField(v, fieldName, "nil")
		}
		vv, err := v.DerefArray()
		if err != nil {
			log.Printf("error printing %s 0x%x: %v", fieldName, v.Addr, err)
			return writeField(v, fieldName, "???")
		}
		v = vv
	}

	switch t := v.Type.(type) {
	case *corefile.NumericType:
		return writeField(v, fieldName, fmt.Sprintf("%v", v.ReadScalar()))

	case *corefile.ArrayType:
		if et, isnum := t.Elem.(*corefile.NumericType); isnum && et.Kind == corefile.NumericUint8 {
			// Special case for []byte.
			return writeField(v, fieldName, fmt.Sprintf("%q", v.Bytes))
		}
		for k := uint64(0); k < t.Len; k++ {
			kname := fieldName + fmt.Sprintf("[%d]", k)
			kv, err := v.Index(k)
			if err != nil {
				if err := writeField(kv, kname, "???"); err != nil {
					return err
				}
			} else {
				if err := fmtValue(kv, kname, writeField); err != nil {
					return err
				}
			}
		}
		return nil

	case *corefile.PtrType:
		if v.IsZero() {
			return writeField(v, fieldName, "nil")
		}
		return writeField(v, fieldName, linkObj(v.ReadUint(), t.Elem))

	case *corefile.UnsafePtrType:
		if v.IsZero() {
			return writeField(v, fieldName, "nil")
		}
		// TODO: type?
		return writeField(v, fieldName, fmt.Sprintf("0x%x", v.ReadUint()))

	case *corefile.InterfaceType:
		if v.IsZero() {
			return writeField(v, fieldName, "nil")
		}
		iv := v
		iv.Type = v.Type.InternalRepresentation()
		dataptr, err := iv.ReadUintFieldByName("data")
		if err != nil {
			log.Printf("error printing %s.$ifacedata 0x%x: %v", fieldName, v.Addr, err)
			return writeField(v, fieldName, "???")
		}
		dt, err := v.DynamicType()
		if err != nil {
			log.Printf("error printing %s.$ifacetype 0x%x: %v", fieldName, v.Addr, err)
			return writeField(v, fieldName, fmt.Sprintf("0x%x (unknown dynamic type)", dataptr))
		}
		// We link to the object with the deferenced type.
		elemt := dt
		if ptrt, ok := dt.(*corefile.PtrType); ok {
			elemt = ptrt.Elem
		}
		return writeField(v, fieldName, linkObj(dataptr, elemt)+" "+dt.String())

	case *corefile.StructType:
		for _, f := range t.Fields {
			fname := f.Name
			if fname == "" {
				fname = fmt.Sprintf("$offset_%d", f.Offset)
			}
			if fieldName != "" {
				fname = fieldName + "." + fname
			}
			fv, err := v.Field(f)
			if err != nil {
				if err := writeField(fv, fname, "???"); err != nil {
					return err
				}
			} else {
				if err := fmtValue(fv, fname, writeField); err != nil {
					return err
				}
			}
		}
		return nil

	case *corefile.StringType:
		if v.IsZero() {
			return writeField(v, fieldName, "nil")
		}
		sv, err := v.DerefArray()
		if err != nil {
			return writeField(v, fieldName, "???")
		}
		return writeField(sv, fieldName, fmt.Sprintf("%q", sv.Bytes))

	case *corefile.MapType:
		return writeField(v, fieldName, "???") // TODO

	case *corefile.FuncType:
		return writeField(v, fieldName, "???") // TODO

	case *corefile.GCObjectType:
		return writeField(v, fieldName, "???") // TODO

	default:
		panic(fmt.Sprintf("unexpected type %s %T", t, t))
	}
}

type mainInfo struct {
	ByteOrder                         string
	PointerSize                       uint64
	GOARCH, GOOS                      string
	MemStats                          runtime.MemStats
	AvgTotalPauseNs, AvgRecentPauseNs uint64
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
		<title>Coredump Viewer</title>
		</head>
	<body>
	<code>
		<h2>Coredump Viewer</h2>
		<a href="packages">Globals</a>
		<a href="goroutines?sort=status">Goroutines</a>
		<br><br>
		Machine parameters:
		<table>
			<tr><td colspan="2">&nbsp;</td></tr>
			<tr><td>ByteOrder = {{.ByteOrder}}</td></tr>
			<tr><td>PointerSize = {{.PointerSize}} bytes</td></tr>
			<tr><td>GOARCH = '{{.GOARCH}}'</td></tr>
			<tr><td>GOOS = '{{.GOOS}}'</td></tr>
		</table>
		<br><br>
		Full runtime.MemStats (FIXME: most of these are currently wrong):
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
		ByteOrder:   program.RuntimeLibrary.Arch.ByteOrder.String(),
		PointerSize: uint64(program.RuntimeLibrary.Arch.PointerSize),
		GOARCH:      program.RuntimeLibrary.GOARCH,
		GOOS:        program.RuntimeLibrary.GOOS,
	}

	if memstats, ok := program.RuntimeLibrary.Vars.FindName("runtime.memstats"); !ok {
		log.Printf("WARNING: could not find runtime.memstats")
	} else {
		readUintField := func(fieldname string) uint64 {
			v, err := memstats.Value.ReadUintFieldByName(fieldname)
			if err != nil {
				log.Printf("WARNING: could read runtime.memstats.%s: %v", fieldname, err)
			}
			return v
		}
		// TODO: see runtime.updatememstats
		info.MemStats.Alloc = readUintField("alloc")
		info.MemStats.TotalAlloc = readUintField("total_alloc")
		info.MemStats.Sys = readUintField("sys")
		info.MemStats.Lookups = readUintField("nlookup")
		info.MemStats.Mallocs = readUintField("nmalloc")
		info.MemStats.Frees = readUintField("nfree")
		info.MemStats.HeapAlloc = readUintField("heap_alloc")
		info.MemStats.HeapSys = readUintField("heap_sys")
		info.MemStats.HeapIdle = readUintField("heap_idle")
		info.MemStats.HeapInuse = readUintField("heap_inuse")
		info.MemStats.HeapReleased = readUintField("heap_released")
		info.MemStats.HeapObjects = readUintField("heap_objects")
		info.MemStats.StackInuse = readUintField("stacks_inuse")
		info.MemStats.StackSys = readUintField("stacks_sys")
		info.MemStats.MSpanInuse = readUintField("mspan_inuse")
		info.MemStats.MSpanSys = readUintField("mspan_sys")
		info.MemStats.MCacheInuse = readUintField("mcache_inuse")
		info.MemStats.MCacheSys = readUintField("mcache_sys")
		info.MemStats.BuckHashSys = readUintField("buckhash_sys")
		info.MemStats.GCSys = readUintField("gc_sys")
		info.MemStats.OtherSys = readUintField("other_sys")
		info.MemStats.NextGC = readUintField("next_gc")
		info.MemStats.PauseTotalNs = readUintField("pause_total_ns")
		info.MemStats.NumGC = uint32(readUintField("numgc"))
		if info.MemStats.NumGC > 0 {
			info.AvgTotalPauseNs = info.MemStats.PauseTotalNs / uint64(info.MemStats.NumGC)
		}
		if pauseNs, err := memstats.Value.FieldByName("pause_ns"); err == nil {
			var total, count uint64
			for k := uint32(0); k < 256 && k < info.MemStats.NumGC; k++ {
				idx := (info.MemStats.NumGC - k) % 256
				v, err := pauseNs.Index(uint64(idx))
				if err != nil {
					log.Printf("WARNING: could read runtime.memstats.PauseNs[%d]: %v", idx, err)
					continue
				}
				total += v.ReadUint()
				count++
			}
			if count > 0 {
				info.AvgRecentPauseNs = total / count
			}
		}
		// See runtime.readmemstats_m.
		info.MemStats.StackSys += info.MemStats.StackInuse
		info.MemStats.HeapInuse -= info.MemStats.StackInuse
		info.MemStats.HeapSys -= info.MemStats.StackInuse
	}

	if err := mainTemplate.Execute(w, info); err != nil {
		log.Print(err)
	}
}

var allPackagesTemplate = template.Must(template.New("allPackages").Parse(`
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
		<title>Packages</title>
	</head>
	<body>
	<code>
		<h2>Imported Packages</h2>
		{{range .}}
		<br/><a href="packages?pkg={{.}}">{{.}}</a>
		{{end}}
	</code>
	</body>
</html>
`))

type packageInfo struct {
	Name  string
	Infos []varInfo
}

var packageTemplate = template.Must(template.New("package").Parse(`
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
		<title>Package {{.Name}}</title>
	</head>
	<body>
	<code>
		<h2>Package {{.Name}}</h2>
		<table>
		<tr>
			<td>Name</td>
			<td>Address</td>
			<td>Type</td>
			<td>Value</td>
		</tr>
		{{range .Infos}}
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

func packagesHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(q["pkg"]) == 0 {
		// Show a list of packages with global vars.
		pkgs := corefile.NewQuery(program.GlobalVars).
			GroupBy(func(v corefile.Var) string { return v.PkgPath }).
			Map(func(g corefile.QueryGrouping) string { return g.Key.(string) }).
			RunAndReturnAll().([]string)
		pkgs = append(pkgs, "runtime")
		sort.Strings(pkgs)
		if err := allPackagesTemplate.Execute(w, pkgs); err != nil {
			log.Print(err)
		}
		return
	}

	// Show a list of all global variables in this package.
	pkg := q["pkg"][0]
	info := packageInfo{Name: pkg}
	if pkg == "runtime" {
		info.Infos = corefile.NewQuery(program.RuntimeLibrary.Vars).
			Map(makeVarInfo).
			RunAndReturnAll().([]varInfo)
	} else {
		info.Infos = corefile.NewQuery(program.GlobalVars).
			Where(func(v corefile.Var) bool { return v.PkgPath == pkg }).
			Map(makeVarInfo).
			RunAndReturnAll().([]varInfo)
	}
	if err := packageTemplate.Execute(w, info); err != nil {
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
	IsRuntime  bool
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

func makeGoroutineInfo(g *corefile.Goroutine) *goroutineInfo {
	info := &goroutineInfo{
		G:      linkValue(g.G),
		Status: g.StatusString,
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
						{{.File}}:{{.Line}}
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
	isRuntime, _ := lookupParam(r.URL.Query(), "runtime", 10)
	info := goroutineListInfo{IsRuntime: isRuntime > 0}
	if info.IsRuntime {
		for _, g := range program.RuntimeLibrary.Goroutines {
			info.Goroutines = append(info.Goroutines, makeGoroutineInfo(g))
		}
	} else {
		for _, g := range program.Goroutines {
			info.Goroutines = append(info.Goroutines, makeGoroutineInfo(g))
		}
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
	Depth            uint64 // depth in the goroutine (0 is the current stack)
	PC, PCOffset     uint64 // current PC and PC-FuncEntry.Offset
	Name, LinkedName string // name of the function (linked name links to the frame's page)
	HavePos          bool   // true if File and Line are valid
	File             string
	Line             uint64
	Caller, Callee   string // links to caller/callee, if any
	Vars             []varInfo
}

func makeFrameInfo(sf *corefile.StackFrame) *frameInfo {
	info := &frameInfo{
		PC:   sf.PC,
		Vars: corefile.NewQuery(sf.LocalVars).Map(makeVarInfo).RunAndReturnAll().([]varInfo),
	}
	for x := sf; x.Callee != nil; x = x.Callee {
		info.Depth++
	}
	if sf.Func != nil {
		info.PCOffset = sf.PC - sf.Func.EntryPC
	}
	pcinfo, err := program.PCInfo(sf.PC)
	if err != nil {
		log.Printf("could not find pcinfo for 0x%x: %v", sf.PC, err)
		info.Name = "???"
	} else {
		info.HavePos = true
		info.File = pcinfo.File
		info.Line = pcinfo.Line
		info.Name = pcinfo.Func.Name
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
	return info
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
					{{.File}}:{{.Line}}
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
	gidx, err := lookupParam(q, "goroutine", 10)
	if err != nil {
		http.Error(w, "could not parse goroutine param", 400)
		return
	}
	depth, err := lookupParam(q, "depth", 10)
	if err != nil {
		http.Error(w, "could not parse depth param", 400)
		return
	}
	if gidx >= uint64(len(program.Goroutines)) {
		http.Error(w, "bad goroutine param", 400)
		return
	}
	g := program.Goroutines[gidx]

	findStackFrame := func() *corefile.StackFrame {
		k := uint64(0)
		for sf := g.Stack; sf != nil; sf = sf.Caller {
			if k == depth {
				return sf
			}
			k++
		}
		return nil
	}
	sf := findStackFrame()
	if sf == nil {
		http.Error(w, "stack frame not found", 404)
		return
	}

	ginfo := makeGoroutineInfo(g)
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
	Addr           string
	Type           string
	Size           uint64 // or estimate if unknown
	BaseObj        string // if known
	BaseObjSize    uint64 // if known
	Offset         uint64 // offset within BaseObj, if known
	ExtraInfo      string
	IsGCObjectType bool
	Fields         []varInfo
	FieldsOverflow string
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
		<title>Object {{.Addr}} : {{.Type}}</title>
	</head>
	<body>
	<code>
		<h2>Object {{.Addr}} : {{.Type}}</h2>
		{{if ne .Offset 0}}
			Address {{.Addr}} is at offset {{.Offset}} of object {{.BaseObj}}, which is {{.BaseObjSize}} bytes.
			{{if .IsGCObjectType}}
				Field size is not known, but it as most {{.Size}} bytes.
			{{else}}
				Field is {{.Size}} bytes.
			{{end}}
		{{else}}
			Object is {{.Size}} bytes.
		{{end}}
		{{.ExtraInfo}}

		<h3>Fields</h3>
		{{if .IsGCObjectType}}
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
	</code>
	</body>
</html>
`))

func objHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	addr, err := lookupParam(q, "addr", 16)
	if err != nil {
		log.Print(err)
		http.Error(w, "could not parse addr param", 400)
		return
	}
	tid, err := lookupParam(q, "type", 10)
	if err != nil {
		http.Error(w, "could not parse type param", 400)
		return
	}
	t := typeFromID[int(tid)]
	if t == nil {
		http.Error(w, "bad type param", 400)
		return
	}
	const defaultMaxFields = 1024
	maxFields, err := lookupParam(q, "maxfields", 10)
	if err != nil {
		maxFields = defaultMaxFields
	}

	// Lookup the value.
	v, err := program.Value(addr, t)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not load value from 0x%x with type %s", addr, t), 400)
		return
	}

	// Basic info about the object.
	info := objInfo{
		Addr: fmt.Sprintf("0x%x", addr),
		Type: t.String(),
		Size: v.Size(),
	}
	_, info.IsGCObjectType = v.Type.(*corefile.GCObjectType)

	// Enumerate all fields.
	all := true
	fmtValue(v, "", func(v corefile.Value, name, value string) error {
		if uint64(len(info.Fields)) >= maxFields {
			all = false
			return nil
		}
		if len(value) > 1000 {
			value = value[:1000] + "..."
		}
		info.Fields = append(info.Fields, varInfo{
			Name:  name,
			Addr:  linkValue(v),
			Type:  v.Type.String(),
			Value: value,
		})
		return nil
	})
	if !all {
		info.FieldsOverflow = fmt.Sprintf("... truncated to %d fields (click %s to show all; may be slow)",
			maxFields, fmt.Sprintf("<a href=obj?addr=%x,maxfields=%d>here</a>", addr, uint64(math.MaxUint64)))
	}

	if err := objTemplate.Execute(w, info); err != nil {
		log.Print(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: heapview heapdump [executable]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if *debugLevel > 0 {
		corefile.DebugLogf = func(verbosityLevel int, format string, args ...interface{}) {
			if verbosityLevel <= *debugLevel {
				log.Printf(format, args...)
			}
		}
	}

	var corename, execname string
	args := flag.Args()
	switch len(args) {
	case 1:
		corename = args[0]
		execname = ""
	case 2:
		corename = args[0]
		execname = args[1]
	default:
		usage()
	}

	fmt.Println("Loading...")
	var err error
	program, err = corefile.OpenProgram(corename, &corefile.OpenProgramOptions{
		ExecutablePath: execname,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ready. Point your browser to localhost:%d\n", *serverPort)
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/packages", packagesHandler)
	http.HandleFunc("/goroutines", goroutinesHandler)
	http.HandleFunc("/frame", frameHandler)
	http.HandleFunc("/obj", objHandler)
	//http.HandleFunc("/histograms", histogramsHandler)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *serverPort), nil); err != nil {
		log.Fatal(err)
	}
}
