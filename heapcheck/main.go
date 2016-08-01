package main

import (
	"flag"
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"

	heapdump "github.com/tombergan/goheapdump"
)

/*
TODO: Ideas for checkers:

1) Check for bugs where the programmer forgot to call Close(). e.g.,:

   Run a program analysis to compute, for each type with a "Close() error" method,
   an expression that is true only after Close() has been called. This shouldn't be
   too hard in many cases, as it's common for structs to have fields to prevent
   multiple close calls or return errors on Read/Write-after-Close, e.g., common
   fields are "closed bool" or "closed sync.Once". Then we can check those expressions
   against all matching types in the heap and report which objects are *not* closed.

   The checker in main() is a manually-built example of this that catches errors
   where the programmer forgot to call http.Response.Body.Close().

2) Look for objects that are unreachable in type-safe programs. For example, say
   there is an array of pointers X and the programmer takes a slice of that array,
   X[2:6]. If that slice is the only remaining reference to X, then the pointers in
   X[0:2] and X[8:] are technically unreachable, but the GC doesn't know this and
   thus they will stay live.

   We can find these pointers by walking over the pointer graph. For each pointer P
   that points-to a heap object H at offset X, where P has type Ptr(T), we update a
   bitmap to mark all fields in H[X:T.Size()] as reachable. We then iterate over all
   heap objects and look for a heap object H where some pointers in H are not
   covered by that bitmap. Those pointers are technically unreachable.

   There may be false-positives in this approach. E.g., the runtime sometimes uses
   zero-length arrays in cases where the size of the array is allocated specially.
   These cases are probably a minority, and further, we can probably filter them
   by filtering out types from the runtime package.

3) Look for leaked goroutines. E.g., look for a goroutine that is blocked on channel
   X where that goroutine has the only reference to X. All data dominated by leaked
   goroutines is leaked an unreachable.

4) We could allow the user to specify an arbitrary expression to match against
   pointers. We'd then report how much data is dominated by pointers that match those
   expressions. (This is a generalized version of #1.)

*/

var verboseDebug = flag.Bool("debug", false, "Print verbose debugging info")

func usage() {
	fmt.Fprintf(os.Stderr, "usage: heapchecker heapdump executable\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if *verboseDebug {
		heapdump.LogPrintf = log.Printf
	}
	if len(flag.Args()) != 2 {
		usage()
	}
	dumpname := flag.Arg(0)
	execname := flag.Arg(1)

	fmt.Println("Loading...")
	dump, err := heapdump.Read(dumpname, execname, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Analyzing...")
	dump.PrecomputeInEdges()

	// TODO: This is a trivial example for demonstration.
	for k := range dump.HeapObjects {
		v := &dump.HeapObjects[k]
		t, isstruct := v.Type.(*heapdump.StructType)
		if !isstruct || t.String() != "net/http.body" {
			continue
		}
		f := t.FieldByName("closed")
		if f == nil {
			fmt.Printf("Error: couldn't find field net/http.body.closed\n")
			continue
		}
		fv, err := v.Field(f)
		if err != nil {
			fmt.Printf("Error extracting net/http.body.closed: %v\n", err)
			continue
		}
		closed, err := fv.ReadUint()
		if err != nil {
			fmt.Printf("Error reading net/http.body.closed: %v\n", err)
			continue
		}
		if closed == 0 {
			fmt.Printf("\nFound open http.Response.Body at 0x%x\n", v.Addr())
		} else {
			// uncomment to see traces of closed bodies
			//fmt.Printf("\nFound closed http.Response.Body at 0x%x\n", v.Addr())
			continue
		}
		roots := dump.FindRootsFor(v)
		if len(roots) == 0 {
			fmt.Printf("... not reachable\n")
		} else {
			for _, rv := range roots {
				fmt.Printf("... reachable from %s (%s)\n", rv.Name, rv.Kind)
			}
		}
	}
}
