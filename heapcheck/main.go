package main

import (
	"flag"
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"

	"github.com/tombergan/goheapdump/corefile"
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

var debugLevel = flag.Int("debuglevel", 0, "debug verbosity level")

func usage() {
	fmt.Fprintf(os.Stderr, "usage: heapchecker corefile executable\n")
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
	if len(flag.Args()) != 2 {
		usage()
	}
	corename := flag.Arg(0)
	execname := flag.Arg(1)

	fmt.Println("Loading...")
	program, err := corefile.OpenProgram(corename, &corefile.OpenProgramOptions{
		ExecutablePath: execname,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer program.Close()

	// TODO: This is a trivial example for demonstration.
	// TODO: Would be more useful to show paths to the open bodies.
	httpBodyType := program.FindType("net/http.body")
	if httpBodyType == nil {
		log.Fatal("could not find net/http.body")
	}
	corefile.NewQuery(program).
		ReachableValues().
		Where(func(v corefile.Value) bool {
			// Look for values of type net/http.body that have closed=false.
			if v.Type != httpBodyType {
				return false
			}
			closed, err := v.ReadScalarFieldByName("closed")
			return err == nil && !closed.(bool)
		}).
		Run(func(v corefile.Value) {
			log.Printf("found open net/http.body at 0x%x", v.Addr)
		})
}
