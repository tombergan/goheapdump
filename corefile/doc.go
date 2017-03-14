// Package corefile implements access to programs contained in core dump files.
//
// A Program is composed of global variables, goroutines, and a heap.
// Each goroutine has a call stack composed of frames, and each stack frame has
// local variables. By default, Program hides global variables and goroutines
// that are used internally by the runtime library; if desired, these hidden
// values can be obtained via Program.RuntimeLibrary.
//
// A Value describes a value in memory, including global values, stack-allocated
// local values, and heap-allocated values. Values are typed. Types include all
// of the standard Go types. In addition, a special GCObjectType represents values
// as viewed by the garbage collector -- these values do not have a known Go type,
// but their reachable heap graph can be traversed using pointer bitmaps embedded
// in the garbage collector’s metadata.
//
// A Query enumerates variables and values in memory. Queries are composed of
// high-level operators such as Where, Reduce, GroupBy, and ReachableValues.
// These operators allow writing concise, declarative queries over program heaps.
// Queries are automatically executed in parallel, and when operating on programs
// with very large heaps, queries abstract away the details of walking over those
// large heaps in an efficient way. Query operators are inspired by parallel
// combinators from libraries such as LINQ, Flume, and Spark.
//
// TODO: Currently unsupported features:
//
// * Traversal over the untyped heap (via GC bitmaps and GCObjectTypes)
//
// * Value.MapLookup and Value.MapForeach (see TODOs in value.go)
//
// * Deferred closures in StackFrames
//
// * Accessing typed free variables in closures (this might require a runtime
// and/or compiler change to support)
//
// * Object roots via finalizers
//
// * CGO types and state
//
// * Queries do not yet support parallel execution or very large heaps
//
// * Dominator tree analysis
//
// * Programs that used dynamically-loaded libraries
//
// * Core files in formats other than Linux/ELF and for architectures
// other than x86
//
// TODO: Features that would make it easier to analyze core files:
//
// * DWARF output should contain info about function closure variables (I believe
// these are stored in runtimefuncval although I don't completely understand this
// quite yet.
//
// * Ideally, each DWARF type should have a link to the type's *runtime._type
// descriptor that is stored in the program's static data segments (for types
// that appear in the static itab list).
//
// * Use of typedefs in the DWARF is a bit confusing: structs and other types have
// a name, but then there's often a typedef with the same name? The typedefs all
// seem unnecessary.
//
// * DWARF output seems to be missing a few struct types in the runtime package.
// e.g., runtime.findfuncbucket.
//
package corefile
