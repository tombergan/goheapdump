package corefile

import (
	"fmt"
	"reflect"
	"sync"
)

var (
	typeofBool               = reflect.TypeOf(true)
	typeofValue              = reflect.TypeOf(Value{})
	typeofVar                = reflect.TypeOf(Var{})
	typeofVarSet             = reflect.TypeOf(VarSet{})
	typeofGoroutine          = reflect.TypeOf(Goroutine{})
	typeofStackFrame         = reflect.TypeOf(StackFrame{})
	typeofProgram            = reflect.TypeOf(Program{})
	typeofQueryGrouping      = reflect.TypeOf(QueryGrouping{})
	typeofRuntimeFinalizers  = reflect.TypeOf(runtimeFinalizers{})
	typeofRuntimeGCRoots     = reflect.TypeOf(runtimeGCRoots{})
	typeofRuntimeHeapObjects = reflect.TypeOf(runtimeHeapObjects{})
)

type queryOp int

const (
	queryInput queryOp = iota
	queryFlatten
	queryWhere
	queryMap
	queryReduce
	queryExists
	queryGroupBy
	queryGroupByAndReduce
	queryReachableValues
)

func (op queryOp) String() string {
	switch op {
	case queryInput:
		return "Input"
	case queryFlatten:
		return "Flatten"
	case queryWhere:
		return "Where"
	case queryMap:
		return "Map"
	case queryReduce:
		return "Reduce"
	case queryExists:
		return "Exists"
	case queryGroupBy:
		return "GroupBy"
	case queryGroupByAndReduce:
		return "GroupByAndReduce"
	case queryReachableValues:
		return "ReachableValues"
	default:
		return "<unknown>"
	}
}

func varToValue(v Var) Value {
	return v.Value
}

// Query is the interface for writing queries over program state.
// A Query is a DAG of operations that transforms an input collection to
// an output collection. The input collection(s) are seeded by NewQuery.
// Queries do not actually evaluate until Run is called.
//
// For example, the following snippet prints the address of all values
// reachable from a given stack frame:
//
//    var sf *StackFrame = ...
//    q := NewQuery(sf).ReachableValues()
//    q.Run(func(v Value) {
//        fmt.Println(v.Addr)
//    })
//
// Query pipelines are typed. For example, the following snippet groups
// exported global variables by package, then prints a count for each package.
// Note how types are piped through each stage of the query, from Vars, to a
// QueryGrouping, and finally to a user-defined type, varsPerPkg:
//
//    func countFn(x, y, uint64) uint64 { return x + y }
//
//    type varsPerPkg struct { pkg string, count uint64 }
//    var p *Program = ...
//    q := NewQuery(p.GlobalVars)
//    q = q.Where(func(v Var) bool { return v.IsExportedGlobal() })
//    q = q.GroupByAndReduce(func(v Var) (string, uint64) { return v.PkgPath, 1 }, countFn)
//    q = q.Map(func(g QueryGrouping) varsPerPackage {
//      return varsPerPkg{
//        t:     g.Key.(string),
//        count: g.Elems.RunAndReturn().(uint64),
//      }
//    })
//    q.Run(func(x varsPerPkg) { fmt.Println(x) })
//
// Query construction will panic if a type mismatch is detected.
// For example, the following snippet will panic at line 3 because
// ReachableValues produces a collection of Values, not Vars:
//
//    var sf *StackFrame = ...
//    q := NewQuery(sf).ReachableValues()
//    q = q.GroupBy(func(v Var) Type { return v.Type })
//
// Queries are naturally amenable to parallel evaluation. Query.Run may use
// multiple goroutines to exploit available CPU resources. As a result, all
// functions passed to Query operators must be safe for concurrent execution.
//
// TODO: (hopefully!) queries make it possible to analyze heaps that are too
// large for all metadata to fit in memory
type Query struct {
	// The operation performed by this query is op(inner, arg, arg2).
	op        queryOp
	inner     *Query
	arg, arg2 interface{}

	// The output is Collection<outType>.
	// If outType is QueryGrouping, then outKeyType is the grouping's key type
	// and outElemType is the grouping's element type.
	outType     reflect.Type
	outKeyType  reflect.Type
	outElemType reflect.Type

	// True for QueryGrouping.Elems inputs that are generated from GroupByAndReduce.
	inputFromReduction bool
}

// NewQuery constructs a new Query using x to produce an input collection.
// The type of the input collection depends on the type of x, which can have
// any of the following types:
//
//   Value or *Value
//      The collection contains a single Value.
//
//   Var or *Var
//      The collection contains a single Var.
//
//   *VarSet
//      The collection contains all variables in the VarSet.
//      Elements in the collection have type Var.
//
//   *StackFrame
//      The collection contains all values in the StackFrame.
//      Elements in the collection have type Value. This is the union
//      of StackFrame.LocalVars and TODO: deferred closures?
//
//   *Goroutine
//      The collection is the union of all StackFrames in the goroutine.
//      Elements in the collection have type Value.
//
//   *Program
//      A collection of all values reachable in the program.
//      Elements in the collection have type Value. This is the union
//      of Program.GlobalVars, Program.Goroutines, and
//      Program.RuntimeLibrary.Finalizers.
//
//   RuntimeLibrary.Finalizers
//      The collection contains all registered finalizers.
//      Elements in the collection have type RegisteredFinalizer.
//
//   RuntimeLibrary.GCRootPointers
//      The collection contains all garbage collection root pointers.
//      This produces values that cover all local variables, global
//      variables, and finalizers, similar to NewQuery(Program). However,
//      NewQuery(Program) produces values as viewed by the Go program,
//      meaning the values have Go types, while NewQuery(GCRootPointers)
//      produces values as viewed by the garbage collector, meaning the
//      values have GCObjectTypes. In particular, GCRootPointers may
//      cover many variables with a single Value of type GCObjectType.
//
//   RuntimeLibrary.HeapObjects
//      The collection contains all heap objects known to the garbage collector.
//      Elements in the collection are Values of type GCObjectType.
//
//   [n]T or []T
//      This is the union of NewQuery(x[i]) for all elements of the array
//      or slice, except that T must be one of the above types.
//
// NewQuery will panic if x does not have one of the above types. It is assumed
// that all Values in x are derived from the same program -- if this assumption
// is broken, NewQuery or methods on the resulting Query may panic.
//
// x should not be modified until the Query has been discarded, otherwise data
// races may occur.
func NewQuery(x interface{}) *Query {
	// Special cases that can be expressed as flattening.
	// TODO: This aggressive flattening simplifies the implementation, but may be inefficient.
	switch x := x.(type) {
	case *StackFrame:
		// TODO: deferred closures?
		return NewQuery(x.LocalVars).Map(varToValue)
	case *Goroutine:
		var q *Query
		for sf := x.Stack; sf != nil; sf = sf.Caller {
			q0 := NewQuery(sf)
			if q == nil {
				q = q0
			} else {
				q = q.Flatten(q0)
			}
		}
		return q
	case *Program:
		return NewQuery(x.GlobalVars)
		q0 := NewQuery(x.GlobalVars).Map(varToValue)
		q1 := NewQuery(x.Goroutines)
		// TODO: q2 := NewQuery(x.RuntimeLibrary.Finalizers)
		return q0.Flatten(q1) // TODO: .Flatten(q2)
	}
	xt := reflect.TypeOf(x)
	if xt.Kind() == reflect.Array || xt.Kind() == reflect.Slice {
		var q *Query
		xv := reflect.ValueOf(x)
		for k := 0; k < xv.Len(); k++ {
			q0 := NewQuery(xv.Index(k).Interface())
			if q == nil {
				q = q0
			} else {
				q = q.Flatten(q0)
			}
		}
		return q
	}

	q := &Query{
		op:  queryInput,
		arg: x,
	}
	// Determine the type of elements in this collection.
	switch xt {
	case typeofValue, reflect.PtrTo(typeofValue),
		typeofRuntimeFinalizers, typeofRuntimeGCRoots, typeofRuntimeHeapObjects:
		q.outType = typeofValue
	case typeofVar, reflect.PtrTo(typeofVar), reflect.PtrTo(typeofVarSet):
		q.outType = typeofVar
	default:
		panic(fmt.Sprintf("bad type %T for NewQuery", x))
	}
	return q
}

// Flatten concatenates q and arg, which much be collections containing
// elements of the same type. Flatten is similar to Go's append, except
// that the order of elements in the output collection is not specified.
func (q *Query) Flatten(arg *Query) *Query {
	if q.outType != arg.outType {
		panic(fmt.Sprintf("cannot flatten collections with elements of type %s and %s", q.outType, arg.outType))
	}
	return &Query{
		op:      queryFlatten,
		inner:   q,
		arg:     arg,
		outType: q.outType,
	}
}

// Where applies a filter to the input collection using the given predicate
// function. An element x is dropped from the input iff fn(x) returns false.
// The types are:
//
//   in:  Query producing Collection<ElemT>
//   out: Query producing Collection<ElemT>
//   fn:  func(x ElemT) bool
//
func (q *Query) Where(fn interface{}) *Query {
	t := reflect.TypeOf(fn)
	if t.Kind() != reflect.Func || t.NumIn() != 1 || t.NumOut() != 1 || t.IsVariadic() || t.In(0) != q.outType || t.Out(0) != typeofBool {
		panic(fmt.Sprintf("bad type %T for fn, want: func(%s) bool", fn, q.outType))
	}
	return &Query{
		op:      queryWhere,
		inner:   q,
		arg:     fn,
		outType: t.In(0),
	}
}

// Map applies a transformation to every element of the input collection
// to produce an output collection. The types are:
//
//   in:  Query producing Collection<ElemT>
//   out: Query producing Collection<NewElemT>
//   fn:  func(x ElemT) NewElemT
//
func (q *Query) Map(fn interface{}) *Query {
	t := reflect.TypeOf(fn)
	if t.Kind() != reflect.Func || t.NumIn() != 1 || t.NumOut() != 1 || t.IsVariadic() || t.In(0) != q.outType {
		panic(fmt.Sprintf("bad type %T for fn, want: func(%s) T", fn, q.outType))
	}
	return &Query{
		op:      queryMap,
		inner:   q,
		arg:     fn,
		outType: t.Out(0),
	}
}

// Reduce applies a reduction (or "aggregation") on the input collection
// to produce a single output value. The types are:
//
//   in:  Query producing Collection<ElemT>
//   out: Query producing ElemT
//   fn:  func(x, y ElemT) ElemT
//
// Reduce implements the following algorithm:
//
//   curr := q[0]
//   foreach x in q[1:] {
//     curr = fn(curr, x)
//   }
//   return curr
//
// The reducer function fn must be distributive and commutative.
// If q is an empty collection, the output is the zero value of ElemT.
func (q *Query) Reduce(fn interface{}) *Query {
	t := reflect.TypeOf(fn)
	if t.Kind() != reflect.Func || t.NumIn() != 2 || t.NumOut() != 1 || t.IsVariadic() ||
		t.In(0) != q.outType || t.In(1) != q.outType || t.Out(0) != q.outType {
		panic(fmt.Sprintf("bad type %T for fn, want: func(%s, %s) %s", fn, q.outType, q.outType, q.outType))
	}
	return &Query{
		op:      queryReduce,
		inner:   q,
		arg:     fn,
		outType: q.outType,
	}
}

// Exists determines if fn(x) is true for at least one element x
// of the input collection. The types are:
//
//   in:  Query producing Collection<ElemT>
//   out: Query producing bool
//   fn:  func(x ElemT) bool
//
// q.Exists(fn) is semantically equivalent to following pipeline:
//
//   q.Map(func(x ElemT) bool { return fn(x) }).
//     Reduce(func(x, y bool) bool { return x || y })
//
// However, Exists can be implemented more efficiently because it
// can halt the query immediately once fn returns true.
func (q *Query) Exists(fn interface{}) *Query {
	t := reflect.TypeOf(fn)
	if t.Kind() != reflect.Func || t.NumIn() != 1 || t.NumOut() != 1 || t.IsVariadic() || t.In(0) != q.outType || t.Out(0) != typeofBool {
		panic(fmt.Sprintf("bad type %T for fn, want: func(%s) bool", fn, q.outType))
	}
	return &Query{
		op:      queryExists,
		inner:   q,
		arg:     fn,
		outType: typeofBool,
	}
}

// GroupBy partitions the input collection. GroupBy has two forms:
//
//   in:  Query producing Collection<ElemT>
//   out: Query producing Collection<QueryGrouping<KeyT, Query producing Collection<ElemT>>>
//   fn:  func(x ElemT) KeyT
//
// Or:
//
//   in:  Query producing Collection<ElemT>
//   out: Query producing Collection<QueryGrouping<KeyT, Query producing Collection<NewElemT>>>
//   fn:  func(x ElemT) (KeyT, NewElemT)
//
// In the first form, the partitioning function maps each input element to
// a grouping key. In the second form, the partitioning function maps each input
// element to a grouping key paired with a new element -- this is effectively a
// shorthand for a GroupBy followed immediately by a Map.
//
// For each unique key output by fn, GroupBy emits a single QueryGrouping object
// into the output collection. Each QueryGrouping contains a nested Query that
// describes the elements partitioned into that grouping.
//
// TODO: what are the restrictions on KeyT? Perhaps, must be able to put in a map,
// but also allow Value and Var as special cases? (Note that Value and Var cannot
// be map keys as-is due to Value.Bytes and Var.Value.Bytes, however, we could
// special-case those.)
func (q *Query) GroupBy(fn interface{}) *Query {
	return q.groupByAndReduce(queryGroupBy, fn, nil)
}

// GroupByAndReduce is like GroupBy, except that the reduce function is applied to
// the values of each group generated by the GroupBy query. Like GroupBy, GroupByAndReduce
// has two forms:
//
//   in:  Query producing Collection<ElemT>
//   out: Query producing Collection<QueryGrouping<KeyT, Query producing Collection<ElemT>>>
//   fn:       func(x ElemT) KeyT
//   reduceFn: func(x, y ElemT) ElemT
//
// Or:
//
//   in:  Query producing Collection<ElemT>
//   out: Query producing Collection<QueryGrouping<KeyT, Query producing Collection<NewElemT>>>
//   fn:       func(x ElemT) (KeyT, NewElemT)
//   reduceFn: func(x, y NewElemT) NewElemT
//
// The reducer function fn must be distributive and commutative.
func (q *Query) GroupByAndReduce(fn interface{}, reduceFn interface{}) *Query {
	return q.groupByAndReduce(queryGroupByAndReduce, fn, reduceFn)
}

func (q *Query) groupByAndReduce(op queryOp, fn interface{}, reduceFn interface{}) *Query {
	t := reflect.TypeOf(fn)
	if t.Kind() != reflect.Func || t.NumIn() != 1 || (t.NumOut() != 1 && t.NumOut() != 2) || t.IsVariadic() || t.In(0) != q.outType {
		panic(fmt.Sprintf("bad type %T for fn, want: func(%s, T) T", fn, q.outType))
	}
	newq := &Query{
		op:         op,
		inner:      q,
		arg:        fn,
		arg2:       reduceFn,
		outType:    typeofQueryGrouping,
		outKeyType: t.Out(0),
	}
	if t.NumOut() == 1 {
		newq.outElemType = q.outType
	} else {
		newq.outElemType = t.Out(1)
	}
	if op == queryGroupByAndReduce {
		t := reflect.TypeOf(reduceFn)
		if t.Kind() != reflect.Func || t.NumIn() != 2 || t.NumOut() != 1 || t.IsVariadic() ||
			t.In(0) != newq.outElemType || t.In(1) != newq.outElemType || t.Out(0) != newq.outElemType {
			panic(fmt.Sprintf("bad type %T for fn, want: func(%s, %s) %s", fn, newq.outElemType, newq.outElemType, newq.outElemType))
		}
	}
	return newq
}

// QueryGrouping is the element type returned by Query.GroupBy or Query.GroupByAndReduce.
//
// XXX: QueryGrouping.Elems.arg points to the eval state struct for the GroupBy
// which generated the query; this allows us to do things like propagate cancellation,
// e.g., to end a query early
type QueryGrouping struct {
	// Key is the key value of this grouping. The dynamic type is defined
	// by the return value of the function passed to Query.GroupBy.
	Key interface{}

	// Elems enumerates the elements grouped under Key.
	// Unlike manually-created queries, Elems can only be evaluated once.
	Elems *Query
}

// ReachableValues enumerates all values reachable from the input set
// of values. Reachability is transitive and reflexive. The input
// collection must contain elements of type Value or Var. The types are:
//
//   in:  Query producing Collection<Value or Var>
//   out: Query producing Collection<Value>
//
// TODO: explain subtleties of repeated visits; in particular, we might
// reach an interior pointer of an object, only to later reach the full
// object at some later time; this is sort-of a repated visit of an address.
// When walking heap objects with GCObjectType values, we can guarantee that
// this won't happen, since the heap walk will always visit full objects.
//
// TODO: options?
// - visit heap objects only (i.e., not GC roots)
// - edge filter (apply "fn(srcVal, srcPtr, dstVal Value) bool" to each edge)
func (q *Query) ReachableValues() *Query {
	if q.outType != typeofValue && q.outType != typeofVar {
		panic(fmt.Sprintf("cannot compute ReachableValues on elements of type %s, expected Value or Var", q.outType))
	}
	if q.outType == typeofVar {
		q = q.Map(varToValue)
	}
	return &Query{
		op:      queryReachableValues,
		inner:   q,
		outType: typeofValue,
	}
}

// FindPathsTo enumerates paths from q to dst. The types are:
//
//   in:  Query producing Collection<Value>
//   out: Query producing Collection<[]Value>
//   fn:  func(x ElemT) (KeyT, NewElemT)
//
// For each element d in dst that is reachable from q, FindPathsTo emits
// one element in the output collection that describes a path from q to
// d. The choice of path is arbitrary. Each path is represented as a slice
// of Values that describe a path of pointers from q to an element in dst.
// For example, given:
//
//   q   = { a, b, c }
//   dst = { x }
//
// Assuming there is a path a.ptr → w[0] → r[5].ptr → x, then FindPathsTo(dst)
// will produce the output slice []Value{a.ptr, w[0], r[5].ptr, x}.
//
// FindPathsTo follows the same reachability rules as ReachableValues.
// TODO: also options?
// TODO: this would be more useful if it described the path of go expressions
//
// TODO: worth implementing?
/*
func (q *Query) FindPathsTo(dst *Query) *Query {
	if q.outType != typeofValue && q.outType != typeofVar {
		panic(fmt.Sprintf("cannot compute FindPathsTo on src elements of type %s, expected Value or Var", q.outType))
	}
	if dst.outType != typeofValue {
		panic(fmt.Sprintf("cannot compute FindPathsTo on dst elements of type %s, expected Value", dst.outType))
	}
	return &Query{
		op:      TODO_queryFindPathsTo,
		inner:   q,
		arg:     dst,
		outType: reflect.SliceOf(typeofValue),
	}
}
*/

// Run evaluates a Query. The function fn is called once for each element
// output by Query q. If fn returns false, the query will stop executing.
// If fn does not have a return value, it Run behaves as if each call to fn
// returns false. The two possible forms are:
//
//   in:  Query producing Collection<ElemT>
//   out: void
//   fn:  func(x ElemT) bool
//
// Or:
//
//   in:  Query producing Collection<ElemT>
//   out: void
//   fn:  func(x ElemT)
//
// A Query can be run many times, even concurrently.
// Run does not mutate q.
func (q *Query) Run(fn interface{}) {
	t := reflect.TypeOf(fn)
	if t.Kind() != reflect.Func || t.NumIn() != 1 || t.NumOut() > 1 || t.IsVariadic() || t.In(0) != q.outType || (t.NumOut() == 1 && t.Out(0) != typeofBool) {
		panic(fmt.Sprintf("bad type %T for fn, want: func(%s) bool", fn, q.outType))
	}
	var es *queryEvalState
	fnv := reflect.ValueOf(fn)
	if t.NumOut() == 1 {
		es = queryCompile(q, func(x interface{}) bool {
			return fnv.Call([]reflect.Value{reflect.ValueOf(x)})[0].Bool()
		})
	} else {
		es = queryCompile(q, func(x interface{}) bool {
			fnv.Call([]reflect.Value{reflect.ValueOf(x)})
			return true
		})
	}
	queryEval(es)
}

// RunAndReturn evaluates a Query, similar to Run, except that RunAndReturn
// directly returns the first result of the Query instead of enumerating all
// results. RunAndReturn can only be used if q is a reduction query (such as
// Reduce or Exists). The types are:
//
//   in:  Query producing ElemT
//   out: ElemT
//
// RunAndReturn does not mutate q.
func (q *Query) RunAndReturn() interface{} {
	if q.op != queryReduce && q.op != queryExists && (q.op != queryInput || !q.inputFromReduction) {
		panic("RunAndReturn must follow Reduce or Exists")
	}
	// TODO: if sanityChecks enabled, panic if called more than once?
	var once sync.Once
	var out interface{}
	es := queryCompile(q, func(x interface{}) bool {
		once.Do(func() { out = x })
		return false // we just want the first result
	})
	queryEval(es)
	return out
}

// RunAndReturnAll is a shorthand for calling Run with a function that adds
// all output elements into a slice. The types are:
//
//   in:  Query producing ElemT
//   out: []ElemT
//
// RunAndReturnAll does not mutate q.
func (q *Query) RunAndReturnAll() interface{} {
	// TODO: concurrent safe
	outv := reflect.MakeSlice(reflect.SliceOf(q.outType), 0, 0)
	es := queryCompile(q, func(x interface{}) bool {
		outv = reflect.Append(outv, reflect.ValueOf(x))
		return true
	})
	queryEval(es)
	return outv.Interface()
}

// queryCompile compiles q into a DAG of queryNodes.
// The output function should return false when no more outputs are desired.
func queryCompile(q *Query, output func(x interface{}) bool) *queryEvalState {
	es := &queryEvalState{
		outNode: &queryOutputNode{fn: output},
	}
	cache := make(map[*Query]queryNode)
	queryBuildDAG(cache, q, es.outNode)

	for q, n := range cache {
		if q.op == queryInput {
			es.inNodes = append(es.inNodes, n.(*queryInputNode))
		}
	}
	visited := make(map[queryNode]bool)
	for _, n := range es.inNodes {
		queryOptimizeDAG(visited, n)
	}

	queryDebugPrint(es)
	return es
}

func queryBuildDAG(cache map[*Query]queryNode, q *Query, succ queryNode) {
	node := cache[q]
	isNew := node == nil
	if isNew {
		switch q.op {
		case queryInput:
			node = &queryInputNode{
				input: q.arg,
			}
		case queryFlatten:
			// Flatten is represented as multiple incoming DAG edges.
			queryBuildDAG(cache, q.inner, succ)
			queryBuildDAG(cache, q.arg.(*Query), succ)
			return
		case queryWhere, queryMap:
			node = &queryDoNode{
				ops: []*Query{q},
			}
		case queryReduce, queryExists:
			node = &queryDoNode{
				ops:       []*Query{q},
				reduceVal: reflect.New(q.outType).Elem().Interface(),
			}
		case queryGroupBy:
			node = &queryGroupByNode{
				keyFn:           q.arg,
				keyFnTwoResults: reflect.TypeOf(q.arg).NumOut() == 2,
				outElemType:     q.outElemType,
			}
		case queryGroupByAndReduce:
			node = &queryGroupByNode{
				keyFn:           q.arg,
				keyFnTwoResults: reflect.TypeOf(q.arg).NumOut() == 2,
				reduceFn:        q.arg2,
				outElemType:     q.outElemType,
			}
		case queryReachableValues:
			node = &queryGraphReachabilityNode{}
		default:
			panic(fmt.Sprintf("unexpected Query.op=%v", q.op))
		}
		cache[q] = node
	}
	node.common().succs = append(node.common().succs, succ)
	succ.common().predsCount++
	if isNew && q.inner != nil {
		queryBuildDAG(cache, q.inner, node)
	}
}

func queryOptimizeDAG(visited map[queryNode]bool, n queryNode) {
	if visited[n] {
		return
	}
	visited[n] = true
	// Fold a sequence of queryDoNodes into a single queryDoNode, stopping when:
	//   - the last node has multiple succs, or
	//   - the last node's succ has multiple preds, or
	//   - the last node is a reduction node
	first, haveFirst := n.(*queryDoNode)
	for haveFirst && len(first.succs) == 1 && first.succs[0].common().predsCount == 1 {
		lastOp := first.ops[len(first.ops)-1].op
		if lastOp == queryReduce || lastOp == queryExists {
			break
		}
		next, ok := first.succs[0].(*queryDoNode)
		if !ok {
			break
		}
		first.ops = append(first.ops, next.ops...)
		first.succs = next.succs
		first.reduceVal = next.reduceVal
		n = first
	}
	// Optimize succs.
	for _, succ := range n.common().succs {
		queryOptimizeDAG(visited, succ)
	}
}

func queryDebugPrint(es *queryEvalState) {
	if DebugLogf == nil {
		return
	}

	logf("Built Query:")
	visited := make(map[queryNode]bool)
	var visit func(n queryNode)
	visit = func(n queryNode) {
		if visited[n] {
			return
		}
		visited[n] = true
		switch n := n.(type) {
		case *queryInputNode:
			logf("  %p input %T", n, n.input)
		case *queryDoNode:
			var ops string
			var sep string
			for _, q := range n.ops {
				ops += sep + fmt.Sprintf("%s %s", q.op, q.outType)
				sep = ", "
			}
			logf("  %p do %s", n, ops)
		case *queryGroupByNode:
			if n.reduceFn != nil {
				logf("  %p groupByAndReduce(%T, %T)", n, n.keyFn, n.reduceFn)
			} else {
				logf("  %p groupBy(%T)", n, n.keyFn)
			}
		case *queryGraphReachabilityNode:
			logf("  %p graphReachability", n)
		case *queryOutputNode:
			logf("  %p output", n)
		}
		for _, succ := range n.common().succs {
			logf("    -> %p", succ)
		}
		for _, succ := range n.common().succs {
			visit(succ)
		}
	}
	for _, n := range es.inNodes {
		visit(n)
	}
}

func queryEval(es *queryEvalState) {
	verbosef("Running Query")
	for _, n := range es.inNodes {
		n.run()
	}
}

type queryEvalState struct {
	inNodes []*queryInputNode
	outNode *queryOutputNode
}

// queryNode is a node in the query evaluation DAG.
// The types of query nodes are:
//   * queryInputNode
//   * queryDoNode (implements Where, Map, Reduce, Exists)
//   * queryGroupByNode (implements GroupBy, GroupByAndReduce)
//   * queryGraphReachabilityNode (implements ReachableValues)
//   * queryOutput (implements Run, RunAndReturn)
//
// Each queryNode receives a stream of processInput calls followed by exactly
// one processEOF call. The processInput calls will continue until either:
// (a) all predecessor nodes have depleted their output, or (b) the node decides
// to "skipInputs", which will cause future processInput calls to be dropped.
//
// Each queryNode can output a value to its successors using common().emit()
// or output EOF using common().emitEOF().
type queryNode interface {
	common() *queryNodeCommon
	processInput(x interface{})
	processEOF()
}

type queryNodeCommon struct {
	succs         []queryNode
	predsCount    uint32 // number of preds
	predsEOFCount uint32 // number of preds that have sent EOF
	skipInputs    bool   // when true, this node wants to skip the remaining inputs (but still gets EOF)
}

func (c *queryNodeCommon) emit(x interface{}) bool {
	verbosef("  %p emit(%T)", c, x)
	var succsDone int
	for _, succ := range c.succs {
		if !succ.common().skipInputs {
			succ.processInput(x)
		}
		if succ.common().skipInputs {
			succsDone++
		}
	}
	if succsDone == len(c.succs) {
		c.skipInputs = true
		return false
	}
	return true
}

func (c *queryNodeCommon) emitEOF() {
	verbosef("  %p emitEOF", c)
	for _, succ := range c.succs {
		sc := succ.common()
		sc.predsEOFCount++
		if sc.predsEOFCount == sc.predsCount {
			succ.processEOF()
		}
	}
}

func (c *queryNodeCommon) common() *queryNodeCommon {
	return c
}

type queryInputNode struct {
	queryNodeCommon
	input interface{}
}

func (*queryInputNode) processInput(_ interface{}) {} // never called
func (*queryInputNode) processEOF()                {} // never called

func (n *queryInputNode) run() {
	switch x := n.input.(type) {
	case *Value:
		n.emit(*x)
	case *Var:
		n.emit(*x)
	case *VarSet:
		for _, v := range x.list {
			if !n.emit(*v) {
				break
			}
		}
	case []interface{}:
		// Special case for a QueryGrouping.
		for _, v := range x {
			if !n.emit(v) {
				break
			}
		}
	case runtimeFinalizers:
		panic("TODO")
	case runtimeGCRoots:
		panic("TODO")
	case runtimeHeapObjects:
		panic("TODO")
	default:
		n.emit(n.input)
	}
	n.emitEOF()
}

type queryDoNode struct {
	queryNodeCommon

	// List of operations to apply in this node.
	// Can be Where, Map, Reduce, or Exists.
	// If Reduce or Exists is present, they must be last.
	ops []*Query

	// State for reductions.
	reduceVal     interface{}
	haveReduceVal bool
}

func (n *queryDoNode) processInput(x interface{}) {
	xv := reflect.ValueOf(x)

	for _, q := range n.ops {
		switch q.op {
		case queryWhere:
			if !reflect.ValueOf(q.arg).Call([]reflect.Value{xv})[0].Bool() {
				return
			}
		case queryMap:
			xv = reflect.ValueOf(q.arg).Call([]reflect.Value{xv})[0]
		case queryReduce:
			if !n.haveReduceVal {
				n.reduceVal = xv.Interface()
				n.haveReduceVal = true
			} else {
				rv := reflect.ValueOf(n.reduceVal)
				rv = reflect.ValueOf(q.arg).Call([]reflect.Value{rv, xv})[0]
				n.reduceVal = rv.Interface()
			}
			return
		case queryExists:
			if !reflect.ValueOf(q.arg).Call([]reflect.Value{xv})[0].Bool() {
				return
			}
			n.reduceVal = true
			n.haveReduceVal = true
			n.skipInputs = true // a matching elem was found, so we can skip the remaining input
			return
		default:
			panic(fmt.Sprintf("unexpected Query.op: %v", q.op))
		}
	}

	n.emit(xv.Interface())
}

func (n *queryDoNode) processEOF() {
	if last := n.ops[len(n.ops)-1].op; last == queryReduce || last == queryExists {
		n.emit(n.reduceVal)
	}
	n.emitEOF()
}

type queryGroupByNode struct {
	queryNodeCommon

	keyFn           interface{}
	keyFnTwoResults bool
	reduceFn        interface{}
	outElemType     reflect.Type

	// Output groups.
	groups map[interface{}][]interface{}
}

func (n *queryGroupByNode) processInput(x interface{}) {
	xv := reflect.ValueOf(x)
	kresults := reflect.ValueOf(n.keyFn).Call([]reflect.Value{xv})

	key := kresults[0].Interface()
	if n.keyFnTwoResults {
		xv = kresults[1]
	}

	if n.groups == nil {
		n.groups = make(map[interface{}][]interface{})
	}

	old, have := n.groups[key]
	if !have {
		n.groups[key] = []interface{}{xv.Interface()}
	} else {
		if n.reduceFn != nil {
			oldv := reflect.ValueOf(old[0])
			old[0] = reflect.ValueOf(n.reduceFn).Call([]reflect.Value{oldv, xv})[0].Interface()
		} else {
			n.groups[key] = append(old, xv.Interface())
		}
	}
}

func (n *queryGroupByNode) processEOF() {
	for key, val := range n.groups {
		n.emit(QueryGrouping{
			Key: key,
			Elems: &Query{
				op:                 queryInput,
				arg:                val,
				outType:            n.outElemType,
				inputFromReduction: n.reduceFn != nil,
			},
		})
	}
	n.emitEOF()
}

type queryGraphReachabilityNode struct {
	queryNodeCommon
	program *Program
	visited *programBitvector
}

// TODO: exit early if all of our succs start skipping input
func (n *queryGraphReachabilityNode) processInput(input interface{}) {
	v := input.(Value)

	if n.program == nil {
		n.program = v.Type.Program()
		n.visited = newProgramBitvector(n.program)
	} else if v.Type.Program() != n.program {
		panic("ReachableValues query cannot operate over values from different programs")
	}

	if !n.visited.acquireRange(v.Addr, v.Size()) {
		verbosef("  %p range already visited: 0x%x 0x%x %s", n, v.Addr, v.Size(), v.Type)
		return
	}
	n.emit(input)
	verbosef("  %p emit value 0x%x %s", n, v.Addr, v.Type)
	n.visitValue(v)
}

// TODO: decide how to handle unsafe.Pointer (UnsafePtrType) when walking the typed heap
func (n *queryGraphReachabilityNode) visitValue(v Value) {
	if !v.Type.containsPointers() {
		return
	}

	// Treat all outgoing pointers as new input.
	switch t := v.Type.(type) {
	case *ArrayType:
		for k := uint64(0); k < t.Len; k++ {
			if x, err := v.Index(k); err == nil {
				n.visitValue(x)
			}
		}

	case *StructType:
		for _, f := range t.Fields {
			if !f.Type.containsPointers() {
				continue
			}
			if x, err := v.Field(f); err == nil {
				n.visitValue(x)
			}
		}

	case *PtrType:
		if x, err := v.Deref(); err == nil {
			n.processInput(x)
		}

	case *UnsafePtrType:
		// TODO

	case *InterfaceType:
		if x, err := v.Deref(); err == nil {
			// When the boxed value is stored in the interface itself,
			// Deref returns a value that is still inside v.
			if v.ContainsAddress(x.Addr) {
				n.visitValue(x)
			} else {
				n.processInput(x)
			}
		}

	case *SliceType, *StringType, *ChanType:
		if x, err := v.DerefArray(); err == nil {
			n.processInput(x)
		}

	case *MapType:
		// TODO

	case *FuncType:
		// TODO

	case *GCObjectType:
		// TODO

	default:
		panic(fmt.Sprintf("unexpected type %s %T", t, t))
	}
}

func (n *queryGraphReachabilityNode) processEOF() {
	n.emitEOF()
}

type queryOutputNode struct {
	queryNodeCommon
	fn func(x interface{}) bool
}

func (n *queryOutputNode) processInput(x interface{}) {
	n.skipInputs = !n.fn(x)
}

func (n *queryOutputNode) processEOF() {}
