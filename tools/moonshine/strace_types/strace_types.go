package strace_types

import (
	"fmt"
	"strconv"
	"bytes"
)

type Operation int
const (
	OR = iota
	AND
	XOR
	NOT
	LSHIFT
	RSHIFT
	ONESCOMP
	TIMES
)

type TraceTree struct {
	TraceMap map[int64]*Trace
	Ptree map[int64][]int64
	RootPid int64
}

func NewTraceTree() (tree *TraceTree) {
	tree = &TraceTree {
		TraceMap: make(map[int64]*Trace),
		Ptree : make(map[int64][]int64),
		RootPid: -1,
	}
	return
}

func (tree *TraceTree) Contains(pid int64) bool {
	if _, ok := tree.TraceMap[pid]; ok {
		return true
	}
	return false
}


func (tree *TraceTree) Add(call *Syscall) (*Syscall){
	if tree.RootPid < 0 {
		tree.RootPid = call.Pid
	}
	if !call.Resumed {
		if !tree.Contains(call.Pid) {
			tree.TraceMap[call.Pid] = NewTrace()
			tree.Ptree[call.Pid] = make([]int64, 0)
		}
	}
	c := tree.TraceMap[call.Pid].Add(call)
	if c.CallName == "clone" && !c.Paused {
		tree.Ptree[c.Pid] = append(tree.Ptree[c.Pid], c.Ret)
	}
	if !c.Paused {
		fmt.Printf(c.String())
	}
	return c
}

func (tree *TraceTree) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Root: %d\n", tree.RootPid))
	buf.WriteString(fmt.Sprintf("Pids: %d\n", len(tree.TraceMap)))
	for pid, arr := range tree.Ptree {
		trace := tree.TraceMap[pid]
		for _, call := range trace.Calls {
			fmt.Printf("Call: %s, Cover: %d\n", call.CallName, len(call.Cover))
		}
		fmt.Printf("Pid: %d\n", pid)
		fmt.Printf("Children: %v\n", arr)
	}
	return buf.String()
}


type Trace struct {
	Calls []*Syscall
}

func NewTrace() (trace *Trace) {
	trace = &Trace{Calls: make([]*Syscall, 0)}
	return
}

func (trace *Trace) Add(call *Syscall) (ret *Syscall){
	if call.Resumed {
		lastCall := trace.Calls[len(trace.Calls)-1]
		lastCall.Args = append(lastCall.Args, call.Args...)
		lastCall.Paused = false
		lastCall.Ret = call.Ret
		ret = lastCall
	} else {
		trace.Calls = append(trace.Calls, call)
		ret = call
	}
	return
}



type Syscall struct {
	CallName string
	Args []Type
	Pid int64
	Ret int64
	Cover []uint64
	Paused bool
	Resumed bool
}

func NewSyscall(pid int64, name string,
			args []Type,
			ret int64,
			paused bool,
			resumed bool) (sys *Syscall) {
	sys = new(Syscall)
	sys.CallName = name
	sys.Args = args
	sys.Pid = pid
	sys.Ret = ret
	sys.Paused = paused
	sys.Resumed = resumed
	return
}

func (s *Syscall) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Pid: %d-", s.Pid))
	buf.WriteString(fmt.Sprintf("Name: %s-", s.CallName))
	for _, typ := range s.Args {
		buf.WriteString("-")
		buf.WriteString(typ.String())
		buf.WriteString("-")
	}
	buf.WriteString(fmt.Sprintf("-Ret: %d\n", s.Ret))
	return buf.String()
}

type Type interface {
	Name() string
	String() string
}

type Expression struct {
	BinOp *Binop
	Unop *Unop
	FlagType *FlagType
	IntType *IntType
}

func NewExpression(typ Type) (exp *Expression) {
	exp = new(Expression)
	switch a := typ.(type) {
	case *Binop:
		exp.BinOp = a
	case *Unop:
		exp.Unop = a
	case *IntType:
		exp.IntType = a
	case *FlagType:
		exp.FlagType = a
	default:
		panic(fmt.Sprintf("Expression received wrong type: %s", typ.Name()))
	}
	return
}

func (r *Expression) Name() string {
	return fmt.Sprintln("Expression Type")
}

func (r *Expression) String() string {
	if r.BinOp != nil {
		return fmt.Sprintf("Relation Expression is Binop. Op 1: %s, Operation: %v, Op 2: %s\n", r.BinOp.Operand1, r.BinOp.Op, r.BinOp.Operand2)
	} else if r.Unop != nil {
		return fmt.Sprintf("Relation Expression is Unop. Operand is: %v, op: %v\n", r.Unop.Operand, r.Unop.Op)

	} else if r.FlagType != nil {
		return fmt.Sprintf("Flag Type: %s\n", r.FlagType.Val)
	} else if r.IntType != nil {
		return fmt.Sprintf("Int Type: %d\n", r.IntType.Val)
	}
	return ""
}

type Call struct {
	CallName string
	Args []Type
}

func NewCallType(name string, args []Type) (typ *Call){
	typ = new(Call)
	typ.CallName = name
	typ.Args = args
	return
}

func (c *Call) Name() string {
	return fmt.Sprintln("Call Type")
}

func (c *Call) String() string {
	var buf bytes.Buffer

	buf.WriteString("Name: " + c.CallName + "\n")
	for _, arg := range c.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

type Binop struct {
	Operand1 Type
	Op Operation
	Operand2 Type
}

func NewBinop(operand1 Type, op Operation, operand2 Type) (b *Binop){
	b = new(Binop)
	b.Operand1 = operand1
	b.Op = op
	b.Operand2 = operand2
	return
}

func (b *Binop) String() string{
	return fmt.Sprintf("op1: %v op2: %v, operand: %v\n", b.Operand1, b.Operand2, b.Op)
}

func (b *Binop) Name() string{
	return "Binop"
}

type Unop struct {
	Operand Type
	Op Operation
}

func NewUnop(operand Type, op Operation) (u *Unop) {
	u = new(Unop)
	u.Operand = operand
	u.Op = op
	return
}

func (u *Unop) String() string{
	return fmt.Sprintf("op1: %v operand: %v\n", u.Operand, u.Op)
}

func (u *Unop) Name() string{
	return "Unop"
}

type Field struct {
	Key string
	Val Type
}

func NewField(key string, val Type) (f *Field) {
	f = new(Field)
	f.Key = key
	f.Val = val
	return
}

func (f *Field) Name() string {
	return "Field Type"
}

func (f *Field) String() string {
	var buf bytes.Buffer

	buf.WriteString(f.Key)
	buf.WriteString(f.Val.String())
	return buf.String()
}

type IntType struct {
	Val int64
}

func NewIntType(val int64) (typ *IntType) {
	typ = new(IntType)
	typ.Val = val
	return
}

func (i *IntType) Name() string {
	return fmt.Sprintln("IntType")
}

func (i *IntType) String() string {
	v := strconv.FormatInt(i.Val, 10)
	return fmt.Sprintf("%s\n", v)
}

type FlagType struct {
	Val string
}

func NewFlagType(val string) (typ *FlagType) {
	typ = new(FlagType)
	typ.Val = val
	return
}

func (f *FlagType) Name() string {
	return fmt.Sprintln("Flag Type")
}

func (f *FlagType) String() string {
	return fmt.Sprintf("%s", f.Val)
}

type BufferType struct {
	Val string
}

func NewBufferType(val string) (typ *BufferType) {
	typ = new(BufferType)
	typ.Val = val
	return
}

func (b *BufferType) Name() string {
	return fmt.Sprintln("Buffer Type")
}

func (b *BufferType) String() string {
	return fmt.Sprintf("String Type: %d\n", len(b.Val))
}

type PointerType struct {
	Address uint64
	Res Type
}

func NewPointerType(addr uint64, res Type) (typ *PointerType) {
	typ = new(PointerType)
	typ.Res = res
	typ.Address = addr
	return
}

func NullPointer() (typ *PointerType) {
	typ = new(PointerType)
	typ.Address = 0
	return
}

func (typ *PointerType) IsNull() bool {
	if typ.Address == 0 {
		return true
	}
	return false
}

func (p *PointerType) Name() string {
	return fmt.Sprintln("Pointer Type")
}

func (p *PointerType) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Address: %d\n", p.Address))
	buf.WriteString(fmt.Sprintf("Res: %s\n", p.Res.String()))
	return buf.String()
}


type StructType struct {
	Fields []Type
}

func NewStructType(types []Type) (typ *StructType) {
	typ = new(StructType)
	typ.Fields = types
	return
}

func (s *StructType) Name() string {
	return fmt.Sprintln("Struct Type")
}

func (s *StructType) String() string {
	var buf bytes.Buffer

	buf.WriteString("{")
	for _, field := range s.Fields {
		buf.WriteString(field.String())
		buf.WriteString(",")
	}
	buf.WriteString("}")
	return buf.String()
}

type ArrayType struct {
	Elems []Type
	Len int
}

func NewArrayType(elems []Type) (typ *ArrayType) {
	typ = new(ArrayType)
	typ.Elems = elems
	typ.Len = len(elems)
	return
}

func (a *ArrayType) Name() string {
	return fmt.Sprintln("Array Type")
}

func (a *ArrayType) String() string {
	var buf bytes.Buffer

	buf.WriteString("[")
	for _, elem := range a.Elems {
		buf.WriteString(elem.String())
		buf.WriteString(",")
	}
	buf.WriteString("]")
	return buf.String()
}


type Ipv4Type struct {
	Str string
}

func NewIpv4Type(val string) (typ *Ipv4Type) {
	typ = new(Ipv4Type)
	typ.Str = val
	return
}

func (i *Ipv4Type) Name() string {
	return fmt.Sprintln("Ipv4 type")
}

func (i *Ipv4Type) String() string {
	return fmt.Sprintf("Ipv4 type :%s", i.Str)
}