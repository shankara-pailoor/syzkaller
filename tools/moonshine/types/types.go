package types

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
)

type Type interface {
	Name() string
	String() string
}

type Binop struct {
	Operand1 Type
	Op Operation
	Operand2 Type
}

type RelationalExpression struct {
	BinOp *Binop
}

type Field struct {
	Key string
	Val Type
}

type IntType struct {
	Val int64
}

type FlagType struct {
	Val string
}

type BufferType struct {
	Val string
}

type PointerType struct {
	Address uint64
	Res Type
}

type StructType struct {
	Fields []*Field
}

type ArrayType struct {
	Elems []Type
	Len int
}

type Call struct {
	CallName string
	Args []Type
}

type Syscall struct {
	CallName string
	Args []Type
	Pid int64
	Ret int64
}

func NewSyscall(pid int64, name string, args []Type, ret int64) (sys *Syscall) {
	sys = new(Syscall)
	sys.CallName = name
	sys.Args = args
	sys.Pid = pid
	sys.Ret = ret
	return
}

func NewField(key string, val Type) (f *Field) {
	f = new(Field)
	f.Key = key
	f.Val = val
	return
}

func NewIntType(val int64) (typ *IntType) {
	typ = new(IntType)
	typ.Val = val
	return
}

func NewFlagType(val string) (typ *FlagType) {
	typ = new(FlagType)
	typ.Val = val
	return
}

func NewPointerType(addr uint64, res Type) (typ *PointerType) {
	typ = new(PointerType)
	typ.Res = res
	typ.Address = addr
	return
}

func NewStructType(fields []*Field) (typ *StructType) {
	typ = new(StructType)
	typ.Fields = fields
	return
}

func NewArrayType(elems []Type) (typ *ArrayType) {
	typ = new(ArrayType)
	typ.Elems = elems
	typ.Len = len(elems)
	return
}

func NewBufferType(val string) (typ *BufferType) {
	typ = new(BufferType)
	typ.Val = val
	return
}

func NewCallType(name string, args []Type) (typ *Call){
	typ = new(Call)
	typ.CallName = name
	typ.Args = args
	return
}

func NewBinop(operand1 Type, op Operation, operand2 Type) (b *Binop){
	b = new(Binop)
	b.Operand1 = operand1
	b.Op = op
	b.Operand2 = operand2
	return
}

func NewRelationalExpression(binop *Binop) (rel *RelationalExpression) {
	rel = new(RelationalExpression)
	if binop != nil {
		rel.BinOp = binop
	}
	return
}

func (i *IntType) Name() string {
	return fmt.Sprintln("IntType")
}

func (i *IntType) String() string {
	v := strconv.FormatInt(i.Val, 10)
	return fmt.Sprintf("%s\n", v)
}

func (f *FlagType) Name() string {
	return fmt.Sprintln("Flag Type")
}


func (f *FlagType) String() string {
	return fmt.Sprintf("%s", f.Val)
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

func (f *Field) String() string {
	var buf bytes.Buffer

	buf.WriteString(f.Key)
	buf.WriteString(f.Val.String())
	return buf.String()
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

func (b *BufferType) Name() string {
	return fmt.Sprintln("Buffer Type")
}

func (b *BufferType) String() string {
	return fmt.Sprintf("%s\n", b.Val)
}

func (r *RelationalExpression) Name() string {
	return fmt.Sprintln("Relational Expression")
}

func (r *RelationalExpression) String() string {
	if r.BinOp != nil {
		return fmt.Sprintf("Relation Expression is Binop. Op 1: %s, Operation: %v, Op 2: %s\n", r.BinOp.Operand1, r.BinOp.Op, r.BinOp.Operand2)
	}
	return ""
}