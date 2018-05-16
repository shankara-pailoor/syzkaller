//line scanner/strace.y:2
package scanner

import __yyfmt__ "fmt"

//line scanner/strace.y:2
import (
	//"fmt"
	types "github.com/google/syzkaller/tools/moonshine/strace_types"
)

//line scanner/strace.y:12
type StraceSymType struct {
	yys              int
	data             string
	val_int          int64
	val_double       float64
	val_uint         uint64
	val_field        *types.Field
	val_call         *types.Call
	val_int_type     *types.IntType
	val_identifiers  []*types.BufferType
	val_buf_type     *types.BufferType
	val_struct_type  *types.StructType
	val_array_type   *types.ArrayType
	val_pointer_type *types.PointerType
	val_flag_type    *types.FlagType
	val_expr_type    *types.Expression
	val_type         types.Type
	val_ipv4_type    *types.Ipv4Type
	val_types        []types.Type
	val_syscall      *types.Syscall
}

const STRING_LITERAL = 57346
const IPV4 = 57347
const IDENTIFIER = 57348
const FLAG = 57349
const DATETIME = 57350
const SIGNAL_PLUS = 57351
const SIGNAL_MINUS = 57352
const INT = 57353
const UINT = 57354
const DOUBLE = 57355
const QUESTION = 57356
const OR = 57357
const AND = 57358
const LOR = 57359
const TIMES = 57360
const LAND = 57361
const NOT = 57362
const ONESCOMP = 57363
const LSHIFT = 57364
const RSHIFT = 57365
const COMMA = 57366
const LBRACKET = 57367
const RBRACKET = 57368
const LBRACKET_SQUARE = 57369
const RBRACKET_SQUARE = 57370
const LPAREN = 57371
const RPAREN = 57372
const EQUALS = 57373
const UNFINISHED = 57374
const UNFINISHED_W_COMMA = 57375
const RESUMED = 57376
const NULL = 57377
const NOFLAG = 57378

var StraceToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"STRING_LITERAL",
	"IPV4",
	"IDENTIFIER",
	"FLAG",
	"DATETIME",
	"SIGNAL_PLUS",
	"SIGNAL_MINUS",
	"INT",
	"UINT",
	"DOUBLE",
	"QUESTION",
	"OR",
	"AND",
	"LOR",
	"TIMES",
	"LAND",
	"NOT",
	"ONESCOMP",
	"LSHIFT",
	"RSHIFT",
	"COMMA",
	"LBRACKET",
	"RBRACKET",
	"LBRACKET_SQUARE",
	"RBRACKET_SQUARE",
	"LPAREN",
	"RPAREN",
	"EQUALS",
	"UNFINISHED",
	"UNFINISHED_W_COMMA",
	"RESUMED",
	"NULL",
	"NOFLAG",
}
var StraceStatenames = [...]string{}

const StraceEofCode = 1
const StraceErrCode = 2
const StraceInitialStackSize = 16

//line yacctab:1
var StraceExca = [...]int{
	-1, 1,
	1, -1,
	-2, 0,
}

const StracePrivate = 57344

const StraceLast = 159

var StraceAct = [...]int{

	107, 20, 8, 11, 78, 75, 3, 17, 28, 19,
	29, 18, 61, 58, 30, 31, 35, 114, 57, 24,
	55, 56, 112, 38, 23, 39, 49, 50, 27, 111,
	26, 109, 22, 34, 4, 32, 106, 105, 25, 98,
	97, 84, 64, 95, 65, 66, 67, 68, 69, 70,
	71, 72, 73, 93, 74, 36, 17, 28, 19, 29,
	18, 103, 101, 30, 31, 96, 92, 91, 24, 81,
	80, 5, 76, 23, 77, 94, 51, 27, 85, 26,
	53, 22, 17, 28, 19, 29, 18, 25, 29, 30,
	31, 37, 30, 31, 24, 79, 102, 2, 104, 23,
	82, 83, 23, 27, 110, 26, 29, 22, 6, 113,
	22, 59, 60, 25, 17, 28, 19, 29, 18, 7,
	100, 30, 31, 16, 99, 33, 24, 86, 87, 90,
	88, 23, 89, 44, 45, 27, 48, 26, 108, 22,
	46, 47, 40, 41, 12, 25, 52, 54, 15, 42,
	43, 13, 14, 9, 21, 10, 1, 62, 63,
}
var StracePact = [...]int{

	86, -1000, 0, 42, 78, 3, -15, 25, 67, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -6,
	127, 118, 81, 81, 64, -1000, 52, 110, -1000, -1000,
	-1000, -1000, -1000, -12, -18, 100, -19, 110, 110, 110,
	81, 81, 81, 81, 81, 81, 81, 81, 81, 24,
	-1000, -26, 44, -1000, 48, -1000, -1000, -27, 84, 41,
	40, 89, -1000, 11, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, 110, -1000, -1000, 116, -1000,
	125, 122, 38, 37, -1000, -1000, 46, 36, -1000, 10,
	9, 117, 113, 33, 99, 32, 99, -1000, -1000, 7,
	6, 132, 1, 132, -1, -1000, -1000, -8, 132, -1000,
	-13, -1000, -1000, -1000, -1000,
}
var StracePgo = [...]int{

	0, 156, 155, 0, 154, 153, 152, 151, 1, 3,
	148, 2, 144, 123, 119,
}
var StraceR1 = [...]int{

	0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	14, 14, 11, 11, 11, 11, 11, 11, 11, 11,
	10, 12, 12, 7, 7, 6, 2, 5, 5, 9,
	9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
	9, 9, 4, 4, 8, 13, 3, 3,
}
var StraceR2 = [...]int{

	0, 4, 5, 5, 5, 5, 8, 8, 6, 6,
	9, 9, 6, 7, 7, 7, 11, 11, 10, 10,
	1, 3, 1, 1, 1, 1, 1, 1, 1, 1,
	4, 4, 1, 3, 2, 3, 3, 1, 1, 1,
	1, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 2, 1, 1, 1, 1, 1, 2,
}
var StraceChk = [...]int{

	-1000, -1, 11, 6, 34, 29, 30, -14, -11, -5,
	-2, -9, -12, -7, -6, -10, -13, 4, 8, 6,
	-8, -4, 29, 21, 16, 35, 27, 25, 5, 7,
	11, 12, 32, -14, 30, 31, 30, 24, 29, 31,
	15, 16, 22, 23, 15, 16, 22, 23, 18, -9,
	-9, 12, -14, 28, -14, 32, 33, 30, 31, 11,
	12, 31, -14, -14, -11, -9, -9, -9, -9, -9,
	-9, -9, -9, -9, 30, 31, 28, 26, 31, 11,
	29, 29, 11, 12, 30, -11, 11, 12, 14, 7,
	7, 29, 29, 7, 29, 7, 29, 30, 30, 7,
	7, 29, -8, 29, -8, 30, 30, -3, 6, 30,
	-3, 30, 30, -3, 30,
}
var StraceDef = [...]int{

	0, -2, 0, 0, 0, 0, 0, 0, 20, 22,
	23, 24, 25, 26, 27, 28, 29, 37, 38, 0,
	39, 40, 0, 0, 0, 32, 0, 0, 55, 54,
	52, 53, 1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	51, 0, 0, 34, 0, 2, 3, 0, 0, 4,
	5, 0, 21, 0, 36, 42, 44, 46, 48, 43,
	45, 47, 49, 50, 41, 0, 33, 35, 0, 12,
	0, 0, 8, 9, 30, 31, 13, 14, 15, 0,
	0, 0, 0, 0, 0, 0, 0, 6, 7, 0,
	0, 0, 0, 0, 0, 10, 11, 0, 56, 18,
	0, 19, 16, 57, 17,
}
var StraceTok1 = [...]int{

	1,
}
var StraceTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36,
}
var StraceTok3 = [...]int{
	0,
}

var StraceErrorMessages = [...]struct {
	state int
	token int
	msg   string
}{}

//line yaccpar:1

/*	parser for yacc output	*/

var (
	StraceDebug        = 0
	StraceErrorVerbose = false
)

type StraceLexer interface {
	Lex(lval *StraceSymType) int
	Error(s string)
}

type StraceParser interface {
	Parse(StraceLexer) int
	Lookahead() int
}

type StraceParserImpl struct {
	lval  StraceSymType
	stack [StraceInitialStackSize]StraceSymType
	char  int
}

func (p *StraceParserImpl) Lookahead() int {
	return p.char
}

func StraceNewParser() StraceParser {
	return &StraceParserImpl{}
}

const StraceFlag = -1000

func StraceTokname(c int) string {
	if c >= 1 && c-1 < len(StraceToknames) {
		if StraceToknames[c-1] != "" {
			return StraceToknames[c-1]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func StraceStatname(s int) string {
	if s >= 0 && s < len(StraceStatenames) {
		if StraceStatenames[s] != "" {
			return StraceStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func StraceErrorMessage(state, lookAhead int) string {
	const TOKSTART = 4

	if !StraceErrorVerbose {
		return "syntax error"
	}

	for _, e := range StraceErrorMessages {
		if e.state == state && e.token == lookAhead {
			return "syntax error: " + e.msg
		}
	}

	res := "syntax error: unexpected " + StraceTokname(lookAhead)

	// To match Bison, suggest at most four expected tokens.
	expected := make([]int, 0, 4)

	// Look for shiftable tokens.
	base := StracePact[state]
	for tok := TOKSTART; tok-1 < len(StraceToknames); tok++ {
		if n := base + tok; n >= 0 && n < StraceLast && StraceChk[StraceAct[n]] == tok {
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}
	}

	if StraceDef[state] == -2 {
		i := 0
		for StraceExca[i] != -1 || StraceExca[i+1] != state {
			i += 2
		}

		// Look for tokens that we accept or reduce.
		for i += 2; StraceExca[i] >= 0; i += 2 {
			tok := StraceExca[i]
			if tok < TOKSTART || StraceExca[i+1] == 0 {
				continue
			}
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}

		// If the default action is to accept or reduce, give up.
		if StraceExca[i+1] != 0 {
			return res
		}
	}

	for i, tok := range expected {
		if i == 0 {
			res += ", expecting "
		} else {
			res += " or "
		}
		res += StraceTokname(tok)
	}
	return res
}

func Stracelex1(lex StraceLexer, lval *StraceSymType) (char, token int) {
	token = 0
	char = lex.Lex(lval)
	if char <= 0 {
		token = StraceTok1[0]
		goto out
	}
	if char < len(StraceTok1) {
		token = StraceTok1[char]
		goto out
	}
	if char >= StracePrivate {
		if char < StracePrivate+len(StraceTok2) {
			token = StraceTok2[char-StracePrivate]
			goto out
		}
	}
	for i := 0; i < len(StraceTok3); i += 2 {
		token = StraceTok3[i+0]
		if token == char {
			token = StraceTok3[i+1]
			goto out
		}
	}

out:
	if token == 0 {
		token = StraceTok2[1] /* unknown char */
	}
	if StraceDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", StraceTokname(token), uint(char))
	}
	return char, token
}

func StraceParse(Stracelex StraceLexer) int {
	return StraceNewParser().Parse(Stracelex)
}

func (Stracercvr *StraceParserImpl) Parse(Stracelex StraceLexer) int {
	var Stracen int
	var StraceVAL StraceSymType
	var StraceDollar []StraceSymType
	_ = StraceDollar // silence set and not used
	StraceS := Stracercvr.stack[:]

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	Stracestate := 0
	Stracercvr.char = -1
	Stracetoken := -1 // Stracercvr.char translated into internal numbering
	defer func() {
		// Make sure we report no lookahead when not parsing.
		Stracestate = -1
		Stracercvr.char = -1
		Stracetoken = -1
	}()
	Stracep := -1
	goto Stracestack

ret0:
	return 0

ret1:
	return 1

Stracestack:
	/* put a state and value onto the stack */
	if StraceDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", StraceTokname(Stracetoken), StraceStatname(Stracestate))
	}

	Stracep++
	if Stracep >= len(StraceS) {
		nyys := make([]StraceSymType, len(StraceS)*2)
		copy(nyys, StraceS)
		StraceS = nyys
	}
	StraceS[Stracep] = StraceVAL
	StraceS[Stracep].yys = Stracestate

Stracenewstate:
	Stracen = StracePact[Stracestate]
	if Stracen <= StraceFlag {
		goto Stracedefault /* simple state */
	}
	if Stracercvr.char < 0 {
		Stracercvr.char, Stracetoken = Stracelex1(Stracelex, &Stracercvr.lval)
	}
	Stracen += Stracetoken
	if Stracen < 0 || Stracen >= StraceLast {
		goto Stracedefault
	}
	Stracen = StraceAct[Stracen]
	if StraceChk[Stracen] == Stracetoken { /* valid shift */
		Stracercvr.char = -1
		Stracetoken = -1
		StraceVAL = Stracercvr.lval
		Stracestate = Stracen
		if Errflag > 0 {
			Errflag--
		}
		goto Stracestack
	}

Stracedefault:
	/* default state action */
	Stracen = StraceDef[Stracestate]
	if Stracen == -2 {
		if Stracercvr.char < 0 {
			Stracercvr.char, Stracetoken = Stracelex1(Stracelex, &Stracercvr.lval)
		}

		/* look through exception table */
		xi := 0
		for {
			if StraceExca[xi+0] == -1 && StraceExca[xi+1] == Stracestate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			Stracen = StraceExca[xi+0]
			if Stracen < 0 || Stracen == Stracetoken {
				break
			}
		}
		Stracen = StraceExca[xi+1]
		if Stracen < 0 {
			goto ret0
		}
	}
	if Stracen == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			Stracelex.Error(StraceErrorMessage(Stracestate, Stracetoken))
			Nerrs++
			if StraceDebug >= 1 {
				__yyfmt__.Printf("%s", StraceStatname(Stracestate))
				__yyfmt__.Printf(" saw %s\n", StraceTokname(Stracetoken))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for Stracep >= 0 {
				Stracen = StracePact[StraceS[Stracep].yys] + StraceErrCode
				if Stracen >= 0 && Stracen < StraceLast {
					Stracestate = StraceAct[Stracen] /* simulate a shift of "error" */
					if StraceChk[Stracestate] == StraceErrCode {
						goto Stracestack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if StraceDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", StraceS[Stracep].yys)
				}
				Stracep--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if StraceDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", StraceTokname(Stracetoken))
			}
			if Stracetoken == StraceEofCode {
				goto ret1
			}
			Stracercvr.char = -1
			Stracetoken = -1
			goto Stracenewstate /* try again in the same state */
		}
	}

	/* reduction by production Stracen */
	if StraceDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", Stracen, StraceStatname(Stracestate))
	}

	Stracent := Stracen
	Stracept := Stracep
	_ = Stracept // guard against "declared and not used"

	Stracep -= StraceR2[Stracen]
	// Stracep is now the index of $0. Perform the default action. Iff the
	// reduced production is ε, $1 is possibly out of range.
	if Stracep+1 >= len(StraceS) {
		nyys := make([]StraceSymType, len(StraceS)*2)
		copy(nyys, StraceS)
		StraceS = nyys
	}
	StraceVAL = StraceS[Stracep+1]

	/* consult goto table to find next state */
	Stracen = StraceR1[Stracen]
	Straceg := StracePgo[Stracen]
	Stracej := Straceg + StraceS[Stracep].yys + 1

	if Stracej >= StraceLast {
		Stracestate = StraceAct[Straceg]
	} else {
		Stracestate = StraceAct[Stracej]
		if StraceChk[Stracestate] != -Stracen {
			Stracestate = StraceAct[Straceg]
		}
	}
	// dummy call; replaced with literal code
	switch Stracent {

	case 1:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line scanner/strace.y:62
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, nil, int64(-1), true, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 2:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line scanner/strace.y:64
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, int64(-1), true, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 3:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line scanner/strace.y:66
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, int64(-1), true, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 4:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line scanner/strace.y:68
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, "tmp", nil, int64(StraceDollar[5].val_int), false, true)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 5:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line scanner/strace.y:70
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, "tmp", nil, int64(StraceDollar[5].val_uint), false, true)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 6:
		StraceDollar = StraceS[Stracept-8 : Stracept+1]
		//line scanner/strace.y:72
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, "tmp", nil, int64(StraceDollar[5].val_int), false, true)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 7:
		StraceDollar = StraceS[Stracept-8 : Stracept+1]
		//line scanner/strace.y:74
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, "tmp", nil, int64(StraceDollar[5].val_uint), false, true)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 8:
		StraceDollar = StraceS[Stracept-6 : Stracept+1]
		//line scanner/strace.y:76
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, "tmp", StraceDollar[3].val_types, int64(StraceDollar[6].val_int), false, true)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 9:
		StraceDollar = StraceS[Stracept-6 : Stracept+1]
		//line scanner/strace.y:78
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, "tmp", StraceDollar[3].val_types, int64(StraceDollar[6].val_uint), false, true)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 10:
		StraceDollar = StraceS[Stracept-9 : Stracept+1]
		//line scanner/strace.y:80
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, "tmp", StraceDollar[3].val_types, int64(StraceDollar[6].val_int), false, true)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 11:
		StraceDollar = StraceS[Stracept-9 : Stracept+1]
		//line scanner/strace.y:82
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, "tmp", StraceDollar[3].val_types, int64(StraceDollar[6].val_uint), false, true)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 12:
		StraceDollar = StraceS[Stracept-6 : Stracept+1]
		//line scanner/strace.y:84
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, nil, StraceDollar[6].val_int, false, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 13:
		StraceDollar = StraceS[Stracept-7 : Stracept+1]
		//line scanner/strace.y:86
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, StraceDollar[7].val_int, false, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 14:
		StraceDollar = StraceS[Stracept-7 : Stracept+1]
		//line scanner/strace.y:89
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, int64(StraceDollar[7].val_uint), false, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 15:
		StraceDollar = StraceS[Stracept-7 : Stracept+1]
		//line scanner/strace.y:92
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, -1, false, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 16:
		StraceDollar = StraceS[Stracept-11 : Stracept+1]
		//line scanner/strace.y:95
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, StraceDollar[7].val_int, false, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 17:
		StraceDollar = StraceS[Stracept-11 : Stracept+1]
		//line scanner/strace.y:98
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, int64(StraceDollar[7].val_uint), false, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 18:
		StraceDollar = StraceS[Stracept-10 : Stracept+1]
		//line scanner/strace.y:101
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, StraceDollar[7].val_int, false, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 19:
		StraceDollar = StraceS[Stracept-10 : Stracept+1]
		//line scanner/strace.y:104
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, int64(StraceDollar[7].val_uint), false, false)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 20:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:111
		{
			types := make([]types.Type, 0)
			types = append(types, StraceDollar[1].val_type)
			StraceVAL.val_types = types
		}
	case 21:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:112
		{
			StraceDollar[3].val_types = append([]types.Type{StraceDollar[1].val_type}, StraceDollar[3].val_types...)
			StraceVAL.val_types = StraceDollar[3].val_types
		}
	case 22:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:115
		{
			StraceVAL.val_type = StraceDollar[1].val_buf_type
		}
	case 23:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:116
		{
			StraceVAL.val_type = StraceDollar[1].val_field
		}
	case 24:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:117
		{
			StraceVAL.val_type = StraceDollar[1].val_expr_type
		}
	case 25:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:118
		{
			StraceVAL.val_type = StraceDollar[1].val_pointer_type
		}
	case 26:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:119
		{
			StraceVAL.val_type = StraceDollar[1].val_array_type
		}
	case 27:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:120
		{
			StraceVAL.val_type = StraceDollar[1].val_struct_type
		}
	case 28:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:121
		{
			StraceVAL.val_type = StraceDollar[1].val_call
		}
	case 29:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:122
		{
			StraceVAL.val_type = StraceDollar[1].val_ipv4_type
		}
	case 30:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line scanner/strace.y:125
		{
			StraceVAL.val_call = types.NewCallType(StraceDollar[1].data, StraceDollar[3].val_types)
		}
	case 31:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line scanner/strace.y:128
		{
			StraceVAL.val_pointer_type = types.NewPointerType(StraceDollar[2].val_uint, StraceDollar[4].val_type)
		}
	case 32:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:129
		{
			StraceVAL.val_pointer_type = types.NullPointer()
		}
	case 33:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:132
		{
			arr := types.NewArrayType(StraceDollar[2].val_types)
			StraceVAL.val_array_type = arr
		}
	case 34:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line scanner/strace.y:133
		{
			arr := types.NewArrayType(nil)
			StraceVAL.val_array_type = arr
		}
	case 35:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:136
		{
			StraceVAL.val_struct_type = types.NewStructType(StraceDollar[2].val_types)
		}
	case 36:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:139
		{
			StraceVAL.val_field = types.NewField(StraceDollar[1].data, StraceDollar[3].val_type)
		}
	case 37:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:142
		{
			StraceVAL.val_buf_type = types.NewBufferType(StraceDollar[1].data)
		}
	case 38:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:143
		{
			StraceVAL.val_buf_type = types.NewBufferType(StraceDollar[1].data)
		}
	case 39:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:146
		{
			StraceVAL.val_expr_type = types.NewExpression(StraceDollar[1].val_flag_type)
		}
	case 40:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:147
		{
			StraceVAL.val_expr_type = types.NewExpression(StraceDollar[1].val_int_type)
		}
	case 41:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:148
		{
			StraceVAL.val_expr_type = types.NewExpression(StraceDollar[2].val_expr_type)
		}
	case 42:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:149
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewBinop(types.NewExpression(StraceDollar[1].val_flag_type), types.OR, StraceDollar[3].val_expr_type))
		}
	case 43:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:150
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewBinop(types.NewExpression(StraceDollar[1].val_int_type), types.OR, StraceDollar[3].val_expr_type))
		}
	case 44:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:151
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewBinop(types.NewExpression(StraceDollar[1].val_flag_type), types.AND, StraceDollar[3].val_expr_type))
		}
	case 45:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:152
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewBinop(types.NewExpression(StraceDollar[1].val_int_type), types.AND, StraceDollar[3].val_expr_type))
		}
	case 46:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:153
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewBinop(types.NewExpression(StraceDollar[1].val_flag_type), types.LSHIFT, StraceDollar[3].val_expr_type))
		}
	case 47:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:154
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewBinop(types.NewExpression(StraceDollar[1].val_int_type), types.LSHIFT, StraceDollar[3].val_expr_type))
		}
	case 48:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:155
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewBinop(types.NewExpression(StraceDollar[1].val_flag_type), types.RSHIFT, StraceDollar[3].val_expr_type))
		}
	case 49:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:156
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewBinop(types.NewExpression(StraceDollar[1].val_int_type), types.RSHIFT, StraceDollar[3].val_expr_type))
		}
	case 50:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line scanner/strace.y:157
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewBinop(types.NewExpression(StraceDollar[1].val_int_type), types.TIMES, StraceDollar[3].val_expr_type))
		}
	case 51:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line scanner/strace.y:158
		{
			StraceVAL.val_expr_type = types.NewExpression(types.NewUnop(types.NewExpression(StraceDollar[2].val_expr_type), types.ONESCOMP))
		}
	case 52:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:161
		{
			StraceVAL.val_int_type = types.NewIntType(StraceDollar[1].val_int)
		}
	case 53:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:162
		{
			StraceVAL.val_int_type = types.NewIntType(int64(StraceDollar[1].val_uint))
		}
	case 54:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:165
		{
			StraceVAL.val_flag_type = types.NewFlagType(StraceDollar[1].data)
		}
	case 55:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:168
		{
			StraceVAL.val_ipv4_type = types.NewIpv4Type(StraceDollar[1].data)
		}
	case 56:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line scanner/strace.y:171
		{
			ids := make([]*types.BufferType, 0)
			ids = append(ids, types.NewBufferType(StraceDollar[1].data))
			StraceVAL.val_identifiers = ids
		}
	case 57:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line scanner/strace.y:172
		{
			StraceDollar[2].val_identifiers = append(StraceDollar[2].val_identifiers, types.NewBufferType(StraceDollar[1].data))
			StraceVAL.val_identifiers = StraceDollar[2].val_identifiers
		}
	}
	goto Stracestack /* stack new state and value */
}
