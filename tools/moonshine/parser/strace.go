//line parser/strace.y:2
package parser

import __yyfmt__ "fmt"

//line parser/strace.y:2
import (
	//"fmt"
	"github.com/google/syzkaller/tools/moonshine/types"
)

//line parser/strace.y:12
type StraceSymType struct {
	yys               int
	data              string
	val_int           int64
	val_double        float64
	val_uint          uint64
	val_field         *types.Field
	val_fields        []*types.Field
	val_call          *types.Call
	val_int_type      *types.IntType
	val_identifiers   []*types.BufferType
	val_buf_type      *types.BufferType
	val_struct_type   *types.StructType
	val_array_type    *types.ArrayType
	val_pointer_type  *types.PointerType
	val_flag_type     *types.FlagType
	val_binop         *types.Binop
	val_rel_expr_type *types.RelationalExpression
	val_type          types.Type
	val_ipv4_type     *types.Ipv4Type
	val_types         []types.Type
	val_syscall       *types.Syscall
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
const LAND = 57360
const NOT = 57361
const LSHIFT = 57362
const RSHIFT = 57363
const COMMA = 57364
const LBRACKET = 57365
const RBRACKET = 57366
const LBRACKET_SQUARE = 57367
const RBRACKET_SQUARE = 57368
const LPAREN = 57369
const RPAREN = 57370
const EQUALS = 57371
const NOFLAG = 57372

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
	"LAND",
	"NOT",
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

const StraceLast = 91

var StraceAct = [...]int{

	70, 14, 8, 10, 36, 51, 7, 18, 28, 26,
	25, 19, 47, 41, 20, 21, 77, 75, 74, 22,
	72, 64, 61, 62, 29, 68, 24, 66, 23, 35,
	34, 39, 6, 44, 45, 43, 46, 42, 48, 49,
	50, 65, 53, 63, 54, 30, 52, 40, 55, 56,
	58, 57, 33, 32, 60, 59, 18, 28, 26, 25,
	19, 31, 2, 20, 21, 67, 25, 69, 22, 73,
	20, 21, 76, 25, 71, 24, 3, 23, 38, 4,
	5, 17, 11, 15, 16, 27, 12, 13, 9, 37,
	1,
}
var StracePact = [...]int{

	51, -1000, 70, 5, -1000, -1000, 52, -4, 23, -1000,
	46, -1000, -1000, -1000, 38, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, 40, 3, 72, -1000, 4, 32, -1000, -16,
	52, 59, 59, -17, 12, -1000, 15, 18, -24, 52,
	59, 37, -1000, -1000, -1000, -1000, -1000, 52, -1000, -1000,
	72, 52, -6, -1000, -1000, 16, 14, -1000, -1000, -1000,
	-1000, -1000, 0, 66, -2, 66, 68, -8, 68, -10,
	-11, 68, -1000, -12, -1000, -1000, -1000, -1000,
}
var StracePgo = [...]int{

	0, 90, 89, 0, 4, 3, 88, 87, 86, 1,
	85, 84, 83, 2, 82, 81, 6,
}
var StraceR1 = [...]int{

	0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	16, 16, 13, 13, 13, 13, 13, 13, 13, 13,
	13, 12, 14, 8, 8, 7, 4, 4, 2, 6,
	6, 11, 10, 10, 10, 10, 10, 10, 5, 5,
	9, 15, 3, 3,
}
var StraceR2 = [...]int{

	0, 7, 7, 7, 11, 11, 10, 10, 2, 2,
	1, 3, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 4, 4, 3, 2, 3, 1, 3, 3, 1,
	1, 1, 3, 3, 3, 3, 3, 3, 1, 1,
	1, 1, 1, 2,
}
var StraceChk = [...]int{

	-1000, -1, 11, 6, 9, 10, 27, -16, -13, -6,
	-5, -14, -8, -7, -9, -12, -11, -15, 4, 8,
	11, 12, 16, 25, 23, 7, 6, -10, 5, 28,
	22, 15, 15, 12, -16, 26, -4, -2, 6, 27,
	15, 29, -16, -5, -9, -9, -5, 29, 26, 24,
	22, 29, -16, -9, -5, 11, 12, 14, -13, -4,
	-13, 28, 7, 27, 7, 27, 27, -9, 27, -9,
	-3, 6, 28, -3, 28, 28, -3, 28,
}
var StraceDef = [...]int{

	0, -2, 0, 0, 8, 9, 0, 0, 10, 12,
	13, 14, 15, 16, 17, 18, 19, 20, 29, 30,
	38, 39, 0, 0, 0, 40, 0, 31, 41, 0,
	0, 0, 0, 0, 0, 24, 0, 26, 0, 0,
	0, 0, 11, 34, 37, 35, 36, 0, 23, 25,
	0, 0, 0, 32, 33, 1, 2, 3, 22, 27,
	28, 21, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 42, 6, 0, 7, 4, 43, 5,
}
var StraceTok1 = [...]int{

	1,
}
var StraceTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30,
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
		StraceDollar = StraceS[Stracept-7 : Stracept+1]
		//line parser/strace.y:65
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, StraceDollar[7].val_int)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 2:
		StraceDollar = StraceS[Stracept-7 : Stracept+1]
		//line parser/strace.y:68
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, int64(StraceDollar[7].val_uint))
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 3:
		StraceDollar = StraceS[Stracept-7 : Stracept+1]
		//line parser/strace.y:71
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, -1)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 4:
		StraceDollar = StraceS[Stracept-11 : Stracept+1]
		//line parser/strace.y:74
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, StraceDollar[7].val_int)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 5:
		StraceDollar = StraceS[Stracept-11 : Stracept+1]
		//line parser/strace.y:77
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, int64(StraceDollar[7].val_uint))
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 6:
		StraceDollar = StraceS[Stracept-10 : Stracept+1]
		//line parser/strace.y:80
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, StraceDollar[7].val_int)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 7:
		StraceDollar = StraceS[Stracept-10 : Stracept+1]
		//line parser/strace.y:83
		{
			StraceVAL.val_syscall = types.NewSyscall(StraceDollar[1].val_int, StraceDollar[2].data, StraceDollar[4].val_types, int64(StraceDollar[7].val_uint))
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 8:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line parser/strace.y:87
		{
			StraceVAL.val_syscall = types.NewSyscall(-1, "signal_plus", nil, -1)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 9:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line parser/strace.y:88
		{
			StraceVAL.val_syscall = types.NewSyscall(-1, "signal_minus", nil, -1)
			Stracelex.(*lexer).result = StraceVAL.val_syscall
		}
	case 10:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:93
		{
			types := make([]types.Type, 0)
			types = append(types, StraceDollar[1].val_type)
			StraceVAL.val_types = types
		}
	case 11:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:94
		{
			StraceDollar[3].val_types = append([]types.Type{StraceDollar[1].val_type}, StraceDollar[3].val_types...)
			StraceVAL.val_types = StraceDollar[3].val_types
		}
	case 12:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:97
		{
			StraceVAL.val_type = StraceDollar[1].val_buf_type
		}
	case 13:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:98
		{
			StraceVAL.val_type = StraceDollar[1].val_int_type
		}
	case 14:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:99
		{
			StraceVAL.val_type = StraceDollar[1].val_pointer_type
		}
	case 15:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:100
		{
			StraceVAL.val_type = StraceDollar[1].val_array_type
		}
	case 16:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:101
		{
			StraceVAL.val_type = StraceDollar[1].val_struct_type
		}
	case 17:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:102
		{
			StraceVAL.val_type = StraceDollar[1].val_flag_type
		}
	case 18:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:103
		{
			StraceVAL.val_type = StraceDollar[1].val_call
		}
	case 19:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:104
		{
			StraceVAL.val_type = StraceDollar[1].val_rel_expr_type
		}
	case 20:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:105
		{
			StraceVAL.val_type = StraceDollar[1].val_ipv4_type
		}
	case 21:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line parser/strace.y:108
		{
			StraceVAL.val_call = types.NewCallType(StraceDollar[1].data, StraceDollar[3].val_types)
		}
	case 22:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line parser/strace.y:111
		{
			StraceVAL.val_pointer_type = types.NewPointerType(StraceDollar[2].val_uint, StraceDollar[4].val_type)
		}
	case 23:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:114
		{
			arr := types.NewArrayType(StraceDollar[2].val_types)
			StraceVAL.val_array_type = arr
		}
	case 24:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line parser/strace.y:115
		{
			arr := types.NewArrayType(nil)
			StraceVAL.val_array_type = arr
		}
	case 25:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:118
		{
			StraceVAL.val_struct_type = types.NewStructType(StraceDollar[2].val_fields)
		}
	case 26:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:121
		{
			fields := make([]*types.Field, 0)
			fields = append(fields, StraceDollar[1].val_field)
			StraceVAL.val_fields = fields
		}
	case 27:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:122
		{
			StraceDollar[3].val_fields = append([]*types.Field{StraceDollar[1].val_field}, StraceDollar[3].val_fields...)
			StraceVAL.val_fields = StraceDollar[3].val_fields
		}
	case 28:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:125
		{
			StraceVAL.val_field = types.NewField(StraceDollar[1].data, StraceDollar[3].val_type)
		}
	case 29:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:128
		{
			StraceVAL.val_buf_type = types.NewBufferType(StraceDollar[1].data)
		}
	case 30:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:129
		{
			StraceVAL.val_buf_type = types.NewBufferType(StraceDollar[1].data)
		}
	case 31:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:132
		{
			StraceVAL.val_rel_expr_type = types.NewRelationalExpression(StraceDollar[1].val_binop)
		}
	case 32:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:135
		{
			StraceVAL.val_binop = types.NewBinop(types.NewRelationalExpression(StraceDollar[1].val_binop), types.OR, StraceDollar[3].val_flag_type)
		}
	case 33:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:136
		{
			StraceVAL.val_binop = types.NewBinop(types.NewRelationalExpression(StraceDollar[1].val_binop), types.OR, StraceDollar[3].val_int_type)
		}
	case 34:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:137
		{
			StraceVAL.val_binop = types.NewBinop(StraceDollar[1].val_int_type, types.OR, StraceDollar[3].val_int_type)
		}
	case 35:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:138
		{
			StraceVAL.val_binop = types.NewBinop(StraceDollar[1].val_flag_type, types.OR, StraceDollar[3].val_flag_type)
		}
	case 36:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:139
		{
			StraceVAL.val_binop = types.NewBinop(StraceDollar[1].val_flag_type, types.OR, StraceDollar[3].val_int_type)
		}
	case 37:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line parser/strace.y:140
		{
			StraceVAL.val_binop = types.NewBinop(StraceDollar[1].val_int_type, types.OR, StraceDollar[3].val_flag_type)
		}
	case 38:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:143
		{
			StraceVAL.val_int_type = types.NewIntType(StraceDollar[1].val_int)
		}
	case 39:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:144
		{
			StraceVAL.val_int_type = types.NewIntType(int64(StraceDollar[1].val_uint))
		}
	case 40:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:147
		{
			StraceVAL.val_flag_type = types.NewFlagType(StraceDollar[1].data)
		}
	case 41:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:150
		{
			StraceVAL.val_ipv4_type = types.NewIpv4Type(StraceDollar[1].data)
		}
	case 42:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line parser/strace.y:153
		{
			ids := make([]*types.BufferType, 0)
			ids = append(ids, types.NewBufferType(StraceDollar[1].data))
			StraceVAL.val_identifiers = ids
		}
	case 43:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line parser/strace.y:154
		{
			StraceDollar[2].val_identifiers = append(StraceDollar[2].val_identifiers, types.NewBufferType(StraceDollar[1].data))
			StraceVAL.val_identifiers = StraceDollar[2].val_identifiers
		}
	}
	goto Stracestack /* stack new state and value */
}
