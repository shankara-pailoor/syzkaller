
// line 1 "parser/lex.rl"
package parser

import (
    "fmt"
    "encoding/hex"
    "strconv"
    "strings"
    "github.com/google/syzkaller/tools/moonshine/types"
)


// line 15 "parser/lex.go"
const strace_start int = 27
const strace_first_final int = 27
const strace_error int = 0

const strace_en_comment int = 44
const strace_en_main int = 27


// line 17 "parser/lex.rl"


type lexer struct {
    result *types.Syscall
    data []byte
    p, pe, cs int
    ts, te, act int
}

func newLexer (data []byte) *lexer {
    lex := &lexer {
        data: data,
        pe: len(data),
    }

    
// line 41 "parser/lex.go"
	{
	 lex.cs = strace_start
	 lex.ts = 0
	 lex.te = 0
	 lex.act = 0
	}

// line 33 "parser/lex.rl"
    return lex
}

func (lex *lexer) Lex(out *StraceSymType) int {
    eof := lex.pe
    tok := 0
    
// line 57 "parser/lex.go"
	{
	if ( lex.p) == ( lex.pe) {
		goto _test_eof
	}
	switch  lex.cs {
	case 27:
		goto st_case_27
	case 1:
		goto st_case_1
	case 0:
		goto st_case_0
	case 28:
		goto st_case_28
	case 2:
		goto st_case_2
	case 29:
		goto st_case_29
	case 3:
		goto st_case_3
	case 30:
		goto st_case_30
	case 31:
		goto st_case_31
	case 32:
		goto st_case_32
	case 4:
		goto st_case_4
	case 33:
		goto st_case_33
	case 34:
		goto st_case_34
	case 35:
		goto st_case_35
	case 36:
		goto st_case_36
	case 5:
		goto st_case_5
	case 6:
		goto st_case_6
	case 7:
		goto st_case_7
	case 8:
		goto st_case_8
	case 9:
		goto st_case_9
	case 10:
		goto st_case_10
	case 11:
		goto st_case_11
	case 12:
		goto st_case_12
	case 13:
		goto st_case_13
	case 14:
		goto st_case_14
	case 15:
		goto st_case_15
	case 16:
		goto st_case_16
	case 17:
		goto st_case_17
	case 18:
		goto st_case_18
	case 19:
		goto st_case_19
	case 20:
		goto st_case_20
	case 21:
		goto st_case_21
	case 22:
		goto st_case_22
	case 23:
		goto st_case_23
	case 24:
		goto st_case_24
	case 25:
		goto st_case_25
	case 37:
		goto st_case_37
	case 26:
		goto st_case_26
	case 38:
		goto st_case_38
	case 39:
		goto st_case_39
	case 40:
		goto st_case_40
	case 41:
		goto st_case_41
	case 42:
		goto st_case_42
	case 43:
		goto st_case_43
	case 44:
		goto st_case_44
	case 45:
		goto st_case_45
	}
	goto st_out
tr2:
// line 53 "parser/lex.rl"

 lex.te = ( lex.p)+1
{out.data = ParseString(string(lex.data[lex.ts+1:lex.te-1])); tok = STRING_LITERAL;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr5:
// line 70 "parser/lex.rl"

 lex.te = ( lex.p)+1
{{goto st44 }}
	goto st27
tr6:
// line 49 "parser/lex.rl"

( lex.p) = ( lex.te) - 1
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 10, 64); tok = INT;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr30:
// line 72 "parser/lex.rl"

 lex.te = ( lex.p)+1

	goto st27
tr31:
// line 65 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = NOT;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr33:
// line 57 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LPAREN;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr34:
// line 58 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = RPAREN;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr36:
// line 68 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = COMMA;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr40:
// line 56 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = EQUALS;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr42:
// line 59 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LBRACKET_SQUARE;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr43:
// line 60 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = RBRACKET_SQUARE;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr45:
// line 61 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LBRACKET;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr47:
// line 62 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = RBRACKET;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr48:
// line 51 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 8, 64); tok = INT; {( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr49:
// line 64 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{tok = AND;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr50:
// line 67 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LAND;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr51:
// line 49 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 10, 64); tok = INT;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr54:
// line 50 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_double, _ = strconv.ParseFloat(string(lex.data[lex.ts : lex.te]), 64); tok= DOUBLE; {( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr60:
// line 69 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = DATETIME; {( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr61:
// line 52 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_uint, _ = strconv.ParseUint(string(lex.data[lex.ts:lex.te]), 0, 64); tok = UINT;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr62:
// line 1 "NONE"

	switch  lex.act {
	case 8:
	{( lex.p) = ( lex.te) - 1
out.data = string(lex.data[lex.ts:lex.te]); tok = FLAG;{( lex.p)++;  lex.cs = 27; goto _out }}
	case 9:
	{( lex.p) = ( lex.te) - 1
out.data = string(lex.data[lex.ts:lex.te]); tok = IDENTIFIER;{( lex.p)++;  lex.cs = 27; goto _out }}
	}
	
	goto st27
tr65:
// line 55 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = IDENTIFIER;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr66:
// line 54 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = FLAG;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr67:
// line 63 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{tok = OR;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
tr68:
// line 66 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LOR;{( lex.p)++;  lex.cs = 27; goto _out }}
	goto st27
	st27:
// line 1 "NONE"

 lex.ts = 0

		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof27
		}
	st_case_27:
// line 1 "NONE"

 lex.ts = ( lex.p)

// line 336 "parser/lex.go"
		switch  lex.data[( lex.p)] {
		case 0:
			goto st1
		case 32:
			goto tr30
		case 33:
			goto tr31
		case 34:
			goto st2
		case 38:
			goto st29
		case 40:
			goto tr33
		case 41:
			goto tr34
		case 44:
			goto tr36
		case 47:
			goto st4
		case 48:
			goto tr38
		case 61:
			goto tr40
		case 91:
			goto tr42
		case 93:
			goto tr43
		case 123:
			goto tr45
		case 124:
			goto st43
		case 125:
			goto tr47
		}
		switch {
		case  lex.data[( lex.p)] < 49:
			switch {
			case  lex.data[( lex.p)] > 13:
				if 43 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 45 {
					goto st3
				}
			case  lex.data[( lex.p)] >= 9:
				goto tr30
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st41
				}
			case  lex.data[( lex.p)] >= 65:
				goto tr41
			}
		default:
			goto st39
		}
		goto st0
	st1:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof1
		}
	st_case_1:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st28
		}
		goto st0
st_case_0:
	st0:
		 lex.cs = 0
		goto _out
	st28:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof28
		}
	st_case_28:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st28
		}
		goto tr48
	st2:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof2
		}
	st_case_2:
		switch  lex.data[( lex.p)] {
		case 34:
			goto tr2
		case 42:
			goto st2
		case 92:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			if 47 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st2
			}
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st2
			}
		default:
			goto st2
		}
		goto st0
	st29:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof29
		}
	st_case_29:
		if  lex.data[( lex.p)] == 38 {
			goto tr50
		}
		goto tr49
	st3:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof3
		}
	st_case_3:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st30
		}
		goto st0
	st30:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof30
		}
	st_case_30:
		if  lex.data[( lex.p)] == 46 {
			goto st31
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st32
		}
		goto tr51
	st31:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof31
		}
	st_case_31:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st31
		}
		goto tr54
	st32:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof32
		}
	st_case_32:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st32
		}
		goto tr51
	st4:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof4
		}
	st_case_4:
		if  lex.data[( lex.p)] == 42 {
			goto tr5
		}
		goto st0
tr38:
// line 1 "NONE"

 lex.te = ( lex.p)+1

	goto st33
	st33:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof33
		}
	st_case_33:
// line 510 "parser/lex.go"
		switch  lex.data[( lex.p)] {
		case 46:
			goto st31
		case 120:
			goto st26
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st34
		}
		goto tr51
	st34:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof34
		}
	st_case_34:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st35
		}
		goto tr51
	st35:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof35
		}
	st_case_35:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto tr58
		}
		goto tr51
tr58:
// line 1 "NONE"

 lex.te = ( lex.p)+1

	goto st36
	st36:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof36
		}
	st_case_36:
// line 550 "parser/lex.go"
		if  lex.data[( lex.p)] == 45 {
			goto st5
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st32
		}
		goto tr51
	st5:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof5
		}
	st_case_5:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st6
		}
		goto tr6
	st6:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof6
		}
	st_case_6:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st7
		}
		goto tr6
	st7:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof7
		}
	st_case_7:
		if  lex.data[( lex.p)] == 45 {
			goto st8
		}
		goto tr6
	st8:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof8
		}
	st_case_8:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st9
		}
		goto tr6
	st9:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof9
		}
	st_case_9:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st10
		}
		goto tr6
	st10:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof10
		}
	st_case_10:
		if  lex.data[( lex.p)] == 84 {
			goto st11
		}
		goto tr6
	st11:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof11
		}
	st_case_11:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st12
		}
		goto tr6
	st12:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof12
		}
	st_case_12:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st13
		}
		goto tr6
	st13:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof13
		}
	st_case_13:
		if  lex.data[( lex.p)] == 58 {
			goto st14
		}
		goto tr6
	st14:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof14
		}
	st_case_14:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st15
		}
		goto tr6
	st15:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof15
		}
	st_case_15:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st16
		}
		goto tr6
	st16:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof16
		}
	st_case_16:
		if  lex.data[( lex.p)] == 58 {
			goto st17
		}
		goto tr6
	st17:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof17
		}
	st_case_17:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st18
		}
		goto tr6
	st18:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof18
		}
	st_case_18:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st19
		}
		goto tr6
	st19:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof19
		}
	st_case_19:
		if  lex.data[( lex.p)] == 43 {
			goto st20
		}
		goto tr6
	st20:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof20
		}
	st_case_20:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st21
		}
		goto tr6
	st21:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof21
		}
	st_case_21:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st22
		}
		goto tr6
	st22:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof22
		}
	st_case_22:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st23
		}
		goto tr6
	st23:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof23
		}
	st_case_23:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st24
		}
		goto tr6
	st24:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof24
		}
	st_case_24:
		if  lex.data[( lex.p)] == 46 {
			goto st25
		}
		goto tr6
	st25:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof25
		}
	st_case_25:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st37
		}
		goto tr6
	st37:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof37
		}
	st_case_37:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st37
		}
		goto tr60
	st26:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof26
		}
	st_case_26:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st38
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st38
			}
		default:
			goto st38
		}
		goto tr6
	st38:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof38
		}
	st_case_38:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st38
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st38
			}
		default:
			goto st38
		}
		goto tr61
	st39:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof39
		}
	st_case_39:
		if  lex.data[( lex.p)] == 46 {
			goto st31
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st34
		}
		goto tr51
tr41:
// line 1 "NONE"

 lex.te = ( lex.p)+1

// line 55 "parser/lex.rl"

 lex.act = 9;
	goto st40
tr63:
// line 1 "NONE"

 lex.te = ( lex.p)+1

// line 54 "parser/lex.rl"

 lex.act = 8;
	goto st40
	st40:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof40
		}
	st_case_40:
// line 827 "parser/lex.go"
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr63
		case 42:
			goto st41
		case 95:
			goto tr63
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st41
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st41
				}
			case  lex.data[( lex.p)] >= 65:
				goto st42
			}
		default:
			goto tr63
		}
		goto tr62
	st41:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof41
		}
	st_case_41:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st41
		case 42:
			goto st41
		case 95:
			goto st41
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st41
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st41
			}
		default:
			goto st41
		}
		goto tr65
	st42:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof42
		}
	st_case_42:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st42
		case 95:
			goto st42
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto st42
			}
		case  lex.data[( lex.p)] >= 48:
			goto st42
		}
		goto tr66
	st43:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof43
		}
	st_case_43:
		if  lex.data[( lex.p)] == 124 {
			goto tr68
		}
		goto tr67
tr69:
// line 44 "parser/lex.rl"

 lex.te = ( lex.p)+1

	goto st44
tr71:
// line 44 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--

	goto st44
tr72:
// line 45 "parser/lex.rl"

 lex.te = ( lex.p)+1
{{goto st27 }}
	goto st44
	st44:
// line 1 "NONE"

 lex.ts = 0

		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof44
		}
	st_case_44:
// line 1 "NONE"

 lex.ts = ( lex.p)

// line 941 "parser/lex.go"
		if  lex.data[( lex.p)] == 42 {
			goto st45
		}
		goto tr69
	st45:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof45
		}
	st_case_45:
		if  lex.data[( lex.p)] == 47 {
			goto tr72
		}
		goto tr71
	st_out:
	_test_eof27:  lex.cs = 27; goto _test_eof
	_test_eof1:  lex.cs = 1; goto _test_eof
	_test_eof28:  lex.cs = 28; goto _test_eof
	_test_eof2:  lex.cs = 2; goto _test_eof
	_test_eof29:  lex.cs = 29; goto _test_eof
	_test_eof3:  lex.cs = 3; goto _test_eof
	_test_eof30:  lex.cs = 30; goto _test_eof
	_test_eof31:  lex.cs = 31; goto _test_eof
	_test_eof32:  lex.cs = 32; goto _test_eof
	_test_eof4:  lex.cs = 4; goto _test_eof
	_test_eof33:  lex.cs = 33; goto _test_eof
	_test_eof34:  lex.cs = 34; goto _test_eof
	_test_eof35:  lex.cs = 35; goto _test_eof
	_test_eof36:  lex.cs = 36; goto _test_eof
	_test_eof5:  lex.cs = 5; goto _test_eof
	_test_eof6:  lex.cs = 6; goto _test_eof
	_test_eof7:  lex.cs = 7; goto _test_eof
	_test_eof8:  lex.cs = 8; goto _test_eof
	_test_eof9:  lex.cs = 9; goto _test_eof
	_test_eof10:  lex.cs = 10; goto _test_eof
	_test_eof11:  lex.cs = 11; goto _test_eof
	_test_eof12:  lex.cs = 12; goto _test_eof
	_test_eof13:  lex.cs = 13; goto _test_eof
	_test_eof14:  lex.cs = 14; goto _test_eof
	_test_eof15:  lex.cs = 15; goto _test_eof
	_test_eof16:  lex.cs = 16; goto _test_eof
	_test_eof17:  lex.cs = 17; goto _test_eof
	_test_eof18:  lex.cs = 18; goto _test_eof
	_test_eof19:  lex.cs = 19; goto _test_eof
	_test_eof20:  lex.cs = 20; goto _test_eof
	_test_eof21:  lex.cs = 21; goto _test_eof
	_test_eof22:  lex.cs = 22; goto _test_eof
	_test_eof23:  lex.cs = 23; goto _test_eof
	_test_eof24:  lex.cs = 24; goto _test_eof
	_test_eof25:  lex.cs = 25; goto _test_eof
	_test_eof37:  lex.cs = 37; goto _test_eof
	_test_eof26:  lex.cs = 26; goto _test_eof
	_test_eof38:  lex.cs = 38; goto _test_eof
	_test_eof39:  lex.cs = 39; goto _test_eof
	_test_eof40:  lex.cs = 40; goto _test_eof
	_test_eof41:  lex.cs = 41; goto _test_eof
	_test_eof42:  lex.cs = 42; goto _test_eof
	_test_eof43:  lex.cs = 43; goto _test_eof
	_test_eof44:  lex.cs = 44; goto _test_eof
	_test_eof45:  lex.cs = 45; goto _test_eof

	_test_eof: {}
	if ( lex.p) == eof {
		switch  lex.cs {
		case 28:
			goto tr48
		case 29:
			goto tr49
		case 30:
			goto tr51
		case 31:
			goto tr54
		case 32:
			goto tr51
		case 33:
			goto tr51
		case 34:
			goto tr51
		case 35:
			goto tr51
		case 36:
			goto tr51
		case 5:
			goto tr6
		case 6:
			goto tr6
		case 7:
			goto tr6
		case 8:
			goto tr6
		case 9:
			goto tr6
		case 10:
			goto tr6
		case 11:
			goto tr6
		case 12:
			goto tr6
		case 13:
			goto tr6
		case 14:
			goto tr6
		case 15:
			goto tr6
		case 16:
			goto tr6
		case 17:
			goto tr6
		case 18:
			goto tr6
		case 19:
			goto tr6
		case 20:
			goto tr6
		case 21:
			goto tr6
		case 22:
			goto tr6
		case 23:
			goto tr6
		case 24:
			goto tr6
		case 25:
			goto tr6
		case 37:
			goto tr60
		case 26:
			goto tr6
		case 38:
			goto tr61
		case 39:
			goto tr51
		case 40:
			goto tr62
		case 41:
			goto tr65
		case 42:
			goto tr66
		case 43:
			goto tr67
		case 45:
			goto tr71
		}
	}

	_out: {}
	}

// line 76 "parser/lex.rl"


    return tok;
}

func (lex *lexer) Error(e string) {
    fmt.Println("error:", e)
}

func ParseString(s string) string{
	var decoded []byte
	var err error
	if decoded, err = hex.DecodeString(strings.Replace(s, `\x`, "", -1)); err != nil {
		panic(fmt.Sprintf("Failed to decode string: %s, with error: %s\n", s, err.Error()))
	}
	decoded = append(decoded, '\0')
	return string(decoded)
}