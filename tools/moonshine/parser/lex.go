
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
const strace_start int = 41
const strace_first_final int = 41
const strace_error int = 0

const strace_en_comment int = 59
const strace_en_main int = 41


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
	case 41:
		goto st_case_41
	case 1:
		goto st_case_1
	case 0:
		goto st_case_0
	case 42:
		goto st_case_42
	case 2:
		goto st_case_2
	case 3:
		goto st_case_3
	case 4:
		goto st_case_4
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
	case 43:
		goto st_case_43
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
	case 44:
		goto st_case_44
	case 45:
		goto st_case_45
	case 46:
		goto st_case_46
	case 17:
		goto st_case_17
	case 18:
		goto st_case_18
	case 19:
		goto st_case_19
	case 47:
		goto st_case_47
	case 48:
		goto st_case_48
	case 49:
		goto st_case_49
	case 50:
		goto st_case_50
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
	case 26:
		goto st_case_26
	case 27:
		goto st_case_27
	case 28:
		goto st_case_28
	case 29:
		goto st_case_29
	case 30:
		goto st_case_30
	case 31:
		goto st_case_31
	case 32:
		goto st_case_32
	case 33:
		goto st_case_33
	case 34:
		goto st_case_34
	case 35:
		goto st_case_35
	case 36:
		goto st_case_36
	case 37:
		goto st_case_37
	case 38:
		goto st_case_38
	case 51:
		goto st_case_51
	case 39:
		goto st_case_39
	case 52:
		goto st_case_52
	case 40:
		goto st_case_40
	case 53:
		goto st_case_53
	case 54:
		goto st_case_54
	case 55:
		goto st_case_55
	case 56:
		goto st_case_56
	case 57:
		goto st_case_57
	case 58:
		goto st_case_58
	case 59:
		goto st_case_59
	case 60:
		goto st_case_60
	}
	goto st_out
tr2:
// line 57 "parser/lex.rl"

 lex.te = ( lex.p)+1
{out.data = ParseString(string(lex.data[lex.ts+1:lex.te-1])); tok = STRING_LITERAL;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr11:
// line 56 "parser/lex.rl"

 lex.te = ( lex.p)+1
{out.data = string(lex.data[lex.ts+1:lex.te-1]); tok=IPV4; {( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr18:
// line 50 "parser/lex.rl"

 lex.te = ( lex.p)+1
{out.data = string(lex.data[lex.ts:lex.te]); fmt.Printf("SIGNAL %s\n", out.data);tok=SIGNAL_PLUS; {( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr20:
// line 51 "parser/lex.rl"

 lex.te = ( lex.p)+1
{out.data = string(lex.data[lex.ts+1:lex.te-1]); tok=SIGNAL_MINUS; {( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr21:
// line 74 "parser/lex.rl"

 lex.te = ( lex.p)+1
{{goto st59 }}
	goto st41
tr22:
// line 52 "parser/lex.rl"

( lex.p) = ( lex.te) - 1
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 10, 64); tok = INT;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr42:
// line 73 "parser/lex.rl"

( lex.p) = ( lex.te) - 1
{out.data = string(lex.data[lex.ts:lex.te]); tok = DATETIME; {( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr46:
// line 76 "parser/lex.rl"

 lex.te = ( lex.p)+1

	goto st41
tr47:
// line 69 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = NOT;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr50:
// line 61 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LPAREN;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr51:
// line 62 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = RPAREN;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr53:
// line 72 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = COMMA;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr58:
// line 60 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = EQUALS;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr59:
// line 75 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = QUESTION; {( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr61:
// line 63 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LBRACKET_SQUARE;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr62:
// line 64 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = RBRACKET_SQUARE;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr64:
// line 65 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LBRACKET;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr66:
// line 66 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = RBRACKET;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr67:
// line 54 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 8, 64); tok = INT; {( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr68:
// line 68 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{tok = AND;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr69:
// line 71 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LAND;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr70:
// line 52 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 10, 64); tok = INT;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr73:
// line 53 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_double, _ = strconv.ParseFloat(string(lex.data[lex.ts : lex.te]), 64); tok= DOUBLE; {( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr79:
// line 73 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = DATETIME; {( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr81:
// line 55 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_uint, _ = strconv.ParseUint(string(lex.data[lex.ts:lex.te]), 0, 64); tok = UINT;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr82:
// line 1 "NONE"

	switch  lex.act {
	case 11:
	{( lex.p) = ( lex.te) - 1
out.data = string(lex.data[lex.ts:lex.te]); tok = FLAG;{( lex.p)++;  lex.cs = 41; goto _out }}
	case 12:
	{( lex.p) = ( lex.te) - 1
out.data = string(lex.data[lex.ts:lex.te]); tok = IDENTIFIER;{( lex.p)++;  lex.cs = 41; goto _out }}
	}
	
	goto st41
tr85:
// line 59 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = IDENTIFIER;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr86:
// line 58 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = FLAG;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr87:
// line 67 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{tok = OR;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
tr88:
// line 70 "parser/lex.rl"

 lex.te = ( lex.p)+1
{tok = LOR;{( lex.p)++;  lex.cs = 41; goto _out }}
	goto st41
	st41:
// line 1 "NONE"

 lex.ts = 0

		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof41
		}
	st_case_41:
// line 1 "NONE"

 lex.ts = ( lex.p)

// line 396 "parser/lex.go"
		switch  lex.data[( lex.p)] {
		case 0:
			goto st1
		case 32:
			goto tr46
		case 33:
			goto tr47
		case 34:
			goto st2
		case 38:
			goto st43
		case 40:
			goto tr50
		case 41:
			goto tr51
		case 43:
			goto st11
		case 44:
			goto tr53
		case 45:
			goto st17
		case 47:
			goto st19
		case 48:
			goto tr56
		case 61:
			goto tr58
		case 63:
			goto tr59
		case 91:
			goto tr61
		case 93:
			goto tr62
		case 123:
			goto tr64
		case 124:
			goto st58
		case 125:
			goto tr66
		}
		switch {
		case  lex.data[( lex.p)] < 49:
			if 9 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 13 {
				goto tr46
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st56
				}
			case  lex.data[( lex.p)] >= 65:
				goto tr60
			}
		default:
			goto st54
		}
		goto st0
	st1:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof1
		}
	st_case_1:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st42
		}
		goto st0
st_case_0:
	st0:
		 lex.cs = 0
		goto _out
	st42:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof42
		}
	st_case_42:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st42
		}
		goto tr67
	st2:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof2
		}
	st_case_2:
		switch  lex.data[( lex.p)] {
		case 34:
			goto tr2
		case 42:
			goto st3
		case 47:
			goto st3
		case 92:
			goto st3
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st4
			}
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st3
			}
		default:
			goto st3
		}
		goto st0
	st3:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof3
		}
	st_case_3:
		switch  lex.data[( lex.p)] {
		case 34:
			goto tr2
		case 42:
			goto st3
		case 92:
			goto st3
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			if 47 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st3
			}
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st3
			}
		default:
			goto st3
		}
		goto st0
	st4:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof4
		}
	st_case_4:
		switch  lex.data[( lex.p)] {
		case 34:
			goto tr2
		case 42:
			goto st3
		case 46:
			goto st5
		case 92:
			goto st3
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			if 47 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st3
			}
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st3
			}
		default:
			goto st3
		}
		goto st0
	st5:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof5
		}
	st_case_5:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st6
		}
		goto st0
	st6:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof6
		}
	st_case_6:
		if  lex.data[( lex.p)] == 46 {
			goto st7
		}
		goto st0
	st7:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof7
		}
	st_case_7:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st8
		}
		goto st0
	st8:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof8
		}
	st_case_8:
		if  lex.data[( lex.p)] == 46 {
			goto st9
		}
		goto st0
	st9:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof9
		}
	st_case_9:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st10
		}
		goto st0
	st10:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof10
		}
	st_case_10:
		if  lex.data[( lex.p)] == 34 {
			goto tr11
		}
		goto st0
	st43:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof43
		}
	st_case_43:
		if  lex.data[( lex.p)] == 38 {
			goto tr69
		}
		goto tr68
	st11:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof11
		}
	st_case_11:
		if  lex.data[( lex.p)] == 43 {
			goto st12
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st44
		}
		goto st0
	st12:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof12
		}
	st_case_12:
		if  lex.data[( lex.p)] == 43 {
			goto st13
		}
		goto st0
	st13:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof13
		}
	st_case_13:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st14
		case 39:
			goto st14
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st14
			}
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st14
			}
		default:
			goto st14
		}
		goto st0
	st14:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof14
		}
	st_case_14:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st14
		case 39:
			goto st14
		case 43:
			goto st15
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st14
			}
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st14
			}
		default:
			goto st14
		}
		goto st0
	st15:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof15
		}
	st_case_15:
		if  lex.data[( lex.p)] == 43 {
			goto st16
		}
		goto st0
	st16:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof16
		}
	st_case_16:
		if  lex.data[( lex.p)] == 43 {
			goto tr18
		}
		goto st0
	st44:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof44
		}
	st_case_44:
		if  lex.data[( lex.p)] == 46 {
			goto st45
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st46
		}
		goto tr70
	st45:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof45
		}
	st_case_45:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st45
		}
		goto tr73
	st46:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof46
		}
	st_case_46:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st46
		}
		goto tr70
	st17:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof17
		}
	st_case_17:
		if  lex.data[( lex.p)] == 45 {
			goto st18
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st44
		}
		goto st0
	st18:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof18
		}
	st_case_18:
		if  lex.data[( lex.p)] == 45 {
			goto tr20
		}
		goto st0
	st19:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof19
		}
	st_case_19:
		if  lex.data[( lex.p)] == 42 {
			goto tr21
		}
		goto st0
tr56:
// line 1 "NONE"

 lex.te = ( lex.p)+1

	goto st47
	st47:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof47
		}
	st_case_47:
// line 782 "parser/lex.go"
		switch  lex.data[( lex.p)] {
		case 46:
			goto st45
		case 120:
			goto st40
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st48
		}
		goto tr70
	st48:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof48
		}
	st_case_48:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st49
		}
		goto tr70
	st49:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof49
		}
	st_case_49:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto tr77
		}
		goto tr70
tr77:
// line 1 "NONE"

 lex.te = ( lex.p)+1

	goto st50
	st50:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof50
		}
	st_case_50:
// line 822 "parser/lex.go"
		if  lex.data[( lex.p)] == 45 {
			goto st20
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st46
		}
		goto tr70
	st20:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof20
		}
	st_case_20:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st21
		}
		goto tr22
	st21:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof21
		}
	st_case_21:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st22
		}
		goto tr22
	st22:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof22
		}
	st_case_22:
		if  lex.data[( lex.p)] == 45 {
			goto st23
		}
		goto tr22
	st23:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof23
		}
	st_case_23:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st24
		}
		goto tr22
	st24:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof24
		}
	st_case_24:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st25
		}
		goto tr22
	st25:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof25
		}
	st_case_25:
		if  lex.data[( lex.p)] == 84 {
			goto st26
		}
		goto tr22
	st26:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof26
		}
	st_case_26:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st27
		}
		goto tr22
	st27:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof27
		}
	st_case_27:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st28
		}
		goto tr22
	st28:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof28
		}
	st_case_28:
		if  lex.data[( lex.p)] == 58 {
			goto st29
		}
		goto tr22
	st29:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof29
		}
	st_case_29:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st30
		}
		goto tr22
	st30:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof30
		}
	st_case_30:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st31
		}
		goto tr22
	st31:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof31
		}
	st_case_31:
		if  lex.data[( lex.p)] == 58 {
			goto st32
		}
		goto tr22
	st32:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof32
		}
	st_case_32:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st33
		}
		goto tr22
	st33:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof33
		}
	st_case_33:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st34
		}
		goto tr22
	st34:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof34
		}
	st_case_34:
		if  lex.data[( lex.p)] == 43 {
			goto st35
		}
		goto tr22
	st35:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof35
		}
	st_case_35:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st36
		}
		goto tr22
	st36:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof36
		}
	st_case_36:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st37
		}
		goto tr22
	st37:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof37
		}
	st_case_37:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st38
		}
		goto tr22
	st38:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof38
		}
	st_case_38:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto tr41
		}
		goto tr22
tr41:
// line 1 "NONE"

 lex.te = ( lex.p)+1

	goto st51
	st51:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof51
		}
	st_case_51:
// line 1012 "parser/lex.go"
		if  lex.data[( lex.p)] == 46 {
			goto st39
		}
		goto tr79
	st39:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof39
		}
	st_case_39:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st52
		}
		goto tr42
	st52:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof52
		}
	st_case_52:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st52
		}
		goto tr79
	st40:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof40
		}
	st_case_40:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st53
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st53
			}
		default:
			goto st53
		}
		goto tr22
	st53:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof53
		}
	st_case_53:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st53
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st53
			}
		default:
			goto st53
		}
		goto tr81
	st54:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof54
		}
	st_case_54:
		if  lex.data[( lex.p)] == 46 {
			goto st45
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st48
		}
		goto tr70
tr60:
// line 1 "NONE"

 lex.te = ( lex.p)+1

// line 59 "parser/lex.rl"

 lex.act = 12;
	goto st55
tr83:
// line 1 "NONE"

 lex.te = ( lex.p)+1

// line 58 "parser/lex.rl"

 lex.act = 11;
	goto st55
	st55:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof55
		}
	st_case_55:
// line 1106 "parser/lex.go"
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr83
		case 42:
			goto st56
		case 95:
			goto tr83
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st56
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st56
				}
			case  lex.data[( lex.p)] >= 65:
				goto st57
			}
		default:
			goto tr83
		}
		goto tr82
	st56:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof56
		}
	st_case_56:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st56
		case 42:
			goto st56
		case 95:
			goto st56
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st56
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st56
			}
		default:
			goto st56
		}
		goto tr85
	st57:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof57
		}
	st_case_57:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st57
		case 95:
			goto st57
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto st57
			}
		case  lex.data[( lex.p)] >= 48:
			goto st57
		}
		goto tr86
	st58:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof58
		}
	st_case_58:
		if  lex.data[( lex.p)] == 124 {
			goto tr88
		}
		goto tr87
tr89:
// line 45 "parser/lex.rl"

 lex.te = ( lex.p)+1

	goto st59
tr91:
// line 45 "parser/lex.rl"

 lex.te = ( lex.p)
( lex.p)--

	goto st59
tr92:
// line 46 "parser/lex.rl"

 lex.te = ( lex.p)+1
{{goto st41 }}
	goto st59
	st59:
// line 1 "NONE"

 lex.ts = 0

		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof59
		}
	st_case_59:
// line 1 "NONE"

 lex.ts = ( lex.p)

// line 1220 "parser/lex.go"
		if  lex.data[( lex.p)] == 42 {
			goto st60
		}
		goto tr89
	st60:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof60
		}
	st_case_60:
		if  lex.data[( lex.p)] == 47 {
			goto tr92
		}
		goto tr91
	st_out:
	_test_eof41:  lex.cs = 41; goto _test_eof
	_test_eof1:  lex.cs = 1; goto _test_eof
	_test_eof42:  lex.cs = 42; goto _test_eof
	_test_eof2:  lex.cs = 2; goto _test_eof
	_test_eof3:  lex.cs = 3; goto _test_eof
	_test_eof4:  lex.cs = 4; goto _test_eof
	_test_eof5:  lex.cs = 5; goto _test_eof
	_test_eof6:  lex.cs = 6; goto _test_eof
	_test_eof7:  lex.cs = 7; goto _test_eof
	_test_eof8:  lex.cs = 8; goto _test_eof
	_test_eof9:  lex.cs = 9; goto _test_eof
	_test_eof10:  lex.cs = 10; goto _test_eof
	_test_eof43:  lex.cs = 43; goto _test_eof
	_test_eof11:  lex.cs = 11; goto _test_eof
	_test_eof12:  lex.cs = 12; goto _test_eof
	_test_eof13:  lex.cs = 13; goto _test_eof
	_test_eof14:  lex.cs = 14; goto _test_eof
	_test_eof15:  lex.cs = 15; goto _test_eof
	_test_eof16:  lex.cs = 16; goto _test_eof
	_test_eof44:  lex.cs = 44; goto _test_eof
	_test_eof45:  lex.cs = 45; goto _test_eof
	_test_eof46:  lex.cs = 46; goto _test_eof
	_test_eof17:  lex.cs = 17; goto _test_eof
	_test_eof18:  lex.cs = 18; goto _test_eof
	_test_eof19:  lex.cs = 19; goto _test_eof
	_test_eof47:  lex.cs = 47; goto _test_eof
	_test_eof48:  lex.cs = 48; goto _test_eof
	_test_eof49:  lex.cs = 49; goto _test_eof
	_test_eof50:  lex.cs = 50; goto _test_eof
	_test_eof20:  lex.cs = 20; goto _test_eof
	_test_eof21:  lex.cs = 21; goto _test_eof
	_test_eof22:  lex.cs = 22; goto _test_eof
	_test_eof23:  lex.cs = 23; goto _test_eof
	_test_eof24:  lex.cs = 24; goto _test_eof
	_test_eof25:  lex.cs = 25; goto _test_eof
	_test_eof26:  lex.cs = 26; goto _test_eof
	_test_eof27:  lex.cs = 27; goto _test_eof
	_test_eof28:  lex.cs = 28; goto _test_eof
	_test_eof29:  lex.cs = 29; goto _test_eof
	_test_eof30:  lex.cs = 30; goto _test_eof
	_test_eof31:  lex.cs = 31; goto _test_eof
	_test_eof32:  lex.cs = 32; goto _test_eof
	_test_eof33:  lex.cs = 33; goto _test_eof
	_test_eof34:  lex.cs = 34; goto _test_eof
	_test_eof35:  lex.cs = 35; goto _test_eof
	_test_eof36:  lex.cs = 36; goto _test_eof
	_test_eof37:  lex.cs = 37; goto _test_eof
	_test_eof38:  lex.cs = 38; goto _test_eof
	_test_eof51:  lex.cs = 51; goto _test_eof
	_test_eof39:  lex.cs = 39; goto _test_eof
	_test_eof52:  lex.cs = 52; goto _test_eof
	_test_eof40:  lex.cs = 40; goto _test_eof
	_test_eof53:  lex.cs = 53; goto _test_eof
	_test_eof54:  lex.cs = 54; goto _test_eof
	_test_eof55:  lex.cs = 55; goto _test_eof
	_test_eof56:  lex.cs = 56; goto _test_eof
	_test_eof57:  lex.cs = 57; goto _test_eof
	_test_eof58:  lex.cs = 58; goto _test_eof
	_test_eof59:  lex.cs = 59; goto _test_eof
	_test_eof60:  lex.cs = 60; goto _test_eof

	_test_eof: {}
	if ( lex.p) == eof {
		switch  lex.cs {
		case 42:
			goto tr67
		case 43:
			goto tr68
		case 44:
			goto tr70
		case 45:
			goto tr73
		case 46:
			goto tr70
		case 47:
			goto tr70
		case 48:
			goto tr70
		case 49:
			goto tr70
		case 50:
			goto tr70
		case 20:
			goto tr22
		case 21:
			goto tr22
		case 22:
			goto tr22
		case 23:
			goto tr22
		case 24:
			goto tr22
		case 25:
			goto tr22
		case 26:
			goto tr22
		case 27:
			goto tr22
		case 28:
			goto tr22
		case 29:
			goto tr22
		case 30:
			goto tr22
		case 31:
			goto tr22
		case 32:
			goto tr22
		case 33:
			goto tr22
		case 34:
			goto tr22
		case 35:
			goto tr22
		case 36:
			goto tr22
		case 37:
			goto tr22
		case 38:
			goto tr22
		case 51:
			goto tr79
		case 39:
			goto tr42
		case 52:
			goto tr79
		case 40:
			goto tr22
		case 53:
			goto tr81
		case 54:
			goto tr70
		case 55:
			goto tr82
		case 56:
			goto tr85
		case 57:
			goto tr86
		case 58:
			goto tr87
		case 60:
			goto tr91
		}
	}

	_out: {}
	}

// line 80 "parser/lex.rl"


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
	decoded = append(decoded, '\x00')
	return string(decoded)
}
