
// line 1 "scanner/lex.rl"
package scanner

import (
    "fmt"
    "encoding/hex"
    "strconv"
    "strings"
    "github.com/google/syzkaller/tools/moonshine/strace_types"
)


// line 15 "scanner/lex.go"
const strace_start int = 79
const strace_first_final int = 79
const strace_error int = 0

const strace_en_comment int = 101
const strace_en_main int = 79


// line 17 "scanner/lex.rl"


type lexer struct {
    result *strace_types.Syscall
    data []byte
    p, pe, cs int
    ts, te, act int
}

func newLexer (data []byte) *lexer {
    lex := &lexer {
        data: data,
        pe: len(data),
    }

    
// line 41 "scanner/lex.go"
	{
	 lex.cs = strace_start
	 lex.ts = 0
	 lex.te = 0
	 lex.act = 0
	}

// line 33 "scanner/lex.rl"
    return lex
}

func (lex *lexer) Lex(out *StraceSymType) int {
    eof := lex.pe
    tok := 0
    
// line 57 "scanner/lex.go"
	{
	if ( lex.p) == ( lex.pe) {
		goto _test_eof
	}
	switch  lex.cs {
	case 79:
		goto st_case_79
	case 1:
		goto st_case_1
	case 0:
		goto st_case_0
	case 80:
		goto st_case_80
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
	case 81:
		goto st_case_81
	case 11:
		goto st_case_11
	case 82:
		goto st_case_82
	case 83:
		goto st_case_83
	case 84:
		goto st_case_84
	case 85:
		goto st_case_85
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
	case 26:
		goto st_case_26
	case 27:
		goto st_case_27
	case 28:
		goto st_case_28
	case 29:
		goto st_case_29
	case 86:
		goto st_case_86
	case 87:
		goto st_case_87
	case 88:
		goto st_case_88
	case 89:
		goto st_case_89
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
	case 46:
		goto st_case_46
	case 47:
		goto st_case_47
	case 48:
		goto st_case_48
	case 90:
		goto st_case_90
	case 49:
		goto st_case_49
	case 91:
		goto st_case_91
	case 50:
		goto st_case_50
	case 92:
		goto st_case_92
	case 93:
		goto st_case_93
	case 51:
		goto st_case_51
	case 52:
		goto st_case_52
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
	case 61:
		goto st_case_61
	case 62:
		goto st_case_62
	case 63:
		goto st_case_63
	case 64:
		goto st_case_64
	case 65:
		goto st_case_65
	case 66:
		goto st_case_66
	case 67:
		goto st_case_67
	case 68:
		goto st_case_68
	case 69:
		goto st_case_69
	case 70:
		goto st_case_70
	case 71:
		goto st_case_71
	case 72:
		goto st_case_72
	case 73:
		goto st_case_73
	case 74:
		goto st_case_74
	case 75:
		goto st_case_75
	case 76:
		goto st_case_76
	case 77:
		goto st_case_77
	case 78:
		goto st_case_78
	case 94:
		goto st_case_94
	case 95:
		goto st_case_95
	case 96:
		goto st_case_96
	case 97:
		goto st_case_97
	case 98:
		goto st_case_98
	case 99:
		goto st_case_99
	case 100:
		goto st_case_100
	case 101:
		goto st_case_101
	case 102:
		goto st_case_102
	}
	goto st_out
tr2:
// line 56 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{out.data = ParseString(string(lex.data[lex.ts+1:lex.te-1])); tok = STRING_LITERAL;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr11:
// line 55 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{out.data = string(lex.data[lex.ts+1:lex.te-1]); tok=IPV4; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr13:
// line 77 "scanner/lex.rl"

( lex.p) = ( lex.te) - 1
{tok = COMMA;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr30:
// line 66 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = UNFINISHED_W_COMMA; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr31:
// line 79 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{{goto st101 }}
	goto st79
tr32:
// line 51 "scanner/lex.rl"

( lex.p) = ( lex.te) - 1
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 10, 64); tok = INT;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr52:
// line 78 "scanner/lex.rl"

( lex.p) = ( lex.te) - 1
{out.data = string(lex.data[lex.ts:lex.te]); tok = DATETIME; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr69:
// line 68 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = RESUMED; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr83:
// line 65 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = UNFINISHED; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr85:
// line 81 "scanner/lex.rl"

 lex.te = ( lex.p)+1

	goto st79
tr86:
// line 72 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = NOT;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr89:
// line 60 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = LPAREN;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr90:
// line 61 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = RPAREN;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr91:
// line 64 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = TIMES; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr98:
// line 59 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = EQUALS;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr99:
// line 80 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = QUESTION; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr102:
// line 62 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = LBRACKET_SQUARE;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr103:
// line 63 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = RBRACKET_SQUARE;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr105:
// line 67 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = LBRACKET;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr107:
// line 69 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = RBRACKET;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr108:
// line 73 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = ONESCOMP; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr109:
// line 53 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 8, 64); tok = INT; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr110:
// line 71 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{tok = AND;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr111:
// line 76 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = LAND;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr112:
// line 51 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 10, 64); tok = INT;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr115:
// line 52 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_double, _ = strconv.ParseFloat(string(lex.data[lex.ts : lex.te]), 64); tok= DOUBLE; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr116:
// line 77 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{tok = COMMA;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr123:
// line 78 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = DATETIME; {( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr125:
// line 54 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.val_uint, _ = strconv.ParseUint(string(lex.data[lex.ts:lex.te]), 0, 64); tok = UINT;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr126:
// line 1 "NONE"

	switch  lex.act {
	case 9:
	{( lex.p) = ( lex.te) - 1
out.data = string(lex.data[lex.ts:lex.te]); tok = FLAG;{( lex.p)++;  lex.cs = 79; goto _out }}
	case 10:
	{( lex.p) = ( lex.te) - 1
out.data = string(lex.data[lex.ts:lex.te]); tok = IDENTIFIER;{( lex.p)++;  lex.cs = 79; goto _out }}
	}
	
	goto st79
tr129:
// line 58 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = IDENTIFIER;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr130:
// line 57 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = FLAG;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr133:
// line 70 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--
{tok = OR;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
tr134:
// line 74 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{tok = LOR;{( lex.p)++;  lex.cs = 79; goto _out }}
	goto st79
	st79:
// line 1 "NONE"

 lex.ts = 0

		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof79
		}
	st_case_79:
// line 1 "NONE"

 lex.ts = ( lex.p)

// line 505 "scanner/lex.go"
		switch  lex.data[( lex.p)] {
		case 0:
			goto st1
		case 32:
			goto tr85
		case 33:
			goto tr86
		case 34:
			goto st2
		case 38:
			goto st81
		case 40:
			goto tr89
		case 41:
			goto tr90
		case 42:
			goto tr91
		case 44:
			goto tr93
		case 47:
			goto st29
		case 48:
			goto tr95
		case 60:
			goto st51
		case 61:
			goto tr98
		case 63:
			goto tr99
		case 78:
			goto st97
		case 91:
			goto tr102
		case 93:
			goto tr103
		case 123:
			goto tr105
		case 124:
			goto st100
		case 125:
			goto tr107
		case 126:
			goto tr108
		}
		switch {
		case  lex.data[( lex.p)] < 49:
			switch {
			case  lex.data[( lex.p)] > 13:
				if 43 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 45 {
					goto st11
				}
			case  lex.data[( lex.p)] >= 9:
				goto tr85
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st95
				}
			case  lex.data[( lex.p)] >= 65:
				goto tr100
			}
		default:
			goto st93
		}
		goto st0
	st1:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof1
		}
	st_case_1:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st80
		}
		goto st0
st_case_0:
	st0:
		 lex.cs = 0
		goto _out
	st80:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof80
		}
	st_case_80:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st80
		}
		goto tr109
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
	st81:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof81
		}
	st_case_81:
		if  lex.data[( lex.p)] == 38 {
			goto tr111
		}
		goto tr110
	st11:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof11
		}
	st_case_11:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st82
		}
		goto st0
	st82:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof82
		}
	st_case_82:
		if  lex.data[( lex.p)] == 46 {
			goto st83
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st84
		}
		goto tr112
	st83:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof83
		}
	st_case_83:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st83
		}
		goto tr115
	st84:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof84
		}
	st_case_84:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st84
		}
		goto tr112
tr93:
// line 1 "NONE"

 lex.te = ( lex.p)+1

	goto st85
	st85:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof85
		}
	st_case_85:
// line 790 "scanner/lex.go"
		if  lex.data[( lex.p)] == 32 {
			goto st12
		}
		goto tr116
	st12:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof12
		}
	st_case_12:
		if  lex.data[( lex.p)] == 32 {
			goto st13
		}
		goto tr13
	st13:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof13
		}
	st_case_13:
		if  lex.data[( lex.p)] == 60 {
			goto st14
		}
		goto tr13
	st14:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof14
		}
	st_case_14:
		if  lex.data[( lex.p)] == 117 {
			goto st15
		}
		goto tr13
	st15:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof15
		}
	st_case_15:
		if  lex.data[( lex.p)] == 110 {
			goto st16
		}
		goto tr13
	st16:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof16
		}
	st_case_16:
		if  lex.data[( lex.p)] == 102 {
			goto st17
		}
		goto tr13
	st17:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof17
		}
	st_case_17:
		if  lex.data[( lex.p)] == 105 {
			goto st18
		}
		goto tr13
	st18:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof18
		}
	st_case_18:
		if  lex.data[( lex.p)] == 110 {
			goto st19
		}
		goto tr13
	st19:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof19
		}
	st_case_19:
		if  lex.data[( lex.p)] == 105 {
			goto st20
		}
		goto tr13
	st20:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof20
		}
	st_case_20:
		if  lex.data[( lex.p)] == 115 {
			goto st21
		}
		goto tr13
	st21:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof21
		}
	st_case_21:
		if  lex.data[( lex.p)] == 104 {
			goto st22
		}
		goto tr13
	st22:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof22
		}
	st_case_22:
		if  lex.data[( lex.p)] == 101 {
			goto st23
		}
		goto tr13
	st23:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof23
		}
	st_case_23:
		if  lex.data[( lex.p)] == 100 {
			goto st24
		}
		goto tr13
	st24:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof24
		}
	st_case_24:
		if  lex.data[( lex.p)] == 32 {
			goto st25
		}
		goto tr13
	st25:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof25
		}
	st_case_25:
		if  lex.data[( lex.p)] == 46 {
			goto st26
		}
		goto tr13
	st26:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof26
		}
	st_case_26:
		if  lex.data[( lex.p)] == 46 {
			goto st27
		}
		goto tr13
	st27:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof27
		}
	st_case_27:
		if  lex.data[( lex.p)] == 46 {
			goto st28
		}
		goto tr13
	st28:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof28
		}
	st_case_28:
		if  lex.data[( lex.p)] == 62 {
			goto tr30
		}
		goto tr13
	st29:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof29
		}
	st_case_29:
		if  lex.data[( lex.p)] == 42 {
			goto tr31
		}
		goto st0
tr95:
// line 1 "NONE"

 lex.te = ( lex.p)+1

	goto st86
	st86:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof86
		}
	st_case_86:
// line 968 "scanner/lex.go"
		switch  lex.data[( lex.p)] {
		case 46:
			goto st83
		case 120:
			goto st50
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st87
		}
		goto tr112
	st87:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof87
		}
	st_case_87:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st88
		}
		goto tr112
	st88:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof88
		}
	st_case_88:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto tr121
		}
		goto tr112
tr121:
// line 1 "NONE"

 lex.te = ( lex.p)+1

	goto st89
	st89:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof89
		}
	st_case_89:
// line 1008 "scanner/lex.go"
		if  lex.data[( lex.p)] == 45 {
			goto st30
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st84
		}
		goto tr112
	st30:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof30
		}
	st_case_30:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st31
		}
		goto tr32
	st31:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof31
		}
	st_case_31:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st32
		}
		goto tr32
	st32:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof32
		}
	st_case_32:
		if  lex.data[( lex.p)] == 45 {
			goto st33
		}
		goto tr32
	st33:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof33
		}
	st_case_33:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st34
		}
		goto tr32
	st34:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof34
		}
	st_case_34:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st35
		}
		goto tr32
	st35:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof35
		}
	st_case_35:
		if  lex.data[( lex.p)] == 84 {
			goto st36
		}
		goto tr32
	st36:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof36
		}
	st_case_36:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st37
		}
		goto tr32
	st37:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof37
		}
	st_case_37:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st38
		}
		goto tr32
	st38:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof38
		}
	st_case_38:
		if  lex.data[( lex.p)] == 58 {
			goto st39
		}
		goto tr32
	st39:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof39
		}
	st_case_39:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st40
		}
		goto tr32
	st40:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof40
		}
	st_case_40:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st41
		}
		goto tr32
	st41:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof41
		}
	st_case_41:
		if  lex.data[( lex.p)] == 58 {
			goto st42
		}
		goto tr32
	st42:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof42
		}
	st_case_42:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st43
		}
		goto tr32
	st43:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof43
		}
	st_case_43:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st44
		}
		goto tr32
	st44:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof44
		}
	st_case_44:
		if  lex.data[( lex.p)] == 43 {
			goto st45
		}
		goto tr32
	st45:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof45
		}
	st_case_45:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st46
		}
		goto tr32
	st46:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof46
		}
	st_case_46:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st47
		}
		goto tr32
	st47:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof47
		}
	st_case_47:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st48
		}
		goto tr32
	st48:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof48
		}
	st_case_48:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto tr51
		}
		goto tr32
tr51:
// line 1 "NONE"

 lex.te = ( lex.p)+1

	goto st90
	st90:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof90
		}
	st_case_90:
// line 1198 "scanner/lex.go"
		if  lex.data[( lex.p)] == 46 {
			goto st49
		}
		goto tr123
	st49:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof49
		}
	st_case_49:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st91
		}
		goto tr52
	st91:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof91
		}
	st_case_91:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st91
		}
		goto tr123
	st50:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof50
		}
	st_case_50:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st92
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st92
			}
		default:
			goto st92
		}
		goto tr32
	st92:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof92
		}
	st_case_92:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st92
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st92
			}
		default:
			goto st92
		}
		goto tr125
	st93:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof93
		}
	st_case_93:
		if  lex.data[( lex.p)] == 46 {
			goto st83
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st87
		}
		goto tr112
	st51:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof51
		}
	st_case_51:
		switch  lex.data[( lex.p)] {
		case 46:
			goto st52
		case 117:
			goto st65
		}
		goto st0
	st52:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof52
		}
	st_case_52:
		if  lex.data[( lex.p)] == 46 {
			goto st53
		}
		goto st0
	st53:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof53
		}
	st_case_53:
		if  lex.data[( lex.p)] == 46 {
			goto st54
		}
		goto st0
	st54:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof54
		}
	st_case_54:
		if  lex.data[( lex.p)] == 32 {
			goto st55
		}
		goto st0
	st55:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof55
		}
	st_case_55:
		switch {
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st56
			}
		case  lex.data[( lex.p)] >= 65:
			goto st56
		}
		goto st0
	st56:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof56
		}
	st_case_56:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st57
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
		goto st0
	st57:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof57
		}
	st_case_57:
		if  lex.data[( lex.p)] == 114 {
			goto st58
		}
		goto st0
	st58:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof58
		}
	st_case_58:
		if  lex.data[( lex.p)] == 101 {
			goto st59
		}
		goto st0
	st59:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof59
		}
	st_case_59:
		if  lex.data[( lex.p)] == 115 {
			goto st60
		}
		goto st0
	st60:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof60
		}
	st_case_60:
		if  lex.data[( lex.p)] == 117 {
			goto st61
		}
		goto st0
	st61:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof61
		}
	st_case_61:
		if  lex.data[( lex.p)] == 109 {
			goto st62
		}
		goto st0
	st62:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof62
		}
	st_case_62:
		if  lex.data[( lex.p)] == 101 {
			goto st63
		}
		goto st0
	st63:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof63
		}
	st_case_63:
		if  lex.data[( lex.p)] == 100 {
			goto st64
		}
		goto st0
	st64:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof64
		}
	st_case_64:
		if  lex.data[( lex.p)] == 62 {
			goto tr69
		}
		goto st0
	st65:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof65
		}
	st_case_65:
		if  lex.data[( lex.p)] == 110 {
			goto st66
		}
		goto st0
	st66:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof66
		}
	st_case_66:
		if  lex.data[( lex.p)] == 102 {
			goto st67
		}
		goto st0
	st67:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof67
		}
	st_case_67:
		if  lex.data[( lex.p)] == 105 {
			goto st68
		}
		goto st0
	st68:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof68
		}
	st_case_68:
		if  lex.data[( lex.p)] == 110 {
			goto st69
		}
		goto st0
	st69:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof69
		}
	st_case_69:
		if  lex.data[( lex.p)] == 105 {
			goto st70
		}
		goto st0
	st70:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof70
		}
	st_case_70:
		if  lex.data[( lex.p)] == 115 {
			goto st71
		}
		goto st0
	st71:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof71
		}
	st_case_71:
		if  lex.data[( lex.p)] == 104 {
			goto st72
		}
		goto st0
	st72:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof72
		}
	st_case_72:
		if  lex.data[( lex.p)] == 101 {
			goto st73
		}
		goto st0
	st73:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof73
		}
	st_case_73:
		if  lex.data[( lex.p)] == 100 {
			goto st74
		}
		goto st0
	st74:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof74
		}
	st_case_74:
		if  lex.data[( lex.p)] == 32 {
			goto st75
		}
		goto st0
	st75:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof75
		}
	st_case_75:
		if  lex.data[( lex.p)] == 46 {
			goto st76
		}
		goto st0
	st76:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof76
		}
	st_case_76:
		if  lex.data[( lex.p)] == 46 {
			goto st77
		}
		goto st0
	st77:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof77
		}
	st_case_77:
		if  lex.data[( lex.p)] == 46 {
			goto st78
		}
		goto st0
	st78:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof78
		}
	st_case_78:
		if  lex.data[( lex.p)] == 62 {
			goto tr83
		}
		goto st0
tr100:
// line 1 "NONE"

 lex.te = ( lex.p)+1

// line 58 "scanner/lex.rl"

 lex.act = 10;
	goto st94
tr127:
// line 1 "NONE"

 lex.te = ( lex.p)+1

// line 57 "scanner/lex.rl"

 lex.act = 9;
	goto st94
	st94:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof94
		}
	st_case_94:
// line 1571 "scanner/lex.go"
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr127
		case 42:
			goto st95
		case 95:
			goto tr127
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st95
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st95
				}
			case  lex.data[( lex.p)] >= 65:
				goto st96
			}
		default:
			goto tr127
		}
		goto tr126
	st95:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof95
		}
	st_case_95:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st95
		case 42:
			goto st95
		case 95:
			goto st95
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st95
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st95
			}
		default:
			goto st95
		}
		goto tr129
	st96:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof96
		}
	st_case_96:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st96
		case 95:
			goto st96
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto st96
			}
		case  lex.data[( lex.p)] >= 48:
			goto st96
		}
		goto tr130
	st97:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof97
		}
	st_case_97:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr127
		case 42:
			goto st95
		case 85:
			goto st98
		case 95:
			goto tr127
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st95
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st95
				}
			case  lex.data[( lex.p)] >= 65:
				goto st96
			}
		default:
			goto tr127
		}
		goto tr129
	st98:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof98
		}
	st_case_98:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st96
		case 76:
			goto st99
		case 95:
			goto st96
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto st96
			}
		case  lex.data[( lex.p)] >= 48:
			goto st96
		}
		goto tr130
	st99:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof99
		}
	st_case_99:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st96
		case 95:
			goto st96
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto st96
			}
		case  lex.data[( lex.p)] >= 48:
			goto st96
		}
		goto tr130
	st100:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof100
		}
	st_case_100:
		if  lex.data[( lex.p)] == 124 {
			goto tr134
		}
		goto tr133
tr135:
// line 46 "scanner/lex.rl"

 lex.te = ( lex.p)+1

	goto st101
tr137:
// line 46 "scanner/lex.rl"

 lex.te = ( lex.p)
( lex.p)--

	goto st101
tr138:
// line 47 "scanner/lex.rl"

 lex.te = ( lex.p)+1
{{goto st79 }}
	goto st101
	st101:
// line 1 "NONE"

 lex.ts = 0

		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof101
		}
	st_case_101:
// line 1 "NONE"

 lex.ts = ( lex.p)

// line 1760 "scanner/lex.go"
		if  lex.data[( lex.p)] == 42 {
			goto st102
		}
		goto tr135
	st102:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof102
		}
	st_case_102:
		if  lex.data[( lex.p)] == 47 {
			goto tr138
		}
		goto tr137
	st_out:
	_test_eof79:  lex.cs = 79; goto _test_eof
	_test_eof1:  lex.cs = 1; goto _test_eof
	_test_eof80:  lex.cs = 80; goto _test_eof
	_test_eof2:  lex.cs = 2; goto _test_eof
	_test_eof3:  lex.cs = 3; goto _test_eof
	_test_eof4:  lex.cs = 4; goto _test_eof
	_test_eof5:  lex.cs = 5; goto _test_eof
	_test_eof6:  lex.cs = 6; goto _test_eof
	_test_eof7:  lex.cs = 7; goto _test_eof
	_test_eof8:  lex.cs = 8; goto _test_eof
	_test_eof9:  lex.cs = 9; goto _test_eof
	_test_eof10:  lex.cs = 10; goto _test_eof
	_test_eof81:  lex.cs = 81; goto _test_eof
	_test_eof11:  lex.cs = 11; goto _test_eof
	_test_eof82:  lex.cs = 82; goto _test_eof
	_test_eof83:  lex.cs = 83; goto _test_eof
	_test_eof84:  lex.cs = 84; goto _test_eof
	_test_eof85:  lex.cs = 85; goto _test_eof
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
	_test_eof26:  lex.cs = 26; goto _test_eof
	_test_eof27:  lex.cs = 27; goto _test_eof
	_test_eof28:  lex.cs = 28; goto _test_eof
	_test_eof29:  lex.cs = 29; goto _test_eof
	_test_eof86:  lex.cs = 86; goto _test_eof
	_test_eof87:  lex.cs = 87; goto _test_eof
	_test_eof88:  lex.cs = 88; goto _test_eof
	_test_eof89:  lex.cs = 89; goto _test_eof
	_test_eof30:  lex.cs = 30; goto _test_eof
	_test_eof31:  lex.cs = 31; goto _test_eof
	_test_eof32:  lex.cs = 32; goto _test_eof
	_test_eof33:  lex.cs = 33; goto _test_eof
	_test_eof34:  lex.cs = 34; goto _test_eof
	_test_eof35:  lex.cs = 35; goto _test_eof
	_test_eof36:  lex.cs = 36; goto _test_eof
	_test_eof37:  lex.cs = 37; goto _test_eof
	_test_eof38:  lex.cs = 38; goto _test_eof
	_test_eof39:  lex.cs = 39; goto _test_eof
	_test_eof40:  lex.cs = 40; goto _test_eof
	_test_eof41:  lex.cs = 41; goto _test_eof
	_test_eof42:  lex.cs = 42; goto _test_eof
	_test_eof43:  lex.cs = 43; goto _test_eof
	_test_eof44:  lex.cs = 44; goto _test_eof
	_test_eof45:  lex.cs = 45; goto _test_eof
	_test_eof46:  lex.cs = 46; goto _test_eof
	_test_eof47:  lex.cs = 47; goto _test_eof
	_test_eof48:  lex.cs = 48; goto _test_eof
	_test_eof90:  lex.cs = 90; goto _test_eof
	_test_eof49:  lex.cs = 49; goto _test_eof
	_test_eof91:  lex.cs = 91; goto _test_eof
	_test_eof50:  lex.cs = 50; goto _test_eof
	_test_eof92:  lex.cs = 92; goto _test_eof
	_test_eof93:  lex.cs = 93; goto _test_eof
	_test_eof51:  lex.cs = 51; goto _test_eof
	_test_eof52:  lex.cs = 52; goto _test_eof
	_test_eof53:  lex.cs = 53; goto _test_eof
	_test_eof54:  lex.cs = 54; goto _test_eof
	_test_eof55:  lex.cs = 55; goto _test_eof
	_test_eof56:  lex.cs = 56; goto _test_eof
	_test_eof57:  lex.cs = 57; goto _test_eof
	_test_eof58:  lex.cs = 58; goto _test_eof
	_test_eof59:  lex.cs = 59; goto _test_eof
	_test_eof60:  lex.cs = 60; goto _test_eof
	_test_eof61:  lex.cs = 61; goto _test_eof
	_test_eof62:  lex.cs = 62; goto _test_eof
	_test_eof63:  lex.cs = 63; goto _test_eof
	_test_eof64:  lex.cs = 64; goto _test_eof
	_test_eof65:  lex.cs = 65; goto _test_eof
	_test_eof66:  lex.cs = 66; goto _test_eof
	_test_eof67:  lex.cs = 67; goto _test_eof
	_test_eof68:  lex.cs = 68; goto _test_eof
	_test_eof69:  lex.cs = 69; goto _test_eof
	_test_eof70:  lex.cs = 70; goto _test_eof
	_test_eof71:  lex.cs = 71; goto _test_eof
	_test_eof72:  lex.cs = 72; goto _test_eof
	_test_eof73:  lex.cs = 73; goto _test_eof
	_test_eof74:  lex.cs = 74; goto _test_eof
	_test_eof75:  lex.cs = 75; goto _test_eof
	_test_eof76:  lex.cs = 76; goto _test_eof
	_test_eof77:  lex.cs = 77; goto _test_eof
	_test_eof78:  lex.cs = 78; goto _test_eof
	_test_eof94:  lex.cs = 94; goto _test_eof
	_test_eof95:  lex.cs = 95; goto _test_eof
	_test_eof96:  lex.cs = 96; goto _test_eof
	_test_eof97:  lex.cs = 97; goto _test_eof
	_test_eof98:  lex.cs = 98; goto _test_eof
	_test_eof99:  lex.cs = 99; goto _test_eof
	_test_eof100:  lex.cs = 100; goto _test_eof
	_test_eof101:  lex.cs = 101; goto _test_eof
	_test_eof102:  lex.cs = 102; goto _test_eof

	_test_eof: {}
	if ( lex.p) == eof {
		switch  lex.cs {
		case 80:
			goto tr109
		case 81:
			goto tr110
		case 82:
			goto tr112
		case 83:
			goto tr115
		case 84:
			goto tr112
		case 85:
			goto tr116
		case 12:
			goto tr13
		case 13:
			goto tr13
		case 14:
			goto tr13
		case 15:
			goto tr13
		case 16:
			goto tr13
		case 17:
			goto tr13
		case 18:
			goto tr13
		case 19:
			goto tr13
		case 20:
			goto tr13
		case 21:
			goto tr13
		case 22:
			goto tr13
		case 23:
			goto tr13
		case 24:
			goto tr13
		case 25:
			goto tr13
		case 26:
			goto tr13
		case 27:
			goto tr13
		case 28:
			goto tr13
		case 86:
			goto tr112
		case 87:
			goto tr112
		case 88:
			goto tr112
		case 89:
			goto tr112
		case 30:
			goto tr32
		case 31:
			goto tr32
		case 32:
			goto tr32
		case 33:
			goto tr32
		case 34:
			goto tr32
		case 35:
			goto tr32
		case 36:
			goto tr32
		case 37:
			goto tr32
		case 38:
			goto tr32
		case 39:
			goto tr32
		case 40:
			goto tr32
		case 41:
			goto tr32
		case 42:
			goto tr32
		case 43:
			goto tr32
		case 44:
			goto tr32
		case 45:
			goto tr32
		case 46:
			goto tr32
		case 47:
			goto tr32
		case 48:
			goto tr32
		case 90:
			goto tr123
		case 49:
			goto tr52
		case 91:
			goto tr123
		case 50:
			goto tr32
		case 92:
			goto tr125
		case 93:
			goto tr112
		case 94:
			goto tr126
		case 95:
			goto tr129
		case 96:
			goto tr130
		case 97:
			goto tr129
		case 98:
			goto tr130
		case 99:
			goto tr130
		case 100:
			goto tr133
		case 102:
			goto tr137
		}
	}

	_out: {}
	}

// line 85 "scanner/lex.rl"


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
