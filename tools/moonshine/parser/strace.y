%{
package parser

import (
    "fmt"
    "github.com/google/syzkaller/tools/moonshine/types"
)
%}

%start syscall

%union {
    data string
    val_int int64
    val_double float64
    val_uint uint64
    val_field *types.Field
    val_fields []*types.Field
    val_call *types.Call
    val_int_type *types.IntType
    val_identifiers []*types.BufferType
    val_buf_type *types.BufferType
    val_struct_type *types.StructType
    val_array_type *types.ArrayType
    val_pointer_type *types.PointerType
    val_flag_type *types.FlagType
    val_binop *types.Binop
    val_rel_expr_type *types.RelationalExpression
    val_type types.Type
    val_types []types.Type
    val_syscall *types.Syscall
}

%token <data> STRING_LITERAL IDENTIFIER FLAG DATETIME
%token <val_int> INT
%token <val_uint> UINT
%token <val_double> DOUBLE
%type <val_field> field
%type <val_identifiers> identifiers
%type <val_fields> fields
%type <val_int_type> int_type
%type <val_buf_type> buf_type
%type <val_struct_type> struct_type
%type <val_array_type> array_type
%type <val_flag_type> flag_type
%type <val_binop> binop
%type <val_rel_expr_type> rel_expr_type
%type <val_call> call_type
%type <val_type> type
%type <val_pointer_type> pointer_type
%type <val_types> types
%type <val_syscall> syscall

%token STRING_LITERAL IDENTIFIER FLAG INT UINT DOUBLE OR AND LOR LAND NOT LSHIFT RSHIFT COMMA LBRACKET RBRACKET LBRACKET_SQUARE RBRACKET_SQUARE LPAREN RPAREN EQUALS

%nonassoc FLAG
%nonassoc NOFLAG

%%
syscall:
    INT IDENTIFIER LPAREN types RPAREN EQUALS INT %prec NOFLAG{
                                                        $$ = types.NewSyscall($1, $2, $4, $7);
                                                        yylex.(*lexer).result = $$;}
    | INT IDENTIFIER LPAREN types RPAREN EQUALS UINT %prec NOFLAG {
                                                        $$ = types.NewSyscall($1, $2, $4, int64($7));
                                                        yylex.(*lexer).result = $$}
    | INT IDENTIFIER LPAREN types RPAREN EQUALS INT FLAG LPAREN identifiers RPAREN {
                                                              $$ = types.NewSyscall($1, $2, $4, $7);
                                                              yylex.(*lexer).result = $$;}
    | INT IDENTIFIER LPAREN types RPAREN EQUALS UINT FLAG LPAREN identifiers RPAREN {
                                                              $$ = types.NewSyscall($1, $2, $4, int64($7));
                                                              yylex.(*lexer).result = $$}
    | INT IDENTIFIER LPAREN types RPAREN EQUALS INT LPAREN flag_type RPAREN {
                                                                  $$ = types.NewSyscall($1, $2, $4, $7);
                                                                  yylex.(*lexer).result = $$;}
    | INT IDENTIFIER LPAREN types RPAREN EQUALS UINT LPAREN flag_type RPAREN {
                                                                  $$ = types.NewSyscall($1, $2, $4, int64($7));
                                                                  yylex.(*lexer).result = $$}



types:
    type {types := make([]types.Type, 0); types = append(types, $1); $$ = types;}
    | type COMMA types {$3 = append([]types.Type{$1}, $3...); $$ = $3;}

type:
    buf_type {$$ = $1}
    | int_type {$$ = $1}
    | pointer_type {$$ = $1}
    | array_type {$$ = $1}
    | struct_type {$$ = $1}
    | flag_type {$$ = $1}
    | call_type {$$ = $1}
    | rel_expr_type {$$ = $1}

call_type:
    IDENTIFIER LPAREN types RPAREN {$$ = types.NewCallType($1, $3)}

pointer_type:
    AND UINT EQUALS type {$$ = types.NewPointerType($2, $4)}

array_type:
    LBRACKET_SQUARE types RBRACKET_SQUARE {arr := types.NewArrayType($2); $$ = arr}

struct_type:
    LBRACKET fields RBRACKET {$$ = types.NewStructType($2)}

fields:
    field {fields := make([]*types.Field, 0); fields = append(fields, $1); $$ = fields;}
    | field COMMA fields {$3 = append([]*types.Field{$1}, $3...); $$ = $3;}

field:
    IDENTIFIER EQUALS type {$$ = types.NewField($1, $3);}

buf_type:
    STRING_LITERAL {fmt.Printf("buffer type: %s\n", $1); $$ = types.NewBufferType($1)}
    | DATETIME {fmt.Printf("datetime: %s\n", $1); $$ = types.NewBufferType($1)}

rel_expr_type:
    binop {$$ = types.NewRelationalExpression($1); fmt.Printf("%s\n", $$.String());}

binop:
    binop OR flag_type {$$ = types.NewBinop(types.NewRelationalExpression($1), types.OR, $3)}
    | binop OR int_type {$$ = types.NewBinop(types.NewRelationalExpression($1), types.OR, $3)}
    | int_type OR int_type {$$ = types.NewBinop($1, types.OR, $3)}
    | flag_type OR flag_type {$$ = types.NewBinop($1, types.OR, $3)}
    | flag_type OR int_type {$$ = types.NewBinop($1, types.OR, $3)}
    | int_type OR flag_type {$$ = types.NewBinop($1, types.OR, $3)}

int_type:
      INT {$$ = types.NewIntType($1)}
    | UINT {$$ = types.NewIntType(int64($1))}

flag_type:
      FLAG {$$ = types.NewFlagType($1)}

identifiers:
    IDENTIFIER {ids := make([]*types.BufferType, 0); ids = append(ids, types.NewBufferType($1)); $$ = ids}
    | IDENTIFIER identifiers {$2 = append($2, types.NewBufferType($1)); $$ = $2}

