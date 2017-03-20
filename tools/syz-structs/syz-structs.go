package syz_structs

type Stack []byte

func (s Stack) Push(c byte) Stack {
	return append(s, c)
}

func (s Stack) Pop() (Stack, byte) {
	l := len(s)
	if l == 0 {
		panic("popping an empty stack")
	}
	r := s[l-1]
	s = s[:l-1]
	return s, r
}

