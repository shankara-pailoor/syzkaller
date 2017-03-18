package syz_structs

type Stack []rune

func (s *Stack) Push(v rune) {
	append(s, v)
}

func (s *Stack) Pop() rune {
	l := len(s)
	if l == 0 {
		panic("popping an empty stack")
	}
	r := s[l-1]
	s = s[:l-1]
	return r
}

