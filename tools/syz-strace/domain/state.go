package domain

import (
	"github.com/google/syzkaller/sys"
	. "github.com/google/syzkaller/prog"
	"fmt"
)

const (
	maxPages = 4 << 10
)

type State struct {
	Files     map[string][]*Call
	Resources map[string][]*Arg
	Strings   map[string]*Call
	Pages     [maxPages]bool
}

func NewState() *State {
	s := &State{
		Files:     make(map[string][]*Call),
		Resources: make(map[string][]*Arg),
		Strings:   make(map[string]*Call),
	}
	return s
}

func (s *State) Analyze(c *Call) {
	ForeachArgArray(&c.Args, c.Ret, func(arg, base *Arg, _ *[]*Arg) {
		switch typ := arg.Type.(type) {
		case *sys.ResourceType:
			if arg.Type.Dir() != sys.DirIn {
				s.Resources[typ.Desc.Name] = append(s.Resources[typ.Desc.Name], arg)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *sys.BufferType:
			if arg.Type.Dir() != sys.DirOut && arg.Kind == ArgData && len(arg.Data) != 0 {
				switch typ.Kind {
				case sys.BufferString:
					fmt.Printf("ADDING STRING\n")
					s.Strings[string(arg.Data)] = c
				case sys.BufferFilename:
					fmt.Printf("ADDING FILENAME\n")
					if _, ok := s.Files[string(arg.Data)]; !ok {
						s.Files[string(arg.Data)] = make([]*Call, 0)
					}
					s.Files[string(arg.Data)] = append(s.Files[string(arg.Data)], c)
				}
			}
		}
	})
	switch c.Meta.Name {
	case "mmap":
		// Filter out only very wrong arguments.
		length := c.Args[1]
		if length.AddrPage == 0 && length.AddrOffset == 0 {
			break
		}
		if flags, fd := c.Args[4], c.Args[3]; flags.Val&sys.MAP_ANONYMOUS == 0 && fd.Kind == ArgConst && fd.Val == sys.InvalidFD {
			break
		}
		s.Addressable(c.Args[0], length, true)
	case "munmap":
		s.Addressable(c.Args[0], c.Args[1], false)
	case "mremap":
		s.Addressable(c.Args[4], c.Args[2], true)
	case "io_submit":
		if arr := c.Args[2].Res; arr != nil {
			for _, ptr := range arr.Inner {
				if ptr.Kind == ArgPointer {
					if ptr.Res != nil && ptr.Res.Type.Name() == "iocb" {
						s.Resources["iocbptr"] = append(s.Resources["iocbptr"], ptr)
					}
				}
			}
		}
	}
}

func (s *State) Addressable(addr, size *Arg, ok bool) {
	if addr.Kind != ArgPointer || size.Kind != ArgPageSize {
		panic("mmap/munmap/mremap args are not pages")
	}
	n := size.AddrPage
	if size.AddrOffset != 0 {
		n++
	}
	if addr.AddrPage+n > uintptr(len(s.Pages)) {
		panic(fmt.Sprintf("address is out of bounds: page=%v len=%v (%v, %v) bound=%v, addr: %+v, size: %+v",
			addr.AddrPage, n, size.AddrPage, size.AddrOffset, len(s.Pages), addr, size))
	}
	for i := uintptr(0); i < n; i++ {
		s.Pages[addr.AddrPage+i] = ok
	}
}
