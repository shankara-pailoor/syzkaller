package domain

import (
	"github.com/google/syzkaller/sys"
	. "github.com/google/syzkaller/prog"
	"fmt"
)

const (
	maxPages = 4 << 10
	PageSize = 4 << 10
	dataOffset = 512 << 20
)

type State struct {
	Files     map[string][]*Call
	Resources map[string][]Arg
	Strings   map[string]*Call
	Pages     [maxPages]bool
}

func NewState() *State {
	s := &State{
		Files:     make(map[string][]*Call),
		Resources: make(map[string][]Arg),
		Strings:   make(map[string]*Call),
	}
	return s
}

func (s *State) Analyze(c *Call) {
	ForeachArgArray(&c.Args, c.Ret, func(arg, base Arg, _ *[]Arg) {
		switch a := arg.Type().(type) {
		case *sys.ResourceType:
			if a.Dir() != sys.DirIn {
				s.Resources[a.Name()] = append(s.Resources[a.Name()], arg)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *sys.BufferType:
			data_arg := arg.(*DataArg)
			if a.Dir() != sys.DirOut {
				switch a.Kind {
				case sys.BufferString:
					fmt.Printf("ADDING STRING\n")
					if len(a.Values) > 0 {
						s.Strings[string(a.Values[0])] = c
					}
				case sys.BufferFilename:
					fmt.Printf("ADDING FILENAME\n")
					if _, ok := s.Files[string(data_arg.Data)]; !ok {
						s.Files[string(data_arg.Data)] = make([]*Call, 0)
					}
					s.Files[string(data_arg.Data)] = append(s.Files[string(data_arg.Data)], c)
				}
			}
		}
	})
	switch c.Meta.Name {
	case "mmap":
		// Filter out only very wrong arguments.
		length := c.Args[1].(*ConstArg)
		if length.Val == 0 {
			break
		}
		flags := c.Args[3].(*ConstArg)
		fd := c.Args[4].(*ResultArg)
		if flags.Val&sys.MAP_ANONYMOUS == 0 && fd.Val == sys.InvalidFD {
			break
		}
		s.Addressable(c.Args[0].(*PointerArg), length, true)
	case "munmap":
		s.Addressable(c.Args[0].(*PointerArg), c.Args[1].(*ConstArg), false)
	case "mremap":
		s.Addressable(c.Args[4].(*PointerArg), c.Args[2].(*ConstArg), true)
	case "io_submit":
		if arr := c.Args[2].(*PointerArg).Res; arr != nil {
			for _, ptr := range arr.(*GroupArg).Inner {
				p := ptr.(*PointerArg)
				if p.Res != nil && p.Res.Type().Name() == "iocb" {
					s.Resources["iocbptr"] = append(s.Resources["iocbptr"], ptr)
				}
			}
		}
	}
}

func (s *State) Addressable(addr *PointerArg, size *ConstArg, ok bool) {
	sizePages := size.Val / PageSize
	if addr.PageIndex+sizePages > uint64(len(s.Pages)) {
		panic(fmt.Sprintf("address is out of bounds: page=%v len=%v bound=%v\naddr: %+v\nsize: %+v",
			addr.PageIndex, sizePages, len(s.Pages), addr, size))
	}
	for i := uint64(0); i < sizePages; i++ {
		s.Pages[addr.PageIndex+i] = ok
	}
}
