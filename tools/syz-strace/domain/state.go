package domain

import (
	"fmt"
	. "github.com/google/syzkaller/prog"
)

const (
	maxPages   = 4 << 10
	PageSize   = 4 << 10
	dataOffset = 512 << 20
)

type State struct {
	Target    *Target
	Files     map[string][]*Call
	Resources map[string][]Arg
	Strings   map[string]*Call
	Pages     [maxPages]bool
	Pages_    [maxPages]int
	Tracker	  *MemoryTracker
	CurrentCall *Call
}


func NewState(target *Target) *State {
	s := &State{
		Target:    target,
		Files:     make(map[string][]*Call),
		Resources: make(map[string][]Arg),
		Strings:   make(map[string]*Call),
		Tracker:   NewTracker(),
		CurrentCall: nil,
	}
	return s
}

func (s *State) Analyze(c *Call) {
	ForeachArgArray(&c.Args, c.Ret, func(arg, base Arg, _ *[]Arg) {
		switch typ := arg.Type().(type) {
		case *ResourceType:
			if typ.Dir() != DirIn {
				s.Resources[typ.Desc.Name] = append(s.Resources[typ.Desc.Name], arg)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *BufferType:
			a := arg.(*DataArg)
			if typ.Dir() != DirOut && len(a.Data) != 0 {
				switch typ.Kind {
				case BufferString:
					if len(typ.Values) > 0 {
						s.Strings[string(typ.Values[0])] = c
					}
				case BufferFilename:
					if _, ok := s.Files[string(a.Data)]; !ok {
						s.Files[string(a.Data)] = make([]*Call, 0)
					}
					s.Files[string(a.Data)] = append(s.Files[string(a.Data)], c)
				}
			}
		}
	})
	start, npages, mapped := s.Target.AnalyzeMmap(c)
	if npages != 0 {
		if start+npages > uint64(len(s.Pages)) {
			panic(fmt.Sprintf("address is out of bounds: page=%v len=%v bound=%v",
				start, npages, len(s.Pages)))
		}
		for i := uint64(0); i < npages; i++ {
			s.Pages[start+i] = mapped
		}
	}
}


