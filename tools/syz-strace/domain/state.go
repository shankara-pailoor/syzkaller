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

type Allocation struct {
	num_bytes uint64
	arg Arg
}

type MemoryTracker struct {
	allocations map[*Call][]*Allocation
}

func NewTracker() *MemoryTracker {
	m := new(MemoryTracker)
	m.allocations = make(map[*Call][]*Allocation, 0)
	return m
}

func (m *MemoryTracker) AddAllocation(call *Call, size uint64, arg Arg) {
	switch arg.(type) {
	case *PointerArg:
	default:
		panic("Adding allocation for non pointer")
	}
	allocation := new(Allocation)
	allocation.arg = arg
	allocation.num_bytes = size
	if _, ok := m.allocations[call]; !ok {
		m.allocations[call] = make([]*Allocation, 0)
	}
	m.allocations[call] = append(m.allocations[call], allocation)
}

func (m *MemoryTracker) FillOutMemory(prog *Prog) {
	offset := uint64(0)


	for _, call := range prog.Calls {
		pages := uint64(0)
		if _, ok := m.allocations[call]; !ok {
			continue
		}
		for _, a := range m.allocations[call] {
			switch arg := a.arg.(type) {
			case *PointerArg:
				switch arg.Type().(type) {
				case *VmaType:
					pages = a.num_bytes % PageSize + 1
				default:
					pages = 0
				}
				arg.PageIndex = uint64(offset/PageSize)
				arg.PageOffset = int(offset % PageSize)
				arg.PagesNum = pages
				offset += a.num_bytes
			default:
				panic("Pointer Arg Failed")
			}
		}

	}
}

func (m *MemoryTracker) GetTotalMemoryNeeded(prog *Prog) uint64{
	sum := uint64(0)
	for _, call := range prog.Calls {
		if _, ok := m.allocations[call]; !ok {
			continue
		}
		for _, a := range m.allocations[call] {
			sum += a.num_bytes
		}
	}
	return sum
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


