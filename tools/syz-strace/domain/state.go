package domain

import (
	"fmt"
	. "github.com/google/syzkaller/prog"
	"sort"
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
	CurrentCallIdx int
}

type Allocation struct {
	num_bytes uint64
	arg Arg
}

type MemoryTracker struct {
	allocations map[int][]*Allocation
}

func NewTracker() *MemoryTracker {
	m := new(MemoryTracker)
	m.allocations = make(map[int][]*Allocation, 0)
	return m
}

func (m *MemoryTracker) AddAllocation(callidx int, size uint64, arg Arg) {
	switch arg.(type) {
	case *PointerArg:
	default:
		panic("Adding allocation for non pointer")
	}
	allocation := new(Allocation)
	allocation.arg = arg
	allocation.num_bytes = size
	if _, ok := m.allocations[callidx]; !ok {
		m.allocations[callidx] = make([]*Allocation, 0)
	}
	m.allocations[callidx] = append(m.allocations[callidx], allocation)
}

func (m *MemoryTracker) GetTotalMemoryNeeded() uint64{
	sum := uint64(0)
	for _, a := range m.allocations {
		for _, a1 := range a {
			sum += a1.num_bytes
		}
	}
	return sum
}

func (m *MemoryTracker) FillOutMemory() {
	offset := uint64(0)
	var pages uint64 = 0
	callIdxs := make([]int, 0)
	for key, _ := range m.allocations {
		callIdxs = append(callIdxs, key)
	}
	sort.Ints(callIdxs)
	for _, idx := range callIdxs {
		for _, a := range m.allocations[idx] {
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


func NewState(target *Target) *State {
	s := &State{
		Target:    target,
		Files:     make(map[string][]*Call),
		Resources: make(map[string][]Arg),
		Strings:   make(map[string]*Call),
		Tracker:   NewTracker(),
		CurrentCallIdx: 0,
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


