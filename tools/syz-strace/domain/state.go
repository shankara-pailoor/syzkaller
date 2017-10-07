package domain

import (
	"fmt"
	. "github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
	"sort"
)

const (
	maxPages   = 4 << 10
	PageSize   = 4 << 10
	dataOffset = 512 << 20
)

type State struct {
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
				case *sys.VmaType:
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


func NewState() *State {
	s := &State{
		Files:     make(map[string][]*Call),
		Resources: make(map[string][]Arg),
		Strings:   make(map[string]*Call),
		Tracker:   NewTracker(),
		CurrentCallIdx: 0,
	}
	return s
}

func (s *State) Analyze(c *Call) {
	fmt.Printf("Call Args: %v\n", c.Args)
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

func (s *State) AllocateMemory(size int) (page_nums []int, offset int, should_allocate bool, err error) {
	needed_pages, remainder_size := int(size/PageSize), int(size%PageSize)
	fmt.Printf("Needed Pages: %d, remainder_size: %d\n", needed_pages, remainder_size)
	if needed_pages < 1 {
		for i := 0; i < maxPages; i++ {
			if PageSize-s.Pages_[i] > remainder_size {
				page_nums, offset = []int{i}, s.Pages_[i]
				if s.Pages_[i] > 0 {
					should_allocate = false
				} else {
					should_allocate = true
				}
				s.Pages_[i] = offset + remainder_size
				fmt.Printf("Found Page: %d, old_offset: %d, new_offset: %d, size: %d, allocating: %b", i, offset, s.Pages_[i], size, should_allocate)
				return
			}
		}
	} else {
		should_allocate = true
		if remainder_size > 0 {
			needed_pages += 1
		}
		for i := 0; i < maxPages-needed_pages; i++ {
			free := true
			fmt.Printf("HERE: %d\n", i)
			for j := 0; j < needed_pages; j++ {
				if s.Pages_[i+j] < 0 || s.Pages_[i+j] > 0 {
					fmt.Printf("Finding pages: %d has offset %d", i+j, s.Pages_[i+j])
					free = false
					break
				}
			}
			if !free {
				continue
			}

			for j := 0; j < needed_pages; j++ {
				page_nums = append(page_nums, i+j)
				if j == needed_pages-1 && remainder_size > 0 {
					s.Pages_[i+j] = remainder_size
					offset = remainder_size
				} else {
					offset = 0
					s.Pages_[i+j] = -1 //marking memory as fully occupied
				}
			}
			return
		}

	}
	fmt.Printf("OUT OF MEMORY\n")
	err = fmt.Errorf("Out of memory\n")
	return
}

