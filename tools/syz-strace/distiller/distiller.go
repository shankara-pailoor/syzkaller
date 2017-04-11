package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"sort"
	"fmt"
)

type Distiller interface {
	MinCover(domain.Seeds) *prog.Prog
	Contributes(domain.Seed, map[uint64]bool) int
}

type DefaultDistiller struct {

}

func (d *DefaultDistiller) MinCover(seeds domain.Seeds) *prog.Prog {
	fmt.Printf("Computing Min Cover with %d seeds\n", len(seeds))
	seenIps := make(map[uint64]bool)
	sort.Sort(sort.Reverse(seeds))
	contributing_progs := 0
	for _, seed := range seeds {
		var ips int = d.Contributes(seed, seenIps)
		if ips > 0 {
			fmt.Printf("Seed: %s contributes: %d ips out of its total of: %d\n", seed.Call.Meta.Name, ips, len(seed.Cover))
			contributing_progs += 1
		}
	}
	fmt.Printf("Total Contributing: %d, out of %d", contributing_progs, len(seeds))
	return nil
}

func (d *DefaultDistiller) Contributes(seed *domain.Seed, seenIps map[uint64]bool) int {
	total := 0
	for _, ip := range seed.Cover {
		if _, ok := seenIps[ip]; !ok {
			seenIps[ip] = true
			total += 1
		}
	}
	return total
}
