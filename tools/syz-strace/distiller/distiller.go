package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"sort"
	"fmt"
)

type Distiller interface {
	MinCover(domain.Seeds) *prog.Prog
}

type DefaultDistiller struct {

}

func (d *DefaultDistiller) MinCover(seeds domain.Seeds) *prog.Prog {
	fmt.Printf("Computing Min Cover with %d seeds", len(seeds))
	seenIps := make(map[uint64]bool)
	sort.Reverse(seeds)
	contributing_progs := 0
	for _, seed := range seeds {
		var ips int = seed.Contributes(seenIps)
		if ips > 0 {
			fmt.Printf("Seed: %s contributes: %d ips", seed.Call.Meta.Name, ips)
			contributing_progs += 1
		}
	}
	fmt.Printf("Total Contributing: %d, out of %d", contributing_progs, len(seeds))
	return nil
}