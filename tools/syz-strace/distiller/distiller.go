package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-strace/config"
)

type Distiller interface {
	Distill([]*prog.Prog) []*prog.Prog
	Add(domain.Seeds)
	Stats(domain.Seeds)
}

type StrongDistiller struct {
	*DistillerMetadata
}

func NewDistiller(conf config.DistillConfig) (d Distiller){
	switch (conf.Type) {
	case "weak":
		d = NewWeakDistiller(conf)
	case "strong":
		d = NewStrongDistiller(conf)
	default:
		d = NewWeakDistiller(conf)
	}
	return
}

func NewStrongDistiller(conf config.DistillConfig) (d *StrongDistiller) {
	d = new(StrongDistiller)
	dm := &DistillerMetadata{
		StatFile: conf.Stats,
		DistilledProgs: make([]*prog.Prog, 0),
		CallToSeed: make(map[*prog.Call]*domain.Seed, 0),
		CallToDistilledProg: make(map[*prog.Call]*prog.Prog, 0),
		CallToIdx: make(map[*prog.Call]int, 0),
		UpstreamDependencyGraph: make(map[*domain.Seed]map[int]map[prog.Arg][]prog.Arg, 0),
		DownstreamDependents: make(map[*domain.Seed]map[int]bool, 0),
	}
	d.DistillerMetadata = dm
	return
}

func NewWeakDistiller(conf config.DistillConfig) (d *WeakDistiller) {
	d = new(WeakDistiller)
	dm := &DistillerMetadata{
		StatFile: conf.Stats,
		DistilledProgs: make([]*prog.Prog, 0),
		CallToSeed: make(map[*prog.Call]*domain.Seed, 0),
		CallToDistilledProg: make(map[*prog.Call]*prog.Prog, 0),
		CallToIdx: make(map[*prog.Call]int, 0),
		UpstreamDependencyGraph: make(map[*domain.Seed]map[int]map[prog.Arg][]prog.Arg, 0),
		DownstreamDependents: make(map[*domain.Seed]map[int]bool, 0),
	}
	d.DistillerMetadata = dm
	return
}
