package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-strace/config"
	"github.com/google/syzkaller/tools/syz-strace/implicit-dependencies"
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
	case "implicit":
		d = NewImplicitDistiller(conf)
	case "trace":
		d = NewTraceDistiller(conf)
	case "random":
		d = NewRandomDistiller(conf)
	default:
		d = NewWeakDistiller(conf)
	}
	return
}

func NewRandomDistiller(conf config.DistillConfig) (d *RandomDistiller) {
	d = new(RandomDistiller)
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


func NewTraceDistiller(conf config.DistillConfig) (d *TraceDistiller) {
	d = new(TraceDistiller)
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

func NewImplicitDistiller(conf config.DistillConfig) (d *ImplicitDistiller) {
	d = new(ImplicitDistiller)
	dm := &DistillerMetadata{
		StatFile: conf.Stats,
		DistilledProgs: make([]*prog.Prog, 0),
		CallToSeed: make(map[*prog.Call]*domain.Seed, 0),
		CallToDistilledProg: make(map[*prog.Call]*prog.Prog, 0),
		CallToIdx: make(map[*prog.Call]int, 0),
		UpstreamDependencyGraph: make(map[*domain.Seed]map[int]map[prog.Arg][]prog.Arg, 0),
		DownstreamDependents: make(map[*domain.Seed]map[int]bool, 0),
	}
	impl_deps := implicit_dependencies.LoadImplicitDependencies(conf.ImplicitDepsFile)
	d.DistillerMetadata = dm
	d.impl_deps = *impl_deps
	return
}