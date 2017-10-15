package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-strace/implicit-dependencies"
)

type ImplicitDistiller struct {
	*DistillerMetadata
	impl_deps implicit_dependencies.ImplicitDependencies
}

func (d *ImplicitDistiller) Add(domain.Seeds) {
	return
}

func (d *ImplicitDistiller) Distill(progs []*prog.Prog) (distilled []*prog.Prog) {
	return
}
