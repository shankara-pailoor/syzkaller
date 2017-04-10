package domain

type WorkloadConfig struct {
	ExecutablePath string
	Iterations int
	FollowFork bool
	Args []string
	StraceOutPath string
	KcovOutPath string
	Name string
}