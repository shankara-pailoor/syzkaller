package domain

type Executor interface {
	RunStrace(wc WorkloadConfig) error
}
