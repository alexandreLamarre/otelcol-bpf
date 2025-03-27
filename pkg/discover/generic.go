package discover

type Discoverer[T any] interface {
	Start() error
	Discovery(filterFunc func(T) bool) ([]T, error)
	Shutdown() error
}
