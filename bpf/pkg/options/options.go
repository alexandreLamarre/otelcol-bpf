package options

type CollectorOptions[T any] struct {
	EventCallback func(T) error
}

type CollectorOption[T any] func(*CollectorOptions[T])

func WithEventCallback[T any](cb func(T) error) CollectorOption[T] {
	return func(opts *CollectorOptions[T]) {
		opts.EventCallback = cb
	}
}

func NewCollectorOptions[T any](opts ...CollectorOption[T]) *CollectorOptions[T] {
	options := &CollectorOptions[T]{}
	for _, opt := range opts {
		opt(options)
	}
	return options
}
