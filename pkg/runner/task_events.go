package runner

import "context"

type TaskStats struct {
	CommandAttempts int `json:"command_attempts"`
	Reused          int `json:"reused"`
	Executed        int `json:"executed"`
	Failed          int `json:"failed"`
	Pending         int `json:"pending"`
}
type TaskEvent struct {
	Tool, State string
	Inputs      int
}
type taskObserverKey struct{}
type refreshKey struct{}

func WithTaskObserver(ctx context.Context, fn func(TaskEvent)) context.Context {
	return context.WithValue(ctx, taskObserverKey{}, fn)
}
func RecordTask(ctx context.Context, tool, state string, inputs int) {
	if fn, ok := ctx.Value(taskObserverKey{}).(func(TaskEvent)); ok {
		fn(TaskEvent{tool, state, inputs})
	}
}
func WithRefresh(ctx context.Context, refresh bool) context.Context {
	return context.WithValue(ctx, refreshKey{}, refresh)
}
func IsRefresh(ctx context.Context) bool { v, _ := ctx.Value(refreshKey{}).(bool); return v }
