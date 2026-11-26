package linux

import (
	"github.com/wnxd/microdbg/debugger"
)

type Context interface {
	debugger.Context
	Errno() Errno
	SetErrno(err Errno)
}

type context struct {
	debugger.Context
	dbg Debugger
}

func NewContext(ctx debugger.Context, dbg Debugger) Context {
	return &context{ctx, dbg}
}

func (ctx *context) Errno() Errno {
	return ctx.dbg.Errno()
}

func (ctx *context) SetErrno(err Errno) {
	ctx.dbg.SetErrno(err)
}

// CancelCause 转发到底层任务的取消接口：exit/exit_group 需要按任务语义
// 正常终止当前任务（如 popen 子任务 _exit(127)），而不是 panic。
func (ctx *context) CancelCause(err error) {
	if t, ok := ctx.Context.(interface{ CancelCause(error) }); ok {
		t.CancelCause(err)
	}
}
