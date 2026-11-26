package kernel

import (
	linux "github.com/wnxd/microdbg-linux"
)

type socket struct {
}

func (s *socket) socket(ctx linux.Context, domain, typ, protocol int32) int32 {
	// 模拟器不提供真实 socket；返回 ENOSYS 让 native 网络探测走失败分支，
	// 不能 panic 中断整条 TigerTally initEx 画像链。
	ctx.SetErrno(linux.ENOSYS)
	return -1
}
