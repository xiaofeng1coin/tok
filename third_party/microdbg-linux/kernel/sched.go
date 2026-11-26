package kernel

import (
	"fmt"
	"log"
	"sync"
	"unsafe"

	linux "github.com/wnxd/microdbg-linux"
	"github.com/wnxd/microdbg/debugger"
	"github.com/wnxd/microdbg/emulator"
	emu_arm "github.com/wnxd/microdbg/emulator/arm"
	emu_arm64 "github.com/wnxd/microdbg/emulator/arm64"
	emu_x86 "github.com/wnxd/microdbg/emulator/x86"
)

type sched struct {
	tasks sync.Map
}

func (s *sched) clone(ctx linux.Context, flags int32, child_stack, parent_tid, tls, child_tid emuptr) int32 {
	const (
		CLONE_VM     = 0x00000100
		CLONE_VFORK  = 0x00004000
		CLONE_SETTLS = 0x00080000
	)
	// 调试插桩：打印 clone 参数与调用者模块，区分 bionic pthread_create 与
	// native 手工 clone，交付前移除。
	pc, _ := ctx.RegRead(ctx.PC())
	caller := "未知区域"
	if m, err := ctx.Debugger().FindModuleByAddr(pc); err == nil {
		base, _ := m.Region()
		caller = fmt.Sprintf("%s+0x%x", m.Name(), pc-base)
	}
	log.Printf("clone: flags=0x%x child_stack=0x%x tls=0x%x child_tid=0x%x 调用者=%s", uint32(flags), child_stack, tls, child_tid, caller)

	task, err := ctx.TaskFork()
	if err != nil {
		ctx.SetErrno(linux.EAGAIN)
		return -1
	}
	dbg := ctx.Debugger()
	taskCtx := task.Context()
	if child_stack == emunullptr {
		taskCtx.RetWrite(nil)
	} else {
		taskCtx.RegWrite(taskCtx.SP(), child_stack)
		var call struct{ fn, arg uintptr }
		dbg.MemExtract(child_stack, &call)
		err = dbg.CallTaskOf(task, uint64(call.fn))
		if err != nil {
			task.Close()
			ctx.SetErrno(linux.EAGAIN)
			return -1
		}
		taskCtx.ArgWrite(debugger.Calling_Default, call.arg)
	}
	if flags&CLONE_SETTLS != 0 {
		switch dbg.Arch() {
		case emulator.ARCH_ARM:
			taskCtx.RegWrite(emu_arm.ARM_REG_C13_C0_3, tls)
		case emulator.ARCH_ARM64:
			taskCtx.RegWrite(emu_arm64.ARM64_REG_TPIDR_EL0, tls)
		case emulator.ARCH_X86:
			taskCtx.RegWrite(emu_x86.X86_REG_GS, tls)
		case emulator.ARCH_X86_64:
			taskCtx.RegWrite(emu_x86.X86_REG_FS, tls)
		}
		// 保留线程创建时的实际 TLS 内容；读取失败不应被当作全零快照。
		if dbg.Arch() == emulator.ARCH_ARM64 && tls >= 8 {
			var snap [80]byte
			if err := ctx.ToPointer(tls-8).MemReadPtr(80, unsafe.Pointer(&snap)); err != nil {
				log.Printf("clone SETTLS: tls=0x%x 快照读取失败: %v", tls, err)
			} else {
				log.Printf("clone SETTLS: tls=0x%x 创建时快照=%x", tls, snap)
			}
		}
	}
	err = task.Run()
	if err != nil {
		task.Close()
		ctx.SetErrno(linux.EAGAIN)
		return -1
	}
	pid := int32(task.ID())
	if child_tid != emunullptr {
		ctx.ToPointer(child_tid).MemWritePtr(4, unsafe.Pointer(&pid))
	}
	if flags&CLONE_VFORK != 0 {
		<-task.Done()
		task.Close()
	} else {
		s.tasks.Store(pid, task)
		go func() {
			<-task.Done()
			s.tasks.Delete(pid)
			task.Close()
		}()
	}
	return pid
}

func (s *sched) execve(ctx linux.Context, filename, argv, envp emuptr) int32 {
	ctx.SetErrno(linux.ENOSYS)
	return -1
}
