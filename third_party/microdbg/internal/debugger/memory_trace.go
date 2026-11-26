package debugger

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/wnxd/microdbg/emulator"
	emu_arm64 "github.com/wnxd/microdbg/emulator/arm64"
)

type memoryFaultTrace string

// 必须在 asyncTask 切换任务之前复制现场，异步回调不能再直读活跃 CPU 作对照。
func captureMemoryFault(dbg Debugger, typ emulator.HookType, addr, size, value uint64) memoryFaultTrace {
	if os.Getenv("MICRODBG_TRACE_FAULT") != "1" {
		return ""
	}
	emu := dbg.Emulator()
	var out strings.Builder
	fmt.Fprintf(&out, "类型=%v 地址=0x%x 大小=%d 值=0x%x", typ, addr, size, value)
	readReg := func(name string, reg emulator.Reg) (uint64, bool) {
		v, err := emu.RegRead(reg)
		if err != nil {
			fmt.Fprintf(&out, " %s读取失败=%v", name, err)
			return 0, false
		}
		fmt.Fprintf(&out, " %s=0x%x", name, v)
		return v, true
	}
	readMemory := func(name string, addr, size uint64) {
		data, err := emu.MemRead(addr, size)
		if err != nil {
			fmt.Fprintf(&out, " %s读取失败=%v", name, err)
			return
		}
		fmt.Fprintf(&out, " %s@0x%x=%x", name, addr, data)
	}
	if pc, ok := readReg("PC", dbg.PC()); ok {
		if m, err := dbg.FindModuleByAddr(pc); err == nil {
			base, _ := m.Region()
			fmt.Fprintf(&out, " 模块=%s+0x%x", m.Name(), pc-base)
		}
		readMemory("指令", pc, 64)
	}
	readReg("SP", dbg.SP())
	if emu.Arch() == emulator.ARCH_ARM64 {
		regs := []struct {
			name string
			reg  emulator.Reg
		}{
			{"X0", emu_arm64.ARM64_REG_X0}, {"X1", emu_arm64.ARM64_REG_X1},
			{"X2", emu_arm64.ARM64_REG_X2}, {"X3", emu_arm64.ARM64_REG_X3},
			{"X8", emu_arm64.ARM64_REG_X8}, {"X9", emu_arm64.ARM64_REG_X9},
			{"X10", emu_arm64.ARM64_REG_X10}, {"X29", emu_arm64.ARM64_REG_X29},
			{"LR", emu_arm64.ARM64_REG_LR},
		}
		for _, reg := range regs {
			readReg(reg.name, reg.reg)
		}
		if tls, ok := readReg("TPIDR", emu_arm64.ARM64_REG_TPIDR_EL0); ok && tls >= 16 {
			readMemory("TLS负槽及槽表", tls-16, 96)
		}
	}
	return memoryFaultTrace(out.String())
}

func (t memoryFaultTrace) log(taskID int) {
	if t != "" {
		log.Printf("[同步故障现场] 任务=%d %s", taskID, t)
	}
}
