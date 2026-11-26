package debugger

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	api "github.com/wnxd/microdbg/debugger"
	"github.com/wnxd/microdbg/emulator"
	arm64 "github.com/wnxd/microdbg/emulator/arm64"
)

type traceTestEmulator struct {
	emulator.Emulator
	regs   map[emulator.Reg]uint64
	memory map[uint64][]byte
}

func (e *traceTestEmulator) Arch() emulator.Arch { return emulator.ARCH_ARM64 }
func (e *traceTestEmulator) RegRead(reg emulator.Reg) (uint64, error) {
	value, ok := e.regs[reg]
	if !ok {
		return 0, errors.New("测试寄存器不可读")
	}
	return value, nil
}
func (e *traceTestEmulator) MemRead(addr, size uint64) ([]byte, error) {
	data, ok := e.memory[addr]
	if !ok || uint64(len(data)) < size {
		return nil, errors.New("测试内存不可读")
	}
	return append([]byte(nil), data[:size]...), nil
}

type traceTestDebugger struct {
	Debugger
	emu emulator.Emulator
}

func (d *traceTestDebugger) Emulator() emulator.Emulator { return d.emu }
func (d *traceTestDebugger) PC() emulator.Reg            { return arm64.ARM64_REG_PC }
func (d *traceTestDebugger) SP() emulator.Reg            { return arm64.ARM64_REG_SP }
func (d *traceTestDebugger) FindModuleByAddr(uint64) (api.Module, error) {
	return nil, api.ErrModuleNotFound
}

func TestMemoryFaultTraceCapturesActualBuffer(t *testing.T) {
	t.Setenv("MICRODBG_TRACE_FAULT", "1")
	emu := &traceTestEmulator{
		regs: map[emulator.Reg]uint64{
			arm64.ARM64_REG_PC: 0x1000, arm64.ARM64_REG_SP: 0x3000,
			arm64.ARM64_REG_TPIDR_EL0: 0x2010,
		},
		memory: map[uint64][]byte{
			0x1000: make([]byte, 64),
			0x2000: bytes.Repeat([]byte{0x7b}, 96),
		},
	}
	trace := captureMemoryFault(&traceTestDebugger{emu: emu}, emulator.HOOK_TYPE_MEM_READ_UNMAPPED, 1, 8, 0)
	text := string(trace)
	if !strings.Contains(text, "TLS负槽及槽表@0x2000="+strings.Repeat("7b", 96)) {
		t.Fatalf("诊断必须打印实际读取的数组，而不是另一个全零数组: %s", text)
	}
	if !strings.Contains(text, "X0读取失败=") {
		t.Fatalf("读取失败必须显式报告: %s", text)
	}
	// 保存现场后调度器可切换 CPU 和共享内存，已捕获内容不能随之改变。
	emu.regs[arm64.ARM64_REG_PC] = 0x9999
	clear(emu.memory[0x2000])
	if string(trace) != text {
		t.Fatal("故障快照受后续上下文切换影响")
	}
}

func TestMemoryFaultTraceDoesNotInventZeroSnapshot(t *testing.T) {
	t.Setenv("MICRODBG_TRACE_FAULT", "1")
	emu := &traceTestEmulator{
		regs: map[emulator.Reg]uint64{arm64.ARM64_REG_TPIDR_EL0: 0x2010},
	}
	text := string(captureMemoryFault(&traceTestDebugger{emu: emu}, emulator.HOOK_TYPE_MEM_READ_UNMAPPED, 1, 8, 0))
	if !strings.Contains(text, "TLS负槽及槽表读取失败=") || strings.Contains(text, "TLS负槽及槽表@") {
		t.Fatalf("读取失败不能被记录为有效内存: %s", text)
	}
}

func TestMemoryFaultTraceDisabled(t *testing.T) {
	t.Setenv("MICRODBG_TRACE_FAULT", "0")
	if got := captureMemoryFault(nil, emulator.HOOK_TYPE_MEM_READ_UNMAPPED, 1, 8, 0); got != "" {
		t.Fatalf("关闭诊断时不应访问模拟器: %s", got)
	}
}
