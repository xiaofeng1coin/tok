package main

import (
	"context"
	"log"
	"unsafe"

	"github.com/wnxd/microdbg/debugger"
)

// linkerSymbols 通过公开的 ModuleManager.Load 注册一个虚拟模块，导出 Android linker
// 私有符号 __loader_dladdr。microdbg-android 内部符号表只注册了 shared_globals/dlopen/
// dlsym 等少数符号，TigerTally 延迟重定位解析 __loader_dladdr 失败会直接 panic，
// 中断整条 initEx 画像链，所以必须在加载 TigerTally 之前补上该符号。
type linkerSymbols struct {
	dbg      debugger.Debugger
	ctrl     debugger.ControlHandler
	addr     uint64
	nameAddr map[uint64]uint64 // 模块基址 → dli_fname 字符串内存，复用避免每次调用泄漏
}

// registerLinkerSymbols 在 pkg.LoadModule 之前调用。
func registerLinkerSymbols(dbg debugger.Debugger) (*linkerSymbols, error) {
	s := &linkerSymbols{dbg: dbg, nameAddr: make(map[uint64]uint64)}
	ctrl, err := dbg.AddControl(s.handleControl, nil)
	if err != nil {
		return nil, err
	}
	s.ctrl = ctrl
	s.addr = ctrl.Addr()
	dbg.Load(s)
	return s, nil
}

func (s *linkerSymbols) Close() error {
	for _, addr := range s.nameAddr {
		_ = s.dbg.MemFree(addr)
	}
	s.nameAddr = nil
	if s.ctrl != nil {
		_ = s.ctrl.Close()
		s.ctrl = nil
	}
	return nil
}

// handleControl 统一入口：dladdr 任何异常都降级为返回 0，不 panic 打断画像链。
func (s *linkerSymbols) handleControl(ctx debugger.Context, _ any) {
	result := int32(0)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("__loader_dladdr 执行异常（按失败返回 0）: %v", r)
			result = 0
		}
		_ = ctx.RetWrite(result)
		_ = ctx.Return()
	}()
	if s.dladdr(ctx) {
		result = 1
	}
}

// dladdr 按 bionic 语义实现：addr 命中已加载模块时填写 Dl_info 的 dli_fname/dli_fbase，
// dli_sname/dli_saddr 置空（与 bionic 找不到更近符号时一致），返回是否命中。
func (s *linkerSymbols) dladdr(ctx debugger.Context) bool {
	var address, info uintptr
	if err := ctx.ArgExtract(debugger.Calling_Default, &address, &info); err != nil {
		return false
	}
	if info == 0 {
		return false
	}
	dbg := ctx.Debugger()
	module, err := dbg.FindModuleByAddr(uint64(address))
	if err != nil {
		return false
	}
	fname, err := s.moduleFName(module)
	if err != nil {
		return false
	}
	base := module.BaseAddr()
	var null uint64
	ptrSize := dbg.PointerSize()
	infoPtr := ctx.ToPointer(uint64(info))
	if err := infoPtr.MemWritePtr(ptrSize, unsafe.Pointer(&fname)); err != nil {
		return false
	}
	if err := infoPtr.Add(ptrSize).MemWritePtr(ptrSize, unsafe.Pointer(&base)); err != nil {
		return false
	}
	if err := infoPtr.Add(2 * ptrSize).MemWritePtr(ptrSize, unsafe.Pointer(&null)); err != nil {
		return false
	}
	if err := infoPtr.Add(3 * ptrSize).MemWritePtr(ptrSize, unsafe.Pointer(&null)); err != nil {
		return false
	}
	log.Printf("__loader_dladdr 命中模块 %s（基址 0x%x）", module.Name(), base)
	return true
}

// moduleFName 分配并缓存模块名字符串；真机 dladdr 返回完整 so 路径，
// 这里用模块名并确保带 .so 后缀，满足 SDK 对 libxxx.so 子串的校验。
func (s *linkerSymbols) moduleFName(module debugger.Module) (uint64, error) {
	base := module.BaseAddr()
	if addr, ok := s.nameAddr[base]; ok {
		return addr, nil
	}
	name := module.Name()
	if name == "" {
		name = "libtiger_tally.so"
	}
	if len(name) < 3 || name[len(name)-3:] != ".so" {
		name += ".so"
	}
	data := append([]byte(name), 0)
	addr, err := s.dbg.MemAlloc(uint64(len(data)))
	if err != nil {
		return 0, err
	}
	if err := s.dbg.ToPointer(addr).MemWrite(data); err != nil {
		_ = s.dbg.MemFree(addr)
		return 0, err
	}
	s.nameAddr[base] = addr
	return addr, nil
}

// --- debugger.Module 虚拟模块实现：只提供符号查找，不占真实内存区域 ---

func (s *linkerSymbols) Name() string             { return "__loader_symbols" }
func (s *linkerSymbols) Region() (uint64, uint64) { return s.addr, 1 }
func (s *linkerSymbols) BaseAddr() uint64         { return s.addr }
func (s *linkerSymbols) EntryAddr() uint64        { return s.addr }

func (s *linkerSymbols) Init(ctx context.Context) error { return nil }

func (s *linkerSymbols) FindSymbol(name string) (uint64, error) {
	if name == "__loader_dladdr" {
		return s.addr, nil
	}
	return 0, debugger.ErrSymbolNotFound
}
