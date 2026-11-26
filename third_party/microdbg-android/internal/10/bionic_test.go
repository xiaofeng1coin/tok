package android

import (
	"testing"
	"unsafe"

	"github.com/wnxd/microdbg/emulator"
)

func checkBionicLayout[P Pointer](t *testing.T, arch emulator.Arch, slots int, tlsSize P) {
	t.Helper()
	var layout staticTlsLayout[P]
	layout.reserve_bionic_tls(arch)
	pointerSize := P(unsafe.Sizeof(P(0)))
	tcbEnd := layout.offset_bionic_tcb_ + P(slots)*pointerSize
	if layout.offset_bionic_tls_ < tcbEnd {
		t.Fatalf("TCB与线程私有数据重叠: tcb=%#x..%#x tls=%#x", layout.offset_bionic_tcb_, tcbEnd, layout.offset_bionic_tls_)
	}
	if layout.offset_ < layout.offset_bionic_tls_+tlsSize || layout.overflowed_ {
		t.Fatalf("静态TLS分配范围无效: %+v", layout)
	}
	if layout.offset_bionic_tls_%pointerSize != 0 || layout.alignment_ < pointerSize {
		t.Fatalf("TLS没有按指针大小对齐: %+v", layout)
	}
	// 模拟 key_data[0].seq 的写入，TCB 首槽必须保持不变。
	memory := make([]byte, layout.offset_)
	memory[layout.offset_bionic_tcb_] = 0xa5
	memory[layout.offset_bionic_tls_] = 1
	if memory[layout.offset_bionic_tcb_] != 0xa5 {
		t.Fatal("写入线程私有数据覆盖了线程控制块")
	}
}

func TestBionicTLSRegionsDoNotOverlap(t *testing.T) {
	t.Run("ARM", func(t *testing.T) {
		checkBionicLayout[uint32](t, emulator.ARCH_ARM, ARM_BIONIC_TLS_SLOTS, uint32(unsafe.Sizeof(bionicTls32{})))
	})
	t.Run("ARM64", func(t *testing.T) {
		checkBionicLayout[uint64](t, emulator.ARCH_ARM64, ARM_BIONIC_TLS_SLOTS, uint64(unsafe.Sizeof(bionicTls64{})))
	})
	t.Run("X86", func(t *testing.T) {
		checkBionicLayout[uint32](t, emulator.ARCH_X86, X86_BIONIC_TLS_SLOTS, uint32(unsafe.Sizeof(bionicTls32{})))
	})
	t.Run("X86_64", func(t *testing.T) {
		checkBionicLayout[uint64](t, emulator.ARCH_X86_64, X86_BIONIC_TLS_SLOTS, uint64(unsafe.Sizeof(bionicTls64{})))
	})
}

func TestARM64BionicTLSLayoutABI(t *testing.T) {
	var layout staticTlsLayout[uint64]
	layout.reserve_bionic_tls(emulator.ARCH_ARM64)
	if layout.offset_bionic_tcb_ != 0 || layout.offset_bionic_tls_ != 0x48 {
		t.Fatalf("ARM64需要为9个指针槽预留0x48字节: %+v", layout)
	}
	if layout.offset_ != 0x2fe8 {
		t.Fatalf("ARM64静态TLS总大小=%#x，期望0x2fe8", layout.offset_)
	}
	var globals globals64
	if got := unsafe.Offsetof(globals.static_tls_layout); got != 0x450 {
		t.Fatalf("shared_globals布局发生变化: static_tls_layout=%#x", got)
	}
}
