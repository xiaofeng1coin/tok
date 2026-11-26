module yongpai-wtoken

go 1.24

require (
	github.com/wnxd/microdbg v0.0.0-20250125163537-004a62dd30f9
	github.com/wnxd/microdbg-android v0.0.0-20250206122758-1659ff734876
	github.com/wnxd/microdbg-java v0.0.0-20250206041613-753119c42393
	github.com/wnxd/microdbg-unicorn v0.0.0-20250123152855-90a6da954f1b
)

require (
	github.com/Xuanwo/go-locale v1.1.2 // indirect
	github.com/ebitengine/purego v0.8.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20240909124753-873cd0166683 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/shirou/gopsutil/v4 v4.24.12 // indirect
	github.com/tklauser/go-sysconf v0.3.14 // indirect
	github.com/tklauser/numcpus v0.9.0 // indirect
	github.com/wnxd/microdbg-linux v0.0.0-20250125163704-40fa69dae17d // indirect
	github.com/wnxd/microdbg-loader v0.0.0-20250125085505-ff5705dfc5e6 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.mozilla.org/pkcs7 v0.9.0 // indirect
	golang.org/x/exp v0.0.0-20250128182459-e0ece0dbea4c // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
)

// 修复上游 socket stub 的 panic：模拟器网络探测失败时返回 ENOSYS，不中断画像链。
replace github.com/wnxd/microdbg-linux => ./third_party/microdbg-linux

// 扩大模拟器主线程栈到 8MB（原 80KB）：TigerTally 画像采集函数单帧 0x1A000，
// 原栈直接压栈越界 MEM_WRITE_UNMAPPED，中断整条 initEx 画像链。
replace github.com/wnxd/microdbg => ./third_party/microdbg

// 为线程控制块单独预留 TLS 槽空间，避免 pthread_setspecific(key 0) 覆盖 TLS 指针。
replace github.com/wnxd/microdbg-android => ./third_party/microdbg-android
