package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	android "github.com/wnxd/microdbg-android"
	android10 "github.com/wnxd/microdbg-android/10"
	"github.com/wnxd/microdbg-android/extend"
	gava "github.com/wnxd/microdbg-android/java"
	"github.com/wnxd/microdbg-android/wrapper"
	java "github.com/wnxd/microdbg-java"
	unicorn "github.com/wnxd/microdbg-unicorn"
	"github.com/wnxd/microdbg/emulator"
	"github.com/wnxd/microdbg/filesystem"
	"yongpai-wtoken/tiger"
)

const defaultAppKey = "iu3Svq54EsA9X6eAvnOu9L6Hnp1_c8CIRnPntFXgNr3dOoYsyIql5W3K6Qrz3M6FT3L_B6YeHQhEDvcWGdoU0pLLdJTTI9bNmL6G08waclB4Ywo90Y-Rh8lWco_UVo85oWeovQH84zUkgajrvPzSYjgs8_cgSXXJCSIInZpnXQ8="

const maxPayloadSize = 1 << 20

// signer 保存已初始化的模拟器和签名方法；原生调用不能并发，统一用互斥锁串行化。
type signer struct {
	mu     sync.Mutex
	emu    emulator.Emulator
	art    android.Runtime
	module android.Module
	method java.IMethod
}

type signRequest struct {
	Data *string `json:"data"`
}

type signResponse struct {
	WToken string `json:"wToken"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func randomBase64(length int) string {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		log.Fatalf("生成随机设备标识失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// newSigner 初始化 ARM64 模拟器、Android 10 运行时、TigerTally 模块，并做一次启动预热。
func newSigner(apkPath, runtimeDir, appKey string) (*signer, error) {
	log.Printf("开始初始化模拟器，APK=%s，运行时=%s", apkPath, runtimeDir)
	started := time.Now()

	emu, err := unicorn.New(emulator.ARCH_ARM64)
	if err != nil {
		return nil, fmt.Errorf("创建 ARM64 模拟器失败: %w", err)
	}
	cleanupEmu := true
	defer func() {
		if cleanupEmu {
			_ = emu.Close()
		}
	}()

	env := wrapper.NewFake(yongpaiHandler{})
	art, err := android10.NewRuntime(emu,
		android10.WithApkPath(apkPath),
		android10.WithRuntimeDir(runtimeDir),
		android10.WithJNIEnv(env),
	)
	if err != nil {
		return nil, fmt.Errorf("创建 Android 10 运行时失败: %w", err)
	}
	cleanupArt := true
	defer func() {
		if cleanupArt {
			_ = art.Close()
		}
	}()

	pkg := art.Package()
	if err := art.LinkFS(pkg.CodePath(), filesystem.SysFileFS(apkPath)); err != nil {
		return nil, fmt.Errorf("挂载 APK 文件系统失败: %w", err)
	}

	cf := env.ClassFactory()
	ex := extend.Define(art, cf)
	ex.SharedPreference("altt", tiger.SharedPreference{
		"TT_COOKIEID":     gava.FakeString(randomBase64(64)),
		"TT_COOKIEID_NEW": gava.FakeString(randomBase64(64)),
	})

	module, err := pkg.LoadModule(context.Background(), art, "tiger_tally")
	if err != nil {
		return nil, fmt.Errorf("加载 tiger_tally 失败: %w", err)
	}
	cleanupModule := true
	defer func() {
		if cleanupModule {
			_ = module.Close()
		}
	}()

	if _, err := module.CallOnLoad(context.Background()); err != nil {
		return nil, fmt.Errorf("调用 JNI_OnLoad 失败: %w", err)
	}

	cls := cf.GetClass("com.aliyun.TigerTally.t.B")
	if cls == nil {
		return nil, errors.New("未找到 TigerTally 签名类")
	}
	initMethod := cls.GetMethod("genericNt1", "(Ljava/util/Map;)I")
	if initMethod == nil {
		return nil, errors.New("未找到 genericNt1")
	}
	initResult := initMethod.CallPrimitive(nil, gava.MapOf(gava.Map{
		gava.FakeString("AppKey"):      gava.FakeString(appKey),
		gava.FakeString("CollectType"): gava.FakeString("0"),
	}))
	if initResult != java.JInt(0) {
		return nil, fmt.Errorf("genericNt1 初始化失败: %v", initResult)
	}

	method := cls.GetMethod("genericNt3", "(I[B)Ljava/lang/String;")
	if method == nil {
		return nil, errors.New("未找到 genericNt3")
	}

	s := &signer{emu: emu, art: art, module: module, method: method}
	// 使用已知可出签名的测试字节做启动预热，空切片在原生桥接上可能被视为 nil 数组。
	if _, err := s.sign([]byte("hello")); err != nil {
		return nil, fmt.Errorf("启动预热失败: %w", err)
	}

	cleanupEmu = false
	cleanupArt = false
	cleanupModule = false
	log.Printf("模拟器初始化完成，耗时 %s", time.Since(started).Round(time.Millisecond))
	return s, nil
}

func validWToken(value string) bool {
	if !strings.HasPrefix(value, "0005_") || !strings.HasSuffix(value, "_fHw=_") {
		return false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(value, "0005_"), "_fHw=_")
	// 主体固定包含 10 位时间 + 2 位状态 + 96 位签名段 + Base64 密文，最短也应超过 100 字符。
	return len(body) > 100
}

// sign 调用 genericNt3 生成 wToken；服务日志只记录长度和格式布尔值，不输出 token 本体。
func (s *signer) sign(payload []byte) (token string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			token = ""
			err = fmt.Errorf("原生签名执行异常: %v", recovered)
		}
	}()

	result := s.method.CallPrimitive(nil, java.JInt(1), gava.BytesOf(payload))
	value, ok := result.(java.IString)
	if !ok {
		return "", fmt.Errorf("genericNt3 返回类型异常: %T", result)
	}
	if !validWToken(value.String()) {
		return "", fmt.Errorf(
			"genericNt3 未返回格式正确的 wToken（长度=%d，前缀=%v，后缀=%v）",
			len(value.String()),
			strings.HasPrefix(value.String(), "0005_"),
			strings.HasSuffix(value.String(), "_fHw=_"),
		)
	}
	return value.String(), nil
}

func (s *signer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.module != nil {
		_ = s.module.Close()
	}
	if s.art != nil {
		_ = s.art.Close()
	}
	if s.emu != nil {
		_ = s.emu.Close()
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func readPayload(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadSize)
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		var request signRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&request); err != nil {
			return nil, errors.New("JSON 请求体无效")
		}
		if request.Data == nil {
			return nil, errors.New("JSON 请求体缺少 data 字段")
		}
		payload, err := base64.StdEncoding.DecodeString(*request.Data)
		if err != nil {
			return nil, errors.New("data 字段不是有效的 Base64")
		}
		return payload, nil
	}
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, errors.New("请求体读取失败或超过 1MiB")
	}
	return payload, nil
}

// handleSign 提供 POST /wtoken 接口：请求体直接作为 genericNt3 的 UTF-8 字节输入。
func (s *signer) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "仅支持 POST"})
		return
	}
	payload, err := readPayload(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	started := time.Now()
	token, err := s.sign(payload)
	if err != nil {
		log.Printf("签名失败，输入字节数=%d，耗时=%s，原因=%v", len(payload), time.Since(started).Round(time.Millisecond), err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "签名失败"})
		return
	}
	log.Printf("签名成功，输入字节数=%d，耗时=%s", len(payload), time.Since(started).Round(time.Millisecond))
	writeJSON(w, http.StatusOK, signResponse{WToken: token})
}

func main() {
	port := envOr("PORT", "4097")
	apkPath := envOr("APK_PATH", "apk/yongpai.apk")
	runtimeDir := envOr("RUNTIME_DIR", "runtime/10.zip")
	appKey := envOr("APP_KEY", defaultAppKey)

	s, err := newSigner(apkPath, runtimeDir, appKey)
	if err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
	defer s.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/wtoken", s.handleSign)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "仅支持 GET"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("关闭 HTTP 服务失败: %v", err)
		}
	}()

	if _, err := strconv.Atoi(port); err != nil {
		log.Fatalf("PORT 不是有效数字: %s", port)
	}
	log.Printf("wToken 签名服务已监听端口 %s", port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务异常: %v", err)
	}
}
