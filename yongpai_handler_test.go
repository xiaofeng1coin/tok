package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	gava "github.com/wnxd/microdbg-android/java"
	java "github.com/wnxd/microdbg-java"
)

func TestReportSigningText(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
		want string
	}{
		{"空参数", url.Values{}, "POST&%2F&"},
		{"字典序", url.Values{"b": {"2"}, "a": {"1"}}, "POST&%2F&a%3D1%26b%3D2"},
		{"空格星号与波浪号", url.Values{"b": {"*~"}, "a": {"hello world"}}, "POST&%2F&a%3Dhello%2520world%26b%3D%252A~"},
		{"加号与百分号", url.Values{"a": {"+%"}}, "POST&%2F&a%3D%252B%2525"},
		{"中文", url.Values{"a": {"中"}}, "POST&%2F&a%3D%25E4%25B8%25AD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := tt.form.Encode()
			if got := reportSigningText(tt.form); got != tt.want {
				t.Errorf("与 Java NetHelper.cs 不一致: 得到 %q，期望 %q", got, tt.want)
			}
			if tt.form.Encode() != before {
				t.Fatal("构造签名原文不应修改参数")
			}
		})
	}
}

// 只替换 genericNt10 的调用入口并计数，不初始化模拟器，也不执行原生签名。
// 嵌入接口以保留其它方法；离线测试不应访问这些方法。
type offlineReportMethodSpy struct {
	java.IMethod
	calls int32
}

func (m *offlineReportMethodSpy) CallPrimitive(_ java.IObject, _ ...any) any {
	atomic.AddInt32(&m.calls, 1)
	return gava.FakeString("unexpected-offline-signature")
}

func TestTallyReportOffline(t *testing.T) {
	const envName = "WTOKEN_ALLOW_REPORT_NETWORK"
	tests := []struct {
		name  string
		value string
		unset bool
	}{
		{name: "默认未设置", unset: true},
		{name: "空值"},
		{name: "显式设置0", value: "0"},
		{name: "非法文本", value: "invalid"},
		{name: "布尔文本不启用", value: "true"},
		{name: "其它数字不启用", value: "2"},
		{name: "带空白的1不启用", value: " 1 "},
	}
	// 环境变量和 genericNt10Method 都是进程全局状态，不能并行运行。
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setenv 负责恢复原值；默认分支另外移除变量，验证真正未设置的情况。
			t.Setenv(envName, tt.value)
			if tt.unset {
				if err := os.Unsetenv(envName); err != nil {
					t.Fatalf("移除测试环境变量失败：%v", err)
				}
			}

			var requests int32
			// 仅在实际执行测试时监听本机。即使离线开关回归，也只会访问此端点。
			// 端点明确返回失败，不能用它伪造真实服务端上报成功。
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&requests, 1)
				http.Error(w, "离线测试不应发出请求", http.StatusServiceUnavailable)
			}))
			t.Cleanup(server.Close)

			method := &offlineReportMethodSpy{}
			previousMethod := genericNt10Method
			genericNt10Method = method
			t.Cleanup(func() {
				genericNt10Method = previousMethod
			})

			// 提供合法的本机目标和参数，避免把参数错误误判为离线保护生效。
			result := tallyReport([]any{
				gava.FakeString(server.URL),
				gava.MapOf(gava.Map{}),
				gava.MapOf(gava.Map{
					gava.FakeString("Version"): gava.FakeString("2020-04-25"),
				}),
			})
			if got := atomic.LoadInt32(&method.calls); got != 0 {
				t.Errorf("离线模式不应调用 genericNt10，实际调用 %d 次", got)
			}
			if got := atomic.LoadInt32(&requests); got != 0 {
				t.Errorf("离线模式不应发送网络请求，本机端点实际收到 %d 次", got)
			}

			text, ok := result.(java.IString)
			if !ok || text == nil {
				t.Fatalf("上报结果应为 Java 字符串，实际类型为 %T", result)
			}
			parts := strings.SplitN(text.String(), "#", 2)
			if len(parts) != 2 {
				t.Fatalf("上报结果应为状态码与Base64消息：得到 %q", text.String())
			}
			if parts[0] != "-1" {
				t.Errorf("离线模式必须明确返回失败码 -1，实际为 %q", parts[0])
			}
			message, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("离线错误说明不是有效的Base64：%v", err)
			}
			const wantMessage = "offline: profile reporting is disabled"
			if string(message) != wantMessage {
				t.Errorf("离线错误说明不符：得到 %q，期望 %q", message, wantMessage)
			}
		})
	}
}
