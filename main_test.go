package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidWToken(t *testing.T) {
	// 样本仅验证格式，不是真实签名，也不表示服务端认可。
	body := "1730000000" + "00" + strings.Repeat("a", 96) + "YWJjZA=="
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "0004完整格式", value: "0004_" + body + "_fHw=_c2Vzc2lvbg==", want: true},
		{name: "0005降级格式", value: "0005_" + body + "_fHw=_", want: true},
		{name: "空值", value: ""},
		{name: "异常消息", value: "java.lang.IllegalStateException: 原生签名失败"},
		{name: "错误前缀", value: "0003_" + body + "_fHw=_"},
		{name: "前缀缺少下划线", value: "0004" + body + "_fHw=_"},
		{name: "缺少分隔段", value: "0004_" + body},
		{name: "错误分隔段", value: "0005_" + body + "_fHw_"},
		{name: "主体过短", value: "0004_short_fHw=_"},
		// 前缀占 5 字节，主体占 95 字节时分隔段下标恰为 100，仍须拒绝。
		{name: "0004主体长度边界不足", value: "0004_" + strings.Repeat("a", 95) + "_fHw=_"},
		{name: "0005主体长度边界不足", value: "0005_" + strings.Repeat("a", 95) + "_fHw=_"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validWToken(tt.value); got != tt.want {
				t.Errorf("格式判断错误：得到 %v，期望 %v（样本长度=%d）", got, tt.want, len(tt.value))
			}
		})
	}
}

func TestReadPayload(t *testing.T) {
	binary := []byte{0x00, 0x01, 0x7f, 0x80, 0xff, '\r', '\n'}
	chinese := []byte("甬派中文签名测试\n")
	jsonPayload := func(payload []byte) []byte {
		return []byte(`{"data":"` + base64.StdEncoding.EncodeToString(payload) + `"}`)
	}
	// 独立固定为 1MiB，防止实现上限变化时边界测试随之变化而漏报。
	const limit = 1 << 20
	atLimit := bytes.Repeat([]byte("x"), limit)
	tests := []struct {
		name        string
		contentType string
		body        []byte
		want        []byte
		wantErr     string
	}{
		{
			name:        "原始二进制字节保持不变",
			contentType: "application/octet-stream",
			body:        binary,
			want:        binary,
		},
		{
			name:        "空原始输入",
			contentType: "application/octet-stream",
			want:        []byte{},
		},
		{
			name:        "中文原始字节",
			contentType: "text/plain; charset=utf-8",
			body:        chinese,
			want:        chinese,
		},
		{
			name: "未声明JSON时保留原始内容与空白",
			body: []byte(" \t{\"data\":\"YWJj\"}\r\n"),
			want: []byte(" \t{\"data\":\"YWJj\"}\r\n"),
		},
		{
			name:        "JSON解码二进制Base64",
			contentType: "application/json",
			body:        jsonPayload(binary),
			want:        binary,
		},
		{
			name:        "JSON解码中文并兼容类型大小写及字符集",
			contentType: "Application/JSON; charset=utf-8",
			body:        jsonPayload(chinese),
			want:        chinese,
		},
		{
			name:        "JSON空data解码为空字节",
			contentType: "application/json",
			body:        jsonPayload(nil),
			want:        []byte{},
		},
		{
			name:        "原始输入恰好1MiB",
			contentType: "application/octet-stream",
			body:        atLimit,
			want:        atLimit,
		},
		{
			name:        "JSON空请求体",
			contentType: "application/json",
			wantErr:     "JSON 请求体无效",
		},
		{
			name:        "JSON语法错误",
			contentType: "application/json",
			body:        []byte(`{"data":`),
			wantErr:     "JSON 请求体无效",
		},
		{
			name:        "JSON缺少data",
			contentType: "application/json",
			body:        []byte(`{}`),
			wantErr:     "JSON 请求体缺少 data 字段",
		},
		{
			name:        "JSON的data为null",
			contentType: "application/json",
			body:        []byte(`{"data":null}`),
			wantErr:     "JSON 请求体缺少 data 字段",
		},
		{
			name:        "JSON整体为null",
			contentType: "application/json",
			body:        []byte(`null`),
			wantErr:     "JSON 请求体缺少 data 字段",
		},
		{
			name:        "JSON的data类型错误",
			contentType: "application/json",
			body:        []byte(`{"data":123}`),
			wantErr:     "JSON 请求体无效",
		},
		{
			name:        "JSON非法Base64",
			contentType: "application/json",
			body:        []byte(`{"data":"%%%"}`),
			wantErr:     "data 字段不是有效的 Base64",
		},
		{
			name:        "原始输入超过1MiB",
			contentType: "application/octet-stream",
			body:        bytes.Repeat([]byte("x"), limit+1),
			wantErr:     "请求体读取失败或超过 1MiB",
		},
		{
			// Base64 本身合法；上限针对整个请求体，而不是解码后的长度。
			name:        "JSON请求体超过1MiB",
			contentType: "application/json",
			body:        []byte(`{"data":"` + strings.Repeat("A", limit) + `"}`),
			wantErr:     "JSON 请求体无效",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 这里只构造内存请求，不监听端口，也不发出网络请求。
			request := httptest.NewRequest(http.MethodPost, "/wtoken", bytes.NewReader(tt.body))
			if tt.contentType != "" {
				request.Header.Set("Content-Type", tt.contentType)
			}
			payload, err := readPayload(httptest.NewRecorder(), request)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("期望错误 %q，实际未返回错误", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Errorf("错误说明不符：得到 %q，期望 %q", err.Error(), tt.wantErr)
				}
				if payload != nil {
					t.Errorf("失败时不应返回载荷，实际返回 %d 字节", len(payload))
				}
				return
			}
			if err != nil {
				t.Fatalf("读取载荷失败：%v", err)
			}
			if !bytes.Equal(payload, tt.want) {
				t.Errorf("载荷字节与预期不一致：得到 %d 字节，期望 %d 字节", len(payload), len(tt.want))
			}
		})
	}
}
