package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	gava "github.com/wnxd/microdbg-android/java"
	"github.com/wnxd/microdbg-android/wrapper"
	java "github.com/wnxd/microdbg-java"
	"yongpai-wtoken/tiger"
)

// genericNt10Method 在 newSigner 里取到 genericNt10（native 请求签名函数）后赋值；
// 赋值发生在 genericNt9（画像上报链）之前，且只在初始化阶段使用，无并发问题。
var genericNt10Method java.IMethod

type yongpaiHandler struct {
	tiger.Handler
}

func (h yongpaiHandler) DefineClass(ctx wrapper.FakeContext, name string) gava.FakeClass {
	if name == "java.util.Objects" {
		cls := ctx.DefineClass(name)
		cls.DefineMethod("hash", "([Ljava/lang/Object;)I", gava.Modifier_PUBLIC|gava.Modifier_STATIC).BindCall(func(obj java.IObject, args ...any) any {
			if len(args) == 0 || args[0] == nil {
				return java.JInt(0)
			}
			array, ok := args[0].(java.IObjectArray)
			if !ok {
				panic("[yongpaiHandler] Objects.hash argument is not an object array")
			}
			result := java.JInt(1)
			for _, element := range array.Elements() {
				if element != nil {
					result = 31*result + element.HashCode()
				}
			}
			return result
		})
		return cls
	}
	if name == "com.aliyun.TigerTally.common.utils.NetHelper" {
		cls := ctx.DefineClass(name)
		cls.DefineMethod("spr", "(Ljava/lang/String;Ljava/util/Map;Ljava/util/Map;)Ljava/lang/String;",
			gava.Modifier_PUBLIC|gava.Modifier_STATIC).BindCall(func(obj java.IObject, args ...any) any {
			return tallyReport(args)
		})
		return cls
	}
	if name == "com.aliyun.TigerTally.common.utils.LogUtil" {
		cls := ctx.DefineClass(name)
		for _, m := range []struct{ name, sig string }{
			{"d", "(Ljava/lang/String;)V"},
			{"e", "(Ljava/lang/String;)V"},
			{"e", "(Ljava/lang/String;Ljava/lang/Throwable;)V"},
			{"i", "(Ljava/lang/String;)V"},
			{"v", "(Ljava/lang/String;)V"},
			{"w", "(Ljava/lang/String;)V"},
		} {
			cls.DefineMethod(m.name, m.sig, gava.Modifier_PUBLIC|gava.Modifier_STATIC).BindCall(func(obj java.IObject, args ...any) any {
				return nil
			})
		}
		return cls
	}
	return h.Handler.DefineClass(ctx, name)
}

// fakeToGoMap 取出 fake HashMap 底层的 Go map；非 fake 对象返回 nil。
func fakeToGoMap(v any) gava.Map {
	if v == nil {
		return nil
	}
	obj, ok := v.(gava.FakeObject)
	if !ok {
		return nil
	}
	m, _ := obj.Value().(gava.Map)
	return m
}

// goEncode 与 NetHelper.encode 一致：URLEncoder.encode 规则（空格→%20、*→%2A、~ 不编码）。
func goEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// randomUUID 生成 UUIDv4 格式随机串，供 SignatureNonce 使用。
func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// tallyReport 复刻 TigerTally NetHelper.spr：构造公共参数 → genericNt10 计算签名 →
// HTTP 表单上报，返回 "code#base64(body)"（网络失败返回 "-1#base64(错误)"）。
// native 画像链依赖这个回调拿到服务端响应，所以走真实 HTTP 而不是假返回。
func tallyReport(args []any) any {
	target := args[0].(java.IString).String()
	headers := fakeToGoMap(args[1])
	params := fakeToGoMap(args[2])

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	form := url.Values{}
	form.Set("TimestampKeep", now)
	form.Set("SignatureNonce", randomUUID())
	if params != nil {
		delete(params, "Signature")
		for k, v := range params {
			key, _ := k.(java.IString)
			value, _ := v.(java.IString)
			if key == nil || value == nil || key.String() == "" || value.String() == "" {
				continue
			}
			name := key.String()
			text := value.String()
			form.Set(name, text)
			if name == "Version" && text == "2020-04-25" {
				form.Set("Timestamp", now)
			}
		}
	}

	// cs()：参数按 key 字典序拼成 query 串，签名原文 = "POST|/|encode(query)"。
	keys := make([]string, 0, len(form))
	for k := range form {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(goEncode(k))
		sb.WriteByte('=')
		sb.WriteString(goEncode(form.Get(k)))
	}
	signature := "null"
	if genericNt10Method != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("genericNt10 签名异常（Signature 置 null）: %v", r)
				}
			}()
			// cs() 原文：POST|encode("/")|encode(query)，两段之间各一个分隔符。
			raw := "POST|" + goEncode("/") + "|" + goEncode(sb.String())
			if res, ok := genericNt10Method.CallPrimitive(nil, gava.FakeString(raw)).(java.IString); ok {
				signature = res.String()
			}
		}()
	}
	form.Set("Signature", signature)

	body := form.Encode()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return gava.FakeString("-1#" + base64.StdEncoding.EncodeToString([]byte(err.Error())))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if headers != nil {
		for k, v := range headers {
			key, _ := k.(java.IString)
			val, _ := v.(java.IString)
			if key == nil || val == nil {
				continue
			}
			req.Header.Set(key.String(), val.String())
		}
	}
	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return gava.FakeString("-1#" + base64.StdEncoding.EncodeToString([]byte(err.Error())))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return gava.FakeString(fmt.Sprintf("%d#%s", resp.StatusCode, base64.StdEncoding.EncodeToString(data)))
}
