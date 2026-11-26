package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
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
			gava.Modifier_PUBLIC|gava.Modifier_STATIC).BindCall(func(obj java.IObject, args ...any) (result any) {
			// 画像链里 spr 任何内部异常都不能打断 genericNt9，按 Java 版语义返回上报失败。
			defer func() {
				if r := recover(); r != nil {
					log.Printf("NetHelper.spr 执行异常（按上报失败处理）: %v", r)
					result = gava.FakeString("-1#" + base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(r))))
				}
			}()
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

// reportSigningText 与 NetHelper.cs 一致：排序、逐项编码后，再编码整段查询串。
func reportSigningText(form url.Values) string {
	keys := make([]string, 0, len(form))
	for key := range form {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, key := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(goEncode(key))
		sb.WriteByte('=')
		sb.WriteString(goEncode(form.Get(key)))
	}
	return "POST&" + goEncode("/") + "&" + goEncode(sb.String())
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
// 默认禁止外发；显式设置 WTOKEN_ALLOW_REPORT_NETWORK=1 才允许真实上报。
// 离线返回失败，不伪造服务端响应或成功状态。
func tallyReport(args []any) any {
	if os.Getenv("WTOKEN_ALLOW_REPORT_NETWORK") != "1" {
		log.Printf("画像上报已阻断（离线模式）")
		return gava.FakeString("-1#" + base64.StdEncoding.EncodeToString([]byte("offline: profile reporting is disabled")))
	}
	if len(args) != 3 {
		return gava.FakeString("-1#" + base64.StdEncoding.EncodeToString([]byte("invalid report arguments")))
	}
	str, _ := args[0].(java.IString)
	if str == nil || str.String() == "" {
		return gava.FakeString("-1#" + base64.StdEncoding.EncodeToString([]byte("empty target")))
	}
	target := str.String()
	headers := fakeToGoMap(args[1])
	params := fakeToGoMap(args[2])

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	form := url.Values{}
	form.Set("TimestampKeep", now)
	form.Set("SignatureNonce", randomUUID())
	if params != nil {
		delete(params, gava.FakeString("Signature"))
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

	// Java 的 SIGN_SPLIT_SYMBOL 是 &，不能用 | 替代。
	signature := "null"
	if genericNt10Method != nil {
		// genericNt10 是 native 方法，此刻模拟器正在执行 genericNt9（JNI 回调进入本函数），
		// 属于模拟器重入。unicorn 实例非线程安全，绝不能跨 goroutine 调用，
		// 必须在当前 goroutine 同步调用；若运行时不支持重入会 panic，
		// 由 spr 入口 recover 接住按上报失败处理，服务不崩。
		raw := reportSigningText(form)
		if res, ok := genericNt10Method.CallPrimitive(nil, gava.FakeString(raw)).(java.IString); ok {
			signature = res.String()
		}
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
