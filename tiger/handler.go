package tiger

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"log"
	"strings"
	"sync"

	android "github.com/wnxd/microdbg-android"
	gava "github.com/wnxd/microdbg-android/java"
	"github.com/wnxd/microdbg-android/wrapper"
	java "github.com/wnxd/microdbg-java"
)

type Handler struct {
}

// loggedMethods 记录已提示过的未实现调用，避免日志重复刷屏。
var (
	loggedMu      sync.Mutex
	loggedMethods = map[string]bool{}
)

func logOnce(kind, className, name, sig string) {
	key := kind + "|" + className + "|" + name + sig
	loggedMu.Lock()
	defer loggedMu.Unlock()
	if loggedMethods[key] {
		return
	}
	loggedMethods[key] = true
	log.Printf("未实现的 Java %s，类=%s，方法=%s%s（按返回类型零值兜底）", kind, className, name, sig)
}

// defaultReturn 按 JNI 签名的返回类型生成兜底实现：
// void/对象返回 null，基础类型返回零值。画像链里任何未实现的辅助方法
// 调到这里都不会 panic，native 侧拿到 null/零值走自己的判空分支。
func defaultReturn(sig string) func(java.IObject, ...any) any {
	ret := sig[strings.LastIndexByte(sig, ')')+1:]
	switch ret {
	case "Z":
		return func(java.IObject, ...any) any { return java.JBoolean(false) }
	case "B":
		return func(java.IObject, ...any) any { return java.JByte(0) }
	case "C":
		return func(java.IObject, ...any) any { return java.JChar(0) }
	case "S":
		return func(java.IObject, ...any) any { return java.JShort(0) }
	case "I":
		return func(java.IObject, ...any) any { return java.JInt(0) }
	case "J":
		return func(java.IObject, ...any) any { return java.JLong(0) }
	case "F":
		return func(java.IObject, ...any) any { return java.JFloat(0) }
	case "D":
		return func(java.IObject, ...any) any { return java.JDouble(0) }
	default:
		return func(java.IObject, ...any) any { return nil }
	}
}

// buildStaticValues Build/Build$VERSION 静态字段真机值表（类名|字段名 → 值）。
// 设备信息取自真机抓包（model=PLQ110、Android 15、SDK 36），
// 让模拟器画像里的设备信息与请求头保持一致。
var buildStaticValues = map[string]any{
	"android.os.Build|MANUFACTURER":                    gava.FakeString("HUAWEI"),
	"android.os.Build|BRAND":                           gava.FakeString("HUAWEI"),
	"android.os.Build|MODEL":                           gava.FakeString("PLQ110"),
	"android.os.Build|DEVICE":                          gava.FakeString("PLQ110"),
	"android.os.Build|PRODUCT":                         gava.FakeString("PLQ110"),
	"android.os.Build|HARDWARE":                        gava.FakeString("kirin900"),
	"android.os.Build|BOARD":                           gava.FakeString("PLQ110"),
	"android.os.Build|DISPLAY":                         gava.FakeString("AP4A.250105.002"),
	"android.os.Build|ID":                              gava.FakeString("AP4A.250105.002"),
	"android.os.Build|TYPE":                            gava.FakeString("user"),
	"android.os.Build|TAGS":                            gava.FakeString("release-keys"),
	"android.os.Build|USER":                            gava.FakeString("root"),
	"android.os.Build|HOST":                            gava.FakeString("cnbbuild"),
	"android.os.Build|SERIAL":                          gava.FakeString("unknown"),
	"android.os.Build|BOOTLOADER":                      gava.FakeString("unknown"),
	"android.os.Build|RADIO":                           gava.FakeString("unknown"),
	"android.os.Build|FINGERPRINT":                     gava.FakeString("HUAWEI/PLQ110/PLQ110:15/HUAWEI/AP4A.250105.002/user/release-keys"),
	"android.os.Build|TIME":                            java.JLong(1735689600000),
	"android.os.Build$VERSION|RELEASE":                 gava.FakeString("15"),
	"android.os.Build$VERSION|RELEASE_OR_CODENAME":     gava.FakeString("15"),
	"android.os.Build$VERSION|CODENAME":                gava.FakeString("REL"),
	"android.os.Build$VERSION|SDK_INT":                 java.JInt(36),
	"android.os.Build$VERSION|PREVIEW_SDK_INT":         java.JInt(0),
	"android.os.Build$VERSION|MEDIA_PERFORMANCE_CLASS": java.JInt(0),
	"android.os.Build$VERSION|INCREMENTAL":             gava.FakeString("AP4A.250105.002"),
	"android.os.Build$VERSION|SECURITY_PATCH":          gava.FakeString("2025-01-01"),
	"android.os.Build$VERSION|BASE_OS":                 gava.FakeString("AP4A.250105.002"),
}

// fieldFallbackValue 字段兜底取值：先查真机值表，再按字段描述符给类型零值。
// native 读基础类型字段时直接断言具体类型（如 GetStaticIntField 断言 int32），
// 返回 nil 会 panic，所以 int/long/boolean 等必须给对应 J 类型零值；
// 对象字段返回 null 由 native 侧判空处理。
func fieldFallbackValue(clazz gava.FakeClass, name, sig string) func(java.IObject) any {
	if v, ok := buildStaticValues[clazz.GetName().String()+"|"+name]; ok {
		return func(java.IObject) any { return v }
	}
	switch sig {
	case "Z":
		return func(java.IObject) any { return java.JBoolean(false) }
	case "B":
		return func(java.IObject) any { return java.JByte(0) }
	case "C":
		return func(java.IObject) any { return java.JChar(0) }
	case "S":
		return func(java.IObject) any { return java.JShort(0) }
	case "I":
		return func(java.IObject) any { return java.JInt(0) }
	case "J":
		return func(java.IObject) any { return java.JLong(0) }
	case "F":
		return func(java.IObject) any { return java.JFloat(0) }
	case "D":
		return func(java.IObject) any { return java.JDouble(0) }
	default:
		return func(java.IObject) any { return nil }
	}
}

func (h Handler) DefineClass(ctx wrapper.FakeContext, name string) gava.FakeClass {
	// fmt.Println("DefineClass", name)
	var cls gava.FakeClass
	switch name {
	case "com.aliyun.TigerTally.common.utils.SecurityUtil":
		cls = ctx.DefineClass(name)
		cls.DefineMethod("getCtx", "()Landroid/content/Context;", gava.Modifier_PUBLIC).BindCall(func(obj java.IObject, args ...any) any {
			return ctx.GetClass("android.content.Context").NewInstance()
		})
	case "com.aliyun.TigerTally.s.A":
		cls = ctx.DefineClass(name)
		cls.DefineMethod("ct", "()Landroid/content/Context;", gava.Modifier_PUBLIC).BindCall(func(obj java.IObject, args ...any) any {
			return ctx.GetClass("android.content.Context").NewInstance()
		})
	case "com.aliyun.TigerTally.s.A$AA":
		cls = ctx.DefineClass(name)
		cls.DefineMethod(gava.ConstructorMethodName, "()V", gava.Modifier_PUBLIC).BindCall(func(obj java.IObject, args ...any) any {
			return cls.NewInstance()
		})
		cls.DefineMethod("en", "(Ljava/lang/String;)Ljava/lang/String;", gava.Modifier_PUBLIC).BindCall(func(obj java.IObject, args ...any) any {
			data := args[0].(java.IString).String()
			sum := md5.Sum([]byte(data))
			return gava.FakeString(hex.EncodeToString(sum[:]))
		})
	case "com.aliyun.TigerTally.s.A$BB":
		cls = ctx.DefineClass(name)
		cls.DefineMethod(gava.ConstructorMethodName, "()V", gava.Modifier_PUBLIC).BindCall(func(obj java.IObject, args ...any) any {
			return cls.NewInstance()
		})
		cls.DefineMethod("en", "(Ljava/lang/String;)Ljava/lang/String;", gava.Modifier_PUBLIC).BindCall(func(obj java.IObject, args ...any) any {
			data := args[0].(java.IString).String()
			sum := sha1.Sum([]byte(data))
			return gava.FakeString(hex.EncodeToString(sum[:]))
		})
	}
	return cls
}

func (h Handler) DefineMethod(ctx wrapper.FakeContext, clazz gava.FakeClass, name, sig string) (method gava.FakeMethod) {
	defer func() {
		if r := recover(); r != nil {
			// 内置类（java.lang.Class 等）没有内部工厂，clazz.DefineMethod 会 panic；
			// 必须改走 ctx 工厂构造并绑定兜底实现再返回，否则 wrapper 层会兜底出
			// 未绑定方法，native 调用时 panic not implemented 打断画像链。
			log.Printf("DefineMethod 内置类兜底，类=%s，方法=%s%s: %v", clazz.GetName(), name, sig, r)
			method = ctx.DefineMethod(clazz, name, sig, gava.Modifier_PUBLIC)
			method.BindCall(defaultReturn(sig))
		}
	}()
	// 类上已有绑定实现的方法直接返回（DefineClass 里定义过的优先）。
	if m := clazz.FindMethod(name, sig); m != nil {
		return m
	}
	logOnce("实例方法", clazz.GetName().String(), name, sig)
	// clazz.DefineMethod 走 classFactory 直接创建并存入方法表（下次查找命中缓存），
	// 不会再回调本 handler，无递归。
	method = clazz.DefineMethod(name, sig, gava.Modifier_PUBLIC)
	if name == gava.ConstructorMethodName {
		// 构造函数兜底返回新实例：native 拿到 null 对象会跳过整块画像逻辑，
		// 返回实例能让后续字段读取走兜底值，尽量保全画像数据。
		method.BindCall(func(obj java.IObject, args ...any) any {
			return clazz.NewInstance()
		})
		return method
	}
	return method.BindCall(defaultReturn(sig))
}

func (h Handler) DefineStaticMethod(ctx wrapper.FakeContext, clazz gava.FakeClass, name, sig string) (method gava.FakeMethod) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("DefineStaticMethod 内置类兜底，类=%s，方法=%s%s: %v", clazz.GetName(), name, sig, r)
			method = ctx.DefineMethod(clazz, name, sig, gava.Modifier_PUBLIC|gava.Modifier_STATIC)
			// Class.forName 返回 null 会让 native 画像逻辑 NPE，按语义解析类名；
			// 未注册的类 ctx.GetClass 会自动定义空类，后续字段/方法读取走兜底。
			if clazz.GetName().String() == "java.lang.Class" && name == "forName" {
				method.BindCall(func(obj java.IObject, args ...any) any {
					if s, ok := args[0].(java.IString); ok && s != nil && s.String() != "" {
						return ctx.GetClass(s.String())
					}
					return nil
				})
				return
			}
			method.BindCall(defaultReturn(sig))
		}
	}()
	if m := clazz.FindMethod(name, sig); m != nil {
		return m
	}
	logOnce("静态方法", clazz.GetName().String(), name, sig)
	return clazz.DefineMethod(name, sig, gava.Modifier_PUBLIC|gava.Modifier_STATIC).BindCall(defaultReturn(sig))
}

func (h Handler) DefineField(ctx wrapper.FakeContext, clazz gava.FakeClass, name, sig string) (field gava.FakeField) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("DefineField 内置类兜底，类=%s，字段=%s%s: %v", clazz.GetName(), name, sig, r)
			field = ctx.DefineField(clazz, name, sig, gava.Modifier_PUBLIC)
			field.BindGet(fieldFallbackValue(clazz, name, sig))
			field.BindSet(func(obj java.IObject, value any) {})
		}
	}()
	if f := clazz.FindField(name, sig); f != nil {
		return f
	}
	logOnce("字段", clazz.GetName().String(), name, sig)
	// BindSet 丢空：兜底字段也要可写，未绑定 setter 的字段被 native 写值会 panic。
	field = clazz.DefineField(name, sig, gava.Modifier_PUBLIC)
	field.BindGet(fieldFallbackValue(clazz, name, sig))
	field.BindSet(func(obj java.IObject, value any) {})
	return field
}

func (h Handler) DefineStaticField(ctx wrapper.FakeContext, clazz gava.FakeClass, name, sig string) (field gava.FakeField) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("DefineStaticField 内置类兜底，类=%s，字段=%s%s: %v", clazz.GetName(), name, sig, r)
			field = ctx.DefineField(clazz, name, sig, gava.Modifier_PUBLIC|gava.Modifier_STATIC)
			field.BindGet(fieldFallbackValue(clazz, name, sig))
			field.BindSet(func(obj java.IObject, value any) {})
		}
	}()
	if f := clazz.FindField(name, sig); f != nil {
		return f
	}
	logOnce("静态字段", clazz.GetName().String(), name, sig)
	field = clazz.DefineField(name, sig, gava.Modifier_PUBLIC|gava.Modifier_STATIC)
	field.BindGet(fieldFallbackValue(clazz, name, sig))
	field.BindSet(func(obj java.IObject, value any) {})
	return field
}

func (h Handler) CallMethod(ctx android.JNIContext, obj gava.FakeObject, name, sig string, args ...any) any {
	// 这里只记录类名和方法名，避免把业务数据写进服务日志。
	log.Printf("未实现的 Java 方法调用，类=%s，方法=%s%s", obj.GetClass().GetName(), name, sig)
	return nil
}

func (h Handler) CallStaticMethod(ctx android.JNIContext, clazz gava.FakeClass, name, sig string, args ...any) any {
	log.Printf("未实现的 Java 静态方法调用，类=%s，方法=%s%s", clazz.GetName(), name, sig)
	return nil
}

func (h Handler) GetField(ctx android.JNIContext, obj gava.FakeObject, name string) any {
	log.Printf("未实现的 Java 字段读取，类=%s，字段=%s", obj.GetClass().GetName(), name)
	return nil
}

func (h Handler) SetField(ctx android.JNIContext, obj gava.FakeObject, name string, value any) {
	log.Printf("未实现的 Java 字段写入，类=%s，字段=%s", obj.GetClass().GetName(), name)
}

func (h Handler) GetStaticField(ctx android.JNIContext, clazz gava.FakeClass, name string) any {
	log.Printf("未实现的 Java 静态字段读取，类=%s，字段=%s", clazz.GetName(), name)
	return nil
}

func (h Handler) SetStaticField(ctx android.JNIContext, clazz gava.FakeClass, name string, value any) {
	log.Printf("未实现的 Java 静态字段写入，类=%s，字段=%s", clazz.GetName(), name)
}

func formatSignature(clazz gava.FakeClass, name, sig string) string {
	return clazz.GetName().String() + name + sig
}
