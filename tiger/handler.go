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
			log.Printf("DefineMethod 异常，类=%s，方法=%s%s: %v", clazz.GetName(), name, sig, r)
			method = nil
		}
	}()
	// 类上已有绑定实现的方法直接返回（DefineClass 里定义过的优先）。
	if m := clazz.FindMethod(name, sig); m != nil {
		return m
	}
	logOnce("实例方法", clazz.GetName().String(), name, sig)
	// clazz.DefineMethod 走 classFactory 直接创建并存入方法表（下次查找命中缓存），
	// 不会再回调本 handler，无递归。
	return clazz.DefineMethod(name, sig, gava.Modifier_PUBLIC).BindCall(defaultReturn(sig))
}

func (h Handler) DefineStaticMethod(ctx wrapper.FakeContext, clazz gava.FakeClass, name, sig string) (method gava.FakeMethod) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("DefineStaticMethod 异常，类=%s，方法=%s%s: %v", clazz.GetName(), name, sig, r)
			method = nil
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
			log.Printf("DefineField 异常，类=%s，字段=%s%s: %v", clazz.GetName(), name, sig, r)
			field = nil
		}
	}()
	if f := clazz.FindField(name, sig); f != nil {
		return f
	}
	logOnce("字段", clazz.GetName().String(), name, sig)
	return clazz.DefineField(name, sig, gava.Modifier_PUBLIC).BindGet(func(obj java.IObject) any { return nil })
}

func (h Handler) DefineStaticField(ctx wrapper.FakeContext, clazz gava.FakeClass, name, sig string) (field gava.FakeField) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("DefineStaticField 异常，类=%s，字段=%s%s: %v", clazz.GetName(), name, sig, r)
			field = nil
		}
	}()
	if f := clazz.FindField(name, sig); f != nil {
		return f
	}
	logOnce("静态字段", clazz.GetName().String(), name, sig)
	return clazz.DefineField(name, sig, gava.Modifier_PUBLIC|gava.Modifier_STATIC).BindGet(func(obj java.IObject) any { return nil })
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
