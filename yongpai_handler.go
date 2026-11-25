package main

import (
	gava "github.com/wnxd/microdbg-android/java"
	"github.com/wnxd/microdbg-android/wrapper"
	java "github.com/wnxd/microdbg-java"
	"yongpai-wtoken/tiger"
)

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
	return h.Handler.DefineClass(ctx, name)
}
