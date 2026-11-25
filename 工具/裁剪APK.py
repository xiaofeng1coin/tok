#!/usr/bin/env python3
# 裁剪甬派 APK，仅保留模拟器签名所需的清单、资源表、DEX 和 arm64 原生库。
import re
import sys
import zipfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    project = Path(__file__).resolve().parents[3]
    source = project / "原安装包" / "甬派.apk"
    output = root / "apk" / "yongpai.apk"
    output.parent.mkdir(parents=True, exist_ok=True)

    dex_pattern = re.compile(r"classes\d*\.dex$")
    kept = []
    total_size = 0

    with zipfile.ZipFile(source, "r") as src, zipfile.ZipFile(
        output, "w", allowZip64=True
    ) as dst:
        for info in src.infolist():
            name = info.filename
            required = (
                name in {"AndroidManifest.xml", "resources.arsc"}
                or dex_pattern.fullmatch(name) is not None
                or name.startswith("lib/arm64-v8a/")
            )
            if not required or info.is_dir():
                continue
            dst.writestr(info, src.read(name))
            kept.append(name)
            total_size += info.file_size

    required_names = {
        "AndroidManifest.xml",
        "resources.arsc",
        "classes.dex",
        "lib/arm64-v8a/libtiger_tally.so",
    }
    missing = required_names.difference(kept)
    if missing:
        output.unlink(missing_ok=True)
        raise RuntimeError(f"裁剪结果缺少必要文件: {sorted(missing)}")

    size_mb = output.stat().st_size / 1024 / 1024
    total_mb = total_size / 1024 / 1024
    print(f"原安装包: {source}")
    print(f"裁剪结果: {output}")
    print(f"保留条目: {len(kept)} 个，解压后 {total_mb:.2f} MiB")
    print(f"裁剪包大小: {size_mb:.2f} MiB")
    if output.stat().st_size >= 100 * 1024 * 1024:
        raise RuntimeError("裁剪包仍超过 GitHub 单文件 100MiB 限制")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"裁剪失败: {exc}", file=sys.stderr)
        raise SystemExit(1)
