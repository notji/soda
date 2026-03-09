/*
 * Copyright 2026 Benjamin Hughes <benjamin@letterwolf.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <winerror.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---- Constants ---- */

#define SVC_NAME    "soda"
#define BIND_IP     "127.0.0.1"
#define BIND_PORT   53
#define RESOLVE_IP4 "127.0.0.1"
#define RESOLVE_IP6 "::1"
#define BUF_SIZE    512
#define MAX_TLDS    16
#define MAX_TLD_LEN 64
#define NRPT_DIR    "SYSTEM\\CurrentControlSet\\Services\\DnsCache\\Parameters\\DnsPolicyConfig\\"

#define log_v(verbose, fmt, ...) do { if (verbose) printf(fmt, ##__VA_ARGS__); } while(0)

/* ---- Data structures ---- */

struct config {
    char    tlds[MAX_TLDS][MAX_TLD_LEN];
    int     tld_count;
    int     verbose;
    uint8_t rdata4[4];
    uint8_t rdata6[16];
};

static struct config s_cfg;

#pragma pack(push, 1)
struct dns_header {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
};
#pragma pack(pop)

struct dns_question {
    char     name[256];
    uint16_t qtype;
    uint16_t qclass;
    int      wire_end;  // byte offset past question section; 0 = parse error
};

/* ---- DNS parsing ---- */

static uint16_t get_u16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return ntohs(v); }

// Wire-format name: sequence of (length, bytes) labels terminated by 0x00.
static struct dns_question dns_parse_question(const uint8_t *buf, int buf_len) {
    struct dns_question q = {0};
    if (buf_len < 17) return q;

    const struct dns_header *hdr = (const struct dns_header *)buf;
    if (ntohs(hdr->qdcount) != 1) return q;

    int i = 12, p = 0;
    while (i < buf_len && buf[i] != 0) {
        if (buf[i] > 63) return q;  // labels max 63 bytes; 0xC0+ = pointer compression
        int len = buf[i++];
        if (i + len > buf_len) return q;
        if (p + len + 1 >= (int)sizeof(q.name)) return q;
        for (int j = 0; j < len; j++) {
            q.name[p++] = buf[i++];
        }
        q.name[p++] = '.';
    }
    if (i >= buf_len) return q;
    if (p > 0) p--;
    q.name[p] = 0;
    i++;

    if (i + 4 > buf_len) return q;
    q.qtype    = get_u16(buf + i);
    q.qclass   = get_u16(buf + i + 2);
    q.wire_end = i + 4;
    return q;
}

static int dns_ends_with_tld(const char *name, const char *tld) {
    size_t name_len = strlen(name);
    size_t tld_len  = strlen(tld);
    if (name_len < tld_len + 1) return 0;
    const char *tail = name + name_len - tld_len - 1;
    return tail[0] == '.' && _stricmp(tail + 1, tld) == 0;
}

static int dns_match_tlds(const char *name, const char tlds[][MAX_TLD_LEN], int count) {
    for (int i = 0; i < count; i++)
        if (dns_ends_with_tld(name, tlds[i])) return 1;
    return 0;
}

/* ---- DNS response building ---- */

static void put_u16(uint8_t *p, uint16_t v) { v = htons(v); memcpy(p, &v, 2); }
static void put_u32(uint8_t *p, uint32_t v) { v = htonl(v); memcpy(p, &v, 4); }

// Builds a DNS response into `out`. Returns response length, or 0 on error.
// rdata=NULL produces NXDOMAIN; otherwise appends a single answer record.
static int dns_build_response(const uint8_t *query, int query_len,
                              const struct dns_question *q,
                              const uint8_t *rdata, uint16_t rdlen,
                              uint8_t *out, int out_size) {
    if (query_len > out_size) return 0;
    memcpy(out, query, query_len);
    struct dns_header *hdr = (struct dns_header *)out;
    hdr->nscount = 0;
    hdr->arcount = 0;

    if (!rdata) {
        hdr->flags   = htons(0x8000 | 0x0400 | 0x0003);  // QR=1, AA=1, RCODE=NXDOMAIN
        hdr->ancount = 0;
        return query_len;
    }

    int off = q->wire_end;
    if (off + 12 + rdlen > out_size) return 0;

    hdr->flags   = htons(0x8000 | 0x0400);  // QR=1, AA=1
    hdr->ancount = htons(1);
    // Name pointer to offset 0x0C (start of question name in the original query)
    out[off++] = 0xC0; out[off++] = 0x0C;
    put_u16(out + off, q->qtype); off += 2;
    put_u16(out + off, 1);        off += 2;  // CLASS IN
    put_u32(out + off, 60);       off += 4;  // TTL 60s
    put_u16(out + off, rdlen);    off += 2;
    memcpy(out + off, rdata, rdlen);  off += rdlen;
    return off;
}

/* ---- NRPT registry management ---- */

static HANDLE s_notify_handle;

static void nrpt_key_path(const char *tld, char *out, int out_size) {
    snprintf(out, out_size, NRPT_DIR "%s-%s", SVC_NAME, tld);
}

static void nrpt_apply(const char *tld, int verbose) {
    char path[256];
    nrpt_key_path(tld, path, sizeof(path));

    HKEY key;
    LONG res = RegCreateKeyExA(HKEY_LOCAL_MACHINE, path,
        0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL);
    if (res != ERROR_SUCCESS) {
        printf("Failed to create registry key (error %ld), are you running as admin?\n", res);
        return;
    }

    DWORD version = 2;
    RegSetValueExA(key, "Version", 0, REG_DWORD, (BYTE *)&version, sizeof(version));

    // REG_MULTI_SZ: ".test\0\0" ; leading dot = suffix match in NRPT
    char name[66];
    int len = snprintf(name, sizeof(name) - 1, ".%s", tld);
    name[len + 1] = '\0';
    RegSetValueExA(key, "Name", 0, REG_MULTI_SZ, (BYTE *)name, len + 2);

    RegSetValueExA(key, "GenericDNSServers", 0, REG_SZ,
                   (BYTE *)BIND_IP, (DWORD)strlen(BIND_IP) + 1);

    // ConfigOptions bit 3 (0x8) enables GenericDNSServers
    DWORD options = 0x8;
    RegSetValueExA(key, "ConfigOptions", 0, REG_DWORD, (BYTE *)&options, sizeof(options));

    RegCloseKey(key);
    log_v(verbose, "Added NRPT rule: .%s -> %s\n", tld, RESOLVE_IP4);
}

static void nrpt_remove(const char *tld, int verbose) {
    char path[256];
    nrpt_key_path(tld, path, sizeof(path));
    LONG res = RegDeleteKeyA(HKEY_LOCAL_MACHINE, path);
    if (res != ERROR_SUCCESS && res != ERROR_FILE_NOT_FOUND) {
        log_v(verbose, "Failed to remove NRPT rule (error %ld)\n", res);
    } else {
        log_v(verbose, "Removed NRPT rule for %s\n", tld);
    }
}

static void nrpt_reload_dnscache(int verbose) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { log_v(verbose, "Failed to open SCM\n"); return; }

    SC_HANDLE svc = OpenServiceA(scm, "DnsCache", SERVICE_PAUSE_CONTINUE);
    if (!svc) {
        log_v(verbose, "Failed to open DnsCache service\n");
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS status;
    if (ControlService(svc, SERVICE_CONTROL_PARAMCHANGE, &status))
        log_v(verbose, "Reloaded DnsCache\n");
    else
        log_v(verbose, "Failed to reload DnsCache (error %lu)\n", GetLastError());

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

// Threadpool callback ; fixed signature, reads s_cfg global
static void WINAPI nrpt_on_interface_change(
    PVOID context, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type
) {
    if (type == MibInitialNotification) return;

    static volatile LONGLONG last_tick = 0;
    LONGLONG now  = (LONGLONG)GetTickCount64();
    LONGLONG prev = last_tick;
    if (now - prev < 1000) return;
    if (InterlockedCompareExchange64(&last_tick, now, prev) != prev) return;

    for (int i = 0; i < s_cfg.tld_count; i++) {
        char path[256];
        nrpt_key_path(s_cfg.tlds[i], path, sizeof(path));
        HKEY key;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key) == ERROR_SUCCESS) {
            RegCloseKey(key);
            continue;
        }
        log_v(s_cfg.verbose, "Network change, reapplying NRPT for .%s\n", s_cfg.tlds[i]);
        nrpt_apply(s_cfg.tlds[i], s_cfg.verbose);
    }
}

/* ---- DNS proxy ---- */

static WSAEVENT s_shutdown_event;

static void proxy_stop(void) {
    WSASetEvent(s_shutdown_event);
}

static void proxy_handle_packet(SOCKET sock, uint8_t *buf, int len,
                                struct sockaddr *client, int client_len,
                                const struct config *cfg) {
    struct dns_question q = dns_parse_question(buf, len);
    if (q.wire_end == 0) return;

    log_v(cfg->verbose, "Q: %s (type=%u class=%u) -> ", q.name, q.qtype, q.qclass);

    const uint8_t *rdata = NULL;
    uint16_t rdlen = 0;

    if (q.qclass == 1 && dns_match_tlds(q.name, cfg->tlds, cfg->tld_count)) {
        if (q.qtype == 1) {
            log_v(cfg->verbose, "%s (A)\n", RESOLVE_IP4);
            rdata = cfg->rdata4; rdlen = 4;
        } else if (q.qtype == 28) {
            log_v(cfg->verbose, "%s (AAAA)\n", RESOLVE_IP6);
            rdata = cfg->rdata6; rdlen = 16;
        } else {
            log_v(cfg->verbose, "NXDOMAIN\n");
        }
    } else {
        log_v(cfg->verbose, "NXDOMAIN\n");
    }

    uint8_t response[BUF_SIZE];
    int resp_len = dns_build_response(buf, len, &q, rdata, rdlen, response, BUF_SIZE);
    if (resp_len > 0) {
        sendto(sock, (char *)response, resp_len, 0, client, client_len);
    }
}

static int proxy_run(const struct config *cfg) {
    WSAEVENT event6  = WSACreateEvent();
    WSAEVENT event4  = WSACreateEvent();
    s_shutdown_event = WSACreateEvent();
    WSAEVENT events[] = { event6, event4, s_shutdown_event };

    SOCKET sock6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock6 == INVALID_SOCKET) {
        printf("IPv6 socket failed\n");
        WSACloseEvent(event6);
        WSACloseEvent(event4);
        WSACloseEvent(s_shutdown_event);
        return 1;
    }

    struct sockaddr_in6 addr6 = {0};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port   = htons(BIND_PORT);
    addr6.sin6_addr   = in6addr_any;
    if (bind(sock6, (struct sockaddr *)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
        printf("IPv6 bind failed\n");
        closesocket(sock6);
        WSACloseEvent(event6);
        WSACloseEvent(event4);
        WSACloseEvent(s_shutdown_event);
        return 1;
    }
    WSAEventSelect(sock6, event6, FD_READ);
    log_v(cfg->verbose, "Listening on [::]:%u\n", BIND_PORT);

    SOCKET sock4 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr4 = {0};
    addr4.sin_family      = AF_INET;
    addr4.sin_port        = htons(BIND_PORT);
    addr4.sin_addr.s_addr = inet_addr(BIND_IP);
    if (bind(sock4, (struct sockaddr *)&addr4, sizeof(addr4)) == SOCKET_ERROR) {
        printf("IPv4 bind on %s:%u failed (non-fatal)\n", BIND_IP, BIND_PORT);
        closesocket(sock4);
        sock4 = INVALID_SOCKET;
    } else {
        WSAEventSelect(sock4, event4, FD_READ);
        log_v(cfg->verbose, "Listening on %s:%u\n", BIND_IP, BIND_PORT);
    }

    uint8_t buf[BUF_SIZE];
    for (;;) {
        DWORD idx = WaitForMultipleObjects(3, events, FALSE, INFINITE);
        if (idx == WAIT_FAILED) break;

        if (idx == WAIT_OBJECT_0) {
            WSAResetEvent(event6);
            struct sockaddr_in6 client;
            int client_len = sizeof(client);
            int len = recvfrom(sock6, (char *)buf, BUF_SIZE, 0,
                               (struct sockaddr *)&client, &client_len);
            proxy_handle_packet(sock6, buf, len, (struct sockaddr *)&client, client_len, cfg);
        } else if (idx == WAIT_OBJECT_0 + 1 && sock4 != INVALID_SOCKET) {
            WSAResetEvent(event4);
            struct sockaddr_in client;
            int client_len = sizeof(client);
            int len = recvfrom(sock4, (char *)buf, BUF_SIZE, 0,
                               (struct sockaddr *)&client, &client_len);
            proxy_handle_packet(sock4, buf, len, (struct sockaddr *)&client, client_len, cfg);
        } else {
            break;
        }
    }

    WSACloseEvent(event6);
    WSACloseEvent(event4);
    WSACloseEvent(s_shutdown_event);
    closesocket(sock6);
    if (sock4 != INVALID_SOCKET) closesocket(sock4);
    return 0;
}

/* ---- Windows service ---- */

static SERVICE_STATUS_HANDLE s_svc_handle;
static SERVICE_STATUS        s_svc_status;

static DWORD WINAPI service_handler(DWORD control, DWORD event_type,
                                    LPVOID event_data, LPVOID context) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            s_svc_status.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(s_svc_handle, &s_svc_status);
            proxy_stop();
            break;
        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(s_svc_handle, &s_svc_status);
            break;
    }
    return NO_ERROR;
}

// SCM entry point ; fixed callback signature, reads s_cfg global
static VOID WINAPI service_main(DWORD argc, LPTSTR *argv) {
    s_svc_handle = RegisterServiceCtrlHandlerEx(SVC_NAME, service_handler, NULL);
    if (!s_svc_handle) return;

    s_svc_status = (SERVICE_STATUS){
        .dwServiceType      = SERVICE_WIN32_OWN_PROCESS,
        .dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        .dwWin32ExitCode    = NO_ERROR,
        .dwCurrentState     = SERVICE_RUNNING,
    };
    SetServiceStatus(s_svc_handle, &s_svc_status);

    proxy_run(&s_cfg);

    s_svc_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(s_svc_handle, &s_svc_status);
}

/* ---- Main ---- */

static BOOL WINAPI on_ctrl_c(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) { proxy_stop(); return TRUE; }
    return FALSE;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -t, --tld <tld>   TLD to resolve (default: test, repeatable: max 16)\n");
    printf("  -v, --verbose     Verbose logging\n");
    printf("  -s, --service     Run as Windows service\n");
}

int main(int argc, char *argv[]) {
    int run_as_service = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tld") == 0 || strcmp(argv[i], "-t") == 0) {
            if (i + 1 >= argc) { printf("--tld requires a value\n"); return 1; }
            if (s_cfg.tld_count >= MAX_TLDS) { printf("too many --tld (max %d)\n", MAX_TLDS); return 1; }
            strncpy(s_cfg.tlds[s_cfg.tld_count], argv[++i], MAX_TLD_LEN - 1);
            s_cfg.tlds[s_cfg.tld_count][MAX_TLD_LEN - 1] = '\0';
            s_cfg.tld_count++;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            s_cfg.verbose = 1;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--service") == 0) {
            run_as_service = 1;
        } else {
            printf("Unknown argument: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (s_cfg.tld_count == 0) {
        strncpy(s_cfg.tlds[0], "test", MAX_TLD_LEN - 1);
        s_cfg.tld_count = 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("WSAStartup failed\n"); return 1; }

    inet_pton(AF_INET, RESOLVE_IP4, s_cfg.rdata4);
    inet_pton(AF_INET6, RESOLVE_IP6, s_cfg.rdata6);

    for (int i = 0; i < s_cfg.tld_count; i++) {
        nrpt_apply(s_cfg.tlds[i], s_cfg.verbose);
    }
    nrpt_reload_dnscache(s_cfg.verbose);
    NotifyIpInterfaceChange(AF_UNSPEC, nrpt_on_interface_change, NULL, TRUE, &s_notify_handle);
    SetConsoleCtrlHandler(on_ctrl_c, TRUE);

    if (run_as_service) {
        SERVICE_TABLE_ENTRY table[] = { { (LPSTR)SVC_NAME, service_main }, { NULL, NULL } };
        StartServiceCtrlDispatcher(table);
    } else {
        log_v(s_cfg.verbose, "Starting DNS proxy");
        for (int i = 0; i < s_cfg.tld_count; i++)
            log_v(s_cfg.verbose, " .%s", s_cfg.tlds[i]);
        log_v(s_cfg.verbose, "\n");
        proxy_run(&s_cfg);
    }

    log_v(s_cfg.verbose, "Shutting down\n");
    CancelMibChangeNotify2(s_notify_handle);
    for (int i = 0; i < s_cfg.tld_count; i++) {
        nrpt_remove(s_cfg.tlds[i], s_cfg.verbose);
    }
    nrpt_reload_dnscache(s_cfg.verbose);
    WSACleanup();
    return 0;
}
