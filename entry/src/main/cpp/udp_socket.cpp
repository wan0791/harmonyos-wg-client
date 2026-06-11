/**
 * Native UDP Socket for WireGuard VPN (HarmonyOS NAPI)
 *
 * 提供原生 UDP socket，及后台收包线程（pthread），
 * 通过 NAPI threadsafe callback 将数据回调到 ArkTS。
 */

#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <pthread.h>
#include <atomic>

#include "napi/native_api.h"

// ── 辅助 ──

static std::string GetString(napi_env env, napi_value val) {
    size_t len = 0;
    napi_get_value_string_utf8(env, val, nullptr, 0, &len);
    if (len == 0) return "";
    std::string s(len, '\0');
    napi_get_value_string_utf8(env, val, &s[0], len + 1, &len);
    return s;
}

// ── 后台收包线程 ──

struct RecvData {
    uint8_t* buf;
    size_t len;
    char fromIP[INET_ADDRSTRLEN];
    int fromPort;
};

struct RecvThreadCtx {
    int fd;
    pthread_t thread;
    std::atomic<bool> running;
    napi_threadsafe_function tsfn;
};

static RecvThreadCtx g_ctx;
static pthread_mutex_t g_ctxMutex = PTHREAD_MUTEX_INITIALIZER;

static void TSFNCallback(napi_env env, napi_value jsCallback, void* context, void* data) {
    RecvData* rd = static_cast<RecvData*>(data);
    if (rd == nullptr || rd->buf == nullptr) return;

    // 创建 ArrayBuffer 并拷贝数据
    napi_value arrayBuffer;
    void* abPtr = nullptr;
    napi_status status = napi_create_arraybuffer(env, rd->len, &abPtr, &arrayBuffer);
    if (status != napi_ok || abPtr == nullptr) {
        delete[] rd->buf;
        delete rd;
        return;
    }
    memcpy(abPtr, rd->buf, rd->len);

    // 创建 from 对象 { address: string, port: number }
    napi_value fromObj, jsIP, jsPort;
    napi_create_object(env, &fromObj);
    napi_create_string_utf8(env, rd->fromIP, NAPI_AUTO_LENGTH, &jsIP);
    napi_create_int32(env, rd->fromPort, &jsPort);
    napi_set_named_property(env, fromObj, "address", jsIP);
    napi_set_named_property(env, fromObj, "port", jsPort);

    // 调用 JS 回调: callback(data, from)
    napi_value args[2];
    args[0] = arrayBuffer;
    args[1] = fromObj;
    napi_call_function(env, nullptr, jsCallback, 2, args, nullptr);

    // 释放堆内存
    delete[] rd->buf;
    delete rd;
}

static void* RecvThreadFunc(void* arg) {
    RecvThreadCtx* ctx = static_cast<RecvThreadCtx*>(arg);
    uint8_t buf[65536];

    while (ctx->running.load()) {
        struct pollfd pfd;
        pfd.fd = ctx->fd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 500);
        if (ret <= 0) continue;

        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        ssize_t n = recvfrom(ctx->fd, buf, sizeof(buf), 0,
                            (struct sockaddr*)&from, &fromLen);
        if (n <= 0) continue;

        // 分配堆内存存储收到的数据
        RecvData* rd = new RecvData();
        rd->buf = new uint8_t[n];
        memcpy(rd->buf, buf, n);
        rd->len = static_cast<size_t>(n);
        inet_ntop(AF_INET, &from.sin_addr, rd->fromIP, sizeof(rd->fromIP));
        rd->fromPort = ntohs(from.sin_port);

        napi_status status = napi_call_threadsafe_function(ctx->tsfn, rd, napi_tsfn_nonblocking);
        if (status != napi_ok) {
            delete[] rd->buf;
            delete rd;
        }
    }

    return nullptr;
}

static napi_value StartRecvThread(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 2) {
        napi_throw_error(env, nullptr, "expected 2 args (fd, callback)");
        return nullptr;
    }

    int fd;
    napi_get_value_int32(env, args[0], &fd);

    // args[1] is the callback function
    napi_value callback = args[1];

    pthread_mutex_lock(&g_ctxMutex);

    if (g_ctx.running.load()) {
        pthread_mutex_unlock(&g_ctxMutex);
        napi_value result;
        napi_get_boolean(env, false, &result);
        return result;
    }

    g_ctx.fd = fd;
    g_ctx.running.store(true);

    // Create threadsafe function for callback
    napi_value tsfnName;
    napi_create_string_utf8(env, "recvCallback", NAPI_AUTO_LENGTH, &tsfnName);

    napi_status tsfnStatus = napi_create_threadsafe_function(
        env, callback, nullptr, tsfnName,
        0, 1, nullptr, nullptr, nullptr,
        TSFNCallback, &g_ctx.tsfn);

    if (tsfnStatus != napi_ok) {
        g_ctx.running.store(false);
        pthread_mutex_unlock(&g_ctxMutex);
        napi_throw_error(env, nullptr, "napi_create_threadsafe_function failed");
        return nullptr;
    }

    pthread_create(&g_ctx.thread, nullptr, RecvThreadFunc, &g_ctx);

    pthread_mutex_unlock(&g_ctxMutex);

    napi_value result;
    napi_get_boolean(env, true, &result);
    return result;
}

static napi_value StopRecvThread(napi_env env, napi_callback_info info) {
    pthread_mutex_lock(&g_ctxMutex);

    if (g_ctx.running.load()) {
        g_ctx.running.store(false);
        pthread_join(g_ctx.thread, nullptr);

        napi_release_threadsafe_function(g_ctx.tsfn, napi_tsfn_release);
        g_ctx.tsfn = nullptr;
    }

    pthread_mutex_unlock(&g_ctxMutex);

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

// ── 创建 UDP Socket ──

static napi_value CreateUdpSocket(napi_env env, napi_callback_info info) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        napi_throw_error(env, nullptr, "socket() failed");
        return nullptr;
    }
    napi_value result;
    napi_create_int32(env, fd, &result);
    return result;
}

// ── 发送数据 ──

static napi_value UdpSendTo(napi_env env, napi_callback_info info) {
    size_t argc = 4;
    napi_value args[4];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 4) {
        napi_throw_error(env, nullptr, "expected 4 args (fd, data, host, port)");
        return nullptr;
    }

    int fd;
    napi_get_value_int32(env, args[0], &fd);

    void* buf = nullptr;
    size_t len = 0;
    napi_get_arraybuffer_info(env, args[1], &buf, &len);

    std::string host = GetString(env, args[2]);
    int port;
    napi_get_value_int32(env, args[3], &port);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &dest.sin_addr) <= 0) {
        napi_throw_error(env, nullptr, "inet_pton failed");
        return nullptr;
    }

    ssize_t sent = sendto(fd, buf, len, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        napi_throw_error(env, nullptr, strerror(errno));
        return nullptr;
    }

    napi_value result;
    napi_create_int32(env, sent < 0 ? 0 : static_cast<int32_t>(sent), &result);
    return result;
}

// ── 接收数据（带超时） ──

static napi_value UdpRecvFrom(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 3) {
        napi_throw_error(env, nullptr, "expected 3 args (fd, bufSize, timeoutMs)");
        return nullptr;
    }

    int fd;
    napi_get_value_int32(env, args[0], &fd);
    int bufSize;
    napi_get_value_int32(env, args[1], &bufSize);
    if (bufSize <= 0 || bufSize > 65535) bufSize = 65535;
    int timeoutMs;
    napi_get_value_int32(env, args[2], &timeoutMs);

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    int ret = poll(&pfd, 1, timeoutMs);
    if (ret == 0) {
        napi_value result;
        napi_get_null(env, &result);
        return result;
    }
    if (ret < 0) {
        napi_throw_error(env, nullptr, strerror(errno));
        return nullptr;
    }

    char stackBuf[65536];
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    ssize_t received = recvfrom(fd, stackBuf, sizeof(stackBuf), 0,
                                (struct sockaddr*)&from, &fromLen);
    if (received <= 0) {
        napi_value result;
        napi_get_null(env, &result);
        return result;
    }

    napi_value arrayBuffer;
    void* abPtr = nullptr;
    napi_create_arraybuffer(env, static_cast<size_t>(received), &abPtr, &arrayBuffer);
    memcpy(abPtr, stackBuf, static_cast<size_t>(received));

    napi_value result;
    napi_create_object(env, &result);
    napi_set_named_property(env, result, "data", arrayBuffer);

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, ipStr, sizeof(ipStr));

    napi_value fromObj, jsIP, jsPort;
    napi_create_object(env, &fromObj);
    napi_create_string_utf8(env, ipStr, NAPI_AUTO_LENGTH, &jsIP);
    napi_create_int32(env, ntohs(from.sin_port), &jsPort);
    napi_set_named_property(env, fromObj, "address", jsIP);
    napi_set_named_property(env, fromObj, "port", jsPort);
    napi_set_named_property(env, result, "from", fromObj);

    return result;
}

// ── 关闭 ──

static napi_value CloseUdpSocket(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 1) {
        napi_throw_error(env, nullptr, "expected 1 argument (fd)");
        return nullptr;
    }
    int fd;
    napi_get_value_int32(env, args[0], &fd);

    pthread_mutex_lock(&g_ctxMutex);
    close(fd);
    pthread_mutex_unlock(&g_ctxMutex);

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

// ── 模块注册 ──

static napi_value Init(napi_env env, napi_value exports) {
    auto def = [&](const char* name, napi_callback func) {
        napi_property_descriptor d = {};
        d.utf8name = name;
        d.method = func;
        d.attributes = napi_default;
        napi_define_properties(env, exports, 1, &d);
    };
    def("createUdpSocket", CreateUdpSocket);
    def("udpSendTo", UdpSendTo);
    def("udpRecvFrom", UdpRecvFrom);
    def("closeUdpSocket", CloseUdpSocket);
    def("startRecvThread", StartRecvThread);
    def("stopRecvThread", StopRecvThread);
    return exports;
}

static napi_module udpSocketModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "udp_socket",
    .nm_priv = nullptr,
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterUdpSocketModule(void) {
    napi_module_register(&udpSocketModule);
}
