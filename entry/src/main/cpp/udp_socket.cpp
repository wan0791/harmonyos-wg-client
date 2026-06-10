/**
 * Native UDP Socket for WireGuard VPN (HarmonyOS NAPI)
 *
 * 创建原生 Linux UDP Socket，返回 fd 给 ArkTS 层调用 vpnConnection.protect(fd)，
 * 从而绕过 HarmonyOS API 23 上 protectProcessNet() 不生效的问题。
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

// ── 绑定端口 ──

static napi_value UdpBind(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    int fd, port;
    napi_get_value_int32(env, args[0], &fd);
    napi_get_value_int32(env, args[1], &port);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        napi_throw_error(env, nullptr, strerror(errno));
        return nullptr;
    }

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

// ── 发送数据 ──

static napi_value UdpSendTo(napi_env env, napi_callback_info info) {
    size_t argc = 4;
    napi_value args[4];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

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

    int fd;
    napi_get_value_int32(env, args[0], &fd);

    int bufSize;
    napi_get_value_int32(env, args[1], &bufSize);
    if (bufSize <= 0 || bufSize > 65535) bufSize = 65535;

    int timeoutMs;
    napi_get_value_int32(env, args[2], &timeoutMs);

    // poll 等待数据
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

    // 接收
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

    // 创建 ArrayBuffer（先声明 ptr 再取地址，避免 NAPI 类型要求）
    napi_value arrayBuffer;
    void* abPtr = nullptr;
    napi_create_arraybuffer(env, static_cast<size_t>(received), &abPtr, &arrayBuffer);
    memcpy(abPtr, stackBuf, static_cast<size_t>(received));

    // 返回 { data, from: { address, port } }
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
    int fd;
    napi_get_value_int32(env, args[0], &fd);
    close(fd);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

// ── 获取本地端口 ──

static napi_value GetLocalPort(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    int fd;
    napi_get_value_int32(env, args[0], &fd);

    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr*)&addr, &addrLen) < 0) {
        napi_throw_error(env, nullptr, strerror(errno));
        return nullptr;
    }
    napi_value result;
    napi_create_int32(env, ntohs(addr.sin_port), &result);
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
    def("udpBind", UdpBind);
    def("udpSendTo", UdpSendTo);
    def("udpRecvFrom", UdpRecvFrom);
    def("closeUdpSocket", CloseUdpSocket);
    def("getLocalPort", GetLocalPort);
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
