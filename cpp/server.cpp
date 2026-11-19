#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <print>

#include "node.hpp"

using namespace node;

namespace {

volatile std::sig_atomic_t g_stop = 0;
constexpr std::size_t kMaxBody = 256 * 1024, kMaxHead = 16 * 1024, kMaxConns = 64;
constexpr std::int64_t kIdleSecs = 10;

[[noreturn]] void die(const std::string& m) {
    std::println(stderr, "FATAL: {}", m);
    std::exit(1);
}

struct MissingParam { std::string name; };

const Value& need(const Object& p, const char* k) {
    auto it = p.find(k);
    if (it == p.end()) throw MissingParam{k};
    return it->second;
}

std::int64_t to_int(const Value& v) {  // Python int(): accepts ints and numeric strings
    if (const auto* n = std::get_if<std::int64_t>(&v.v)) return *n;
    if (const auto* s = std::get_if<std::string>(&v.v)) {
        std::int64_t n{};
        auto [p, ec] = std::from_chars(s->data(), s->data() + s->size(), n);
        if (ec == std::errc{} && p == s->data() + s->size()) return n;
    }
    throw Malformed{};
}

using Reply = std::pair<int, std::string>;

std::string dumps(const Value& v) {
    std::string s;
    gj::dump(v, s);
    return s;
}

Reply rpc_ok(const Value& id, Value result) {
    return {200, dumps(jobj({{"jsonrpc", jstr("2.0")}, {"id", id}, {"result", std::move(result)}}))};
}

Reply rpc_err(const Value& id, int code, std::string msg, int status = 400) {
    Object e{{"code", jint(code)}, {"message", jstr(std::move(msg))}};
    return {status, dumps(jobj({{"jsonrpc", jstr("2.0")}, {"id", id}, {"error", jobj(std::move(e))}}))};
}

Reply handle_rpc(Agent& ag, const std::string& body, std::int64_t now) {
    auto doc = gj::parse(body);
    if (!doc) return rpc_err(Value{}, -32700, "Parse error");
    const Object* po = std::get_if<Object>(&doc->v);
    if (!po) return rpc_err(Value{}, -32600, "Invalid Request");
    Value id;
    if (auto it = po->find("id"); it != po->end()) id = it->second;
    const auto jv = po->find("jsonrpc");
    const auto* js = jv == po->end() ? nullptr : std::get_if<std::string>(&jv->second.v);
    if (!js || *js != "2.0") return rpc_err(id, -32600, "Invalid Request");

    Value params;
    if (auto it = po->find("params"); it != po->end()) params = it->second;
    if (params.falsy()) params = jobj({});
    const Object* pp = std::get_if<Object>(&params.v);
    if (!pp) return rpc_err(id, -32602, "Params must be a JSON object");

    std::string method = "None";
    if (auto it = po->find("method"); it != po->end())
        if (const auto* ms = std::get_if<std::string>(&it->second.v)) method = *ms;
    std::println("[{}] RPC call: {} (id={})", now, method, dumps(id));

    try {
        const Object& p = *pp;
        if (method == "node.execute") return rpc_ok(id, ag.handle_command(need(p, "envelope"), now));
        if (method == "node.freeze") {
            const std::string& scope = need(p, "scope").as<std::string>();
            const auto ts = to_int(need(p, "ts"));
            const std::string& sig = need(p, "sig").as<std::string>();
            const std::string detail = ag.handle_freeze(scope, ts, sig, now);
            return rpc_ok(id, jobj({{"detail", jstr(detail)}, {"frozen", jbool(ag.frozen())}}));
        }
        if (method == "node.unfreeze") {
            const std::string& scope = need(p, "scope").as<std::string>();
            const auto ts = to_int(need(p, "ts"));
            const std::string& sig = need(p, "sig").as<std::string>();
            const auto ts2 = to_int(need(p, "ts2"));
            const std::string& sig2 = need(p, "sig2").as<std::string>();
            const std::string detail = ag.handle_unfreeze(scope, ts, sig, ts2, sig2, now);
            return rpc_ok(id, jobj({{"detail", jstr(detail)}, {"frozen", jbool(ag.frozen())}}));
        }
        if (method == "node.heartbeat") {
            Value m = jobj({});
            if (auto it = p.find("metrics"); it != p.end()) m = it->second;
            return rpc_ok(id, ag.heartbeat(std::move(m), now));
        }
        if (method == "node.enroll_request") return rpc_ok(id, ag.enroll_request(need(p, "region"), now));
        return rpc_err(id, -32601, "Method not found: " + method, 404);
    } catch (const MissingParam& m) {
        return rpc_err(id, -32602, "Missing required parameter: '" + m.name + "'");
    } catch (const Malformed&) {
        return rpc_err(id, -32602, "Invalid parameter type");
    }
}

struct Conn {
    int fd;
    std::int64_t deadline;
    std::string in{}, out{};
    std::size_t off = 0;
    bool replied = false;
};

void reply(Conn& c, int status, const std::string& body) {
    const char* reason = status == 200 ? "OK" : status == 400 ? "Bad Request" : status == 404 ? "Not Found"
                       : status == 405 ? "Method Not Allowed" : status == 411 ? "Length Required"
                       : status == 413 ? "Payload Too Large" : "Request Header Fields Too Large";
    c.out = std::format(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, reason, body.size(), body);
    c.replied = true;
}

// Called whenever more bytes arrive; replies once the full request is buffered.
void process(Conn& c, Agent& ag, std::int64_t now) {
    const auto he = c.in.find("\r\n\r\n");
    if (he == std::string::npos) {
        if (c.in.size() > kMaxHead) reply(c, 431, R"({"error":"headers too large"})");
        return;
    }
    if (he > kMaxHead) return reply(c, 431, R"({"error":"headers too large"})");

    const std::string_view head(c.in.data(), he);
    const auto le = head.find("\r\n");
    const std::string_view line = head.substr(0, le);
    const auto sp1 = line.find(' ');
    const auto sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return reply(c, 400, R"({"error":"bad request line"})");
    const std::string_view method = line.substr(0, sp1);
    const std::string_view path = line.substr(sp1 + 1, sp2 - sp1 - 1);

    std::optional<std::size_t> cl;
    std::size_t pos = le == std::string_view::npos ? head.size() : le + 2;
    while (pos < head.size()) {
        auto e = head.find("\r\n", pos);
        if (e == std::string_view::npos) e = head.size();
        const std::string_view h = head.substr(pos, e - pos);
        pos = e + 2;
        const auto colon = h.find(':');
        if (colon == std::string_view::npos) continue;
        std::string name(h.substr(0, colon));
        std::ranges::transform(name, name.begin(), [](unsigned char ch) { return char(std::tolower(ch)); });
        if (name != "content-length") continue;
        std::string_view v = h.substr(colon + 1);
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
        while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
        std::size_t n{};
        auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
        if (ec != std::errc{} || p != v.data() + v.size()) return reply(c, 400, R"({"error":"bad content-length"})");
        cl = n;
    }

    if (path == "/health") {
        if (method != "GET") return reply(c, 405, R"({"error":"method not allowed"})");
        return reply(c, 200, dumps(ag.health(now)));
    }
    if (path == "/rpc") {
        if (method != "POST") return reply(c, 405, R"({"error":"method not allowed"})");
        if (!cl) return reply(c, 411, R"({"error":"content-length required"})");
        if (*cl > kMaxBody) return reply(c, 413, R"({"error":"body too large"})");
        if (c.in.size() < he + 4 + *cl) return;  // wait for the rest of the body
        const auto [status, out] = handle_rpc(ag, c.in.substr(he + 4, *cl), now);
        return reply(c, status, out);
    }
    reply(c, 404, R"({"error":"not found"})");
}

bool flush(Conn& c) {  // true when finished or the peer is gone
    while (c.off < c.out.size()) {
        const ssize_t n = ::send(c.fd, c.out.data() + c.off, c.out.size() - c.off, MSG_NOSIGNAL);
        if (n > 0) { c.off += std::size_t(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return false;
        return true;
    }
    return true;
}

void set_nonblock(int fd) { ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK); }

int listen_on(int port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    const int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port));
    ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || ::listen(fd, 16) < 0) {
        std::perror("bind/listen");
        ::close(fd);
        return -1;
    }
    set_nonblock(fd);
    return fd;
}

}  // namespace

int main(int argc, char** argv) {
    gc::init();
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    const std::string dir = argc > 1 ? argv[1] : ".";
    const int port = argc > 2 ? std::atoi(argv[2]) : 8444;

    auto eu1 = gc::load_priv(dir + "/keys/eu1.key");
    if (!eu1) die(eu1.error());
    gib::PubMap fixed;
    for (const char* r : {"policy", "owner", "owner_confirm"}) {
        auto k = gc::load_pub(dir + "/keys/" + r + ".pub");
        if (!k) die(k.error());
        fixed[r] = *k;
    }
    Registry trust(fixed.at("owner"), fixed, dir + "/cpp_trust.json");
    if (auto err = trust.load(); !err.empty()) die(err);

    // pre-signed omega registration (made by mkreg.py on the owner side); node never holds owner.key
    const std::string inbox = dir + "/omega_reg.json";
    if (file_exists(inbox)) {
        auto d = load_json(inbox);
        if (!d) {
            std::println("omega inbox unreadable: {}", d.error());
        } else {
            try {
                const Object& o = d->as<Object>();
                const auto v = trust.reg(field(o, "rec"), field(o, "sig").as<std::string>(),
                                         field(o, "ts").as<std::int64_t>(), unix_now());
                std::println("omega registration: {}", v.why);
                if (v.ok) std::rename(inbox.c_str(), (inbox + ".done").c_str());
            } catch (const Malformed&) {
                std::println("omega inbox malformed");
            }
        }
    }
    std::println("omega key: {}", trust.omega_status(unix_now()));

    Agent agent("eu1", *eu1, trust, dir + "/cpp_state.json");
    if (auto err = agent.load(); !err.empty()) die(err);

    ::signal(SIGPIPE, SIG_IGN);
    struct sigaction sa{};
    sa.sa_handler = [](int) { g_stop = 1; };
    ::sigaction(SIGTERM, &sa, nullptr);
    ::sigaction(SIGINT, &sa, nullptr);

    const int lfd = listen_on(port);
    if (lfd < 0) die("cannot listen on 127.0.0.1:" + std::to_string(port));
    std::println("[{}] C++ NodeAgent listening on http://127.0.0.1:{}", unix_now(), port);

    std::vector<Conn> conns;
    while (!g_stop) {
        std::vector<pollfd> fds{{lfd, POLLIN, 0}};
        for (const auto& c : conns) fds.push_back({c.fd, short(c.replied ? POLLOUT : POLLIN), 0});
        if (::poll(fds.data(), fds.size(), 1000) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        const std::int64_t now = unix_now();
        const std::size_t n_old = conns.size();

        if (fds[0].revents & POLLIN) {
            for (;;) {
                const int fd = ::accept(lfd, nullptr, nullptr);
                if (fd < 0) break;
                if (conns.size() >= kMaxConns) { ::close(fd); continue; }
                set_nonblock(fd);
                conns.push_back(Conn{.fd = fd, .deadline = now + kIdleSecs});
            }
        }

        for (std::size_t i = 0; i < n_old; ++i) {
            Conn& c = conns[i];
            const short ev = fds[i + 1].revents;
            bool done = (ev & (POLLERR | POLLNVAL)) != 0 || now > c.deadline;
            if (!done && !c.replied && (ev & (POLLIN | POLLHUP))) {
                char buf[8192];
                const ssize_t n = ::recv(c.fd, buf, sizeof buf, 0);
                if (n > 0) {
                    c.in.append(buf, std::size_t(n));
                    process(c, agent, now);
                } else if (n == 0 || (errno != EAGAIN && errno != EINTR && errno != EWOULDBLOCK)) {
                    done = true;
                }
            }
            if (!done && c.replied) done = flush(c);
            if (done) { ::close(c.fd); c.fd = -1; }
        }
        std::erase_if(conns, [](const Conn& c) { return c.fd < 0; });
    }
    for (auto& c : conns) ::close(c.fd);
    ::close(lfd);
    std::println("shutting down");
    return 0;
}
// END server.cpp
