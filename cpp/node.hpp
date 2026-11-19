#pragma once
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>

#include "gib.hpp"

namespace node {

using gib::Value;
using gj::Array;
using gj::field;
using gj::Malformed;
using gj::Object;

inline constexpr std::int64_t kMaxTtl = 3600;         // longest request lifetime accepted
inline constexpr std::int64_t kPruneMargin = 60;      // keep a nonce this long past its expiry
inline constexpr std::int64_t kUnfreezeMaxAge = 600;  // ts2 must be this fresh
inline constexpr std::int64_t kHbBatch = 64;          // heartbeat counter saved every N beats
inline constexpr const char* kHealthCheckOut = "healthy";  // see srv_test.py

inline Value jint(std::int64_t x) { return Value{x}; }
inline Value jbool(bool x) { return Value{x}; }
inline Value jstr(std::string x) { return Value{std::move(x)}; }
inline Value jobj(Object x) { return Value{std::move(x)}; }

inline std::int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

inline bool file_exists(const std::string& p) { return ::access(p.c_str(), F_OK) == 0; }

// write tmp, fsync, rename: a crash leaves either the old file or the new one
inline bool atomic_write(const std::string& path, const std::string& data) {
    const std::string tmp = path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            ::unlink(tmp.c_str());
            return false;
        }
        off += std::size_t(n);
    }
    bool ok = ::fsync(fd) == 0;
    ok = (::close(fd) == 0) && ok;
    if (!ok) { ::unlink(tmp.c_str()); return false; }
    return ::rename(tmp.c_str(), path.c_str()) == 0;
}

inline std::expected<Value, std::string> load_json(const std::string& path) {
    auto t = gc::read_trimmed(path);
    if (!t) return std::unexpected(t.error());
    return gj::parse(*t);
}

// ---------------------------------------------------------------- trust registry
// Holds the single newest omega record. Port of trust_registry_new.py with the
// record itself persisted, so a restart needs no owner key and no re-signing.
class Registry {
public:
    static constexpr std::int64_t kRegWindow = 120, kSkew = 60;

    Registry(gc::Pub owner, gib::PubMap fixed, std::string path)
        : owner_(owner), fixed_(std::move(fixed)), path_(std::move(path)) {}

    std::string load() {  // "" on success, else an error (corrupt trust state is fatal)
        if (!file_exists(path_)) return {};
        auto d = load_json(path_);
        if (!d) return path_ + ": " + d.error();
        try {
            const Object& o = d->as<Object>();
            max_issued_ = field(o, "max_issued").as<std::int64_t>();
            if (auto it = o.find("record"); it != o.end()) {
                const auto ts = field(o, "ts").as<std::int64_t>();
                const std::string& sig = field(o, "sig").as<std::string>();
                if (!signed_ok(it->second, ts, sig)) return path_ + ": stored record signature invalid";
                auto p = parse_rec(it->second);
                if (!p) return path_ + ": stored record malformed";
                rec_ = it->second; rec_ts_ = ts; rec_sig_ = sig;
                issued_ = p->issued; expires_ = p->expires; omega_pk_ = p->pk;
                max_issued_ = std::max(max_issued_, issued_);
            }
        } catch (const Malformed&) { return path_ + ": malformed trust state"; }
        return {};
    }

    gib::Verdict reg(const Value& rec, const std::string& sig, std::int64_t ts, std::int64_t now) {
        if (!signed_ok(rec, ts, sig)) return {false, "DENY: record not signed by owner"};
        if (std::abs(now - ts) > kRegWindow) return {false, "DENY: registration stale"};
        auto p = parse_rec(rec);
        if (!p) return {false, "DENY: malformed record"};
        if (!(p->issued < p->expires) || p->issued > now + kSkew) return {false, "DENY: bad validity window"};
        if (p->issued <= max_issued_) return {false, "DENY: not newer than current record (replay)"};
        if (!persist(rec, ts, sig, p->issued)) return {false, "DENY: state write failed"};
        rec_ = rec; rec_ts_ = ts; rec_sig_ = sig;
        issued_ = p->issued; expires_ = p->expires; omega_pk_ = p->pk; max_issued_ = p->issued;
        return {true, "REGISTERED"};
    }

    gib::PubMap pubkeys_for(std::int64_t now) const {
        gib::PubMap m = fixed_;
        if (rec_ && issued_ <= now && now < expires_) m["omega"] = omega_pk_;
        return m;
    }

    const char* omega_status(std::int64_t now) const {
        if (!rec_) return "absent";
        if (now < issued_) return "not-yet-valid";
        if (now >= expires_) return "expired";
        return "ok";
    }

private:
    struct Parsed { std::int64_t issued, expires; gc::Pub pk; };

    static std::optional<Parsed> parse_rec(const Value& recv) {
        try {
            const Object& r = recv.as<Object>();
            Parsed p{};
            p.issued = field(r, "issued_at").as<std::int64_t>();
            p.expires = field(r, "expires_at").as<std::int64_t>();
            auto kb = gc::unhex(field(r, "pubkey").as<std::string>());
            if (!kb || kb->size() != p.pk.size()) return std::nullopt;
            std::copy(kb->begin(), kb->end(), p.pk.begin());
            return p;
        } catch (const Malformed&) { return std::nullopt; }
    }

    bool signed_ok(const Value& rec, std::int64_t ts, const std::string& sig) const {
        return gc::verify(owner_, sig, std::format("register|{}|{}", gib::digest(rec), ts));
    }

    bool persist(const Value& rec, std::int64_t ts, const std::string& sig, std::int64_t max_issued) const {
        Object o{{"max_issued", jint(max_issued)}, {"record", rec}, {"ts", jint(ts)}, {"sig", jstr(sig)}};
        std::string s;
        gj::dump(Value{std::move(o)}, s);
        return atomic_write(path_, s);
    }

    gc::Pub owner_;
    gib::PubMap fixed_;
    std::string path_;
    std::optional<Value> rec_;
    std::int64_t rec_ts_ = 0, issued_ = 0, expires_ = 0, max_issued_ = 0;
    std::string rec_sig_;
    gc::Pub omega_pk_{};
};

// ---------------------------------------------------------------- node agent
class Agent {
public:
    Agent(std::string node_id, gc::Priv key, Registry& trust, std::string path)
        : node_id_(std::move(node_id)), key_(key), trust_(trust), path_(std::move(path)) {}

    std::string load() {  // "" on success; a corrupt replay state must never silently reset
        if (!file_exists(path_)) return {};
        auto d = load_json(path_);
        if (!d) return path_ + ": " + d.error();
        try {
            const Object& o = d->as<Object>();
            for (const Value& n : field(o, "used").as<Array>()) used_.insert(n.as<std::string>());
            last_seq_ = field(o, "last_seq").as<std::int64_t>();
            frozen_ = field(o, "frozen").as<bool>();
            last_ctl_ = field(o, "last_ctl").as<std::int64_t>();
            if (auto it = o.find("hb_seq"); it != o.end()) hb_seq_ = it->second.as<std::int64_t>();
            hb_reserved_ = hb_seq_;
            if (auto it = o.find("used_exp"); it != o.end())
                for (const auto& [n, e] : it->second.as<Object>()) used_exp_[n] = e.as<std::int64_t>();
        } catch (const Malformed&) { return path_ + ": malformed state"; }
        return {};
    }

    const std::string& node_id() const { return node_id_; }
    bool frozen() const { return frozen_; }

    Value health(std::int64_t now) const {
        return jobj({{"status", jstr("ok")}, {"node_id", jstr(node_id_)}, {"frozen", jbool(frozen_)},
                     {"last_seq", jint(last_seq_)}, {"omega", jstr(trust_.omega_status(now))}});
    }

    Value handle_command(const Value& env, std::int64_t now) {
        try {
            const Object& e = env.as<Object>();
            const Value& reqv = field(e, "request");
            const Value& apv = field(e, "approvals");
            const Object& req = reqv.as<Object>();
            const Object& action = field(req, "action").as<Object>();
            const Value& nidv = field(e, "node_id");
            const auto* nid = std::get_if<std::string>(&nidv.v);
            const auto an = action.find("node");
            const bool addressed = nid && *nid == node_id_ && an != action.end() &&
                                   std::holds_alternative<std::string>(an->second.v) &&
                                   std::get<std::string>(an->second.v) == node_id_;
            if (!addressed) return result(env, "DENIED", "not addressed to this node", now);
            const auto seq = field(e, "seq").as<std::int64_t>();
            if (seq <= last_seq_) return result(env, "DENIED", "stale sequence", now);
            const auto flags = gib::derive_flags(action, field(req, "snapshot_id"), field(req, "omega_flags"));
            const auto tier = gib::compute_tier(field(action, "type").as<std::string>(), flags);
            if (frozen_ && tier != gib::Tier::Green) return result(env, "DENIED", "node frozen: read-only", now);

            // checked before authorize() so oversized-lifetime requests never burn a nonce
            const auto created = field(req, "created_at").as<std::int64_t>();
            const auto expires = field(req, "expires_at").as<std::int64_t>();
            if (expires - created > kMaxTtl) return result(env, "DENIED", "request ttl too long", now);

            const auto verdict = gib::authorize(reqv, apv, trust_.pubkeys_for(now), used_, now);
            track_nonce(req);
            prune(now);
            if (!save()) return result(env, "DENIED", "state write failed", now);  // nonce burn must persist
            if (!verdict.ok) return result(env, "DENIED", verdict.why, now);

            const auto out = run_handler(action);
            if (!out) return result(env, "DENIED", "action not in node allowlist", now);
            // handlers are dry-run stubs. When real ones arrive, persist last_seq BEFORE running them.
            last_seq_ = seq;
            if (!save()) return result(env, "DENIED", "state write failed", now);
            return result(env, "EXECUTED", verdict.why + " | " + *out, now);
        } catch (const Malformed&) {
            return result(env, "DENIED", "malformed command", now);
        }
    }

    std::string handle_freeze(const std::string& scope, std::int64_t ts, const std::string& sig, std::int64_t now) {
        const auto pubs = trust_.pubkeys_for(now);
        if (!gc::verify(pubs.at("owner"), sig, std::format("freeze|{}|{}", scope, ts)))
            return "DENY: freeze not signed by owner";
        if ((scope != node_id_ && scope != "*") || std::abs(now - ts) > 120 || ts <= last_ctl_)
            return "DENY: wrong scope, stale, or replayed";
        frozen_ = true;  // fail safe: stays frozen in memory even if the save fails
        last_ctl_ = ts;
        save();
        return "FROZEN: read-only";
    }

    std::string handle_unfreeze(const std::string& scope, std::int64_t ts, const std::string& sig,
                                std::int64_t ts2, const std::string& sig2, std::int64_t now) {
        const auto pubs = trust_.pubkeys_for(now);
        if (!gc::verify(pubs.at("owner"), sig, std::format("unfreeze|{}|{}", scope, ts)) ||
            !gc::verify(pubs.at("owner_confirm"), sig2, std::format("unfreeze_confirm|{}|{}", scope, ts2)))
            return "DENY: unfreeze needs owner and owner_confirm";
        if ((scope != node_id_ && scope != "*") || ts2 < ts + gib::COOLOFF || ts <= last_ctl_ ||
            now < ts2 || now - ts2 > kUnfreezeMaxAge)
            return "DENY: scope, cooling-off, or replay check failed";
        const auto old_ctl = last_ctl_;
        frozen_ = false;
        last_ctl_ = ts;
        if (!save()) {
            frozen_ = true;
            last_ctl_ = old_ctl;
            return "DENY: state write failed";
        }
        return "UNFROZEN";
    }

    Value heartbeat(Value metrics, std::int64_t now) {
        ++hb_seq_;
        if (hb_seq_ > hb_reserved_) {
            hb_reserved_ = hb_seq_ + kHbBatch - 1;
            save();
        }
        Object b{{"type", jstr("heartbeat")}, {"node_id", jstr(node_id_)}, {"seq", jint(hb_seq_)},
                 {"ts", jint(now)}, {"frozen", jbool(frozen_)}, {"metrics", std::move(metrics)}};
        return signed_value(std::move(b));
    }

    Value enroll_request(Value region, std::int64_t now) {
        unsigned char r[8];
        randombytes_buf(r, sizeof r);
        const std::string nonce = gc::hex(r);
        Object cert{{"node_id", jstr(node_id_)}, {"pubkey", jstr(gc::hex(key_.pk))}, {"region", std::move(region)},
                    {"issued_at", jint(now)}, {"expires_at", jint(now + 90 * 86400)}, {"nonce", jstr(nonce)}};
        const std::string pop = gc::sign_hex(
            key_, gib::digest(jobj({{"pop", jstr(node_id_)}, {"nonce", jstr(nonce)}})));
        return jobj({{"cert", jobj(std::move(cert))}, {"pop_sig", jstr(pop)}});
    }

private:
    Value signed_value(Object b) const {
        const std::string sig = gc::sign_hex(key_, gib::digest(Value{b}));
        b.emplace("sig", jstr(sig));
        return Value{std::move(b)};
    }

    Value result(const Value& env, const std::string& status, const std::string& detail, std::int64_t now) const {
        Value seq, ph;  // null unless the envelope carries them
        if (const auto* eo = std::get_if<Object>(&env.v)) {
            if (auto it = eo->find("seq"); it != eo->end()) seq = it->second;
            if (auto it = eo->find("request"); it != eo->end())
                if (const auto* ro = std::get_if<Object>(&it->second.v))
                    if (auto jt = ro->find("plan_hash"); jt != ro->end()) ph = jt->second;
        }
        Object b{{"type", jstr("result")}, {"node_id", jstr(node_id_)}, {"seq", seq}, {"ts", jint(now)},
                 {"plan_hash", ph}, {"status", jstr(status)}, {"detail", jstr(detail)}};
        return signed_value(std::move(b));
    }

    static std::optional<std::string> run_handler(const Object& action) {
        const std::string& type = field(action, "type").as<std::string>();
        static const std::map<std::string, const char*, std::less<>> verbs{
            {"scale", "scaled"}, {"place", "placed"}, {"workload_create", "created"},
            {"config_edit", "edited"}, {"delete", "deleted"}};
        if (type == "read") return std::string("state returned");
        if (type == "health_check") return std::string(kHealthCheckOut);
        if (auto it = verbs.find(type); it != verbs.end())
            return std::format("dry-run: {} {}", it->second, field(action, "target").as<std::string>());
        return std::nullopt;
    }

    // Record a nonce's expiry only when plan_hash proves expires_at is authentic,
    // otherwise a forged request could shorten a real nonce's lifetime.
    void track_nonce(const Object& req) {
        try {
            const Value& phv = field(req, "plan_hash");
            Object body = req;
            body.erase("plan_hash");
            const auto* ph = std::get_if<std::string>(&phv.v);
            if (!ph || gib::digest(Value{body}) != *ph) return;
            const std::string& n = field(req, "nonce").as<std::string>();
            if (used_.contains(n) && !used_exp_.contains(n))
                used_exp_[n] = field(req, "expires_at").as<std::int64_t>();
        } catch (const Malformed&) {}
    }

    void prune(std::int64_t now) {
        for (auto it = used_exp_.begin(); it != used_exp_.end();) {
            if (it->second + kPruneMargin < now) {
                used_.erase(it->first);
                it = used_exp_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // File stays readable by the Python NodeAgent: same keys, plus an ignored "used_exp".
    bool save() {
        gj::Array used;
        Object exp;
        for (const auto& n : used_) used.push_back(jstr(n));
        for (const auto& [n, e] : used_exp_) exp.emplace(n, jint(e));
        Object o{{"used", Value{std::move(used)}}, {"last_seq", jint(last_seq_)}, {"frozen", jbool(frozen_)},
                 {"last_ctl", jint(last_ctl_)}, {"hb_seq", jint(hb_reserved_)},
                 {"used_exp", jobj(std::move(exp))}};
        std::string s;
        gj::dump(Value{std::move(o)}, s);
        return atomic_write(path_, s);
    }

    std::string node_id_;
    gc::Priv key_;
    Registry& trust_;
    std::string path_;
    std::set<std::string> used_;
    std::map<std::string, std::int64_t> used_exp_;
    std::int64_t last_seq_ = -1, hb_seq_ = 0, hb_reserved_ = 0, last_ctl_ = 0;
    bool frozen_ = false;
};

}  // namespace node
// END node.hpp
