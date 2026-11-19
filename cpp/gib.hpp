#pragma once
#include <algorithm>
#include <format>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "json.hpp"

namespace gib {

using gj::Array;
using gj::field;
using gj::Malformed;
using gj::Object;
using gj::Value;

inline constexpr std::int64_t COOLOFF = 300;

enum class Tier { Green, Amber, Red };
inline const char* tier_name(Tier t) {
    static constexpr const char* n[] = {"GREEN", "AMBER", "RED"};
    return n[int(t)];
}

inline const std::map<std::string, Tier, std::less<>> BASE_TIER{
    {"read", Tier::Green}, {"health_check", Tier::Green}, {"route", Tier::Green},
    {"workload_create", Tier::Amber}, {"scale", Tier::Amber}, {"place", Tier::Amber},
    {"config_edit", Tier::Amber}, {"delete", Tier::Red}, {"wipe", Tier::Red},
    {"key_rotate", Tier::Red}, {"node_add", Tier::Red}, {"node_remove", Tier::Red},
    {"gibraltar_edit", Tier::Red}};
inline const std::set<std::string, std::less<>> RED_FLAGS{
    "KEY_MATERIAL", "NEW_NODE", "PRIVILEGE_ESCALATION", "UNREVERSIBLE", "DESTRUCTIVE"};
inline const std::set<std::string, std::less<>> AMBER_FLAGS{"EXTERNAL_EXPOSURE"};
inline const std::set<std::string, std::less<>> SNAPSHOT_REQUIRED{
    "key_rotate", "gibraltar_edit", "delete", "config_edit", "node_remove", "wipe"};

inline const std::vector<std::string>& required(Tier t) {
    static const std::vector<std::string> g{"omega"}, a{"omega", "policy", "owner"},
        r{"omega", "policy", "owner", "owner_confirm"};
    return t == Tier::Green ? g : t == Tier::Amber ? a : r;
}

inline std::string digest(const Value& v) {
    std::string s;
    gj::dump(v, s);
    return gc::sha256_hex(s);
}

inline std::string approval_msg(std::string_view role, std::string_view plan_hash, std::int64_t ts) {
    return std::format("gibraltar-approval-v2|{}|{}|{}", role, plan_hash, ts);
}

inline void add_flags(std::set<std::string>& out, const Value& v) {
    for (const Value& e : v.as<Array>()) out.insert(e.as<std::string>());
}

inline std::set<std::string> derive_flags(const Object& action, const Value& snapshot_id,
                                          const Value& omega_flags) {
    std::set<std::string> f;
    if (auto it = action.find("omega_flags"); it != action.end()) add_flags(f, it->second);
    if (!omega_flags.falsy()) add_flags(f, omega_flags);
    const std::string& type = field(action, "type").as<std::string>();
    static const Object none;
    const Object* params = &none;
    if (auto it = action.find("params"); it != action.end()) params = &it->second.as<Object>();
    if (type == "delete" || type == "wipe") f.insert("DESTRUCTIVE");
    if (SNAPSHOT_REQUIRED.contains(type) && snapshot_id.falsy()) f.insert("UNREVERSIBLE");
    if (type == "key_rotate") f.insert("KEY_MATERIAL");
    if (type == "node_add") f.insert("NEW_NODE");
    auto is_true = [&](const char* k) {
        auto it = params->find(k);
        return it != params->end() && std::holds_alternative<bool>(it->second.v) &&
               std::get<bool>(it->second.v);
    };
    if (is_true("expose")) f.insert("EXTERNAL_EXPOSURE");
    if (is_true("grant")) f.insert("PRIVILEGE_ESCALATION");
    return f;
}

inline Tier compute_tier(const std::string& type, const std::set<std::string>& flags) {
    int level = 2;  // unknown action types default to RED
    if (auto it = BASE_TIER.find(type); it != BASE_TIER.end()) level = int(it->second);
    auto any = [&](const auto& s) {
        return std::ranges::any_of(flags, [&](const std::string& x) { return s.contains(x); });
    };
    if (any(RED_FLAGS)) level = 2;
    if (any(AMBER_FLAGS)) level = std::max(level, 1);
    if (flags.contains("ANOMALY") || flags.size() >= 2) level = std::min(level + 1, 2);
    return Tier(level);
}

struct Verdict {
    bool ok;
    std::string why;
};
using PubMap = std::map<std::string, gc::Pub>;

inline std::string join(const std::vector<std::string>& v, std::string_view sep, std::string_view quote = "") {
    std::string o;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) o += sep;
        o += quote;
        o += v[i];
        o += quote;
    }
    return o;
}

// Port of gibraltar.authorize. Burns the nonce on first sight, even if denied later.
inline Verdict authorize(const Value& reqv, const Value& approvalsv, const PubMap& pubs,
                         std::set<std::string>& used, std::int64_t now) {
    try {
        const Object& req = reqv.as<Object>();
        Object body = req;
        body.erase("plan_hash");
        const Value& phv = field(req, "plan_hash");
        const auto* ph = std::get_if<std::string>(&phv.v);
        if (!ph || digest(Value{body}) != *ph) return {false, "DENY: request integrity check failed"};

        const std::string& nonce = field(req, "nonce").as<std::string>();
        if (used.contains(nonce)) return {false, "DENY: nonce already used (replay)"};
        used.insert(nonce);

        const auto created = field(req, "created_at").as<std::int64_t>();
        const auto expires = field(req, "expires_at").as<std::int64_t>();
        if (!(created <= now && now <= expires)) return {false, "DENY: request expired or not yet valid"};

        const Object& action = field(req, "action").as<Object>();
        const auto flags = derive_flags(action, field(req, "snapshot_id"), field(req, "omega_flags"));
        const Tier tier = compute_tier(field(action, "type").as<std::string>(), flags);
        const auto& needed = required(tier);

        std::map<std::string, const Object*> by_role;
        for (const Value& a : approvalsv.as<Array>()) {
            const Object& ao = a.as<Object>();
            const std::string& role = field(ao, "role").as<std::string>();
            if (!by_role.emplace(role, &ao).second) return {false, "DENY: duplicate approval for " + role};
        }

        std::vector<std::string> unexpected, missing;
        for (const auto& [role, _] : by_role)
            if (std::ranges::find(needed, role) == needed.end()) unexpected.push_back(role);
        if (!unexpected.empty())
            return {false, "DENY: unexpected approvals: [" + join(unexpected, ", ", "'") + "]"};
        for (const auto& role : needed)
            if (!by_role.contains(role)) missing.push_back(role);
        if (!missing.empty())
            return {false, std::string("DENY ") + tier_name(tier) + ": missing " + join(missing, ", ")};

        std::set<gc::Pub> distinct;
        for (const auto& role : needed) {
            auto it = pubs.find(role);
            if (it == pubs.end()) return {false, "DENY: no public key for " + role};
            distinct.insert(it->second);
        }
        if (distinct.size() != needed.size()) return {false, "DENY: required roles must use distinct keys"};

        std::map<std::string, std::int64_t> ts_of;
        for (const auto& role : needed) {
            const Object& ao = *by_role.at(role);
            const auto ts = field(ao, "ts").as<std::int64_t>();
            if (!(created <= ts && ts <= now)) return {false, "DENY: invalid approval time for " + role};
            const std::string& sig = field(ao, "sig").as<std::string>();
            if (!gc::verify(pubs.at(role), sig, approval_msg(role, *ph, ts)))
                return {false, "DENY: invalid signature for " + role};
            ts_of[role] = ts;
        }
        if (tier == Tier::Red && ts_of["owner_confirm"] < ts_of["owner"] + COOLOFF)
            return {false, "DENY RED: cooloff not satisfied"};
        return {true, std::string("AUTHORIZED ") + tier_name(tier)};
    } catch (const Malformed&) {
        return {false, "DENY: malformed request or approvals"};
    }
}

}  // namespace gib
