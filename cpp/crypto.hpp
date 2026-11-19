#pragma once
#include <sodium.h>

#include <array>
#include <cctype>
#include <cstdlib>
#include <expected>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gc {

using Pub = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>;
struct Priv {
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> sk;
    Pub pk;
};

inline void init() { if (sodium_init() < 0) std::abort(); }

inline std::optional<std::vector<unsigned char>> unhex(std::string_view h) {
    if (h.size() % 2) return std::nullopt;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<unsigned char> o;
    o.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2) {
        int a = nib(h[i]), b = nib(h[i + 1]);
        if (a < 0 || b < 0) return std::nullopt;
        o.push_back(static_cast<unsigned char>((a << 4) | b));
    }
    return o;
}

inline std::string hex(std::span<const unsigned char> b) {
    static constexpr char d[] = "0123456789abcdef";
    std::string o;
    for (unsigned char c : b) { o += d[c >> 4]; o += d[c & 15]; }
    return o;
}

inline std::string sha256_hex(std::string_view m) {
    unsigned char out[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(out, reinterpret_cast<const unsigned char*>(m.data()), m.size());
    return hex(out);
}

inline std::expected<std::string, std::string> read_trimmed(const std::string& path) {
    std::ifstream f(path);
    if (!f) return std::unexpected("cannot open " + path);
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    return s;
}

inline std::expected<Pub, std::string> load_pub(const std::string& path) {
    auto t = read_trimmed(path);
    if (!t) return std::unexpected(t.error());
    auto b = unhex(*t);
    if (!b || b->size() != crypto_sign_PUBLICKEYBYTES) return std::unexpected("bad public key: " + path);
    Pub p;
    std::copy(b->begin(), b->end(), p.begin());
    return p;
}

// .key files hold the 32-byte Ed25519 seed as hex, same as the Python side
inline std::expected<Priv, std::string> load_priv(const std::string& path) {
    auto t = read_trimmed(path);
    if (!t) return std::unexpected(t.error());
    auto b = unhex(*t);
    if (!b || b->size() != crypto_sign_SEEDBYTES) return std::unexpected("bad private key: " + path);
    Priv k;
    crypto_sign_seed_keypair(k.pk.data(), k.sk.data(), b->data());
    return k;
}

inline std::string sign_hex(const Priv& k, std::string_view msg) {
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr, reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), k.sk.data());
    return hex(sig);
}

inline bool verify(const Pub& pk, std::string_view sig_hex, std::string_view msg) {
    auto s = unhex(sig_hex);
    if (!s || s->size() != crypto_sign_BYTES) return false;
    return crypto_sign_verify_detached(s->data(), reinterpret_cast<const unsigned char*>(msg.data()),
                                       msg.size(), pk.data()) == 0;
}

}  // namespace gc
