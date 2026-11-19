#pragma once
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace gj {

struct Malformed {};  // any shape mismatch; authorize() maps it to "malformed"

struct Value;
using Array  = std::vector<Value>;
using Object = std::map<std::string, Value>;  // byte order == Python sort_keys order

struct Value {
    std::variant<std::nullptr_t, bool, std::int64_t, std::string, Array, Object> v;

    template <class T> const T& as() const {
        if (auto* p = std::get_if<T>(&v)) return *p;
        throw Malformed{};
    }
    bool falsy() const {  // Python truthiness
        return std::visit([](const auto& a) -> bool {
            using T = std::decay_t<decltype(a)>;
            if constexpr (std::is_same_v<T, std::nullptr_t>) return true;
            else if constexpr (std::is_same_v<T, bool>) return !a;
            else if constexpr (std::is_same_v<T, std::int64_t>) return a == 0;
            else return a.empty();
        }, v);
    }
};

inline const Value& field(const Object& o, const char* k) {
    auto it = o.find(k);
    if (it == o.end()) throw Malformed{};
    return it->second;
}

struct ParseError { std::string msg; };

class Parser {
    std::string_view s_;
    std::size_t i_ = 0;
    int depth_ = 0;

    [[noreturn]] void fail(const char* m) const {
        throw ParseError{std::string(m) + " at " + std::to_string(i_)};
    }
    void ws() {
        while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r')) ++i_;
    }
    void expect(char c) {
        if (i_ >= s_.size() || s_[i_] != c) fail("unexpected character");
        ++i_;
    }
    void lit(std::string_view w) {
        if (s_.substr(i_, w.size()) != w) fail("bad literal");
        i_ += w.size();
    }
    unsigned hex4() {
        if (i_ + 4 > s_.size()) fail("short \\u escape");
        unsigned x = 0;
        for (int k = 0; k < 4; ++k) {
            char c = s_[i_++];
            x <<= 4;
            if (c >= '0' && c <= '9') x |= unsigned(c - '0');
            else if (c >= 'a' && c <= 'f') x |= unsigned(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') x |= unsigned(c - 'A' + 10);
            else fail("bad hex digit");
        }
        return x;
    }
    static void utf8(std::string& o, unsigned cp) {
        if (cp < 0x80) o += char(cp);
        else if (cp < 0x800) {
            o += char(0xC0 | (cp >> 6));
            o += char(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            o += char(0xE0 | (cp >> 12));
            o += char(0x80 | ((cp >> 6) & 0x3F));
            o += char(0x80 | (cp & 0x3F));
        } else {
            o += char(0xF0 | (cp >> 18));
            o += char(0x80 | ((cp >> 12) & 0x3F));
            o += char(0x80 | ((cp >> 6) & 0x3F));
            o += char(0x80 | (cp & 0x3F));
        }
    }
    std::string str() {
        expect('"');
        std::string o;
        for (;;) {
            if (i_ >= s_.size()) fail("unterminated string");
            unsigned char c = static_cast<unsigned char>(s_[i_++]);
            if (c == '"') return o;
            if (c < 0x20) fail("control character in string");
            if (c != '\\') { o += char(c); continue; }
            if (i_ >= s_.size()) fail("bad escape");
            char e = s_[i_++];
            switch (e) {
                case '"':  o += '"';  break;
                case '\\': o += '\\'; break;
                case '/':  o += '/';  break;
                case 'b':  o += '\b'; break;
                case 'f':  o += '\f'; break;
                case 'n':  o += '\n'; break;
                case 'r':  o += '\r'; break;
                case 't':  o += '\t'; break;
                case 'u': {
                    unsigned cp = hex4();
                    if (cp >= 0xD800 && cp < 0xDC00) {
                        if (s_.substr(i_, 2) != "\\u") fail("lone surrogate");
                        i_ += 2;
                        unsigned lo = hex4();
                        if (lo < 0xDC00 || lo > 0xDFFF) fail("bad surrogate pair");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        fail("lone surrogate");
                    }
                    utf8(o, cp);
                    break;
                }
                default: fail("bad escape");
            }
        }
    }
    Value number() {
        std::size_t st = i_;
        if (i_ < s_.size() && s_[i_] == '-') ++i_;
        std::size_t ds = i_;
        while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') ++i_;
        if (i_ == ds) fail("bad value");
        if (s_[ds] == '0' && i_ - ds > 1) fail("leading zero");
        if (i_ < s_.size() && (s_[i_] == '.' || s_[i_] == 'e' || s_[i_] == 'E')) fail("floats unsupported");
        std::int64_t n{};
        auto [p, ec] = std::from_chars(s_.data() + st, s_.data() + i_, n);
        if (ec != std::errc{} || p != s_.data() + i_) fail("integer out of range");
        return Value{n};
    }
    Value array() {
        if (++depth_ > 64) fail("too deep");
        expect('[');
        Array a;
        ws();
        if (i_ < s_.size() && s_[i_] == ']') { ++i_; --depth_; return Value{std::move(a)}; }
        for (;;) {
            a.push_back(value());
            ws();
            if (i_ < s_.size() && s_[i_] == ',') { ++i_; continue; }
            expect(']');
            break;
        }
        --depth_;
        return Value{std::move(a)};
    }
    Value object() {
        if (++depth_ > 64) fail("too deep");
        expect('{');
        Object o;
        ws();
        if (i_ < s_.size() && s_[i_] == '}') { ++i_; --depth_; return Value{std::move(o)}; }
        for (;;) {
            ws();
            std::string k = str();
            ws(); expect(':');
            Value val = value();
            o.insert_or_assign(std::move(k), std::move(val));
            ws();
            if (i_ < s_.size() && s_[i_] == ',') { ++i_; continue; }
            expect('}');
            break;
        }
        --depth_;
        return Value{std::move(o)};
    }
    Value value() {
        ws();
        if (i_ >= s_.size()) fail("unexpected end");
        switch (s_[i_]) {
            case '{': return object();
            case '[': return array();
            case '"': return Value{str()};
            case 't': lit("true");  return Value{true};
            case 'f': lit("false"); return Value{false};
            case 'n': lit("null");  return Value{};
            default:  return number();
        }
    }

public:
    explicit Parser(std::string_view s) : s_(s) {}
    std::expected<Value, std::string> run() {
        try {
            Value r = value();
            ws();
            if (i_ != s_.size()) fail("trailing data");
            return r;
        } catch (const ParseError& e) {
            return std::unexpected(e.msg);
        }
    }
};

inline std::expected<Value, std::string> parse(std::string_view s) { return Parser(s).run(); }

// Matches Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)
inline void dump_str(std::string_view s, std::string& o) {
    o += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\u%04x", c);
                    o += b;
                } else {
                    o += char(c);
                }
        }
    }
    o += '"';
}

inline void dump(const Value& x, std::string& o) {
    std::visit([&](const auto& a) {
        using T = std::decay_t<decltype(a)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) o += "null";
        else if constexpr (std::is_same_v<T, bool>) o += a ? "true" : "false";
        else if constexpr (std::is_same_v<T, std::int64_t>) o += std::to_string(a);
        else if constexpr (std::is_same_v<T, std::string>) dump_str(a, o);
        else if constexpr (std::is_same_v<T, Array>) {
            o += '[';
            bool first = true;
            for (const auto& e : a) { if (!first) o += ','; first = false; dump(e, o); }
            o += ']';
        } else {
            o += '{';
            bool first = true;
            for (const auto& [k, e] : a) {
                if (!first) o += ',';
                first = false;
                dump_str(k, o);
                o += ':';
                dump(e, o);
            }
            o += '}';
        }
    }, x.v);
}

}  // namespace gj
