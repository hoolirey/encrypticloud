#include <iostream>
#include <iterator>
#include <print>

#include "gib.hpp"

int main(int argc, char** argv) {
    gc::init();
    if (argc < 2) {
        std::println(stderr, "usage: conform digest | conform auth <keydir>");
        return 2;
    }
    const std::string mode = argv[1];
    const std::string in((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    auto doc = gj::parse(in);
    if (!doc) {
        std::println(stderr, "parse error: {}", doc.error());
        return 2;
    }
    if (mode == "digest") {
        std::println("{}", gib::digest(*doc));
        return 0;
    }
    if (mode == "auth" && argc == 3) {
        gib::PubMap pubs;
        for (const char* r : {"omega", "policy", "owner", "owner_confirm"}) {
            auto k = gc::load_pub(std::string(argv[2]) + "/" + r + ".pub");
            if (!k) {
                std::println(stderr, "{}", k.error());
                return 2;
            }
            pubs[r] = *k;
        }
        try {
            const auto& o = doc->as<gj::Object>();
            std::set<std::string> used;
            auto v = gib::authorize(gj::field(o, "req"), gj::field(o, "approvals"), pubs, used,
                                    gj::field(o, "now").as<std::int64_t>());
            std::println("{}\t{}", int(v.ok), v.why);
        } catch (const gj::Malformed&) {
            std::println(stderr, "bad harness input");
            return 2;
        }
        return 0;
    }
    std::println(stderr, "usage: conform digest | conform auth <keydir>");
    return 2;
}
