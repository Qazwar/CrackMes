#include <vector>
#include <string>
#include <iostream>
#include <map>
#include "sha256.h"
#include <Windows.h>

class Checker {
    std::string code_ = "This is a super secret string";
public:

    bool checkMe(const std::string& code) {
        sha256::Sha256 hasher;
        hasher.update(std::vector<sha256::BYTE>(code_.begin(), code_.end()));
        auto hash = hasher.hexDigest();
        //std::cout << hash.substr(0, 5) << std::endl;
        return hash.substr(0, 5) == code;

    }
};

int main(int argc, char* argv[]) {
    if (IsDebuggerPresent()) {
        //Should still be able to attach durring the getline without issue.
        std::cerr << "Thats not how to you run me...\n";
        exit(-1);
    }
    if (argc > 1) {
        if (argv[1] == std::string("--hint")) {
            std::cout << "What are these constants\n";
        }
    }

    std::cout << "Please Enter the key: ";
    std::string entry;
    std::getline(std::cin, entry);
    Checker checker;
    if (checker.checkMe(entry)) {
        std::cout << "Proceed to level 3\n";
    }
    else {
        std::cout << "Try again soon...\n";
    }
    return 0;
}
