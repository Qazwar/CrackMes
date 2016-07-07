#include <vector>
#include <string>
#include <iostream>
#include <map>

class Checker {
    std::map<char, char> dict_ = { {'u','e'}, {'e','u'}, {'a','o'}, {'b', 'l'} };
    std::string code_ = "enback mu";

public:
    Checker() {
        for (auto& c : code_) {
            if (dict_.count(c) > 0)
            {
                c = dict_[c];
            }
        }
    }

    bool checkMe(const std::string& code) {
        return code == code_;
    }
};

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (argv[1] == std::string("--hint")) {
            std::cout << "enback mu\n";
        }
    }

    std::cout << "Please Enter the key: ";
    std::string entry;
    std::getline(std::cin, entry);
    Checker checker;
    if (checker.checkMe(entry)) {
        std::cout << "Proceed to level 2\n";
    }
    else {
        std::cout << "Try again soon...\n";
    }
    return 0;
}