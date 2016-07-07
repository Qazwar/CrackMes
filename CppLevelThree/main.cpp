#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <map>
#include "sha256.h"
#include <Windows.h>
#include <algorithm>

class Checker {
    std::string code1_;
    std::string code2_;
public:
    Checker(const std::string& code1, const std::string& code2) :code1_(code1), code2_(code2) {}

    bool checkMe(const std::string& code) {
        try {
            sha256::Sha256 hasher1;
            hasher1.update(std::vector<sha256::BYTE>(code1_.begin(), code1_.end()));
            auto hash1 = hasher1.digest();
            sha256::Sha256 hasher2;
            hasher2.update(std::vector<sha256::BYTE>(code2_.begin(), code2_.end()));
            auto hash2 = hasher2.digest();

            //print out the answer....
            /*
            std::cout << "answer: ";
            for (auto i = 0U; i < 10; ++i)
                std::cout << std::setw(2) << std::hex << std::setfill('0') << static_cast<int>(hash1[i] ^ hash2[i]);
            std::cout << std::endl;
            */

            if (code.size() != 20)
                return false;

            std::vector<sha256::BYTE> test;
            for (auto i = 0; i < 20; i += 2) {
                test.push_back(std::stoi(code.substr(i, 2), nullptr, 16));
            }
            
            auto index = 0U;
            std::transform(hash1.begin(), hash1.begin() + 10, hash1.begin(), [test, &index](sha256::BYTE c) { return c ^ test[index++]; });
            return std::equal(hash1.begin(), hash1.begin() + 10, hash2.begin(), hash2.begin() + 10);
        }
        catch (const std::exception&) {
            return false;
        }
    }
};

const std::string winner = "Ta Ta That's all folks!!!\n";
const std::string loser = "Try again soon...\n";
const std::vector<std::string> codes = { //size 18
    "Today it's up to you to create the peacefulness you long for.",
    "A friend asks only for your time not your money.",
    "If you refuse to accept anything but the best, you very often get it.",
    "A smile is your passport into the hearts of others.",
    "A good way to keep healthy is to eat more Chinese food.",
    "Your high - minded principles spell success.",
    "Hard work pays off in the future, laziness pays off now.",
    "Change can hurt, but it leads a path to something better.",
    "Enjoy the good luck a companion brings you.",
    "People are naturally attracted to you.",
    "Hidden in a valley beside an open stream - This will be the type of place where you will find your dream.",
    "A chance meeting opens new doors to success and friendship.",
    "You learn from your mistakes... You will learn a lot today.",
    "If you have something good in your life, don't let it go!",
    "What ever you're goal is in life, embrace it visualize it, and for it will be yours.",
    "Your shoes will make you happy today.",
    "You cannot love life until you live the life you love.",
    "Nothing astonishes men so much as common sense and plain dealing.",
    "Its amazing how much good you can do if you dont care who gets the credit." };

int main(int argc, char* argv[]) try{
    /*
    if (IsDebuggerPresent()) {
        std::cerr << "Thats not how to you run me...\n";
        exit(-1);
    }
    */
    if (argc > 1) {
        if (argv[1] == std::string("--hint")) {
            std::cout << "Don't interupt me when I'm interupting.";
        }
    }

    std::cout << "Please Enter the key: ";
    auto c = winner[29]; //exception!!!! Tricky Trickster
    std::string entry;
    std::getline(std::cin, entry);
    Checker checker(codes[2], codes[argc]);
    if (checker.checkMe(entry)) {
        std::cout << winner;
    }
    else {
        std::cout << loser;
    }
    return 0;
}
catch (...) {
//Anit C++ fun...
    std::string entry;
    std::getline(std::cin, entry);
    Checker checker(codes[14], codes[8]);
    if (checker.checkMe(entry)) {
        /*
        if (IsDebuggerPresent()) {
            std::cerr << "Thats not how to you run me...\n";
            exit(-1);
        }
        */
        std::cout << winner;
    }
    else {
        std::cout << loser;
    }
    return 0;
}
