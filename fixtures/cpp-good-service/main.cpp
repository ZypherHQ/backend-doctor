#include <iostream>
#include <optional>
#include <string>

std::optional<std::string> normalize_name(const std::string& input) {
    if (input.empty() || input.size() > 80) {
        return std::nullopt;
    }
    return input;
}

int main() {
    std::string name;
    if (std::getline(std::cin, name)) {
        if (auto normalized = normalize_name(name)) {
            std::cout << "hello " << *normalized << '\n';
        }
    }
    return 0;
}
