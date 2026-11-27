#pragma once
#include <string>

class Repo {
public:
    virtual std::string save(const std::string &item) { return item; }
};
