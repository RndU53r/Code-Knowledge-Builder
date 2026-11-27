#pragma once
#include <sqlite3.h>
#include "repo.h"

class OrderRepo : public Repo {
public:
    std::string save(const std::string &item) override;

private:
    sqlite3 *db_;
};
