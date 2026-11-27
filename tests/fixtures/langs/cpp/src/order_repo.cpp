#include "order_repo.h"

std::string OrderRepo::save(const std::string &item)
{
    std::string sql = "INSERT INTO orders(item) VALUES ('" + item + "')";
    sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr);
    return item;
}
