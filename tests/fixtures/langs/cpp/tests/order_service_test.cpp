#include <gtest/gtest.h>
#include "../src/order_service.h"

TEST(OrderService, Places)
{
    OrderService svc;
    EXPECT_EQ(svc.place("book"), "book");
}
