cmake_minimum_required(VERSION 3.16)
project(shop CXX)
add_executable(shop src/main.cpp src/order_controller.cpp src/order_service.cpp src/order_repo.cpp src/auth.cpp)
