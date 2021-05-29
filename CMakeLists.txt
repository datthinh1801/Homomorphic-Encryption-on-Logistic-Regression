cmake_minimum_required(VERSION 3.20)

add_executable(main src/main.cpp)

find_package(SEAL 3.6 REQUIRED)
target_link_libraries(main SEAL::seal)