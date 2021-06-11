cmake_minimum_required(VERSION 3.20)
project("Homomorphic Encrypt on Logistic Regression")

add_executable(main src/main.cpp)

find_package (SEAL)
target_link_libraries(main SEAL::seal)
