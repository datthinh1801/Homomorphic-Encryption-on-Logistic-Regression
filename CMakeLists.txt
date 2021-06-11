cmake_minimum_required(VERSION 3.20)
project("Homomorphic Encrypt on Logistic Regression")

add_executable(main src/main.cpp)

set(CMAKE_PREFIX_PATH "./SEAL-3.6.5/cmake/SEALConfig.cmake.in")
find_package (SEAL)
target_link_libraries(main SEAL::seal)
