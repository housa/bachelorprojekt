cmake_minimum_required(VERSION 3.7)
project(project)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(libsnark)

include_directories(libsnark)

add_definitions(-DCURVE_BN128)

add_executable(project src/main.cpp src/suppe/snark.h src/suppe/snark.tpp)

target_link_libraries(project snark)