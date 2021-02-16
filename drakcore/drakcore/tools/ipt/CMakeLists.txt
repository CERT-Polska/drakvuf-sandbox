cmake_minimum_required(VERSION 3.2)
project(ipt-tools CXX)

add_executable(ipt-blocks ipt-blocks.cpp)
target_link_libraries(ipt-blocks ipt json-c spdlog fmt)
set_property(TARGET ipt-blocks PROPERTY CXX_STANDARD 17)
