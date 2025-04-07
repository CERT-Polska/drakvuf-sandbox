cmake_minimum_required(VERSION 3.2)
project(drak-ipt-tools CXX)

add_executable(drak-ipt-blocks drak-ipt-blocks.cpp)
target_link_libraries(drak-ipt-blocks ipt json-c spdlog fmt)
set_property(TARGET drak-ipt-blocks PROPERTY CXX_STANDARD 17)
install(TARGETS drak-ipt-blocks RUNTIME DESTINATION bin)
