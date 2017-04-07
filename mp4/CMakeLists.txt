cmake_minimum_required(VERSION 3.6)
project(mp4)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
        client-server.cpp)

add_executable(mp4 ${SOURCE_FILES})