cmake_minimum_required(VERSION 3.7)
project(project)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp Node.cpp Node.h accessrights/AccessRight.cpp accessrights/AccessRight.h accessrights/Command.cpp accessrights/Command.h accessrights/Path.cpp accessrights/Path.h accessrights/Taglist.cpp accessrights/Taglist.h TestTree1.h)
add_executable(project ${SOURCE_FILES})