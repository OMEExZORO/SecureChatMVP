cmake_minimum_required(VERSION 3.10)
project(SecureChatServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-specific settings
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
endif()

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/main.cpp
)

# Create executable
add_executable(SecureChatServer ${SOURCES})

# Link Windows Socket library
if(WIN32)
    target_link_libraries(SecureChatServer ws2_32)
endif()

# Set output directory
set_target_properties(SecureChatServer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
