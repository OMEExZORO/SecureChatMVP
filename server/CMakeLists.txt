cmake_minimum_required(VERSION 3.10)
project(SecureChatServer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Drogon REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/XorCipher.cpp
    src/CaesarCipher.cpp
    src/Sha256Hasher.cpp
    src/ReplayGuard.cpp
    src/ConnRegistry.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE 
    Drogon::Drogon
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
