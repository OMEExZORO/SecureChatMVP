cmake_minimum_required(VERSION 3.10)
project(SecureChatServer CXX)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)
pkg_check_modules(CARES REQUIRED libcares)
pkg_check_modules(UUID REQUIRED uuid)
pkg_check_modules(ZLIB REQUIRED zlib)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(BROTLIDEC REQUIRED libbrotlidec)
pkg_check_modules(BROTLIENC REQUIRED libbrotlienc)
pkg_check_modules(BROTLICOMMON REQUIRED libbrotlicommon)

set(C-ARES_INCLUDE_DIRS ${CARES_INCLUDE_DIRS})
set(C-ARES_LIBRARIES ${CARES_LIBRARIES})
find_library(ZLIB_LIBRARY NAMES z PATHS ${ZLIB_LIBRARY_DIRS} NO_DEFAULT_PATH)
set(ZLIB_INCLUDE_DIR ${ZLIB_INCLUDE_DIRS})
find_library(SQLITE3_LIBRARY NAMES sqlite3 PATHS ${SQLITE3_LIBRARY_DIRS} NO_DEFAULT_PATH)
set(SQLITE3_INCLUDE_DIRS ${SQLITE3_INCLUDE_DIRS})
find_library(BROTLIDEC_LIBRARY NAMES brotlidec PATHS ${BROTLIDEC_LIBRARY_DIRS} NO_DEFAULT_PATH)
find_library(BROTLIENC_LIBRARY NAMES brotlienc PATHS ${BROTLIENC_LIBRARY_DIRS} NO_DEFAULT_PATH)
find_library(BROTLICOMMON_LIBRARY NAMES brotlicommon PATHS ${BROTLICOMMON_LIBRARY_DIRS} NO_DEFAULT_PATH)
set(BROTLI_INCLUDE_DIR ${BROTLIDEC_INCLUDE_DIRS})

find_package(Drogon REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${JSONCPP_INCLUDE_DIRS})
include_directories(${CARES_INCLUDE_DIRS})
include_directories(${UUID_INCLUDE_DIRS})

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
    ${JSONCPP_LIBRARIES}
    ${CARES_LIBRARIES}
    ${UUID_LIBRARIES}
)

link_directories(${JSONCPP_LIBRARY_DIRS})
link_directories(${CARES_LIBRARY_DIRS})
link_directories(${UUID_LIBRARY_DIRS})

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
