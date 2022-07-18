# CMake 프로그램의 최소 버전
cmake_minimum_required(VERSION 3.11)

# 프로젝트 정보
project(crypto_mode_prac
    VERSION 1.0
    DESCRIPTION "ARIA"
    LANGUAGES C
)

add_executable(program
    ./test/test.c
)

add_dependencies(program
    ARIA_MODULE
)

# 확인할 디렉토리 추가
add_subdirectory(lib)

# target_include_directories(program PUBLIC
#     ${CMAKE_SOURCE_DIR}/include
# )

target_compile_options(program PUBLIC
    -Wall
)

target_link_libraries(program
    ARIA_MODULE
)
