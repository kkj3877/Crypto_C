# /lib/CMakeLists.txt

# 동적 라이브러리 ARIA_MODULE 을 만든다.
add_library(CRYPTO_MODULE SHARED
    lea.c
    aria.c
    block.c
    util.c
    test.c
)

# 해당 라이브러리 컴파일 시 사용할 헤더파일 경로
target_include_directories(CRYPTO_MODULE PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/crypto
)

# 해당 라이브러리를 컴파일 할 옵션
target_compile_options(CRYPTO_MODULE PRIVATE
    # -Wall
    # -Werror
)
