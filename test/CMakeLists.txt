
add_executable(test_aria ./test_aria.c)
target_link_libraries(test_aria PUBLIC CRYPTO_MODULE)

add_executable(test_lea ./test_lea.c)
target_link_libraries(test_lea PUBLIC CRYPTO_MODULE)

# add_dependencies(program
#     CRYPTO_MODULE
# )

