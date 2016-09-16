cmake_minimum_required(VERSION 3.2.0)
project(tracey VERSION 0.0.0)

find_package(Threads)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(TRACEY_IS_ROOT TRUE)
else()
    set(TRACEY_IS_ROOT FALSE)
endif()

get_filename_component(TRACEY_EXTERN_DIR extern ABSOLUTE)

add_library(tracey INTERFACE)
add_library(tracey::tracey ALIAS tracey)
target_include_directories(tracey
    INTERFACE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    )
target_compile_features(tracey
    INTERFACE
        cxx_strong_enums
        cxx_thread_local
    )
target_link_libraries(tracey INTERFACE Threads::Threads)

if(TRACEY_IS_ROOT)
    include(CTest)
    enable_testing()
    if(BUILD_TESTING)
        get_filename_component(catch_hpp extern/catch/catch.hpp ABSOLUTE)
        add_subdirectory(tests)
    endif()
    set(CPACK_PROJECT_NAME ${PROJECT_NAME})
    set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
    include(CPack)
endif()