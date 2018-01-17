cmake_minimum_required(VERSION 3.8)
project(gstcencwidevinedec)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig)
pkg_check_modules(GST REQUIRED gstreamer-1.0)
pkg_check_modules(GSTBASE REQUIRED gstreamer-base-1.0)
pkg_check_modules(SSL REQUIRED openssl)
pkg_check_modules(XML REQUIRED libxml-2.0)

set(SOURCE_FILES
        src/gstcencdec.c
        src/gstcencdec.h
        src/gstcencelements.c
        deps/b64/b64.c
        deps/b64/b64.h
        )
set(PACKAGE_NAME "CencWidevineDec")
set(PACKAGE "https://github.com/bruni68510/cencdec")
set(VERSION "0.0.1" CACHE STRING "The verison of this plugin")


add_library(gstcencwidevinedec MODULE ${SOURCE_FILES})

set_target_properties(gstcencwidevinedec PROPERTIES LINKER_LANGUAGE C)

target_include_directories(gstcencwidevinedec SYSTEM PUBLIC ${GST_INCLUDE_DIRS})
target_include_directories(gstcencwidevinedec SYSTEM PUBLIC ${GSTBASE_INCLUDE_DIRS})
target_include_directories(gstcencwidevinedec SYSTEM PUBLIC ${SSL_INCLUDE_DIRS})
target_include_directories(gstcencwidevinedec SYSTEM PUBLIC ${XML_INCLUDE_DIRS})

target_link_libraries(gstcencwidevinedec ${GST_LIBRARIES})
target_link_libraries(gstcencwidevinedec ${GSTBASE_LIBRARIES})
target_link_libraries(gstcencwidevinedec ${SSL_LIBRARIES})
target_link_libraries(gstcencwidevinedec ${XML_LIBRARIES})

target_link_libraries(gstcencwidevinedec widevinecwrapperlib)


