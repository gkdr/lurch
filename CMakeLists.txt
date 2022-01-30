# Copyright (c) 2022 Sebastian Pipping <sebastian@pipping.org>
# Licensed under the GPL v2 or later

cmake_minimum_required(VERSION 3.16.3)

project(lurch
    VERSION
        0.7.0
    LANGUAGES
        C
)

include(FindPkgConfig)
include(GNUInstallDirs)


#
# Public configuration
#
option(BUILD_SHARED_LIBS "Build shared libraries (rather than static ones)" ON)
option(LURCH_INSTALL "Install build artifacts" ON)
option(LURCH_WITH_TESTS "Build test suite (depends on cmocka)" ON)
option(LURCH_WITH_SYSTEM_AXC "Use system-wide axc (rather than the bundled copy)" ON)
option(LURCH_WITH_SYSTEM_OMEMO "Use system-wide libomemo (rather than the bundled copy)" ON)
if(NOT _LURCH_HELP)  # hide from "cmake -D_LURCH_HELP=ON -LH ." output
    option(_LURCH_WARNINGS_AS_ERRORS "(Unofficial!) Turn warnings into errors" OFF)
    option(_LURCH_WITH_COVERAGE "(Unofficial!) Build with coverage" OFF)
endif()


#
# Global CPPFLAGS and CFLAGS
#
add_compile_definitions(
    _XOPEN_SOURCE=700
    _DEFAULT_SOURCE
)
add_compile_options(
    -std=c99
    -Wall
    -Wstrict-overflow
)

if(_LURCH_WARNINGS_AS_ERRORS)
    add_compile_options(-Werror)
endif()

if(_LURCH_WITH_COVERAGE)
    set(_LURCH_COVERAGE_FLAGS -g -O0 --coverage)
    add_compile_options(${_LURCH_COVERAGE_FLAGS})
    link_libraries(${_LURCH_COVERAGE_FLAGS})
endif()


#
# Build dependencies
#
function(_lurch_add_bundled name source_dir)
    add_subdirectory(${source_dir})
    get_directory_property(_bundled_version DIRECTORY ${source_dir} DEFINITION PROJECT_VERSION)
    message(STATUS "Checking for module '${name}'")  # sending this late to workaround output ordering issues
    message(STATUS "  Found ${name}, version ${_bundled_version}(+) -- bundle from ${source_dir}")
endfunction()

function(_lurch_complain_if_missing var_prefix module_name flag_name)
    if(NOT ${var_prefix}_FOUND)
        message(SEND_ERROR
            "Required package \"${module_name}\" was not found. "
            "Please either "
            "(a) install the related package of your operating system or "
            "(b) pass argument -D${flag_name}=OFF to CMake "
            "to use the bundled copy of ${module_name}.")
    endif()
endfunction()

# NOTE: We cannot use "pkg_check_modules([..] IMPORTED_TARGET [..])"
#       because we'd run into a (false positive) CMake error
#       "contains relative path in its INTERFACE_INCLUDE_DIRECTORIES"
#       when using "target_link_libraries([..] PkgConfig::[..])" with msys2.
if(LURCH_WITH_SYSTEM_AXC)
    # NOTE: Avoiding REQUIRED just to do custom messaging
    pkg_check_modules(AXC "libaxc")
    _lurch_complain_if_missing(AXC "libaxc" LURCH_WITH_SYSTEM_AXC)
else()
    _lurch_add_bundled(libaxc ${CMAKE_CURRENT_SOURCE_DIR}/lib/axc)
    if(BUILD_SHARED_LIBS)
        set(_LURCH_AXC_BINARY_GLOB ${CMAKE_CURRENT_BINARY_DIR}/lib/axc/libaxc${CMAKE_SHARED_LIBRARY_SUFFIX}*)
    endif()
endif()

if(LURCH_WITH_SYSTEM_OMEMO)
    # NOTE: Avoiding REQUIRED just to do custom messaging
    pkg_check_modules(OMEMO "libomemo>=0.8.0")
    _lurch_complain_if_missing(OMEMO "libomemo" LURCH_WITH_SYSTEM_OMEMO)
else()
    _lurch_add_bundled(libomemo ${CMAKE_CURRENT_SOURCE_DIR}/lib/libomemo)
    if(BUILD_SHARED_LIBS)
        set(_LURCH_OMEMO_BINARY_GLOB ${CMAKE_CURRENT_BINARY_DIR}/lib/libomemo/libomemo${CMAKE_SHARED_LIBRARY_SUFFIX}*)
    endif()
endif()

if(LURCH_WITH_TESTS)
    pkg_check_modules(CMOCKA REQUIRED "cmocka")
endif()

pkg_check_modules(GLIB REQUIRED "glib-2.0")
pkg_check_modules(GMODULE REQUIRED "gmodule-2.0")
pkg_check_modules(PURPLE REQUIRED "purple")
pkg_check_modules(SIGNAL REQUIRED "libsignal-protocol-c")
pkg_check_modules(XML REQUIRED "libxml-2.0")
pkg_get_variable(PURPLE_PLUGINDIR "purple" "plugindir")


#
# C Pidgin plug-in (with public symbol "purple_init_plugin")
#   plus an equivalent
# internal C library for tests to link against
#
file(GLOB _LURCH_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/lurch*.[ch])
add_library(lurch_internal STATIC ${_LURCH_SOURCES})

if(WIN32)
    set(_LURCH_LIBRARY_TYPE MODULE)
else()
    set(_LURCH_LIBRARY_TYPE SHARED)
endif()

# NOTE: On Linux, by default CMake builds binaries with one set of RPATH
#       and then sets a different value at install time.
#       For "make install-home" we need a binary that already has the right
#       RPATH set at build time because there is no install phase where CMake
#       would change RPATH for us.  If we'd use the install-time RPATH
#       right away, then the tests wouldn't run, at least not with bundled
#       axc or libomemo, and at least not the test_lurch_loadable one.
#       So we separate those two things into two distinct binaries on Linux.
#       On Windows, RPATH is not a topic and so we don't need to even build
#       that extra binary on Windows.
if(NOT WIN32)
    set(_LURCH_HOME_TARGET lurch_home)
ENDIF()

foreach(_target lurch ${_LURCH_HOME_TARGET})
    add_library(${_target} ${_LURCH_LIBRARY_TYPE} ${_LURCH_SOURCES})
    set_target_properties(${_target} PROPERTIES PREFIX "")  # for lurch.so not liblurch.so
endforeach()

if(WIN32)
    if(BUILD_SHARED_LIBS)
        set(_LURCH_OUTPUT_NAME lurch_fully_shared)
    else()
        set(_LURCH_OUTPUT_NAME lurch_semi_shared)
    endif()
    set_target_properties(lurch PROPERTIES OUTPUT_NAME ${_LURCH_OUTPUT_NAME})
else()
    set(_LURCH_OUTPUT_NAME lurch)
endif()

if(LURCH_INSTALL)
    install(TARGETS lurch
        ARCHIVE DESTINATION ${PURPLE_PLUGINDIR}
        LIBRARY DESTINATION ${PURPLE_PLUGINDIR}
        RUNTIME DESTINATION ${PURPLE_PLUGINDIR}
    )
endif()

if(WIN32)
    set(_LURCH_INSTALL_HOME_DEPENDS lurch)
    set(_LURCH_INSTALL_HOME_OUTPUT_NAME ${_LURCH_OUTPUT_NAME})
else()
    set(_LURCH_INSTALL_HOME_DEPENDS ${_LURCH_HOME_TARGET})
    set(_LURCH_INSTALL_HOME_OUTPUT_NAME ${_LURCH_HOME_TARGET})
endif()

add_custom_target(install-home
    COMMAND mkdir -p ~/.purple/plugins
    COMMAND cp -v
            ${CMAKE_CURRENT_BINARY_DIR}/${_LURCH_INSTALL_HOME_OUTPUT_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}
            ${_LURCH_AXC_BINARY_GLOB}
            ${_LURCH_OMEMO_BINARY_GLOB}
            ~/.purple/plugins/
    DEPENDS ${_LURCH_INSTALL_HOME_DEPENDS}
)

# NOTE: This is a 1:1 port of a potentially outdated check
#       for the name of the Pidgin jabber plug-in acrosses operating systems.
#       If it turns out outdated, please open bug upstream.  Thank you!
if(EXISTS /etc/redhat-release)
    set(_LURCH_OS "Red Hat Linux")
    set(_LURCH_LIBJABBER xmpp)
elseif(EXISTS /etc/SuSE-release)
    set(_LURCH_OS "openSUSE Linux")
    set(_LURCH_LIBJABBER xmpp)
else()
    if(WIN32)
        set(_LURCH_OS "generic Windows")
    else()
        set(_LURCH_OS "generic Unix")
    endif()
    set(_LURCH_LIBJABBER jabber)
endif()
message(STATUS "Detected ${_LURCH_OS}; will link with -l${_LURCH_LIBJABBER} -L${PURPLE_PLUGINDIR} for Jabber plug-in")

foreach(_target lurch lurch_internal ${_LURCH_HOME_TARGET})
    target_link_directories(${_target} PUBLIC ${PURPLE_PLUGINDIR})
    target_link_libraries(${_target} PRIVATE -l${_LURCH_LIBJABBER})
endforeach()

if(NOT WIN32)
    set_target_properties(lurch PROPERTIES INSTALL_RPATH ${PURPLE_PLUGINDIR})
    set_target_properties(${_LURCH_HOME_TARGET} PROPERTIES
        INSTALL_RPATH "\$ORIGIN;${PURPLE_PLUGINDIR}"
        BUILD_WITH_INSTALL_RPATH ON
    )
endif()


#
# C test suite
#
if(LURCH_WITH_TESTS)
    set(_LURCH_TEST_TARGETS test_lurch_api test_lurch_crypto test_lurch_util test_lurch_loadable)

    enable_testing()

    foreach(_target ${_LURCH_TEST_TARGETS})
        add_executable(${_target} ${CMAKE_CURRENT_SOURCE_DIR}/test/${_target}.c)
        target_link_libraries(${_target} PRIVATE lurch_internal)

        if(_target STREQUAL test_lurch_loadable)
            if(BUILD_SHARED_LIBS)
                target_compile_options(${_target} PRIVATE ${GMODULE_CFLAGS})
                target_link_libraries(${_target} PRIVATE ${GMODULE_LIBRARIES})
            else()
                target_compile_options(${_target} PRIVATE ${GMODULE_STATIC_CFLAGS})
                target_link_libraries(${_target} PRIVATE ${GMODULE_STATIC_LIBRARIES})
            endif()

            add_test(NAME ${_target} COMMAND ${_target} ${CMAKE_CURRENT_BINARY_DIR}/${_LURCH_OUTPUT_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX})
        else()
            add_test(NAME ${_target} COMMAND ${_target})
        endif()

        if(BUILD_SHARED_LIBS)
            target_compile_options(${_target} PRIVATE ${CMOCKA_CFLAGS})
            target_link_libraries(${_target} PRIVATE ${CMOCKA_LIBRARIES})
        else()
            target_compile_options(${_target} PRIVATE ${CMOCKA_STATIC_CFLAGS})
            target_link_libraries(${_target} PRIVATE ${CMOCKA_STATIC_LIBRARIES})
        endif()
    endforeach()

    target_link_options(test_lurch_api PRIVATE
        -Wl,--wrap=purple_account_get_username
        -Wl,--wrap=purple_account_get_connection
        -Wl,--wrap=purple_connection_get_protocol_data
        -Wl,--wrap=purple_signal_register
        -Wl,--wrap=purple_signal_unregister
        -Wl,--wrap=purple_signal_connect
        -Wl,--wrap=purple_signal_disconnect
        -Wl,--wrap=purple_find_conversation_with_account
        -Wl,--wrap=jabber_pep_publish
        -Wl,--wrap=jabber_chat_find_by_conv
        -Wl,--wrap=jabber_iq_send
        -Wl,--wrap=axc_get_device_id
        -Wl,--wrap=axc_key_load_public_own
        -Wl,--wrap=axc_key_load_public_addr
        -Wl,--wrap=axc_session_exists_any
        -Wl,--wrap=omemo_storage_user_devicelist_retrieve
        -Wl,--wrap=omemo_storage_chatlist_delete
        -Wl,--wrap=omemo_storage_chatlist_save
        -Wl,--wrap=omemo_storage_chatlist_exists
        -Wl,--wrap=omemo_storage_user_devicelist_retrieve
        -Wl,--wrap=lurch_util_fp_get_printable
    )

    target_link_options(test_lurch_crypto PRIVATE
        -Wl,--wrap=axc_message_encrypt_and_serialize
        -Wl,--wrap=axc_session_exists_initiated
    )

    target_link_options(test_lurch_util PRIVATE
        -Wl,--wrap=purple_user_dir
        -Wl,--wrap=purple_prefs_get_bool
        -Wl,--wrap=purple_prefs_get_int
        -Wl,--wrap=purple_debug_error
        -Wl,--wrap=purple_debug_info
        -Wl,--wrap=purple_debug_misc
        -Wl,--wrap=purple_base16_encode_chunked
    )
endif()


#
# External build dependencies
#
foreach(_target lurch lurch_internal ${_LURCH_HOME_TARGET} ${_LURCH_TEST_TARGETS})
    target_include_directories(${_target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/headers/jabber)

    if(LURCH_WITH_SYSTEM_AXC)
        if(BUILD_SHARED_LIBS)
            target_compile_options(${_target} PRIVATE ${AXC_CFLAGS})
            target_link_libraries(${_target} PRIVATE ${AXC_LIBRARIES})
        else()
            target_compile_options(${_target} PRIVATE ${AXC_STATIC_CFLAGS})
            target_link_libraries(${_target} PRIVATE ${AXC_STATIC_LIBRARIES})
        endif()
    else()
        target_link_libraries(${_target} PRIVATE axc)
    endif()

    if(LURCH_WITH_SYSTEM_OMEMO)
        if(BUILD_SHARED_LIBS)
            target_compile_options(${_target} PRIVATE ${OMEMO_CFLAGS})
            target_link_libraries(${_target} PRIVATE ${OMEMO_LIBRARIES})
        else()
            target_compile_options(${_target} PRIVATE ${OMEMO_STATIC_CFLAGS})
            target_link_libraries(${_target} PRIVATE ${OMEMO_STATIC_LIBRARIES})
        endif()
    else()
        target_link_libraries(${_target} PRIVATE omemo)
    endif()

    if(BUILD_SHARED_LIBS)
        target_compile_options(${_target} PRIVATE ${GLIB_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${GLIB_LIBRARIES})

        target_compile_options(${_target} PRIVATE ${PURPLE_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${PURPLE_LIBRARIES})

        target_compile_options(${_target} PRIVATE ${XML_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${XML_LIBRARIES})
    else()
        target_compile_options(${_target} PRIVATE ${GLIB_STATIC_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${GLIB_STATIC_LIBRARIES})

        target_compile_options(${_target} PRIVATE ${PURPLE_STATIC_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${PURPLE_STATIC_LIBRARIES})

        target_compile_options(${_target} PRIVATE ${XML_STATIC_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${XML_STATIC_LIBRARIES})
    endif()
endforeach()


#
# Coverage reporting
#
if(_LURCH_WITH_COVERAGE)
    add_custom_target(coverage
        COMMAND gcovr -r ${CMAKE_CURRENT_SOURCE_DIR} --html --html-details -o coverage.html
        COMMAND gcovr -r ${CMAKE_CURRENT_SOURCE_DIR} -s
    )
endif()
