cmake_minimum_required(VERSION 3.15)
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR i386)
set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(AutoInjectRvRolClient C)

# ---- Reproducible builds ----
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -frandom-seed=0 -Wl,--no-insert-timestamp -Wl,--no-as-needed")
if(NOT DEFINED ENV{SOURCE_DATE_EPOCH})
    set(ENV{SOURCE_DATE_EPOCH} 1)  # fallback for deterministic timestamps
endif()
string(TIMESTAMP BUILD_DATE "%Y-%m-%d" UTC)
add_definitions(-DBUILD_DATE="${BUILD_DATE}")
# Remove absolute paths from debug info
add_compile_options(-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.)

# ---- Build options (everything optional) ----
option(BUILD_WINE_COMPONENTS "Build hooklib.dll, inject.exe, start_rvpn.exe" ON)
option(BUILD_WINDOWS_COMPONENTS "Build RvROLClient.dll (Windows proxy)" ON)

# ---- Python generator (unchanged logic) ----
find_package(Python3 COMPONENTS Interpreter QUIET)
set(GEN_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/gen_proxy.py")
set(ORIG_DLL   "${CMAKE_CURRENT_SOURCE_DIR}/RvROLClient_orig.dll")

# If Windows components are requested, require original DLL
if(BUILD_WINDOWS_COMPONENTS AND NOT EXISTS "${ORIG_DLL}")
    message(WARNING "RvROLClient_orig.dll not found! This file is required to build RvROLClient.dll (BUILD_WINDOWS_COMPONENTS=ON). Disabling BUILD_WINDOWS_COMPONENTS so configuration can continue.")
    set(BUILD_WINDOWS_COMPONENTS OFF CACHE BOOL "Build RvROLClient.dll (Windows proxy)" FORCE)
endif()

if(BUILD_WINDOWS_COMPONENTS AND Python3_FOUND AND EXISTS "${ORIG_DLL}")
    add_custom_command(
        OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/rvrolclient_proxy.c"
                "${CMAKE_CURRENT_BINARY_DIR}/rvrolclient.def"
        COMMAND ${Python3_EXECUTABLE} "${GEN_SCRIPT}" "${ORIG_DLL}"
        DEPENDS "${GEN_SCRIPT}" "${ORIG_DLL}"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "Generating RvROLClient proxy stubs"
        VERBATIM
    )
    set(RVROLC_GEN_FILES
        "${CMAKE_CURRENT_BINARY_DIR}/rvrolclient_proxy.c"
        "${CMAKE_CURRENT_BINARY_DIR}/rvrolclient.def"
    )
elseif(BUILD_WINDOWS_COMPONENTS)
    message(WARNING "Python3 or original DLL missing – cannot generate RvROLClient proxy stubs. Disabling BUILD_WINDOWS_COMPONENTS so configuration can continue.")
    set(BUILD_WINDOWS_COMPONENTS OFF CACHE BOOL "Build RvROLClient.dll (Windows proxy)" FORCE)
endif()

set(EMULATOR_CORE_SOURCES
    emulate_driver_running.c
    config.c
    tap_client_udp.c
    inject.c
)

# ==================== RvROLClient.dll (Windows only) ====================
if(BUILD_WINDOWS_COMPONENTS)
    add_library(rvrolclient_proxy SHARED
        ${RVROLC_GEN_FILES}
        inject.c
        ${EMULATOR_CORE_SOURCES}
    )

    target_include_directories(rvrolclient_proxy BEFORE PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/shim
        ${CMAKE_CURRENT_SOURCE_DIR}
    )

    target_link_libraries(rvrolclient_proxy PRIVATE
        kernel32 user32 ws2_32 crypt32
        advapi32 ole32 oleaut32 setupapi uuid wbemuuid
        -Wl,-Bstatic -lpthread -Wl,-Bdynamic
    )

    target_link_options(rvrolclient_proxy PRIVATE
        -static-libgcc -static-libstdc++
        -Wl,--kill-at
    )

    set_target_properties(rvrolclient_proxy PROPERTIES
        PREFIX ""
        OUTPUT_NAME "RvROLClient"
    )
endif()

# ==================== hooklib.dll (WINE) ====================
if(BUILD_WINE_COMPONENTS)
    add_library(hooklib SHARED
        hooklib.c
        ${EMULATOR_CORE_SOURCES}
    )

    target_include_directories(hooklib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_include_directories(hooklib BEFORE PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/shim
        ${CMAKE_CURRENT_SOURCE_DIR}
    )

    target_compile_options(hooklib PRIVATE -Os -fno-builtin)
    target_link_libraries(hooklib PRIVATE
        kernel32 user32 ws2_32 crypt32
        advapi32 ole32 oleaut32 setupapi uuid wbemuuid
        -Wl,-Bstatic -lpthread -Wl,-Bdynamic
    )
    target_link_options(hooklib PRIVATE
        -static-libgcc
        -Wl,--kill-at
        -Wl,-s
    )

    set_target_properties(hooklib PROPERTIES
        PREFIX ""
        SUFFIX ".dll"
    )
endif()

# ==================== inject.exe (WINE) ====================
if(BUILD_WINE_COMPONENTS)
    add_executable(inject inject_exe.c)
    target_compile_options(inject PRIVATE -Os -fno-builtin)
    target_link_options(inject PRIVATE
        -static-libgcc
        -Wl,-subsystem,console
        -Wl,-s
    )
    target_link_libraries(inject PRIVATE kernel32)
    set_target_properties(inject PROPERTIES
        RUNTIME_OUTPUT_NAME "inject"
        SUFFIX ".exe"
    )
endif()

# ==================== start_rvpn.exe (WINE) ====================
if(BUILD_WINE_COMPONENTS)
    add_executable(start_rvpn start_rvpn.c)
    target_link_libraries(start_rvpn PRIVATE kernel32 user32)
    target_link_options(start_rvpn PRIVATE -static-libgcc)
    set_target_properties(start_rvpn PROPERTIES
        RUNTIME_OUTPUT_NAME "start_rvpn"
        SUFFIX ".exe"
    )
endif()

# ==================== Native Linux TAP bridge (unchanged) ====================
if(NOT DEFINED CMAKE_SYSTEM_NAME OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(linux_tap linux_tap.c)
    target_link_libraries(linux_tap PRIVATE pthread)
    set_target_properties(linux_tap PROPERTIES
        RUNTIME_OUTPUT_NAME "linux_tap"
    )
endif()

# ==================== cryptbase.dll (fake proxy) ====================
# (Always built as it may be used by injection)
add_library(cryptbase SHARED 
    ${EMULATOR_CORE_SOURCES}
    cryptbase_proxy.c
    cryptbase.def
)
target_include_directories(cryptbase PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(cryptbase BEFORE PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/shim
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_options(cryptbase PRIVATE -Os -fno-builtin)
target_link_libraries(cryptbase PRIVATE
    kernel32 user32 ws2_32 crypt32
    advapi32 ole32 oleaut32 setupapi uuid wbemuuid
    -Wl,-Bstatic -lpthread -Wl,-Bdynamic
)
target_link_options(cryptbase PRIVATE
    -static-libgcc
    -Wl,--kill-at
    -Wl,-s
)
set_target_properties(cryptbase PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
)

# (Commented-out proxy libraries remain as is for future use)
