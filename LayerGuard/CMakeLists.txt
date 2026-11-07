cmake_minimum_required(VERSION 3.20)
project(LayerGuard LANGUAGES C CXX)

if(NOT WIN32)
  message(FATAL_ERROR "LayerGuard is a Windows-only project (MSVC + Windows 10 SDK).")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)

if(MSVC)
  add_compile_options(/W4 /utf-8 /GS /guard:cf)
  add_link_options(/DYNAMICBASE /NXCOMPAT /guard:cf)
endif()

add_executable(LayerGuard WIN32
  src/main.cpp
  src/layermgr.cpp
  src/sandbox.cpp
  src/procfreeze.cpp
  src/trust.cpp
  src/procmon.cpp
  src/resources.rc
  src/securedesk.cpp
  src/usbguard.cpp
  src/layers.c
  src/audit.c
  src/paths.c
)

target_include_directories(LayerGuard PRIVATE src)

# The manager must run elevated (it disables devices, creates Job Objects
# and launches High-integrity layers), so request admin via the manifest.
if(MSVC)
  target_link_options(LayerGuard PRIVATE
    "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
endif()

target_link_libraries(LayerGuard PRIVATE
  user32 gdi32 comctl32 comdlg32 advapi32 userenv bcrypt cfgmgr32 setupapi wintrust crypt32 shell32 ole32)
