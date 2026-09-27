cmake_minimum_required(VERSION 3.24)
cmake_policy(SET CMP0091 NEW)
project(JTSUnattendedBootstrap VERSION 2.5.0 LANGUAGES CXX RC)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "The bootstrap requires a Windows x64 toolchain.")
endif()
if(NOT MSVC AND NOT MINGW)
  message(FATAL_ERROR "Use MSVC or MinGW-w64 with a statically linked C++ runtime.")
endif()
set(JTS_PAYLOAD_DIR "" CACHE PATH "Generated directory containing payload_table.h and payload.rc")
foreach(payload_input payload_table.h payload.rc)
  if(NOT EXISTS "${JTS_PAYLOAD_DIR}/${payload_input}")
    message(FATAL_ERROR "Generate ${payload_input} with the reviewed payload packager first.")
  endif()
endforeach()

add_executable(JTSUnattendedBootstrap WIN32 Main.cpp Security.cpp Staging.cpp Digest.cpp Payload.cpp Child.cpp
  bootstrap.rc "${JTS_PAYLOAD_DIR}/payload.rc")
set_target_properties(JTSUnattendedBootstrap PROPERTIES OUTPUT_NAME "JTS.WindowsCompanion.Setup"
  CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_compile_definitions(JTSUnattendedBootstrap PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
  _WIN32_WINNT=0x0A00 WINVER=0x0A00)
target_include_directories(JTSUnattendedBootstrap PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${JTS_PAYLOAD_DIR}")
target_link_libraries(JTSUnattendedBootstrap PRIVATE bcrypt advapi32 user32 shell32 ole32 uuid)
if(MSVC)
  target_compile_options(JTSUnattendedBootstrap PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/W4;/WX;/guard:cf;/sdl;/permissive-;/utf-8>")
  target_link_options(JTSUnattendedBootstrap PRIVATE /MANIFEST:NO /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /guard:cf)
else()
  target_compile_options(JTSUnattendedBootstrap PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Werror;-fstack-protector-strong>")
  target_link_options(JTSUnattendedBootstrap PRIVATE -municode -static -static-libgcc -static-libstdc++
    -Wl,--dynamicbase,--nxcompat,--high-entropy-va)
endif()
