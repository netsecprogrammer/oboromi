cmake_minimum_required(VERSION 3.22)
project(oboromi LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(GNUInstallDirs)

# Rust core via Corrosion
include(FetchContent)
FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG 1499b14e4906a2890f5cee1547c8848db261753d # v0.6
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH ${CMAKE_SOURCE_DIR}/Cargo.toml)

# Qt6 GUI
# Configure with: cmake -B build -DCMAKE_PREFIX_PATH="C:/Qt/6.10.3/msvc2022_64" (or your path)
# Qt kit ABI must match Rust toolchain (MSVC vs MinGW)
find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

qt_add_executable(oboromi-gui
    gui-qt/src/main.cpp
    gui-qt/src/MainWindow.h
    gui-qt/src/MainWindow.cpp
    gui-qt/src/RustBridge.h
    gui-qt/src/RustBridge.cpp
    gui-qt/resources.qrc
)

target_include_directories(oboromi-gui PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
)

target_link_libraries(oboromi-gui PRIVATE
    Qt6::Widgets
    oboromi_core
)

# Windows system libs needed by rust staticlib
if(WIN32)
    target_link_libraries(oboromi-gui PRIVATE ws2_32 userenv ntdll bcrypt)
endif()

set_target_properties(oboromi-gui PROPERTIES
    WIN32_EXECUTABLE ON
    MACOSX_BUNDLE ON
    OUTPUT_NAME "oboromi"
)

install(TARGETS oboromi-gui
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(WIN32 OR APPLE)
    qt_generate_deploy_app_script(
        TARGET oboromi-gui
        OUTPUT_SCRIPT oboromi_deploy_script
        NO_TRANSLATIONS
        NO_UNSUPPORTED_PLATFORM_ERROR
    )
    install(SCRIPT ${oboromi_deploy_script})
endif()
