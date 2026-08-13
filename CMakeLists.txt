cmake_minimum_required(VERSION 3.25)

project(nitheesh_mart
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Drogon CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)

add_executable(nitheesh_mart
    src/main.cpp
)

target_link_libraries(nitheesh_mart PRIVATE
    Drogon::Drogon
    jwt-cpp::jwt-cpp
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    yaml-cpp
)