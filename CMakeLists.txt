cmake_minimum_required(VERSION 3.16)
project(multirom_dataloader C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(minivcs)
include_directories(minivcs)
include_directories(minivcs/CTransform/CEasyException)

add_library(multirom_dataloader multirom_dataloader.c multirom_dataloader.h)
target_link_libraries(multirom_dataloader minivcs_project)