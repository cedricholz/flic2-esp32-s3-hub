cmake_minimum_required(VERSION 3.16)

# Set target to ESP32-S3
set(IDF_TARGET esp32s3)

# Set custom partition table
set(PARTITION_TABLE_CUSTOM_FILENAME "partitions.csv")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32-flic)