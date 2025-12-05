# Add OTA components to your existing REQUIRES list
idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_netif esp_eth esp_http_client json esp_http_server bt esp_driver_gpio flic2 espressif__mdns spi_flash driver esp_https_ota app_update esp_timer)

# Generate timestamp-based firmware version using CMake's built-in functions
string(TIMESTAMP BUILD_TIMESTAMP "%Y%m%d-%H%M%S" UTC)

# Fallback if timestamp is empty (shouldn't happen with CMake 3.0+)
if(NOT BUILD_TIMESTAMP)
    # Use CMake's built-in epoch time as fallback
    string(TIMESTAMP BUILD_TIMESTAMP "%s" UTC)
    set(BUILD_TIMESTAMP "build-${BUILD_TIMESTAMP}")
endif()

set(FIRMWARE_VERSION "${BUILD_TIMESTAMP}")

# Debug output to see what we got
message(STATUS "Generated timestamp: '${BUILD_TIMESTAMP}'")
message(STATUS "Firmware version: '${FIRMWARE_VERSION}'")

# Create version header file for ESP32 code
set(VERSION_HEADER_CONTENT
"#ifndef VERSION_H
#define VERSION_H
#define FIRMWARE_VERSION \"${FIRMWARE_VERSION}\"
#define BUILD_TIMESTAMP \"${BUILD_TIMESTAMP}\"
#endif // VERSION_H
")

file(WRITE "${CMAKE_BINARY_DIR}/version.h" "${VERSION_HEADER_CONTENT}")

# Create version JSON file for Server to read
set(VERSION_JSON_CONTENT
"{
  \"version\": \"${FIRMWARE_VERSION}\",
  \"build_timestamp\": \"${BUILD_TIMESTAMP}\"
}")

file(WRITE "${CMAKE_BINARY_DIR}/firmware_version.json" "${VERSION_JSON_CONTENT}")

# Add the build directory to include path so main.c can find version.h
target_include_directories(${COMPONENT_LIB} PRIVATE ${CMAKE_BINARY_DIR})

# Add compile definition as backup
target_compile_definitions(${COMPONENT_LIB} PRIVATE FIRMWARE_VERSION="${FIRMWARE_VERSION}")

message(STATUS "Building firmware version: ${FIRMWARE_VERSION}")
message(STATUS "Version files created in: ${CMAKE_BINARY_DIR}")

# Verify the files were created correctly
if(EXISTS "${CMAKE_BINARY_DIR}/version.h")
    message(STATUS "✓ version.h created successfully")
else()
    message(WARNING "✗ Failed to create version.h")
endif()

if(EXISTS "${CMAKE_BINARY_DIR}/firmware_version.json")
    message(STATUS "✓ firmware_version.json created successfully")
else()
    message(WARNING "✗ Failed to create firmware_version.json")
endif()