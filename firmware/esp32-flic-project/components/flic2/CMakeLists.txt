idf_component_register(SRCS "flic2_esp32.c"
                           "../../flic2lib-c-module-main/flic2.c"
                           "../../flic2lib-c-module-main/flic2_crypto.c"
                    INCLUDE_DIRS "include"
                                 "../../flic2lib-c-module-main"
                    REQUIRES bt esp_timer nvs_flash json)

# Add explicit Bluetooth include paths
idf_component_get_property(bt_lib bt COMPONENT_LIB)
