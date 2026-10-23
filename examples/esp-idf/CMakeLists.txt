cmake_minimum_required(VERSION 3.16)
# The repository root is the component; ESP-IDF's example_connect() brings the network up.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../.."
                         "$ENV{IDF_PATH}/examples/common_components/protocol_examples_common")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tailscale_embedded_example)
