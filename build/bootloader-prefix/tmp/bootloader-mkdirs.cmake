# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/Users/mbie/esp/esp-idf/components/bootloader/subproject"
  "/Users/mbie/dev/wifi_monitor/build/bootloader"
  "/Users/mbie/dev/wifi_monitor/build/bootloader-prefix"
  "/Users/mbie/dev/wifi_monitor/build/bootloader-prefix/tmp"
  "/Users/mbie/dev/wifi_monitor/build/bootloader-prefix/src/bootloader-stamp"
  "/Users/mbie/dev/wifi_monitor/build/bootloader-prefix/src"
  "/Users/mbie/dev/wifi_monitor/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/mbie/dev/wifi_monitor/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/mbie/dev/wifi_monitor/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
