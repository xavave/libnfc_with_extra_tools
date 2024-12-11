# Ajoutez cette ligne au début du fichier pour spécifier la version minimale de CMake
cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0115 NEW)
cmake_policy(SET CMP0040 NEW)

if (NOT DEFINED CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
endif ()
# Déclarez le projet et spécifiez le langage
project(libnfc LANGUAGES C)

SET(VERSION_MAJOR "1")
SET(VERSION_MINOR "8")
SET(VERSION_PATCH "0")

SET(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

SET(PACKAGE_NAME "libnfc")
SET(PACKAGE_VERSION ${VERSION})
SET(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")


# Définir les dépendances supplémentaires globales
#set_property(GLOBAL PROPERTY GLOBAL_DEPENDENCIES "nfc;C:/Program Files (x86)/Windows Kits/10/Lib/${WINDOWS_KIT_VERSION}/um/x64/winscard.lib")
set_property(GLOBAL PROPERTY GLOBAL_DEPENDENCIES "nfc")
# Fonction pour appliquer les dépendances supplémentaires à toutes les cibles
function(apply_global_dependencies target)
  foreach(dep ${GLOBAL_DEPENDENCIES})
    target_link_libraries(${target} PRIVATE ${dep})
  endforeach()
endfunction()


# Récupérer toutes les cibles définies dans le projet
get_property(TARGETS GLOBAL PROPERTY TARGETS)

# Appliquer les dépendances supplémentaires à chaque cible
foreach(target ${TARGETS})
  apply_global_dependencies(${target})
endforeach()

# config.h
IF(WIN32)
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Messages de débogage
message(STATUS "CMAKE_BINARY_DIR: ${CMAKE_BINARY_DIR}")
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")

  SET(LIBNFC_SYSCONFDIR "./config" CACHE PATH "libnfc configuration directory")
  CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/cmake/config_windows.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)
  INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32)
    IF(NOT MINGW)
      SET(CMAKE_C_FLAGS "-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE ${CMAKE_C_FLAGS}")
    ENDIF(NOT MINGW)
ELSE(WIN32)
  SET(_XOPEN_SOURCE 600)
  SET(SYSCONFDIR "/etc" CACHE PATH "System configuration directory")
  CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/cmake/config_posix.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)
ENDIF(WIN32)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

ADD_DEFINITIONS("-DHAVE_CONFIG_H")

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)




# make it easy to locate CMake modules for finding libraries
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/")

# Options
option (LIBNFC_LOG "Enable log facility (errors, warning, info and debug messages)" ON)
IF(LIBNFC_LOG)
  ADD_DEFINITIONS(-DLOG)
ENDIF(LIBNFC_LOG)

option (LIBNFC_ENVVARS "Enable envvars facility" ON)
IF(LIBNFC_ENVVARS)
  ADD_DEFINITIONS(-DENVVARS)
ENDIF(LIBNFC_ENVVARS)

SET(LIBNFC_DEBUG_MODE OFF CACHE BOOL "Debug mode")
IF(LIBNFC_DEBUG_MODE)
  ADD_DEFINITIONS(-DDEBUG)
  SET(CMAKE_C_FLAGS "-g3 ${CMAKE_C_FLAGS}")
  SET(WIN32_MODE "debug")
  SET(CMAKE_RC_FLAGS "-D_DEBUG ${CMAKE_RC_FLAGS}")
ELSE(LIBNFC_DEBUG_MODE)
  SET(WIN32_MODE "release")
ENDIF(LIBNFC_DEBUG_MODE)

option (LIBNFC_CONFFILES_MODE "Enable configuration files" ON)
IF(LIBNFC_CONFFILES_MODE)
  ADD_DEFINITIONS(-DCONFFILES)
ENDIF(LIBNFC_CONFFILES_MODE)

option (BUILD_EXAMPLES "build examples ON/OFF" ON)
option (BUILD_UTILS "build utils ON/OFF" ON)

option (BUILD_DEBPKG "build debian package ON/OFF" OFF)


# Doxygen
SET(builddir "${CMAKE_BINARY_DIR}")
SET(top_srcdir "${CMAKE_SOURCE_DIR}")
INCLUDE(UseDoxygen)

IF(DEFINED CMAKE_INSTALL_LIBDIR)
  SET(libdir ${CMAKE_INSTALL_LIBDIR})
ELSE(DEFINED CMAKE_INSTALL_LIBDIR)
  SET(CMAKE_INSTALL_LIBDIR lib)
  SET(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
ENDIF(DEFINED CMAKE_INSTALL_LIBDIR)

IF(DEFINED INCLUDE_INSTALL_DIR)
  SET(includedir ${INCLUDE_INSTALL_DIR})
ELSE(DEFINED INCLUDE_INSTALL_DIR)
  SET(INCLUDE_INSTALL_DIR include)
  SET(includedir ${CMAKE_INSTALL_PREFIX}/${INCLUDE_INSTALL_DIR})
ENDIF(DEFINED INCLUDE_INSTALL_DIR)

IF(NOT DEFINED SHARE_INSTALL_PREFIX)
  SET(SHARE_INSTALL_PREFIX share)
ENDIF(NOT DEFINED SHARE_INSTALL_PREFIX)

# Additonnal GCC flags
IF(CMAKE_COMPILER_IS_GNUCC)
  # Make sure we will not miss some warnings ;)
  SET(CMAKE_C_FLAGS "-Wall -pedantic -std=c99 ${CMAKE_C_FLAGS}")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

# Workarounds for libusb in C99
ADD_DEFINITIONS(-Du_int8_t=uint8_t -Du_int16_t=uint16_t)

IF(MINGW)
  IF (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    # force MinGW-w64 in 32bit mode
    SET(CMAKE_C_FLAGS "-m32 ${CMAKE_C_FLAGS}")
    SET(CMAKE_MODULE_LINKER_FLAGS "-m32 -Wl,--enable-stdcall-fixup ${CMAKE_SHARED_LINKER_FLAGS}")
    SET(CMAKE_SHARED_LINKER_FLAGS "-m32 -Wl,--enable-stdcall-fixup ${CMAKE_SHARED_LINKER_FLAGS}")
    SET(CMAKE_EXE_LINKER_FLAGS "-m32 -Wl,--enable-stdcall-fixup ${CMAKE_EXE_LINKER_FLAGS}")
    SET(CMAKE_RC_FLAGS "--target=pe-i386 --output-format=coff ${CMAKE_RC_FLAGS}")
  ELSE(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    IF(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        # force MinGW-w64 in 32bit mode
        MESSAGE("Building 32-bit Windows DLL")
        #SET(CMAKE_C_FLAGS "-m32 ${CMAKE_C_FLAGS}")
        #SET(CMAKE_MODULE_LINKER_FLAGS "--Wl,--enable-stdcall-fixup ${CMAKE_SHARED_LINKER_FLAGS}")
        #SET(CMAKE_SHARED_LINKER_FLAGS "--Wl,--enable-stdcall-fixup ${CMAKE_SHARED_LINKER_FLAGS}")
        #SET(CMAKE_EXE_LINKER_FLAGS "--Wl,--enable-stdcall-fixup ${CMAKE_EXE_LINKER_FLAGS}")
        SET(CMAKE_RC_FLAGS "--target=pe-i386 --output-format=coff ${CMAKE_RC_FLAGS}")
    ELSEIF(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        MESSAGE("Building 64-bit Windows DLL")
        SET(CMAKE_RC_FLAGS "--target=pe-x86-64 --output-format=coff ${CMAKE_RC_FLAGS}")
    ELSE(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        MESSAGE(FATAL_ERROR "Unknown Processor: ${CMAKE_SYSTEM_PROCESSOR}")
    ENDIF(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
  ENDIF(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")

  FIND_PROGRAM(DLLTOOL dlltool CMAKE_FIND_ROOT_PATH_BOTH)
  IF (NOT DLLTOOL)
    MESSAGE(FATAL_ERROR "Could not find dlltool command")
  ENDIF (NOT DLLTOOL)
ENDIF(MINGW)

IF(NOT WIN32)
  # Set some pkg-config variables
  SET(prefix ${CMAKE_INSTALL_PREFIX})
  SET(exec_prefix ${CMAKE_INSTALL_PREFIX})
  SET(PACKAGE "libnfc")
  IF(LIBNFC_DRIVER_PN53X_USB)
    SET(PKG_REQ ${PKG_REQ} "libusb")
  ENDIF(LIBNFC_DRIVER_PN53X_USB)
   IF(LIBNFC_DRIVER_PN532_UART)
    SET(PKG_REQ ${PKG_REQ} "libusb")
  ENDIF(LIBNFC_DRIVER_PN53X_USB)
  IF(LIBNFC_DRIVER_ACR122_USB)
    SET(PKG_REQ ${PKG_REQ} "libusb")
  ENDIF(LIBNFC_DRIVER_ACR122_USB)
   IF(LIBNFC_DRIVER_ACR122_PCSC)
    SET(PKG_REQ ${PKG_REQ} "libpcsclite")
  ENDIF(LIBNFC_DRIVER_ACR122_PCSC)
  IF(LIBNFC_DRIVER_PCSC)
    SET(PKG_REQ ${PKG_REQ} "libpcsclite")
  ENDIF(LIBNFC_DRIVER_PCSC)
 
  # CMake lists are separated by a semi colon, replace with colon
  STRING(REPLACE ";" "," PKG_CONFIG_REQUIRES "${PKG_REQ}")
  CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/libnfc.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libnfc.pc @ONLY) 
  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/libnfc.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
ENDIF(NOT WIN32)

INCLUDE(LibnfcDrivers)

IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    IF(I2C_REQUIRED)
        # Inspired from http://cmake.3232098.n2.nabble.com/RFC-cmake-analog-to-AC-SEARCH-LIBS-td7585423.html
        INCLUDE (CheckFunctionExists)
        INCLUDE (CheckLibraryExists)
        CHECK_FUNCTION_EXISTS (clock_gettime HAVE_CLOCK_GETTIME)
        IF (NOT HAVE_CLOCK_GETTIME)
            CHECK_LIBRARY_EXISTS (rt clock_gettime "" HAVE_CLOCK_GETTIME_IN_RT)
            IF (HAVE_CLOCK_GETTIME_IN_RT)
                SET(LIBRT_FOUND TRUE)
                SET(LIBRT_LIBRARIES "rt")
            ENDIF (HAVE_CLOCK_GETTIME_IN_RT)
        ENDIF (NOT HAVE_CLOCK_GETTIME)
    ENDIF(I2C_REQUIRED)
  ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

IF(PCSC_INCLUDE_DIRS)
  INCLUDE_DIRECTORIES(${PCSC_INCLUDE_DIRS})
  LINK_DIRECTORIES(${PCSC_LIBRARY_DIRS})
ENDIF(PCSC_INCLUDE_DIRS)

add_library(libnfc SHARED
libnfc/chips/pn53x.c
libnfc/drivers/acr122_pcsc.c
libnfc/iso14443-subr.c
libnfc/log-internal.c
 libnfc/log.c
   libnfc/nfc.c
    libnfc/nfc-internal.c
   utils/nfc-utils.c
   libnfc/target-subr.c)  # Assurez-vous que ce fichier contient la définition de snprint_nfc_target
  # Ajoutez ici les autres fichiers sources nécessaires

  # Ajouter le répertoire des modules CMake personnalisés
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")

# Trouver libusb-1.0
find_package(libusb REQUIRED)

if(LIBUSB_FOUND)
  message(STATUS "libusb-1.0 found:")
  message(STATUS "  Include dirs: ${LIBUSB_INCLUDE_DIRS}")
  message(STATUS "  Libraries: ${LIBUSB_LIBRARIES}")
endif(LIBUSB_FOUND)

IF(LIBUSB_INCLUDE_DIRS)
    
    target_include_directories(libnfc PRIVATE ${LIBUSB_INCLUDE_DIRS})
    target_link_libraries(libnfc PRIVATE ${LIBUSB_LIBRARIES})
    
  SET(LIBUSB_FOUND TRUE)
ENDIF(LIBUSB_INCLUDE_DIRS)

  
IF(PCSC_LIBRARIES)
  target_link_libraries(libnfc PRIVATE ${PCSC_LIBRARIES})
ENDIF(PCSC_LIBRARIES)
# version.rc for Windows
IF(WIN32)
  # Date for filling in rc file information
  IF (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    MACRO (GET_CURRENT_YEAR RESULT)
        EXECUTE_PROCESS(COMMAND "cmd" " /C date /T" OUTPUT_VARIABLE ${RESULT})
        STRING(REGEX REPLACE "\n" "" ${RESULT} ${${RESULT}})
        STRING(REGEX REPLACE ".*(..)/(..)/(....).*" "\\3" ${RESULT} ${${RESULT}})
    ENDMACRO (GET_CURRENT_YEAR)
  ELSE(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    MACRO (GET_CURRENT_YEAR RESULT)
        EXECUTE_PROCESS(COMMAND "date" "+%Y" OUTPUT_VARIABLE ${RESULT})
        STRING(REGEX REPLACE "\n" "" ${RESULT} ${${RESULT}})
    ENDMACRO (GET_CURRENT_YEAR)
  ENDIF(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
  GET_CURRENT_YEAR(CURRENT_YEAR)
  MESSAGE("Year for copyright is " ${CURRENT_YEAR})

  SET(prefix ${CMAKE_INSTALL_PREFIX})
  SET(RC_COMMENT "${PACKAGE_NAME} library")
  SET(RC_INTERNAL_NAME "${PACKAGE_NAME} ${WIN32_MODE}")
  SET(RC_ORIGINAL_NAME ${PACKAGE_NAME}.dll)
  # RC_FILE_TYPE: VFT_DLL
  SET(RC_FILE_TYPE 0x00000002L)
  CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/windows/libnfc.rc @ONLY)

  # Compile the .rc file to .res
  #add_custom_command(
  #  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/windows/libnfc.res
  #  COMMAND ${CMAKE_RC_COMPILER} ${CMAKE_CURRENT_BINARY_DIR}/windows/libnfc.rc -o ${CMAKE_CURRENT_BINARY_DIR}/windows/libnfc.res
   # DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/windows/libnfc.rc
   # COMMENT "Compiling resource file"
  #)

  # Add the .res file to the target
 # add_library(libnfc_resources OBJECT ${CMAKE_CURRENT_BINARY_DIR}/windows/libnfc.res)
 #   set_target_properties(libnfc_resources PROPERTIES LINKER_LANGUAGE C)
 
   # Ajoutez ici les fichiers sources de libnfc
 # target_sources(${PROJECT_NAME} PRIVATE $<TARGET_OBJECTS:libnfc_resources>)
ENDIF(WIN32)




ADD_SUBDIRECTORY(libnfc)
ADD_SUBDIRECTORY(include)

if (BUILD_UTILS)
  add_subdirectory (utils)
endif ()

if (BUILD_EXAMPLES)
  add_subdirectory (examples)
endif ()

if (NOT MSVC)
  # config script install path
  if ( NOT DEFINED LIBNFC_CMAKE_CONFIG_DIR )
    set ( LIBNFC_CMAKE_CONFIG_DIR lib${LIB_SUFFIX}/cmake/libnfc )
  endif ()

  set ( LIBNFC_INCLUDE_DIR ${includedir} )
  set ( LIBNFC_INCLUDE_DIRS ${LIBNFC_INCLUDE_DIR} )
  list ( APPEND LIBNFC_INCLUDE_DIRS ${LIBUSB_INCLUDE_DIRS} )
  set ( LIBNFC_LIBRARY nfc )
  set ( LIBNFC_LIBRARIES ${LIBNFC_LIBRARY} )
  list ( APPEND LIBNFC_LIBRARIES ${LIBUSB_LIBRARIES} )
  set ( LIBNFC_LIBRARY_DIRS ${libdir} )
  set ( LIBNFC_ROOT_DIR ${prefix} )
  set ( LIBNFC_VERSION_STRING ${VERSION} )
  set ( LIBNFC_VERSION_MAJOR ${VERSION_MAJOR} )
  set ( LIBNFC_VERSION_MINOR ${VERSION_MINOR} )
  set ( LIBNFC_VERSION_PATCH ${VERSION_PATCH} )

  set ( LIBNFC_USE_FILE ${CMAKE_INSTALL_PREFIX}/${LIBNFC_CMAKE_CONFIG_DIR}/UseLibNFC.cmake )



  if(CMAKE_VERSION VERSION_LESS 2.8.8)
    configure_file ( cmake/LibNFCConfig.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/LibNFCConfig.cmake @ONLY )
    configure_file ( cmake/LibNFCConfigVersion.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/LibNFCConfigVersion.cmake @ONLY )
  else ()
    include(CMakePackageConfigHelpers)
    configure_package_config_file (
      cmake/LibNFCConfig.cmake.in
      ${CMAKE_CURRENT_BINARY_DIR}/LibNFCConfig.cmake
      INSTALL_DESTINATION ${LIBNFC_CMAKE_CONFIG_DIR}
      PATH_VARS
        LIBNFC_USE_FILE
        LIBNFC_ROOT_DIR
        LIBNFC_INCLUDE_DIR
        LIBNFC_INCLUDE_DIRS
        LIBNFC_LIBRARY_DIRS
        NO_CHECK_REQUIRED_COMPONENTS_MACRO
    )
    write_basic_package_version_file (
      LibNFCConfigVersion.cmake
      VERSION ${LIBNFC_VERSION_STRING}
      COMPATIBILITY AnyNewerVersion
    )
  endif ()

  install ( FILES ${CMAKE_CURRENT_BINARY_DIR}/LibNFCConfig.cmake
                  ${CMAKE_CURRENT_BINARY_DIR}/LibNFCConfigVersion.cmake
                  cmake/UseLibNFC.cmake
            DESTINATION ${LIBNFC_CMAKE_CONFIG_DIR}
          )

endif ()

# Binary Package
IF(WIN32)
  SET(CPACK_GENERATOR "ZIP")
ELSE(WIN32)
  SET(CPACK_GENERATOR "TBZ2")
  IF(BUILD_DEBPKG)
    SET(CPACK_GENERATOR "DEB")
  ENDIF(BUILD_DEBPKG)
ENDIF(WIN32)

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Near Field Communication (NFC) library")
SET(CPACK_PACKAGE_VENDOR "Roel Verdult")
SET(CPACK_PACKAGE_CONTACT "Roel Verdult <roel@libnfc.org>")

#Readme file
IF(WIN32)
  SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README-Windows.md")
ELSE(WIN32)
  SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
ENDIF(WIN32)

SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "libnfc")
SET(CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH})
SET(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "NFC Library")
SET(CPACK_COMPONENT_EXAMPLES_DISPLAY_NAME "Example Applications")
SET(CPACK_COMPONENT_HEADERS_DISPLAY_NAME "Development Headers")
IF(NOT WIN32)
  SET(CPACK_COMPONENT_MANUALS_DISPLAY_NAME "Example Applications Manuals")
  SET(CPACK_COMPONENT_MANUALS_DISABLED TRUE)
  SET(CPACK_COMPONENT_MANUALS_DEPENDS examples)
ENDIF(NOT WIN32)
SET(CPACK_COMPONENT_HEADERS_DISABLED TRUE)
SET(CPACK_COMPONENT_HEADERS_DEPENDS libraries)
SET(CPACK_COMPONENT_EXAMPLES_DEPENDS libraries)

# Source Package
IF(WIN32)
  SET(CPACK_SOURCE_GENERATOR "ZIP")
ELSE(WIN32)
  SET(CPACK_SOURCE_GENERATOR "ZIP;TBZ2")
ENDIF(WIN32)

SET(CPACK_SOURCE_PACKAGE_FILE_NAME "libnfc-${VERSION}")
SET(CPACK_SOURCE_IGNORE_FILES "~$" "/\\\\.git/" "bin/")
INCLUDE(CPack)
