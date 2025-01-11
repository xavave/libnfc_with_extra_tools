# Ajoutez cette ligne au début du fichier pour spécifier la version minimale de CMake
cmake_minimum_required(VERSION 3.10)

# Déclarez le projet et spécifiez le langage
project(libnfc LANGUAGES C)

# Windows MinGW workarounds
IF(WIN32)
  SET(WINDOWS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/stdlib.c)
  INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32)

  # Add in the rc for version information in the dll
  LIST(APPEND WINDOWS_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/../windows/libnfc.rc)
  IF (NOT MINGW)
    LIST(APPEND WINDOWS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}./../contrib/win32/nfc_msvc.def)
  ENDIF()
ENDIF(WIN32)

# Library's chips
SET(CHIPS_SOURCES   ${CMAKE_CURRENT_SOURCE_DIR}/chips/pn53x.c)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/chips)

# Library's buses
IF(USB_REQUIRED)
  LIST(APPEND BUSES_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/buses/usbbus.c)
ENDIF(USB_REQUIRED)

IF(UART_REQUIRED)
  IF(WIN32)
    # Windows have a special implementation for UART
    LIST(APPEND BUSES_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/libnfc/buses/uart.c)
  ELSE(WIN32)
    LIST(APPEND BUSES_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/buses/uart.c)
  ENDIF(WIN32)
ENDIF(UART_REQUIRED)

IF(I2C_REQUIRED)
  IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    LIST(APPEND BUSES_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/buses/i2c.c)
  ELSE(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    # Only Linux is supported at the moment
    #LIST(APPEND BUSES_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/libnfc/buses/i2c.c)
    MESSAGE( FATAL_ERROR "I2C is only (yet) supported in Linux!" )
  ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
ENDIF(I2C_REQUIRED)

IF(SPI_REQUIRED)
  IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    LIST(APPEND BUSES_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/buses/spi.c)
  ELSE(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    # Only Linux is supported at the moment
    #LIST(APPEND BUSES_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/libnfc/buses/spi.c)
    MESSAGE( FATAL_ERROR "SPI is only (yet) supported in Linux!" )
  ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
ENDIF(SPI_REQUIRED)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/buses)

IF(PCSC_FOUND)
  INCLUDE_DIRECTORIES(${PCSC_INCLUDE_DIRS})
  LINK_DIRECTORIES(${PCSC_LIBRARY_DIRS})
ENDIF(PCSC_FOUND)

IF(LIBUSB_FOUND)
  INCLUDE_DIRECTORIES(${LIBUSB_INCLUDE_DIRS})
  LINK_DIRECTORIES(${LIBUSB_LIBRARY_DIRS})
  
ENDIF(LIBUSB_FOUND)

 set(DRIVER_SOURCES
   
    drivers/acr122_pcsc.c
    drivers/acr122s.c
    drivers/arygon.c
    drivers/pn532_uart.c
    # Ajoutez d'autres pilotes si nécessaire
  )

  if(LIBNFC_DRIVER_PCSC)
    list(APPEND DRIVER_SOURCES drivers/pcsc.c)
    add_definitions(-DLIBNFC_DRIVER_PCSC)
  endif()
   if(LIBNFC_DRIVER_ACR122_USB)
    list(APPEND DRIVER_SOURCES drivers/acr122_usb.c)
    add_definitions(-DLIBNFC_DRIVER_ACR122_USB)
  endif()
  
  set(UTILS_SOURCES
    ../utils/nfc-utils.c
  )
    set(LOG_SOURCES
    log.c
    log-internal.c
  )

   set(LIBNFC_SOURCES
   ${LOG_SOURCES}
    nfc.c
    nfc-internal.c
    nfc-device.c
    target-subr.c
   
    # Ajoutez tous les autres fichiers sources nécessaires
  )
   
# Library
SET(LIBRARY_SOURCES 
  ${LIBNFC_SOURCES}
  ${CMAKE_CURRENT_SOURCE_DIR}/nfc-emulation.c 
  ${CMAKE_CURRENT_SOURCE_DIR}/conf.c 
  ${CMAKE_CURRENT_SOURCE_DIR}/iso14443-subr.c 
  ${CMAKE_CURRENT_SOURCE_DIR}/mirror-subr.c 
  ${DRIVERS_SOURCES} 
  ${BUSES_SOURCES} 
  ${CHIPS_SOURCES} 
  ${WINDOWS_SOURCES}
)
ADD_LIBRARY(nfc SHARED ${LIBRARY_SOURCES})

# Ajoutez les sources supplémentaires
target_sources(nfc PRIVATE ${LIBRARY_SOURCES})
target_sources(nfc PRIVATE ${UTILS_SOURCES})
target_sources(nfc PRIVATE ${CONTEXT_SOURCES})

# Include directories
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})


IF(LIBNFC_LOG)
  IF(WIN32)
    IF(MINGW)
      SET(CMAKE_C_FLAGS "-fgnu89-inline ${CMAKE_C_FLAGS}")
    ENDIF(MINGW)
    LIST(APPEND LIBRARY_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/log.c ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/libnfc/log-internal.c)
  ELSE(WIN32)
    LIST(APPEND LIBRARY_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/log.c ${CMAKE_CURRENT_SOURCE_DIR}/log-internal.c)
  ENDIF(WIN32)
ENDIF(LIBNFC_LOG)

# Après
IF(PCSC_FOUND)
  target_link_libraries(nfc PRIVATE ${PCSC_LIBRARIES})
ENDIF(PCSC_FOUND)

IF(LIBUSB_FOUND)
  target_link_libraries(nfc PRIVATE ${LIBUSB_LIBRARIES})
ENDIF(LIBUSB_FOUND)

IF(LIBRT_FOUND)
  target_link_libraries(nfc PRIVATE ${LIBRT_LIBRARIES})
ENDIF(LIBRT_FOUND)

IF(WIN32)

ENDIF()

SET_TARGET_PROPERTIES(nfc PROPERTIES SOVERSION 6 VERSION 6.0.0)

IF(WIN32)
  # Libraries that are windows specific
  TARGET_LINK_LIBRARIES(nfc PRIVATE wsock32 winscard)
  IF(MINGW)
    ADD_CUSTOM_COMMAND(
      OUTPUT nfc.lib
      COMMAND ${DLLTOOL} -d ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/nfc.def -l ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_CONFIG_NAME}nfc.lib ${CMAKE_CURRENT_BINARY_DIR}/nfc.dll
      DEPENDS nfc ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/nfc.def
    )
    ADD_CUSTOM_TARGET(win32lib ALL DEPENDS nfc.lib)
  ELSE()
    ADD_LIBRARY(win32lib ALIAS nfc)
  ENDIF()

  # On Windows the shared (runtime) library should be either in the same 
  # directory as the excutables or in the path, we add it to same directory
  INSTALL(TARGETS nfc RUNTIME DESTINATION bin COMPONENT libraries)
    
  # At compile time we need the .LIB file, we place it in the lib directory
  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE}/nfc.lib DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libraries)

ELSE(WIN32)
  INSTALL(TARGETS nfc LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libraries)
ENDIF(WIN32)