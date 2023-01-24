SET(UTILS-SOURCES 
  nfc-barcode
  nfc-emulate-forum-tag4
  nfc-jewel
  nfc-list
  nfc-mfclassic
  nfc-mfultralight
  nfc-read-forum-tag3
  nfc-relay-picc
  nfc-scan-device
  mfcuk
 
)

ADD_LIBRARY(nfcutils STATIC 
  nfc-utils.c
)
TARGET_LINK_LIBRARIES(nfcutils nfc)

# Examples
FOREACH(source ${UTILS-SOURCES})
  SET (TARGETS ${source}.c)

  IF(WIN32)
    SET(RC_COMMENT "${PACKAGE_NAME} utility")
    SET(RC_INTERNAL_NAME ${source})
    SET(RC_ORIGINAL_NAME ${source}.exe)
    # RC_FILE_TYPE: VFT_APP
    SET(RC_FILE_TYPE 0x00000001L)
    CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/../windows/${source}.rc @ONLY)
    LIST(APPEND TARGETS ${CMAKE_CURRENT_BINARY_DIR}/../windows/${source}.rc)
  ENDIF(WIN32)

  IF(${source} MATCHES "nfc-jewel")
    LIST(APPEND TARGETS jewel)
  ENDIF(${source} MATCHES "nfc-jewel")

  IF((${source} MATCHES "nfc-mfultralight") OR (${source} MATCHES "nfc-mfclassic"))
    LIST(APPEND TARGETS mifare)
  ENDIF((${source} MATCHES "nfc-mfultralight") OR (${source} MATCHES "nfc-mfclassic"))

  IF(WIN32)
    IF((${source} MATCHES "nfc-scan-device") OR (${source} MATCHES "nfc-mfclassic") OR (${source} MATCHES "nfc-list") OR (${source} MATCHES "mfoc") OR (${source} MATCHES "mfcuk"))
      LIST(APPEND TARGETS ../contrib/win32/stdlib)
      INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32)
       LIST(APPEND TARGETS ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/getopt.c)
    ENDIF()
    IF((${source} MATCHES "nfc-read-forum-tag3"))
      LIST(APPEND TARGETS ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/getopt.c)
    ENDIF()
      IF(${source} MATCHES "mfcuk")
      LIST(APPEND TARGETS mfcuk_mifare parity crypto1 crapto1 mfcuk_utils mfcuk_finger mifare)
       LIST(APPEND TARGETS ../contrib/win32/stdlib)
    ENDIF()
     IF(${source} MATCHES "mfoc")
       INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/lzma)
       INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/hardnested)
     LIST(APPEND TARGETS ${CMAKE_CURRENT_SOURCE_DIR}/hardnested/hardnested_bf_core_NOSIMD  ${CMAKE_CURRENT_SOURCE_DIR}/hardnested/hardnested_cpu_dispatch ${CMAKE_CURRENT_SOURCE_DIR}/hardnested/hardnested_bitarray_core_NOSIMD ${CMAKE_CURRENT_SOURCE_DIR}/hardnested/tables ${CMAKE_CURRENT_SOURCE_DIR}/hardnested/hardnested_cpu_dispatch ${CMAKE_CURRENT_SOURCE_DIR}/hardnested/hardnested_bruteforce ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/pthread.lib ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/bf_bench_data.bin  bf_bench_data util_posix util ui pthread sched lzma cmdhfmfhard config_w parity crypto1 crapto1 mifare)
   
    ENDIF()
  ENDIF(WIN32)

  ADD_EXECUTABLE(${source} ${TARGETS})
    IF(${source} MATCHES "mfoc")
         TARGET_LINK_LIBRARIES(${source} ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/pthreadVSE3 ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/lzma)
    ENDIF()
  TARGET_LINK_LIBRARIES(${source} nfc)
  TARGET_LINK_LIBRARIES(${source} nfcutils)

  INSTALL(TARGETS ${source} RUNTIME DESTINATION bin COMPONENT utils)
ENDFOREACH(source)

#install required libraries
IF(WIN32 AND NOT MINGW)
  INCLUDE(InstallRequiredSystemLibraries)
  CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/cmake/FixBundle.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/FixBundle.cmake @ONLY)
  INSTALL(SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/FixBundle.cmake)
ENDIF()

IF(NOT WIN32)
  # Manuals for the examples
  FILE(GLOB manuals "${CMAKE_CURRENT_SOURCE_DIR}/*.1")
  INSTALL(FILES ${manuals} DESTINATION ${SHARE_INSTALL_PREFIX}/man/man1 COMPONENT manuals)
ENDIF(NOT WIN32)
