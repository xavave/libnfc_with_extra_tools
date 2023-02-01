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

   SET(WINDOWS_SOURCES ../contrib/win32/stdlib)
  INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32)
     IF(${source} MATCHES "nfc-list")
 
  # Add in the rc for version information in the dll
  #LIST(APPEND WINDOWS_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/../windows/libnfc.rc)
 IF (NOT MINGW)
   LIST(APPEND WINDOWS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/nfc-list.def)
  ENDIF()
  ENDIF(${source} MATCHES "nfc-list")
    SET(RC_COMMENT "${PACKAGE_NAME} utility")
    SET(RC_INTERNAL_NAME ${source})
   # SET(RC_ORIGINAL_NAME ${source}.exe) 
    SET(RC_ORIGINAL_NAME ${source}.dll)
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
      IF(${source} MATCHES "nfc-mfclassic")
         INCLUDE_DIRECTORIES(${source} ${CMAKE_CURRENT_SOURCE_DIR}/include)
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



    ADD_LIBRARY(${source} ${TARGETS} ${WINDOWS_SOURCES})
    #ADD_EXECUTABLE(${source} ${TARGETS})

   IF(${source} MATCHES "mfoc")
         TARGET_LINK_LIBRARIES(${source} ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/pthreadVSE3 ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/lzma)
    ENDIF()

    IF(${source} MATCHES "nfc-mfclassic")
         TARGET_INCLUDE_DIRECTORIES(${source} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    ENDIF()
   
  TARGET_LINK_LIBRARIES(${source} nfc)
  TARGET_LINK_LIBRARIES(${source} nfcutils)

 
  INSTALL(TARGETS ${source} RUNTIME DESTINATION bin COMPONENT utils)
 # INSTALL(FILES nfc.dll DESTINATION bin COMPONENT nfc)
 

 
ENDFOREACH(source)

#install required libraries
IF(WIN32 AND NOT MINGW)
  INCLUDE(InstallRequiredSystemLibraries)
  CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/cmake/FixBundle.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/FixBundle.cmake @ONLY)
  add_custom_command(TARGET utils POST_BUILD        # Adds a post-build event to MyTest
    COMMAND ${CMAKE_COMMAND} -E copy_if_different  # which executes "cmake - E copy_if_different..."
        "${PROJECT_SOURCE_DIR}/out/build/x64-Debug/libnfc/${CMAKE_BUILD_TYPE}/nfc.dll"      # <--this is in-file
        $<TARGET_FILE_DIR:MyTest>)                 # <--this is out-file path
  INSTALL(SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/FixBundle.cmake)
    # At compile time we need the .LIB file, we place it in the lib directory
  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE}/nfc.lib DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libraries)
ENDIF()

IF(NOT WIN32)
  # Manuals for the examples
  FILE(GLOB manuals "${CMAKE_CURRENT_SOURCE_DIR}/*.1")
  INSTALL(FILES ${manuals} DESTINATION ${SHARE_INSTALL_PREFIX}/man/man1 COMPONENT manuals)
ENDIF(NOT WIN32)
