cmake_minimum_required(VERSION 3.10)
project(utils LANGUAGES C)

# Déclarez les sources des utilitaires
set(UTILS_SOURCES
  ../utils/nfc-utils.c
)



# Créez la bibliothèque partagée nfcutils
add_library(nfcutils SHARED ${UTILS_SOURCES})
target_compile_definitions(nfcutils PRIVATE BUILDING_NFCUTILS)
set_target_properties(nfcutils PROPERTIES LINKER_LANGUAGE C)

# Définir les répertoires de sortie pour les DLL et les fichiers .lib
set_target_properties(nfcutils PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  OUTPUT_NAME "nfcutils"
)

target_link_libraries(nfcutils nfc)

# Ajouter une commande personnalisée pour vérifier l'existence de nfcutils.lib
#add_custom_command(TARGET nfcutils POST_BUILD
#  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/check_file_exists.cmake
# )
# Liste des utilitaires à compiler
set(UTILS_EXECUTABLES
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

# Boucle pour créer chaque exécutable
foreach(util ${UTILS_EXECUTABLES})
if(${util} STREQUAL "mfcuk")
    add_executable(${util} ${util}.c ../utils/nfc-utils.c ../utils/crypto1.c  ../utils/crapto1.c ../utils/mfcuk_mifare.c ../utils/mfcuk_utils.c  ../utils/mfcuk_finger.c ../utils/mifare.c ../utils/getopt.c  ../utils/slre.c)
  elseif(${util} STREQUAL "nfc-mfsetuid")
  add_executable(${util} ${util}.c  ../utils/nfc-utils.c ../utils/mifare.c ../utils/getopt.c )
   elseif(${util} STREQUAL "nfc-jewel")
  add_executable(${util} ${util}.c  ../utils/nfc-utils.c ../utils/mifare.c ../utils/getopt.c ../utils/jewel.c )
    else()
    add_executable(${util} ${util}.c ../utils/mifare.c ../utils/getopt.c ../utils/nfc-utils.c)
  endif()
  target_link_libraries(${util} nfc nfcutils)
  install(TARGETS ${util} RUNTIME DESTINATION bin COMPONENT utils)
endforeach()

# Installer la bibliothèque nfcutils
install(TARGETS nfcutils
  RUNTIME DESTINATION bin COMPONENT utils
  LIBRARY DESTINATION lib COMPONENT utils
  ARCHIVE DESTINATION lib COMPONENT utils
)

# Installer explicitement le fichier .lib
if (WIN32)
  install(FILES ${CMAKE_BINARY_DIR}/lib/nfcutils.lib DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libraries)
endif()

# Messages de débogage
message(STATUS "CMAKE_BINARY_DIR: ${CMAKE_BINARY_DIR}")
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")