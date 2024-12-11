# FindLIBUSB.cmake

   find_path(LIBUSB_INCLUDE_DIRS
     NAMES libusb.h
     HINTS
       "../../libusb_1.0.27_binaries/include"
       "../../libusb_1.0.27_binaries/include/libusb-1.0"
   )

   find_library(LIBUSB_LIBRARIES
     NAMES  libusb-1.0 
     HINTS
       "../../libusb_1.0.27_binaries/VS2022/MS64/dll"
   )

   include(FindPackageHandleStandardArgs)
   find_package_handle_standard_args(LIBUSB DEFAULT_MSG LIBUSB_LIBRARIES LIBUSB_INCLUDE_DIRS)

   if(LIBUSB_FOUND)
     set(LIBUSB_LIBRARIES ${LIBUSB_LIBRARIES})
     set(LIBUSB_INCLUDE_DIRS ${LIBUSB_INCLUDE_DIR})
   endif()
   