bin_PROGRAMS = \
		nfc-barcode \
		nfc-emulate-forum-tag4 \
		nfc-jewel \
		nfc-list \
		nfc-mfclassic \
		nfc-mfultralight \
		nfc-read-forum-tag3 \
		nfc-relay-picc \
		nfc-scan-device

# set the include path found by configure
AM_CPPFLAGS = $(all_includes) $(LIBNFC_CFLAGS)

noinst_LTLIBRARIES = libnfcutils.la

libnfcutils_la_SOURCES = nfc-utils.c
libnfcutils_la_LIBADD = -lnfc

nfc_barcode_SOURCES = nfc-barcode.c
nfc_barcode_LDADD = $(top_builddir)/libnfc/libnfc.la \
		    libnfcutils.la

nfc_emulate_forum_tag4_SOURCES = nfc-emulate-forum-tag4.c nfc-utils.h
nfc_emulate_forum_tag4_LDADD = libnfcutils.la \
			       $(top_builddir)/libnfc/libnfc.la

nfc_jewel_SOURCES = nfc-jewel.c jewel.c jewel.h nfc-utils.h
nfc_jewel_LDADD = $(top_builddir)/libnfc/libnfc.la

nfc_list_SOURCES = nfc-list.c nfc-utils.h
nfc_list_LDADD = libnfcutils.la \
		 $(top_builddir)/libnfc/libnfc.la

nfc_mfclassic_SOURCES = nfc-mfclassic.c mifare.c mifare.h nfc-utils.h
nfc_mfclassic_LDADD = libnfcutils.la \
		    $(top_builddir)/libnfc/libnfc.la

nfc_mfultralight_SOURCES = nfc-mfultralight.c mifare.c mifare.h nfc-utils.h
nfc_mfultralight_LDADD = $(top_builddir)/libnfc/libnfc.la

nfc_read_forum_tag3_SOURCES = nfc-read-forum-tag3.c nfc-utils.h
nfc_read_forum_tag3_LDADD = libnfcutils.la \
		            $(top_builddir)/libnfc/libnfc.la

nfc_relay_picc_SOURCES = nfc-relay-picc.c nfc-utils.h
nfc_relay_picc_LDADD = libnfcutils.la \
		       $(top_builddir)/libnfc/libnfc.la

nfc_scan_device_SOURCES = nfc-scan-device.c nfc-utils.h
nfc_scan_device_LDADD = libnfcutils.la \
		 $(top_builddir)/libnfc/libnfc.la

if WIN32
nfc_scan_device_SOURCES += stdlib-win32.c
endif


dist_man_MANS = \
		nfc-barcode.1 \
		nfc-emulate-forum-tag4.1 \
		nfc-jewel.1 \
		nfc-list.1 \
		nfc-mfclassic.1 \
		nfc-mfultralight.1 \
		nfc-read-forum-tag3.1 \
		nfc-relay-picc.1 \
		nfc-scan-device.1

EXTRA_DIST = CMakeLists.txt
