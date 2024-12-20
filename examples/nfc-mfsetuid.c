/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 * Copyright (C) 2011      Adam Laurie
 * Copyright (C) 2014      Dario Carluccio
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */

 /**
  * @file nfc-mfsetuid.c
  * @brief Set UID of special Mifare cards
  */

  /**
   * based on nfc-anticol.c
   */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <nfc/nfc.h>

#include "../utils/nfc-utils.h"

#define SAK_FLAG_ATS_SUPPORTED 0x20

#define MAX_FRAME_LEN 264
#define MAX_DEVICE_COUNT 16
#define MAX_TARGET_COUNT 16

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;
static uint8_t abtRawUid[12];
static uint8_t abtAtqa[2];
static uint8_t abtSak;
static uint8_t abtAts[MAX_FRAME_LEN];
static uint8_t szAts = 0;
static size_t szCL = 1;//Always start with Cascade Level 1 (CL1)
static nfc_device* pnd;

bool    quiet_output = false;
bool    iso_ats_supported = false;

// ISO14443A Anti-Collision Commands
uint8_t  abtReqa[1] = { 0x26 };
uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtRats[4] = { 0xe0, 0x50, 0x00, 0x00 };
uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };
#define CASCADE_BIT 0x04

// special unlock command
uint8_t  abtUnlock1[1] = { 0x40 };
uint8_t  abtUnlock2[1] = { 0x43 };
uint8_t  abtWipe[1] = { 0x41 };
uint8_t abtWrite[4] = { 0xa0,  0x00,  0x5f,  0xb1 };
uint8_t abtData[18] = { 0x01,  0x23,  0x45,  0x67,  0x00,  0x08,  0x04,  0x00,  0x46,  0x59,  0x25,  0x58,  0x49,  0x10,  0x23,  0x02,  0x23,  0xeb };
uint8_t abtBlank[18] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x36, 0xCC };


static bool transmit_bits(const uint8_t* pbtTx, const size_t szTxBits)
{
	// Show transmitted command
	if (!quiet_output) {
		printf("Sent bits:     ");
		print_hex_bits(pbtTx, szTxBits);
	}
	// Transmit the bit frame command, we don't use the arbitrary parity feature
	if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
		return false;

	// Show received answer
	if (!quiet_output) {
		printf("Received bits: ");
		print_hex_bits(abtRx, szRxBits);
	}
	// Succesful transfer
	return true;
}
uint16_t UpdateCrc(uint8_t ch, uint16_t* lpwCrc)
{
	ch = (ch ^ (uint8_t)((*lpwCrc) & 0x00FF));
	ch = (ch ^ (ch << 4));
	*lpwCrc = (*lpwCrc >> 8) ^ ((uint16_t)ch << 8) ^ ((uint16_t)ch << 3) ^ ((uint16_t)ch >> 4);
	return(*lpwCrc);
}
static void ComputeCrc(uint16_t wCrcPreset, uint8_t* Data, int Length, uint16_t* usCRC)
{
	uint8_t chBlock;
	uint16_t testRet;
	do {
		chBlock = *Data++;
		testRet = UpdateCrc(chBlock, &wCrcPreset);
	} while (--Length);
	*usCRC = wCrcPreset;
	return;
}
static void Convert7ByteUIDTo4ByteNUID(uint8_t* uc7ByteUID, uint8_t* uc4ByteUID)
{
	uint16_t CRCPreset = 0x6363;
	uint16_t CRCCalculated = 0x0000;
	ComputeCrc(CRCPreset, uc7ByteUID, 3, &CRCCalculated);
	uc4ByteUID[0] = (CRCCalculated >> 8) & 0xFF;//MSB
	uc4ByteUID[1] = CRCCalculated & 0xFF; //LSB
	CRCPreset = CRCCalculated;
	ComputeCrc(CRCPreset, uc7ByteUID + 3, 4, &CRCCalculated);
	uc4ByteUID[2] = (CRCCalculated >> 8) & 0xFF;//MSB
	uc4ByteUID[3] = CRCCalculated & 0xFF; //LSB
	uc4ByteUID[0] = uc4ByteUID[0] | 0x0F;
	uc4ByteUID[0] = uc4ByteUID[0] & 0xEF;
}

static  bool transmit_bytes(const uint8_t* pbtTx, const size_t szTx)
{
	// Show transmitted command
	if (!quiet_output) {
		printf("Sent bits:     ");
		print_hex(pbtTx, szTx);
	}
	int res;
	// Transmit the command bytes
	if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
		return false;

	// Show received answer
	if (!quiet_output) {
		printf("Received bits: ");
		print_hex(abtRx, res);
	}
	// Succesful transfer
	return true;
}

static void
print_usage(char* argv[])
{
	printf("Usage: %s [OPTIONS] [UID|BLOCK0]\n", argv[0]);
	printf("Options:\n");
	printf("\t-h\tHelp. Print this message.\n");
	printf("\t-f\tFormat. Delete all data (set to 0xFF) and reset ACLs to default.\n");
	printf("\t-i\t[value 0 or 1]. Force intrusive scan.\n");
	printf("\t-q\tQuiet mode. Suppress output of READER and CARD data (improves timing).\n");
	printf("\n\tSpecify UID (4 HEX OR 7 HEX bytes) to set UID, or leave blank for default '01234567'.\n");
	printf("\n\tSpecify BLOCK0 (16 HEX bytes) to set content of Block0. CRC (Byte 4) is recalculated an overwritten'.\n");
	printf("\tThis utility can be used to recover cards that have been damaged by writing bad\n");
	printf("\tdata (e.g. wrong BCC), thus making them non-selectable by most tools/readers.\n");
	printf("\n\t*** Note: this utility only works with special Mifare 1K cards (Chinese clones).\n\n");
}

int
main(int argc, char* argv[])
{
	int      arg, i;
	bool     format = false;
	uint32_t c;
	char     tmp[3] = { 0x00, 0x00, 0x00 };
	int intrusiveScan = -1;

	// Get commandline options
	for (arg = 1; arg < argc; arg++) {
		if (0 == strcmp(argv[arg], "-h")) {
			print_usage(argv);
			exit(EXIT_SUCCESS);
		}
		else if (0 == strcmp(argv[arg], "-f")) {
			format = true;
		}
		else if (0 == strcmp(argv[arg], "-q")) {
			quiet_output = true;
		}
		else if ((0 == strcmp(argv[arg], "-i")) && (arg + 1 < argc)) {
			arg++;
			if (strcmp((char*)argv[arg], "0") == 0)
				intrusiveScan = 0;
			else if (strcmp((char*)argv[arg], "1") == 0)
				intrusiveScan = 1;
			else
			{
				ERR("-i %s is invalid value for intrusive scan.", argv[arg]);
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}
		}
		else if (strlen(argv[arg]) == 8) {
			for (i = 0; i < 4; ++i) {
				memcpy(tmp, argv[arg] + i * 2, 2);
				sscanf(tmp, "%02x", &c);
				abtData[i] = (char)c;
			}
			abtData[4] = abtData[0] ^ abtData[1] ^ abtData[2] ^ abtData[3];
			iso14443a_crc_append(abtData, 16);
		}
		else if (strlen(argv[arg]) == 32) {
			for (i = 0; i < 16; ++i) {
				memcpy(tmp, argv[arg] + i * 2, 2);
				sscanf(tmp, "%02x", &c);
				abtData[i] = (char)c;
			}
			abtData[4] = abtData[0] ^ abtData[1] ^ abtData[2] ^ abtData[3];
			iso14443a_crc_append(abtData, 16);
		}
		//to test: write 7 bytes UID
		else if (strlen(argv[arg]) == 14) {
			for (i = 0; i < 7; ++i) {
				memcpy(tmp, argv[arg] + i * 2, 2);
				sscanf(tmp, "%02x", &c);
				abtData[i] = (char)c;
			}
			uint8_t uc4ByteUID[4] = { 0x00,0x00,0x00,0x00 };
			Convert7ByteUIDTo4ByteNUID(abtData, uc4ByteUID);
			printf("7-byte UID = ");
			for (i = 0; i < 7; i++)
				printf("%02x", abtData[i]);

			printf("\t4-byte FNUID = ");
			for (i = 0; i < 4; i++)
				printf("%02x", uc4ByteUID[i]);

			abtData[4] = abtData[0] ^ abtData[1] ^ abtData[2] ^ abtData[3];
			printf("\n");
			iso14443a_crc_append(abtData, 16);
		}
		else
		{
			ERR("%s is not supported option.", argv[arg]);
			print_usage(argv);
			exit(EXIT_FAILURE);
		}
	}
	if (intrusiveScan > -1)
	{ // This has to be done before the call to nfc_init()
		setenv("LIBNFC_INTRUSIVE_SCAN", intrusiveScan == 0 ? "no" : intrusiveScan == 1 ? "yes" : "no", 1);
	}
	nfc_context* context;
	nfc_init(&context);
	if (context == NULL) {
		ERR("Unable to init libnfc (malloc)");
		exit(EXIT_FAILURE);
	}
	// Display libnfc version
	printf("%s uses libnfc %s\n", argv[0], nfc_version());

	// Try to open the NFC reader

	nfc_connstring connstrings[MAX_DEVICE_COUNT];
	size_t szDeviceFound = nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);

	if (szDeviceFound == 0) {
		printf("No NFC device found.\n");
	}

	for (i = 0; i < szDeviceFound; i++) {
		nfc_target ant[MAX_TARGET_COUNT];
		pnd = nfc_open(context, connstrings[i]);
		if (pnd == NULL) {
			printf("Unable to open NFC device: %s\n", connstrings[i]);
			continue;
		}
		else
		{
			printf("NFC device: %s found\n", nfc_device_get_name(pnd));
			break;
		}

	}

	if (pnd == NULL) {
		ERR("Error opening NFC reader");
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	// Initialise NFC device as "initiator"
	if (nfc_initiator_init(pnd) < 0) {
		nfc_perror(pnd, "nfc_initiator_init");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	// Configure the CRC
	if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}
	// Use raw send/receive methods
	if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}
	// Disable 14443-4 autoswitching
	if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

	// Send the 7 bits request command specified in ISO 14443A (0x26)
	if (!transmit_bits(abtReqa, 7)) {
		printf("Error: No tag available\n");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}
	memcpy(abtAtqa, abtRx, 2);

	// Anti-collision
	transmit_bytes(abtSelectAll, 2);

	// Check answer
	if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
		printf("WARNING: BCC check failed!\n");
	}

	// Save the UID CL1
	memcpy(abtRawUid, abtRx, 4);

	//Prepare and send CL1 Select-Command
	memcpy(abtSelectTag + 2, abtRx, 5);
	iso14443a_crc_append(abtSelectTag, 7);
	transmit_bytes(abtSelectTag, 9);
	abtSak = abtRx[0];

	// Test if we are dealing with a CL2
	if (abtSak & CASCADE_BIT) {
		szCL = 2;//or more
		// Check answer
		if (abtRawUid[0] != 0x88) {
			printf("WARNING: Cascade bit set but CT != 0x88!\n");
		}
	}

	if (szCL == 2) {
		// We have to do the anti-collision for cascade level 2

		// Prepare CL2 commands
		abtSelectAll[0] = 0x95;

		// Anti-collision
		transmit_bytes(abtSelectAll, 2);

		// Check answer
		if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
			printf("WARNING: BCC check failed!\n");
		}

		// Save UID CL2
		memcpy(abtRawUid + 4, abtRx, 4);

		// Selection
		abtSelectTag[0] = 0x95;
		memcpy(abtSelectTag + 2, abtRx, 5);
		iso14443a_crc_append(abtSelectTag, 7);
		transmit_bytes(abtSelectTag, 9);
		abtSak = abtRx[0];

		// Test if we are dealing with a CL3
		if (abtSak & CASCADE_BIT) {
			szCL = 3;
			// Check answer
			if (abtRawUid[0] != 0x88) {
				printf("WARNING: Cascade bit set but CT != 0x88!\n");
			}
		}

		if (szCL == 3) {
			// We have to do the anti-collision for cascade level 3

			// Prepare and send CL3 AC-Command
			abtSelectAll[0] = 0x97;
			transmit_bytes(abtSelectAll, 2);

			// Check answer
			if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
				printf("WARNING: BCC check failed!\n");
			}

			// Save UID CL3
			memcpy(abtRawUid + 8, abtRx, 4);

			// Prepare and send final Select-Command
			abtSelectTag[0] = 0x97;
			memcpy(abtSelectTag + 2, abtRx, 5);
			iso14443a_crc_append(abtSelectTag, 7);
			transmit_bytes(abtSelectTag, 9);
			abtSak = abtRx[0];
		}
	}

	// Request ATS, this only applies to tags that support ISO 14443A-4
	if (abtRx[0] & SAK_FLAG_ATS_SUPPORTED) {
		iso_ats_supported = true;
	}

	printf("\nFound tag with\n UID: ");
	switch (szCL) {
	case 1:
		printf("%02x%02x%02x%02x", abtRawUid[0], abtRawUid[1], abtRawUid[2], abtRawUid[3]);
		break;
	case 2:
		printf("%02x%02x%02x", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
		printf("%02x%02x%02x%02x", abtRawUid[4], abtRawUid[5], abtRawUid[6], abtRawUid[7]);
		break;
	case 3:
		printf("%02x%02x%02x", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
		printf("%02x%02x%02x", abtRawUid[5], abtRawUid[6], abtRawUid[7]);
		printf("%02x%02x%02x%02x", abtRawUid[8], abtRawUid[9], abtRawUid[10], abtRawUid[11]);
		break;
	}
	printf("\n");
	printf("ATQA: %02x%02x\n SAK: %02x\n", abtAtqa[1], abtAtqa[0], abtSak);
	if (szAts > 1) { // if = 1, it's not actual ATS but error code
		printf(" ATS: ");
		print_hex(abtAts, szAts);
	}
	printf("\n");

	// now reset UID
	iso14443a_crc_append(abtHalt, 2);
	transmit_bytes(abtHalt, 4);

	if (!transmit_bits(abtUnlock1, 7)) {
		printf("Warning: Unlock command [1/2]: failed / not acknowledged.\n");
	}
	else {
		if (format) {
			transmit_bytes(abtWipe, 1);
			transmit_bytes(abtHalt, 4);
			transmit_bits(abtUnlock1, 7);
		}

		if (transmit_bytes(abtUnlock2, 1)) {
			printf("Card unlocked\n");
		}
		else {
			printf("Warning: Unlock command [2/2]: failed / not acknowledged.\n");
		}
	}

	transmit_bytes(abtWrite, 4);
	transmit_bytes(abtData, 18);
	if (format) {
		for (i = 3; i < 64; i += 4) {
			abtWrite[1] = (char)i;
			iso14443a_crc_append(abtWrite, 2);
			transmit_bytes(abtWrite, 4);
			transmit_bytes(abtBlank, 18);
		}
	}

	nfc_close(pnd);
	nfc_exit(context);
	exit(EXIT_SUCCESS);
}
