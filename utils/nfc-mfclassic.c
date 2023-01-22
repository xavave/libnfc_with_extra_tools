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
 * Copyright (C) 2011-2013 Adam Laurie
 * Copyright (C) 2018-2019 Danielle Bruneo
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
  * @file nfc-mfclassic.c
  * @brief MIFARE Classic manipulation example
  */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <string.h>
#include <ctype.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#ifdef _MSC_VER
#include "getopt.h"
#endif
#include <nfc/nfc.h>

#include "mifare.h"
#include "nfc-utils.h"

static nfc_context* context;
static nfc_device* pnd;
static nfc_target nt;
static mifare_param mp;
static mifare_classic_tag mtKeys;
static mifare_classic_tag mtDump;
static bool bUseKeyA = true;
static bool bUseKeyFile = false;
static bool bForceKeyFile = false;
static int intrusiveScan = -1;
static bool bTolerateFailures = true;
static bool bFormatCard = false;
static bool dWrite = false;
static bool unlocked = false;
static uint8_t uiBlocks;
static uint8_t uiStartBlock = 0;
static uint8_t uiEndBlock = -1;
static uint8_t keys[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7,
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
  0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd,
  0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
  0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xab, 0xcd, 0xef, 0x12, 0x34, 0x56
};
static const uint8_t default_key[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t _default_acl[] = { 0xff, 0x07, 0x80, 0x69 };
static uint8_t* default_acl = _default_acl;
static uint8_t* custom_acl = _default_acl;
static uint8_t* pbtUID;
static uint8_t _tag_uid[4] = { 0x12, 0x34, 0x56, 0x78 };
static uint8_t* tag_uid = _tag_uid;
//-p W -e A -u -d "C:\Program Files (x86)\AVXTEC\MWT\dumps\blank_tag.dump" -k "G:\work\Mifare-Windows-Tool\MifareWindowsTool\bin\Debug\dumps\Dump_01234567.mfd" -f -i 0   -s 5  -t 5
static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

static size_t num_keys = sizeof(keys) / 6;

#define MAX_FRAME_LEN 264
#define MAX_DEVICE_COUNT 16
#define MAX_TARGET_COUNT 16
static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;

uint8_t abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

// special unlock command
uint8_t abtUnlock1[1] = { 0x40 };
uint8_t abtUnlock2[1] = { 0x43 };

static bool transmit_bits(const uint8_t* pbtTx, const size_t szTxBits)
{
	// Show transmitted command
	printf("Sent bits:     ");
	print_hex_bits(pbtTx, szTxBits);
	// Transmit the bit frame command, we don't use the arbitrary parity feature
	if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
		return false;

	// Show received answer
	printf("Received bits: ");
	print_hex_bits(abtRx, szRxBits);
	// Succesful transfer
	return true;
}

static bool transmit_bytes(const uint8_t* pbtTx, const size_t szTx)
{
	// Show transmitted command
	printf("Sent bits:     ");
	print_hex(pbtTx, szTx);
	// Transmit the command bytes
	int res;
	if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
		return false;

	// Show received answer
	printf("Received bits: ");
	print_hex(abtRx, res);
	// Succesful transfer
	return true;
}

static void print_success_or_failure(bool bFailure, uint32_t* uiBlockCounter)
{
	printf("%c", (bFailure) ? 'x' : '.');
	if (uiBlockCounter && !bFailure)
		*uiBlockCounter += 1;
}

static bool is_first_block(uint32_t uiBlock)
{
	// Test if we are in the small or big sectors
	if (uiBlock < 128)
		return ((uiBlock) % 4 == 0);
	else
		return ((uiBlock) % 16 == 0);
}

static bool is_trailer_block(uint32_t uiBlock)
{
	// Test if we are in the small or big sectors
	if (uiBlock < 128)
		return ((uiBlock + 1) % 4 == 0);
	else
		return ((uiBlock + 1) % 16 == 0);
}

static uint32_t get_trailer_block(uint32_t uiFirstBlock)
{
	// Test if we are in the small or big sectors
	uint32_t trailer_block = 0;
	if (uiFirstBlock < 128) {
		trailer_block = uiFirstBlock + (3 - (uiFirstBlock % 4));
	}
	else {
		trailer_block = uiFirstBlock + (15 - (uiFirstBlock % 16));
	}
	return trailer_block;
}

static bool authenticate(uint32_t uiBlock)
{
	mifare_cmd mc;

	// Set the authentication information (uid)
	memcpy(mp.mpa.abtAuthUid, nt.nti.nai.abtUid + nt.nti.nai.szUidLen - 4, 4);

	// Should we use key A or B?
	mc = (bUseKeyA) ? MC_AUTH_A : MC_AUTH_B;

	// Key file authentication.
	if (bUseKeyFile) {

		// Locate the trailer (with the keys) used for this sector
		uint32_t uiTrailerBlock;
		uiTrailerBlock = get_trailer_block(uiBlock);

		// Extract the right key from dump file
		if (bUseKeyA)
			memcpy(mp.mpa.abtKey, mtKeys.amb[uiTrailerBlock].mbt.abtKeyA, sizeof(mp.mpa.abtKey));
		else
			memcpy(mp.mpa.abtKey, mtKeys.amb[uiTrailerBlock].mbt.abtKeyB, sizeof(mp.mpa.abtKey));

		// Try to authenticate for the current sector
		if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp))
			return true;

		// If formatting or not using key file, try to guess the right key
	}
	else if (bFormatCard || !bUseKeyFile) {
		for (size_t key_index = 0; key_index < num_keys; key_index++) {
			memcpy(mp.mpa.abtKey, keys + (key_index * 6), 6);
			if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp)) {
				if (bUseKeyA)
					memcpy(mtKeys.amb[uiBlock].mbt.abtKeyA, &mp.mpa.abtKey, sizeof(mtKeys.amb[uiBlock].mbt.abtKeyA));
				else
					memcpy(mtKeys.amb[uiBlock].mbt.abtKeyB, &mp.mpa.abtKey, sizeof(mtKeys.amb[uiBlock].mbt.abtKeyB));
				return true;
			}
			if (nfc_initiator_select_passive_target(pnd, nmMifare, nt.nti.nai.abtUid, nt.nti.nai.szUidLen, NULL) <= 0) {
				ERR("tag was removed");
				return false;
			}
		}
	}

	return false;
}

static bool unlock_card(bool write)
{
	// Configure the CRC
	if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
		nfc_perror(pnd, "nfc_configure");
		return false;
	}
	// Use raw send/receive methods
	if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
		nfc_perror(pnd, "nfc_configure");
		return false;
	}

	iso14443a_crc_append(abtHalt, 2);
	transmit_bytes(abtHalt, 4);
	// now send unlock
	if (!transmit_bits(abtUnlock1, 7)) {
		printf("Warning: Unlock command [1/2]: failed / not acknowledged.\n");
		dWrite = true;
		if (write) {
			printf("Trying to rewrite block 0 on a direct write tag.\n");
		}
	}
	else {
		if (transmit_bytes(abtUnlock2, 1)) {
			printf("Card unlocked\n");
			unlocked = true;
		}
		else {
			printf("Warning: Unlock command [2/2]: failed / not acknowledged.\n");
		}
	}

	// reset reader
	if (!unlocked) {
		if (nfc_initiator_select_passive_target(pnd, nmMifare, nt.nti.nai.abtUid, nt.nti.nai.szUidLen, NULL) <= 0) {
			printf("Error: tag was removed\n");
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}
		return true;
	}
	// Configure the CRC
	if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, true) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool");
		return false;
	}
	// Switch off raw send/receive methods
	if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool");
		return false;
	}
	return true;
}

static int get_rats(void)
{
	int res;
	uint8_t abtRats[2] = { 0xe0, 0x50 };
	// Use raw send/receive methods
	if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
		nfc_perror(pnd, "nfc_configure");
		return -1;
	}
	res = nfc_initiator_transceive_bytes(pnd, abtRats, sizeof(abtRats), abtRx, sizeof(abtRx), 0);
	if (res > 0) {
		// ISO14443-4 card, turn RF field off/on to access ISO14443-3 again
		if (nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, false) < 0) {
			nfc_perror(pnd, "nfc_configure");
			return -1;
		}
		if (nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, true) < 0) {
			nfc_perror(pnd, "nfc_configure");
			return -1;
		}
	}
	// Reselect tag
	if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
		printf("Error: tag disappeared\n");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}
	return res;
}

static bool read_card(bool read_unlocked)
{
	int32_t iBlock;
	bool bFailure = false;
	uint32_t uiReadBlocks = 0;

	if (read_unlocked) {
		unlock_card(false);
		//If the user is attempting an unlocked read, but has a direct-write type magic card, they don't
		//need to use the R mode. We'll trigger a warning and let them proceed.
		if (dWrite) {
			printf("Note: This card can't do an unlocked read (R) \n");
			read_unlocked = 0;
		}
	}
	printf("Reading out %d blocks |", uiBlocks + 1);
	// Read the card from end to begin
	for (iBlock = uiBlocks; iBlock >= 0; iBlock--) {
		// Authenticate everytime we reach a trailer block
		if (is_trailer_block(iBlock)) {
			if (bFailure) {
				// When a failure occured we need to redo the anti-collision
				if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
					printf("!\nError: tag was removed\n");
					return false;
				}
				bFailure = false;
			}

			fflush(stdout);

			// Try to authenticate for the current sector
			if (!read_unlocked && !authenticate(iBlock)) {
				printf("!\nError: authentication failed for block 0x%02x\n", iBlock);
				return false;
			}
			// Try to read out the trailer
			if (nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
				if (read_unlocked) {
					memcpy(mtDump.amb[iBlock].mbd.abtData, mp.mpd.abtData, sizeof(mtDump.amb[iBlock].mbd.abtData));
				}
				else {
					// Copy the keys over from our key dump and store the retrieved access bits
					memcpy(mtDump.amb[iBlock].mbt.abtKeyA, mtKeys.amb[iBlock].mbt.abtKeyA, sizeof(mtDump.amb[iBlock].mbt.abtKeyA));
					memcpy(mtDump.amb[iBlock].mbt.abtAccessBits, mp.mpt.abtAccessBits, sizeof(mtDump.amb[iBlock].mbt.abtAccessBits));
					memcpy(mtDump.amb[iBlock].mbt.abtKeyB, mtKeys.amb[iBlock].mbt.abtKeyB, sizeof(mtDump.amb[iBlock].mbt.abtKeyB));
				}
			}
			else {
				printf("!\nfailed to read trailer block 0x%02x\n", iBlock);
				bFailure = true;
			}
		}
		else {
			// Make sure a earlier readout did not fail
			if (!bFailure) {
				// Try to read out the data block
				if (nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
					memcpy(mtDump.amb[iBlock].mbd.abtData, mp.mpd.abtData, sizeof(mtDump.amb[iBlock].mbd.abtData));
				}
				else {
					printf("!\nError: unable to read block 0x%02x\n", iBlock);
					bFailure = true;
				}
			}
		}
		// Show if the readout went well for each block
		print_success_or_failure(bFailure, &uiReadBlocks);
		if ((!bTolerateFailures) && bFailure)
			return false;
	}
	printf("|\n");
	printf("Done, %d of %d blocks read.\n", uiReadBlocks, uiBlocks + 1);
	fflush(stdout);

	return true;
}

static bool write_card(bool write_block_zero)
{
	uint32_t uiBlock;
	bool bFailure = false;
	uint32_t uiWriteBlocks = 0;
	bool bUseCustomACL = memcmp(custom_acl, default_acl, sizeof(default_acl)) != 0;
	//Determine if we have to unlock the card
	if (write_block_zero) {
		unlock_card(true);
	}
	int32_t blockCount = uiEndBlock - uiStartBlock;
	printf("Writing %d blocks |", blockCount + write_block_zero);
	// Completely write the card, but skipping block 0 if we don't need to write on it
	for (uiBlock = uiStartBlock; uiBlock <= uiEndBlock; uiBlock++) {
		//Determine if we have to write block 0
		if (!write_block_zero && uiBlock == 0) {
			continue;
		}
		// Authenticate everytime we reach the first sector of a new block
		if (uiBlock == 1 || is_first_block(uiBlock)) {
			if (bFailure) {
				// When a failure occured we need to redo the anti-collision

				if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {

					printf("!\nError: tag was removed\n");
					return false;
				}
				bFailure = false;
			}

			fflush(stdout);

			// Try to authenticate for the current sector
			// If we are are writing to a chinese magic card, we've already unlocked
			// If we're writing to a direct write card, we need to authenticate
			// If we're writing something else, we'll need to authenticate
			if ((write_block_zero && dWrite) || !write_block_zero) {
				if (!authenticate(uiBlock) && !bTolerateFailures) {
					printf("!\nError: authentication failed for block %02x\n", uiBlock);
					return false;
				}
			}
		}

		if (is_trailer_block(uiBlock)) {
			if (bFormatCard) {
				// Copy the default key and reset the access bits
				memcpy(mp.mpt.abtKeyA, default_key, sizeof(mp.mpt.abtKeyA));
				memcpy(mp.mpt.abtAccessBits, default_acl, sizeof(mp.mpt.abtAccessBits));
				memcpy(mp.mpt.abtKeyB, default_key, sizeof(mp.mpt.abtKeyB));
			}
			else {
				// Copy the keys over from our key dump and store the retrieved access bits
				memcpy(mp.mpt.abtKeyA, mtDump.amb[uiBlock].mbt.abtKeyA, sizeof(mp.mpt.abtKeyA));
				memcpy(mp.mpt.abtAccessBits, bUseCustomACL ? custom_acl : mtDump.amb[uiBlock].mbt.abtAccessBits, sizeof(mp.mpt.abtAccessBits));
				memcpy(mp.mpt.abtKeyB, mtDump.amb[uiBlock].mbt.abtKeyB, sizeof(mp.mpt.abtKeyB));
			}

			// Try to write the trailer
			if (nfc_initiator_mifare_cmd(pnd, MC_WRITE, uiBlock, &mp) == false) {
				printf("failed to write trailer block %d \n", uiBlock);
				bFailure = true;
			}
		}
		else {
			// Make sure a earlier write did not fail
			if (!bFailure) {
				// Try to write the data block
				if (bFormatCard && uiBlock)

					memset(mp.mpd.abtData, 0x00, sizeof(mp.mpd.abtData));
				else
					memcpy(mp.mpd.abtData, mtDump.amb[uiBlock].mbd.abtData, sizeof(mp.mpd.abtData));
				// do not write a block 0 with incorrect BCC - card will be made invalid!
				if (uiBlock == 0) {
					if ((mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^ mp.mpd.abtData[2] ^ mp.mpd.abtData[3] ^ mp.mpd.abtData[4]) != 0x00) {
						printf("!\nError: incorrect BCC in MFD file!\n");
						printf("Expecting BCC=%02X\n", mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^ mp.mpd.abtData[2] ^ mp.mpd.abtData[3]);
						return false;
					}
				}
				if (!nfc_initiator_mifare_cmd(pnd, MC_WRITE, uiBlock, &mp)) {
					bFailure = true;
					printf("Failure to write to data block %i\n", uiBlock);
				}
				if (uiBlock == 0 && dWrite) {
					if (nfc_initiator_init(pnd) < 0) {
						nfc_perror(pnd, "nfc_initiator_init");
						nfc_close(pnd);
						nfc_exit(context);
						exit(EXIT_FAILURE);
					};
					if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
						printf("!\nError: tag was removed\n");
						return false;
					}
				}
			}
			else {
				printf("Failure during write process.\n");
			}
		}
		//}
		// Show if the write went well for each block
		print_success_or_failure(bFailure, &uiWriteBlocks);
		if ((!bTolerateFailures) && bFailure)
			return false;
	}

	printf("|\n");
	printf("Done, %d of %d blocks written.\n", uiWriteBlocks, blockCount + 1);
	fflush(stdout);

	return true;
}

typedef enum {
	ACTION_READ,
	ACTION_WRITE,
	ACTION_USAGE
} action_t;

static void
print_usage(const char* pcProgramName)
{
	printf("Usage: ");
#ifndef _WIN32
	printf("%s -p [f|r|R|w|W] -e [a|A|b|B] -u [01AB23CD] -i [0|1] -d <dump.mfd> -k <keys.mfd> -F -v\n", pcProgramName);
#else
	printf("%s -p [f|r|R|w|W] -e [a|A|b|B] -u [01AB23CD] -i [0|1] -d <dump.mfd> -k <keys.mfd> -F\n", pcProgramName);
#endif
	printf(" -p [f|r|R|w|W] - Perform format (f) or read from (r) or unlocked read from (R) or write to (w) or block 0 write to (W) card\n");
	printf("                  *** format will reset all keys to FFFFFFFFFFFF and all data to 00 and all ACLs to default\n");
	printf("                  *** unlocked read does not require authentication and will reveal A and B keys\n");
	printf("                  *** note that block 0 write will attempt to overwrite block 0 including UID\n");
	printf("                  *** block 0 write only works with special Mifare cards (Chinese clones)\n");
	printf(" -e [a|A|b|B]   - Use A or B keys for action; Halt on errors (a|b) or tolerate errors (A|B)\n");
	printf(" -u [0|UID]     - Use any uid (-u 0) \n");
	printf("                  *** or supply a custom UID as -u 01AB23CD.\n");
	printf(" -i [0|1]       - force intrusive scan ON or OFF (0 for NO or 1 for YES).\n");
	printf(" -d <dump.mfd>  - MiFare Dump (MFD) used to write (card to MFD) or (MFD to card)\n");
	printf(" -k <keys.mfd>  - MiFare Dump (MFD) that contain the keys (optional)\n");
	printf(" -s <0..x>      - Write from specified block (example: -s 4 (decimal number)) x depends on the tag size\n");
	printf(" -t <0..x>      - Write to specified block (example: -t 12 (decimal number))  x depends on the tag size\n");
	printf("                  *** max block: 19 for 320 bytes tags\n");
	printf("                  *** max block: 63 for 1K/2K tags\n");
	printf("                  *** max block: 127 for MIFARE Plus 2K tags\n");
	printf("                  *** max block: 255 for 4K tags\n");
	printf(" -a [ACL]       - Force custom ACL (4 bytes) instead of default FF078069.\n");
	printf(" -f             - Force using the keyfile even if UID does not match (optional)\n");


#ifndef _WIN32
	printf("  -v            - Sends libnfc log output to console (optional)\n");
#endif
	printf("Examples: \n\n");
	printf("  Read card to file, using key A:\n\n");
	printf("    %s -p r -e a -u -d mycard.mfd\n\n", pcProgramName);
	printf("  Search tag readers with intrusive scan, then read card to file, using key A:\n\n");
	printf("    %s -p r -e a -u -d mycard.mfd -i 1\n\n", pcProgramName);
	printf("  Write file to blank card, using key A:\n\n");
	printf("    %s -p w -e a -u -d mycard.mfd\n\n", pcProgramName);
	printf("  Write new data and/or keys to previously written card, using key A:\n\n");
	printf("    %s -p w -e a -u -d newdata.mfd -k mycard.mfd\n\n", pcProgramName);
	printf("  Format/wipe card (note two passes required to ensure writes for all ACL cases):\n\n");
	printf("    %s -p f -e A -u -k keyfile.mfd f\n", pcProgramName);
	printf("    %s -p f -e B -u -k keyfile.mfd f\n\n", pcProgramName);
	printf("  Read card to file, using key A and uid 0x01 0xab 0x23 0xcd:\n\n");
	printf("    %s -p r -e a -u 01ab23cd -d mycard.mfd\n\n", pcProgramName);
}
static char* keysFileName = "";
static char* dumpFileName = "";

int main(int argc, const char* argv[])
{
	action_t atAction = ACTION_USAGE;

	bool    unlock = false;
	bool verbose = false;
	//File pointers for the keyfile 
	FILE* pfKeys;

#ifndef _WIN32
	// Send noise from lib to /dev/null
	if (!verbose) {
		int fd = open("/dev/null", O_WRONLY);
		dup2(fd, 2);
		close(fd);
	}
#endif
	int ch, tmpStartBlock, tmpEndBlock;
	tag_uid = NULL;
	// Parse command line arguments
	//	printf("%s -p [f|r|R|w|W] -e [a|A|b|B] -u [0|01AB23CD] -i [0|1] -d <dump.mfd> -k <keys.mfd> -F\n", pcProgramName);
	while ((ch = getopt(argc, argv, "p:e:u:i:d:k:s:t:a:fv")) != -1) {
		switch (ch) {
		case 'f':
			bForceKeyFile = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'p':
			// Perform action
			if (optarg == NULL)
			{
				ERR("argument [f|r|R|w|W] missing after -p (action to perform)");
				exit(EXIT_FAILURE);
			}
			if (stricmp(optarg, "r") == 0) {
				atAction = ACTION_READ;
				if (strcmp(optarg, "R") == 0)
					unlock = true;
			}
			else if (stricmp(optarg, "w") == 0 || strcmp(optarg, "f") == 0)
			{
				atAction = ACTION_WRITE;
				if (strcmp(optarg, "W") == 0)
					unlock = true;
				bFormatCard = strcmp(optarg, "f") == 0;
			}
			break;
		case 'e':
			if (optarg == NULL || stricmp(optarg, "A") != 0 && stricmp(optarg, "B") != 0)
			{
				ERR("missing or invalid argument after -e [a|A|b|B]  - Use A or B keys for action; Halt on errors (a|b) or tolerate errors (A|B)");
				exit(EXIT_FAILURE);
			}
			bUseKeyA = (stricmp(optarg, "A") == 0);
			bTolerateFailures = (strcmp(optarg, "A") == 0) || (strcmp(optarg, "B") == 0);
			break;
		case 'i':
			if (strcmp(optarg, "0") == 0)
				intrusiveScan = 0;
			else 	if (strcmp(optarg, "1") == 0)
				intrusiveScan = 1;
			else
			{
				ERR("missing argument 0 or 1  after -i (intrusive tag reader devices scan)");
				exit(EXIT_FAILURE);
			}
			break;
		case 's':
			tmpStartBlock = atoi(optarg);
			if (tmpStartBlock >= 0)
				uiStartBlock = tmpStartBlock;
			break;
		case 't':
			tmpEndBlock = atoi(optarg);
			if (tmpEndBlock >= 0)
				uiEndBlock = tmpEndBlock;
			break;
		case 'k':
			if (optarg == NULL || !(pfKeys = fopen(optarg, "rb"))) {
				fprintf(stderr, "Cannot open keyfile: %s, exiting\n", optarg);
				exit(EXIT_FAILURE);
			}
			keysFileName = optarg;
			bUseKeyFile = true;
			break;
		case 'd':
			if (optarg == NULL)
			{
				fprintf(stderr, "Missing dumpfile path: %s, exiting\n", optarg);
				exit(EXIT_FAILURE);
			}
			dumpFileName = optarg;
			break;
		case 'u':

			if (optarg == NULL || (strlen(optarg) != 8 && strlen(optarg) != 1)) {
				printf("Error, illegal custom UID specification, use -u 01AB23CD for example.\n");
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			unsigned long int _uid = strtoul(optarg + 1, NULL, 16);
			if (_uid != 0)
			{
				tag_uid[0] = (_uid & 0xff000000UL) >> 24;
				tag_uid[1] = (_uid & 0x00ff0000UL) >> 16;
				tag_uid[2] = (_uid & 0x0000ff00UL) >> 8;
				tag_uid[3] = (_uid & 0x000000ffUL);
				printf("Attempting to use specific UID: 0x%2x 0x%2x 0x%2x 0x%2x\n", tag_uid[0], tag_uid[1], tag_uid[2], tag_uid[3]);
			}
			break;
		case 'a':
			if (optarg == NULL || (strlen(optarg) != 8))
			{
				printf("Error, illegal custom ACL specification, use -a FF078069 for example.\n");
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			else
			{
				unsigned long int _acl = strtoul(optarg + 1, NULL, 16);
				custom_acl[0] = (_acl & 0xff000000UL) >> 24;
				custom_acl[1] = (_acl & 0x00ff0000UL) >> 16;
				custom_acl[2] = (_acl & 0x0000ff00UL) >> 8;
				custom_acl[3] = (_acl & 0x000000ffUL);
				printf("Attempting to use specific ACL: 0x%2x 0x%2x 0x%2x 0x%2x\n", custom_acl[0], custom_acl[1], custom_acl[2], custom_acl[3]);
			}
			break;
		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
			break;
		}

	}

	if (atAction == ACTION_USAGE) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	// We don't know yet the card size so let's read only the UID from the keyfile for the moment
	if (bUseKeyFile) {

		if (pfKeys == NULL) {
			exit(EXIT_FAILURE);
		}
		if (fread(&mtKeys, 1, 4, pfKeys) != 4) {
			printf("Could not read UID from key file: %s\n", keysFileName);
			fclose(pfKeys);
			exit(EXIT_FAILURE);
		}
		fclose(pfKeys);
	}
	if (intrusiveScan > -1)
	{
		// This has to be done before the call to nfc_init()
		setenv("LIBNFC_INTRUSIVE_SCAN", intrusiveScan == 0 ? "no" : intrusiveScan == 1 ? "yes" : "no", 1);
	}
	nfc_init(&context);
	if (context == NULL) {
		ERR("Unable to init libnfc (malloc)");
		exit(EXIT_FAILURE);
	}

	// Try to open the NFC reader
	// Display libnfc version
	printf("%s uses libnfc %s\n", argv[0], nfc_version());

	nfc_connstring connstrings[MAX_DEVICE_COUNT];
	size_t szDeviceFound = nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);

	if (szDeviceFound == 0) {
		printf("No NFC device found.\n");
	}

	for (int i = 0; i < szDeviceFound; i++) {
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

	if (nfc_initiator_init(pnd) < 0) {
		nfc_perror(pnd, "nfc_initiator_init");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	};
	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));
	// Drop the field for a while, so can be reset
	if (nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, true) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool activate field");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	// Let the reader only try once to find a tag
	if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}
	// Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
	if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	// Configure the CRC and Parity settings
	if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, true) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool crc");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}
	if (nfc_device_set_property_bool(pnd, NP_HANDLE_PARITY, true) < 0) {
		nfc_perror(pnd, "nfc_device_set_property_bool parity");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}


	// Try to find a MIFARE Classic tag
	int tags;
	tags = nfc_initiator_select_passive_target(pnd, nmMifare, tag_uid, tag_uid == NULL ? 0 : 4, &nt);
	if (tags <= 0) {
		printf("Error: no tag was found\n");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}
	// Test if we are dealing with a MIFARE compatible tag
	if (((nt.nti.nai.btSak & 0x08) == 0) && (nt.nti.nai.btSak != 0x01)) {
		//  if ((nt.nti.nai.btSak & 0x08) == 0) {
		printf("Warning: tag is probably not a MFC!\n");
	}

	// Get the info from the current tag
	pbtUID = nt.nti.nai.abtUid;

	if (bUseKeyFile) {
		uint8_t fileUid[4];
		memcpy(fileUid, mtKeys.amb[0].mbm.abtUID, 4);
		// Compare if key dump UID is the same as the current tag UID, at least for the first 4 bytes
		if (memcmp(pbtUID, fileUid, 4) != 0) {
			printf("Expected MIFARE Classic card with UID starting as: %02x%02x%02x%02x\n",
				fileUid[0], fileUid[1], fileUid[2], fileUid[3]);
			printf("Got card with UID starting as:                     %02x%02x%02x%02x\n",
				pbtUID[0], pbtUID[1], pbtUID[2], pbtUID[3]);
			if (!bForceKeyFile) {
				printf("Aborting!\n");
				nfc_close(pnd);
				nfc_exit(context);
				exit(EXIT_FAILURE);
			}
		}
	}
	printf("Found MIFARE Classic card:\n");
	print_nfc_target(&nt, false);

	// Guessing size
	if ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x02 || nt.nti.nai.btSak == 0x18)
		// 4K
		uiBlocks = 0xff;
	else if (nt.nti.nai.btSak == 0x09)
		// 320b
		uiBlocks = 0x13;
	else
		// 1K/2K, checked through RATS
		uiBlocks = 0x3f;

	// Testing RATS
	int res;
	if ((res = get_rats()) > 0) {
		printf("RATS support: yes\n");
		if ((res >= 10) && (abtRx[5] == 0xc1) && (abtRx[6] == 0x05)
			&& (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f)
			&& ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x00)) {
			// MIFARE Plus 2K
			uiBlocks = 0x7f;
		}
	}
	else
		printf("RATS support: no\n");
	printf("Guessing size: seems to be a %lu-byte card\n", (unsigned long)((uiBlocks + 1) * sizeof(mifare_classic_block)));

	if (uiEndBlock == -1)
	{
		uiEndBlock = uiBlocks;
	}
	else
	{
		if (uiEndBlock > uiBlocks)
		{
			printf("Wrong max block for this tag (%d), it should be less or equal: %d\n", uiEndBlock, uiBlocks);
			fclose(pfKeys);
			exit(EXIT_FAILURE);
		}
	}
	if (uiStartBlock > uiEndBlock)
	{
		printf("Wrong start block for this tag (%d), it should be less or equal end block: %d\n", uiStartBlock, uiEndBlock);
		fclose(pfKeys);
		exit(EXIT_FAILURE);
	}

	if (bUseKeyFile) {
		FILE* pfKeys = fopen(keysFileName, "rb");
		if (pfKeys == NULL) {
			printf("Could not open keys file: %s\n", keysFileName);
			exit(EXIT_FAILURE);
		}
		if (fread(&mtKeys, 1, (uiBlocks + 1) * sizeof(mifare_classic_block), pfKeys) != (uiBlocks + 1) * sizeof(mifare_classic_block)) {
			printf("Could not read keys file: %s\n", keysFileName);
			fclose(pfKeys);
			exit(EXIT_FAILURE);
		}
		fclose(pfKeys);
	}

	if (atAction == ACTION_READ) {
		memset(&mtDump, 0x00, sizeof(mtDump));
	}
	else {
		FILE* pfDump = fopen(dumpFileName, "rb");

		if (pfDump == NULL) {
			printf("Could not open dump file: %s\n", dumpFileName);
			exit(EXIT_FAILURE);

		}

		if (fread(&mtDump, 1, (uiBlocks + 1) * sizeof(mifare_classic_block), pfDump) != (uiBlocks + 1) * sizeof(mifare_classic_block)) {
			printf("Could not read dump file: %s\n", dumpFileName);
			fclose(pfDump);
			exit(EXIT_FAILURE);
		}
		fclose(pfDump);
	}
	// printf("Successfully opened required files\n");

	if (atAction == ACTION_READ) {
		if (read_card(unlock)) {
			printf("Writing data to file: %s ...", dumpFileName);
			fflush(stdout);
			FILE* pfDump = fopen(dumpFileName, "wb");
			if (pfDump == NULL) {
				printf("Could not open dump file: %s\n", dumpFileName);
				nfc_close(pnd);
				nfc_exit(context);
				exit(EXIT_FAILURE);
			}
			if (fwrite(&mtDump, 1, (uiBlocks + 1) * sizeof(mifare_classic_block), pfDump)
				!= ((uiBlocks + 1) * sizeof(mifare_classic_block))) {
				printf("\nCould not write to file: %s\n", dumpFileName);
				fclose(pfDump);
				nfc_close(pnd);
				nfc_exit(context);
				exit(EXIT_FAILURE);
			}
			printf("Done.\n");
			fclose(pfDump);
		}
		else {
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}
	}
	else if (atAction == ACTION_WRITE) {
		if (!write_card(unlock)) {
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}
	}

	nfc_close(pnd);
	nfc_exit(context);
	exit(EXIT_SUCCESS);
}
