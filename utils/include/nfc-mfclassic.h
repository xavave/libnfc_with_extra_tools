//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// utilities
//-----------------------------------------------------------------------------


#ifndef _MFCLASSIC_H__
# define _MFCLASSIC_H__
#include "mifare.h"
#include "..\nfc-utils.h"
long long unsigned int bytes_to_num(uint8_t* src, uint32_t len);
bool tryToGuessKey(mifare_cmd mc, uint32_t uiBlock);

#endif // _MFCLASSIC_H_