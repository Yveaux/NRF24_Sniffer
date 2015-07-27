/**
 * NRF24Sniff -- Nordic NRF24L01+ 2.4Ghz wireless module sniffer
 *
 * Copyright (c) 2014 by Ivo Pullens <info@emmission.nl>
 * Ported to linux by Dietmar Malli (2015) <dietmar@malli.co.at>
 *
 * This file is part of NRF24Sniff.
 * 
 * NRF24Sniff is free software: you can redistribute 
 * it and/or modify it under the terms of the GNU General Public 
 * License as published by the Free Software Foundation, either 
 * version 3 of the License, or (at your option) any later version.
 * 
 * NRF24Sniff is distributed in the hope that it will 
 * be useful, but WITHOUT ANY WARRANTY; without even the implied warranty 
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with NRF24Sniff.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @license GPL-3.0+ <http://spdx.org/licenses/GPL-3.0+>
 */

#ifndef LINUXFUNCTIONS_H
#define	LINUXFUNCTIONS_H

#include <termios.h>

/**
 * Wrapper function to close a file descriptor in Windows coding style.
 */
void CloseHandle (int fd);

/**
 * Wrapper function to create a FIFO/NamedPipe in Windows coding style.
 */
#define PIPE_ACCESS_OUTBOUND 0
#define PIPE_TYPE_MESSAGE 0
#define PIPE_WAIT 0
int CreateNamedPipe (const char* pipeName, int unused1, int unused2, int unused3, int unused4, int unused5, int unused6, void* unused7);

/**
 * Wrapper function for errno in Windows coding style.
 */
long unsigned GetLastError ();

/**
 * Wrapper function to open a file descriptor in Windows coding style.
 */
int ConnectNamedPipe (const char* pipeName, void* whoCares);

/**
 * Wrapper function to read current serial device parameters in Windows coding style.
 */
int GetCommState (int fd, struct termios* pTermios);

/**
 * Wrapper function to write RTS/DTS in Windows coding style.
 */
#define CLRDTR -1
#define CLRRTS -2
#define SETDTR -3
#define SETRTS -4
int EscapeCommFunction (int fd, int whatToDo);

/**
 * Wrapper function to flush serial device buffers in Windows coding style.
 */
#define PURGE_RXCLEAR -1
#define PURGE_TXCLEAR -2
void PurgeComm(int fd, int whatEver);

/**
 * Function checks the given baudrate agains the defines from termios.h and returns the right value for the termios
 * speed setting functions or -1 if the wanted baudrate isn't available.
 */
int getSerialMaskFromInt (int baudrate);

#endif	/* LINUXFUNCTIONS_H */

