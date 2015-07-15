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

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include "linuxFunctions.h"

void CloseHandle (int fd)
{
  close(fd);
}

int CreateNamedPipe (const char* pipeName, int unused1, int unused2, int unused3, int unused4, int unused5, int unused6, void* unused7)
{
  return mkfifo(pipeName, 0666);
}

long unsigned GetLastError ()
{
  return (long unsigned) errno;
}

int ConnectNamedPipe (const char* pipeName, void* whoCares)
{
  return open(pipeName, O_WRONLY);
}

int GetCommState (int fd, struct termios* pTermios)
{
  return (tcgetattr(fd, pTermios) < 0);
}

int setRTS (int fd, int level) //http://www.linuxquestions.org/questions/programming-9/manually-controlling-rts-cts-326590/
{
    int status;

    if (ioctl(fd, TIOCMGET, &status) == -1) {
        printf("setRTS(): TIOCMGET");
        return 0;
    }
    if (level)
        status |= TIOCM_RTS;
    else
        status &= ~TIOCM_RTS;
    if (ioctl(fd, TIOCMSET, &status) == -1) {
        printf("setRTS(): TIOCMSET");
        return 0;
    }
    return 1;
}

int setDTR (int fd, int level) //http://www.linuxquestions.org/questions/programming-9/manually-controlling-rts-cts-326590/
{
    int status;

    if (ioctl(fd, TIOCMGET, &status) == -1) {
        printf("setDTR(): TIOCMGET");
        return 0;
    }
    if (level)
        status |= TIOCM_DTR;
    else
        status &= ~TIOCM_DTR;
    if (ioctl(fd, TIOCMSET, &status) == -1) {
        printf("setDTR(): TIOCMSET");
        return 0;
    }
    return 1;
}

int EscapeCommFunction (int fd, int whatToDo)
{
  switch(whatToDo)
  {
    case CLRDTR: return setDTR(fd, 0); break;
    case CLRRTS: return setRTS(fd, 0); break;
    case SETDTR: return setDTR(fd, 1); break;
    case SETRTS: return setRTS(fd, 1); break;
  default: return (setDTR(fd, 0) && setRTS(fd, 0)); break; //is this a good idea? :/
  }
}

void PurgeComm(int fd, int whatEver)
{
  tcflush(fd, TCIOFLUSH);
}