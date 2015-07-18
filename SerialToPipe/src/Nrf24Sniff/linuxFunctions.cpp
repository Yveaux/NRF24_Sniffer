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
  if(access(pipeName,F_OK) == 0)
  { //pipe already exists
    unlink(pipeName);
  }
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
  return (tcgetattr(fd, pTermios) == 0);
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

void PurgeComm (int fd, int whatEver)
{
  tcflush(fd, TCIOFLUSH);
}

int getSerialMaskFromInt (int baudrate)
{
  int speedDefine;
  switch(baudrate)
  {
    case 50: speedDefine = B50; break;
    case 75: speedDefine = B75; break;
    case 110: speedDefine = B110; break;
    case 134: speedDefine = B134; break;
    case 150: speedDefine = B150; break;
    case 200: speedDefine = B200; break;
    case 300: speedDefine = B300; break;
    case 600: speedDefine = B600; break;
    case 1200: speedDefine = B1200; break;
    case 1800: speedDefine = B1800; break;
    case 2400: speedDefine = B2400; break;
    case 4800: speedDefine = B4800; break;
    case 9600: speedDefine = B9600; break;
    case 19200: speedDefine = B19200; break;
    case 38400: speedDefine = B38400; break;
    case 57600: speedDefine = B57600; break;
    case 115200: speedDefine = B115200; break;
    case 230400: speedDefine = B230400; break;
    case 460800: speedDefine = B460800; break;
    case 500000: speedDefine = B500000; break;
    case 576000: speedDefine = B576000; break;
    case 921600: speedDefine = B921600; break;
    case 1000000: speedDefine = B1000000; break;
    case 1152000: speedDefine = B1152000; break;
    case 1500000: speedDefine = B1500000; break;
    case 2000000: speedDefine = B2000000; break;
    case 2500000: speedDefine = B2500000; break;
    case 3000000: speedDefine = B3000000; break;
    case 3500000: speedDefine = B3500000; break;
    case 4000000: speedDefine = B4000000; break;
    default:
      printf("Cannot set serial port speed to %d. Possible speeds are: \n", baudrate);
      printf("50\n75\n110\n134\n150\n200\n300\n600\n1200\n1800\n2400\n4800\n9600\n19200\n38400\n57600\n115200\n230400\n460800\n500000\n576000\n921600\n1000000\n1152000\n1500000\n2000000\n2500000\n3000000\n3500000\n4000000\n");
      return -1;
    break;
  }
  return speedDefine;
}