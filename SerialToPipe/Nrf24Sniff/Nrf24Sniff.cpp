/**
 * NRF24Sniff -- Nordic NRF24L01+ 2.4Ghz wireless module sniffer
 *
 * Copyright (c) 2014 by Ivo Pullens <info@emmission.nl>
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

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <errno.h>
#include "XGetopt.h"

#define BITS_TO_BYTES(x)  (((x)+7)>>3)
#define BYTES_TO_BITS(x)  ((x)<<3)

#define TIMESTAMP_LENGTH           (4)      // Timestamp received through serial interface, in bytes.
#define PACKETS_LOST_LENGTH        (1)      // Nr. of packets lost received through serial interface, in bytes.
#define NRF_ADDRESS_LENGTH         (5)      // Length of address, in bytes
#define NRF_CONTROL_LENGTH_BITS    (9)
#define NRF_MIN_PAYLOAD_LENGTH     (0)
#define NRF_MAX_PAYLOAD_LENGTH     (32)
#define NRF_CRC_LENGTH             (2)      // Length of NRF24 CRC field, in bytes
#define SERIAL_PACKET_LENGTH(payloadLen)  (TIMESTAMP_LENGTH+PACKETS_LOST_LENGTH+NRF_ADDRESS_LENGTH+BITS_TO_BYTES(NRF_CONTROL_LENGTH_BITS+BYTES_TO_BITS(payloadLen)+BYTES_TO_BITS(NRF_CRC_LENGTH)))
#define SERIAL_MINIMUM_PACKET_LENGTH      (SERIAL_PACKET_LENGTH(NRF_MIN_PAYLOAD_LENGTH))
#define SERIAL_MAXIMUM_PACKET_LENGTH      (SERIAL_PACKET_LENGTH(NRF_MAX_PAYLOAD_LENGTH))
#define PCAP_MAXIMUM_PACKET_LENGTH        (SERIAL_MAXIMUM_PACKET_LENGTH)

static struct {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr = { 0xa1b2c3d4, 2, 4, 0, 0, 65535, 147 /*LINKTYPE_USER0*/ };

typedef struct _pcaprec_hdr {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr;

static void printHex( uint8_t* p, const int len, const bool newline = true )
{
  for (int i = 0; i < len; ++i)
  {
    printf("%02x ", *p++);
  }
  if (newline)
    printf("\n");
}  

#define DEFAULT_BAUDRATE (115200)
#define DEFAULT_COMPORT  (0)

static void printProgress( const uint32_t numCaptured, const uint32_t numLost )
{
  printf("\rCaptured %lu packets, Lost %lu packets", numCaptured, numLost);
}


int _tmain(int argc, _TCHAR* argv[])
{
  const char* pipeName = "\\\\.\\pipe\\wireshark";     // \\.\pipe\wireshark
  uint8_t buff[1024];
  DWORD buffIdx;
  uint64_t timestamp_us;
  uint32_t prevSerTimestamp_us;
  bool firstPacket;
  HANDLE hPipe = INVALID_HANDLE_VALUE;
  HANDLE hComm = INVALID_HANDLE_VALUE;
  bool printHelp = false;
  DWORD baudrate = DEFAULT_BAUDRATE;
  int comport = DEFAULT_COMPORT;
  uint32_t numCaptured;
  uint32_t numLost;
  bool verbose = false;

  /* Parse commandline arguments */
  int c;
  while (!printHelp && ((c = getopt(argc, argv, _T("b:c:hv"))) != EOF))
  {
    switch (c)
    {
      case _T('b'):
        printHelp = !optarg;
        if (optarg)
        {
          baudrate = strtol(optarg, NULL, 10);
          printHelp = (baudrate == 0) || (errno == ERANGE);
        }
        break;
      case _T('c'):
        printHelp = !optarg;
        if (optarg)
        {
          comport = strtol(optarg, NULL, 10);
          printHelp = ((comport == 0) && (optarg[0] != '0')) || (errno == ERANGE);
        }
        break;
      case _T('v'):
        verbose = true;
        break;
      case _T('h'):
        printHelp = true;
        break;
      default:
        printHelp = true;
        break;
    }
  }
  if (printHelp)
  {
    printf("\n");
    printf("NRF24Sniff v1.0 - NRF24L01+ 2.4Ghz module sniffer for Wireshark\n");
    printf("\n");
    printf("(c)2014, Ivo Pullens, Emmission - www.emmission.nl\n");
    printf("This program is free software, but comes with ABSOLUTELY NO WARRANTY\n");
    printf("\n");
    printf("Usage: nrf24sniff [OPTION]\n");
    printf("\n");
    printf("Where [OPTION] can be one or more options of:\n");
    printf(" -b    Set baudrate, e.g. -b9600. Defaults to %d\n", DEFAULT_BAUDRATE);
    printf(" -c    Set comport, e.g. -c17. Defaults to COM%d\n", DEFAULT_COMPORT);
    printf(" -v    Enable verbose output\n");
    printf(" -h    Print this helptext\n");
    goto out;
  }


  while (1)
  {
    numCaptured = 0;
    numLost = 0;

    if (INVALID_HANDLE_VALUE != hComm)
    {
      CloseHandle(hComm);
      hComm = INVALID_HANDLE_VALUE;
    }

    if (INVALID_HANDLE_VALUE != hPipe)
    {
      CloseHandle(hPipe);
      hPipe = INVALID_HANDLE_VALUE;
    }

    hPipe = CreateNamedPipe(
                        pipeName,
                        PIPE_ACCESS_OUTBOUND,
                        PIPE_TYPE_MESSAGE | PIPE_WAIT,
                        1, 65536, 65536,
                        300,
                        NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
      printf("Failed to open Wireshark pipe: %d\n", GetLastError());
      goto out_pipe;
    }

    printf("Connect Wireshark to %s to continue...\n", pipeName);
    if (!ConnectNamedPipe(hPipe, NULL))
    {
      printf("Failed to connect to Wireshark pipe: %d\n", GetLastError());
      goto out_pipe;
    }

    DWORD numWritten;
    assert(sizeof(pcap_hdr) == 24 );
    (void)WriteFile(hPipe, &pcap_hdr, sizeof(pcap_hdr), &numWritten, NULL);

    char portName[100];
    _snprintf_s(portName, sizeof(portName), _TRUNCATE, "\\\\.\\COM%d", comport);   // See http://support.microsoft.com/default.aspx?scid=kb;EN-US;q115831
    hComm = CreateFile( portName,  
                        GENERIC_READ | GENERIC_WRITE, 
                        0, 
                        0, 
                        OPEN_EXISTING,
                        0,
                        0);
    if (hComm == INVALID_HANDLE_VALUE)
    {
      printf("Error!\n", portName);
      if(GetLastError() == ERROR_FILE_NOT_FOUND)
      {
          printf("Port %s not available.\n", portName);
      }
      goto out_comm;
    }
    // set the comm parameters
    DCB dcbSerialParams;

    // get the current comm parameters
    if (!GetCommState(hComm, &dcbSerialParams))
    {
      printf("Failed to get current serial parameters!");
      goto out_comm;
    }

    dcbSerialParams.BaudRate = baudrate;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity   = NOPARITY;
    if(!SetCommState(hComm, &dcbSerialParams))
    {
      printf("ALERT: Could not set Serial Port parameters");
      goto out_comm;
    }
    // Purge serial buffer
    (void)PurgeComm(hComm, PURGE_RXCLEAR | PURGE_TXCLEAR);

    firstPacket = true;

    // Flush buffer
    (void)memset(buff, 0, sizeof(buff));
    buffIdx = 0;

    printProgress(numCaptured, numLost);

    bool pipeOPen = true;
    while (pipeOPen)
    {
      if (sizeof(buff)-buffIdx <= 0)
      {
        // Buffer completely filled.. Something's terribly wrong --> Flush buffer
        printf("\nBuffer completely filled.... This is bad news!\n");
        (void)memset(buff, 0, sizeof(buff));
        buffIdx = 0;
      }
        
      // Use the ClearCommError function to get status info on the Serial port
      DWORD errors;
      COMSTAT stat;
      ClearCommError(hComm, &errors, &stat);
      DWORD numToRead = min(1, min(stat.cbInQue, sizeof(buff)-buffIdx));
        
      // Blocking read on serial port,reading either 1 byte when nothing is available (block),
      // the amount of data available on the port or the amount that still fits in the buffer.
      // This offloads the CPU compared to continuously polling for available data in the port.
      assert(buffIdx < sizeof(buff));
      DWORD numRead;
      if (ReadFile(hComm, (LPVOID)&buff[buffIdx], 1, &numRead, NULL))
      {
        buffIdx += numRead;
      }
      else
      {
        printf("\nError ReadFile %d\n", GetLastError() );
      }

      // Loop until there are no complete packets available in the buffer
      assert(buffIdx <= sizeof(buff));
      bool consumed = true;
      while ((buffIdx > 0) && consumed)
      {
//        printHex( reinterpret_cast<uint8_t*>(&buff), min(buffIdx,50) );
        uint8_t* sp = buff;
        DWORD lenSerPacket = *sp++;
        DWORD lenInBuff = 1 + lenSerPacket;
        if ((lenSerPacket < SERIAL_MINIMUM_PACKET_LENGTH) || (lenSerPacket > SERIAL_MAXIMUM_PACKET_LENGTH))
        {
          printf("\nIllegal serial packet size %d\n", lenSerPacket);
          if (verbose)
            printHex( buff, lenSerPacket );
          goto out;
        }
        if (buffIdx >= lenInBuff)
        {
          // Full packet is available in buffer. Consume it.
          // Format:
          // 1 byte                       length of serial packet, excluding this byte
          // TIMESTAMP_LENGTH byte(s)     timestamp of packet, in [us] since start of Arduino (wraps after ca. 70 minutes for 4 bytes)
          // PACKETS_LOST_LENGTH byte(s)  Nr of packets lost since last packet, stops counting at 255 (for 1 byte).
          // NRF_ADDRESS_LENGTH byte(s)   full target node address
          // 9bits                        NRF24 control field
          // [0..32]*8bits                NRF24 payload, not byte aligned!
          // NRF_CRC_LENGTH byte(s)       NRF24 CRC field, not byte aligned!

          uint8_t pcapPacket[PCAP_MAXIMUM_PACKET_LENGTH+1];
          uint8_t* pp = pcapPacket;

          // PCap packet will contain everything from serial packet, except timestamp
          DWORD lenPCapPacket = lenSerPacket - TIMESTAMP_LENGTH;

          // Read timestamp (passed through pcap header)
          uint32_t serTimestamp_us = *(reinterpret_cast<uint32_t*>(sp));
          sp += TIMESTAMP_LENGTH;
          if (firstPacket)
          {
            timestamp_us = 0ULL;
            // Previous timestamp not registered yet. Store it now so first packet gets timestamp 0.
            prevSerTimestamp_us = serTimestamp_us;
          }
          // Increment timestamp with time passed since previous packet.
          timestamp_us += serTimestamp_us - prevSerTimestamp_us;
          prevSerTimestamp_us = serTimestamp_us;

          uint8_t packetsLost = *sp++;
          numLost += packetsLost;
//          if (packetsLost > 0)
//            printf("%d packets lost since last packet\n", packetsLost);

          // Copy data 1:1 from serial packet, not byte aligned.
          (void)memcpy(pp, sp, lenPCapPacket);
          // For last byte only the MSbit has value; rest will be cleared
          *(pp+lenPCapPacket-1) &= 0x80;

          // Create packet header
          assert(sizeof(pcaprec_hdr) == 16);
          pcaprec_hdr hdr = { (uint32_t)(timestamp_us/1000000), (uint32_t)(timestamp_us%1000000), lenPCapPacket, lenPCapPacket };

          if (verbose)
          {
            printf("\n");
            printHex( buff, lenInBuff );
//          printHex( pcapPacket, lenPCapPacket );
          }
          // Write record header & data
          DWORD numWritten;
          if (    !WriteFile(hPipe, &hdr, sizeof(hdr), &numWritten, NULL) 
               || !WriteFile(hPipe, &pcapPacket, lenPCapPacket, &numWritten, NULL))
          {
            /* Restarting the pipe */
            printf("\nPipe disconnected\n");
            pipeOPen = false;
          }
          // Remove packet from buffer
          (void)memmove(buff, buff+lenInBuff, buffIdx-lenInBuff);             // Memmove! Regions overlap.
          (void)memset(buff+buffIdx, 0, sizeof(buff)-buffIdx);                // Optional: Clear remaining buffer
          buffIdx -= lenInBuff;
//          printf("Consumed %d bytes. New idx %d\n", lenInBuff, buffIdx);
          firstPacket = false;
          numCaptured++;
          printProgress(numCaptured, numLost);
        }
        else
        {
          consumed = false;
        }
      }
    }
  }

out_comm:
  if ( INVALID_HANDLE_VALUE != hComm )
  {
    CloseHandle(hComm);
  }

out_pipe:
  if ( INVALID_HANDLE_VALUE != hPipe )
  {
    CloseHandle(hPipe);
  }
out:
  return 0;
}

