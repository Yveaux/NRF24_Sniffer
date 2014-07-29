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

#define MSG_TYPE_PACKET          (0)
#define MSG_TYPE_CONFIG          (1)
#define GET_MSG_LEN(var)         ((var) & 0x3F)
#define SET_MSG_TYPE(var,type)   (((var) & 0x3F) | ((type) << 6))
#define GET_MSG_TYPE(var)        ((var) >> 6)

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

#define DEFAULT_BAUDRATE                (115200)
#define DEFAULT_COMPORT                 (0)
#define DEFAULT_RF_CHANNEL              (76)
#define DEFAULT_RF_DATARATE             (0)
#define DEFAULT_RF_ADDRESS_LEN          (5)
#define DEFAULT_RF_ADDRESS_PROMISC_LEN  (4)
#define DEFAULT_RF_BASE_ADDRESS         ((uint64_t)0xA8A8E1FC00ULL)
#define DEFAULT_RF_CRC_LEN              (2)
#define DEFAULT_RF_PAYLOAD_LEN          (32)

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

#pragma pack(push)
#pragma pack(1)
typedef struct _serialConfig
{
  uint8_t channel;
  uint8_t rate;                        // rf24_datarate_e: 0 = 1Mb/s, 1 = 2Mb/s, 2 = 250Kb/s
  uint8_t addressLen;                  // Number of bytes used in address, range [2..5]
  uint8_t addressPromiscLen;           // Number of bytes used in promiscuous address, range [2..5]. E.g. addressLen=5, addressPromiscLen=4 => 1 byte unique identifier.
  uint64_t address;                    // Base address, LSB first.
  uint8_t crcLength;                   // Length of active CRC, range [0..2]
  uint8_t maxPayloadSize;              // Maximum size of payload for nRF (including nRF header), range[4?..32]
} serialConfig;

static serialConfig config = { DEFAULT_RF_CHANNEL, DEFAULT_RF_DATARATE, DEFAULT_RF_ADDRESS_LEN, DEFAULT_RF_ADDRESS_PROMISC_LEN, DEFAULT_RF_BASE_ADDRESS, DEFAULT_RF_CRC_LEN, DEFAULT_RF_PAYLOAD_LEN };
#pragma pack(pop)

static void spin( const bool run )
{
  static const char spinner[] = "|/-\\"; // ".oO@*";
  static size_t i = 0;
  putchar('\b');
  if (run)
  {
    putchar(spinner[i]);
    i = (i + 1) % sizeof(spinner);
  }
  else
  {
    i = 0;  // Reset for next run
  }
}

static void printHex( uint8_t* p, const int len, const bool newline = true )
{
  for (int i = 0; i < len; ++i)
  {
    printf("%02x ", *p++);
  }
  if (newline)
    printf("\n");
}  

static void printProgress( const uint32_t numCaptured, const uint32_t numLost )
{
  printf("\rCaptured %lu packets, Lost %lu packets", numCaptured, numLost);
}
    
void printConfig( const serialConfig& config)
{
  printf("Channel:      %d\n", config.channel);
  printf("Datarate:     %s\n", config.rate == 0 ? "1Mb/s" : config.rate == 1 ? "2Mb/s" : "250Kb/s" );
  printf("Address:      0x");
  uint64_t adr = config.address;
  for (int8_t i = config.addressLen-1; i >= 0; --i)
  {
    if ( i >= config.addressLen - config.addressPromiscLen ) printf("%02x", (uint8_t)(adr >> (8*i)));
    else                                                     printf("**");
  }
  puts("");
  printf("Max payload:  %d\n", config.maxPayloadSize);
  printf("CRC length:   %d\n", config.crcLength);
}

bool serialReadConfig( HANDLE hComm, serialConfig& config )
{
    // Use the ClearCommError function to get status info on the Serial port
    // TODO: Use a timeout and return false when elapsed
    COMSTAT stat;
    uint8_t lenAndType;
    while(1)
    {
      DWORD errors;
      spin( true );
      ClearCommError(hComm, &errors, &stat);
      if (stat.cbInQue >= sizeof(lenAndType) + sizeof(config))
        break;
      Sleep(200 /*ms*/);
    }
    spin( false );

    DWORD numRead;
    bool ok = true;
    ok &= TRUE == ReadFile(hComm, (LPVOID)&lenAndType, sizeof(lenAndType), &numRead, NULL);
    ok &= TRUE == ReadFile(hComm, (LPVOID)&config, sizeof(config), &numRead, NULL);
    ok &= GET_MSG_TYPE(lenAndType) == MSG_TYPE_CONFIG;
    ok &= GET_MSG_LEN(lenAndType) == sizeof(config);
    return ok;
}

bool writeSerialConfig( HANDLE hComm, const serialConfig& config )
{
  DWORD numWritten;
  uint8_t lenAndType = SET_MSG_TYPE( sizeof(config), MSG_TYPE_CONFIG );
  return    WriteFile(hComm, (LPVOID)&lenAndType, sizeof(lenAndType), &numWritten, NULL)
         && WriteFile(hComm, (LPVOID)&config, sizeof(config), &numWritten, NULL);
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
  uint8_t lenAndType;

  /* Parse commandline arguments */
  int c;
  while (!printHelp && ((c = getopt(argc, argv, _T("b:P:c:r:l:p:a:C:m:vh"))) != EOF))
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
      case _T('P'):
        printHelp = !optarg;
        if (optarg)
        {
          comport = strtol(optarg, NULL, 10);
          printHelp = ((comport == 0) && (optarg[0] != '0')) || (errno == ERANGE);
        }
        break;
      case _T('c'):
        printHelp = !optarg;
        if (optarg)
        {
          long ch = strtol(optarg, NULL, 10);
          printHelp = (ch < 0) || (ch > 127) || (errno == ERANGE);
          config.channel = (uint8_t)ch;
        }
        break;
      case _T('r'):
        printHelp = !optarg;
        if (optarg)
        {
          long r = strtol(optarg, NULL, 10);
          printHelp = (r < 0) || (r > 2) || (errno == ERANGE);
          config.rate = (uint8_t)r;
        }
        break;
      case _T('l'):
        printHelp = !optarg;
        if (optarg)
        {
          long l = strtol(optarg, NULL, 10);
          printHelp = (l < 3) || (l > 5) || (errno == ERANGE);
          config.addressLen = (uint8_t)l;
        }
        break;
      case _T('p'):
        printHelp = !optarg;
        if (optarg)
        {
          long l = strtol(optarg, NULL, 10);
          printHelp = (l < 3) || (l > 5) || (errno == ERANGE);
          config.addressPromiscLen = (uint8_t)l;
        }
        break;
      case _T('a'):
        printHelp = !optarg;
        if (optarg)
        {
          config.address = _strtoui64(optarg, NULL, 0); // 0 = text defines bas, e.g. prefix 0x for HEX.
          printHelp = (config.address < 0) || (config.address > 0xFFFFFFFFFFULL) || (errno == ERANGE);
        }
        break;
      case _T('C'):
        printHelp = !optarg;
        if (optarg)
        {
          long l = strtol(optarg, NULL, 10);
          printHelp = (l < 0) || (l > 2) || (errno == ERANGE);
          config.crcLength = (uint8_t)l;
        }
        break;
      case _T('m'):
        printHelp = !optarg;
        if (optarg)
        {
          long s = strtol(optarg, NULL, 10);
          printHelp = (s < 0) || (s > 32) || (errno == ERANGE);
          config.maxPayloadSize = (uint8_t)s;
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
    printf(" -b    Set baudrate. Default -b%d\n", DEFAULT_BAUDRATE);
    printf(" -P    Set comport. Default -P%d (for COM%d)\n", DEFAULT_COMPORT, DEFAULT_COMPORT);
    printf(" -c    RF channel, range [0..127]. Default -c%d\n", DEFAULT_RF_CHANNEL);
    printf(" -r    Data rate, range [0..2], where 0=1Mb/s, 1=2Mb/b, 2=250Kb/s. Default -r%d\n", DEFAULT_RF_DATARATE);
    printf(" -l    Address length in bytes, range [3..5]. Default -l%d\n", DEFAULT_RF_ADDRESS_LEN);
    printf(" -p    Promiscuous address length in bytes, range [3..5]. Default -p%d\n", DEFAULT_RF_ADDRESS_PROMISC_LEN);
    printf(" -a    Base address. Default -a0x%05llx\n", DEFAULT_RF_BASE_ADDRESS);
    printf(" -C    CRC length in bytes, range [0..2]. Default -C%d\n", DEFAULT_RF_CRC_LEN);
    printf(" -m    Maximum payload size in bytes, range [0..32]. Default -m%d\n", DEFAULT_RF_PAYLOAD_LEN);
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

    printf("\nConnect Wireshark to %s to continue...\n", pipeName);
    if (!ConnectNamedPipe(hPipe, NULL))
    {
      printf("Failed to connect to Wireshark pipe: %d\n", GetLastError());
      goto out_pipe;
    }

    assert(sizeof(pcap_hdr) == 24 );
    DWORD numWritten;
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
      puts("Failed to get current serial parameters!");
      goto out_comm;
    }

    // Set serial port parameters.
    dcbSerialParams.BaudRate = baudrate;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity   = NOPARITY;
    if(!SetCommState(hComm, &dcbSerialParams))
    {
      puts("ALERT: Could not set Serial Port parameters");
      goto out_comm;
    }

    // Reset the arduino!
    if (!(    EscapeCommFunction(hComm,CLRDTR) && EscapeCommFunction(hComm,CLRRTS)
           && EscapeCommFunction(hComm,SETDTR) && EscapeCommFunction(hComm,SETRTS) ))
    {
      puts("\nALERT: Failed to reset sniffer");
      goto out_comm;
    }

    // Purge serial buffer
    (void)PurgeComm(hComm, PURGE_RXCLEAR | PURGE_TXCLEAR);

    printf("Wait for sniffer to restart  ");

    // Sniffer will send configuration on startup. Wait for this packet, then
    // send our configuration and start listening for packets.
    serialConfig dummyConfig;
    if (!serialReadConfig(hComm, dummyConfig ))
    {
      puts("\nALERT: Failed waiting for sniffer to restart");
      goto out_comm;
    }

    puts("Ok\n");
    printConfig(config);

    if (!writeSerialConfig( hComm, config ))
    {
      puts("ALERT: Could not send config");
      goto out_comm;
    }
    // Sniffer will respond with new config. Safe to ignore here; it will be handled in regular packet handler.

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
      DWORD numToRead = max(1, min(stat.cbInQue, sizeof(buff)-buffIdx));
        
      // Blocking read on serial port,reading either 1 byte when nothing is available (block),
      // the amount of data available on the port or the amount that still fits in the buffer.
      // This offloads the CPU compared to continuously polling for available data in the port.
      assert(buffIdx < sizeof(buff));
      DWORD numRead;
      if (ReadFile(hComm, (LPVOID)&buff[buffIdx], 1 /* TODO: should be numToRead I think */, &numRead, NULL))
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
        lenAndType = *sp++;
        DWORD lenSerPacket = GET_MSG_LEN(lenAndType);
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
          // 1 byte                       length & type of serial packet, excluding this byte
          // MSG_TYPE_PACKET
          //     TIMESTAMP_LENGTH byte(s)     timestamp of packet, in [us] since start of Arduino (wraps after ca. 70 minutes for 4 bytes)
          //     PACKETS_LOST_LENGTH byte(s)  Nr of packets lost since last packet, stops counting at 255 (for 1 byte).
          //     NRF_ADDRESS_LENGTH byte(s)   full target node address
          //     9bits                        NRF24 control field
          //     [0..32]*8bits                NRF24 payload, not byte aligned!
          //     NRF_CRC_LENGTH byte(s)       NRF24 CRC field, not byte aligned!
          // MSG_TYPE_CONFIG
          //     <ignored>

          switch( GET_MSG_TYPE(lenAndType) )
          {
            case MSG_TYPE_PACKET:
              {
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
              }
              firstPacket = false;
              numCaptured++;
              printProgress(numCaptured, numLost);
              break;

            default:   // Ignore
              break;
          } // switch MSG_TYPE

          // Remove packet from buffer
          (void)memmove(buff, buff+lenInBuff, buffIdx-lenInBuff);             // Memmove! Regions overlap.
          (void)memset(buff+buffIdx, 0, sizeof(buff)-buffIdx);                // Optional: Clear remaining buffer
          buffIdx -= lenInBuff;
//          printf("Consumed %d bytes. New idx %d\n", lenInBuff, buffIdx);
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

