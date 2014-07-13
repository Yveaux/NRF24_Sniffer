/*
  This file is part of NRF24_Sniff.

  Created by Ivo Pullens, Emmission, 2014 -- www.emmission.nl
    
  NRF24_Sniff is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  NRF24_Sniff is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with NRF24_Sniff.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef NRF24_sniff_types_h
#define NRF24_sniff_types_h

typedef struct _NRF24_packet_t
{
  uint32_t timestamp;
  uint8_t  packetsLost;
  uint8_t  packet[RF_PAYLOAD_SIZE];
} NRF24_packet_t;

inline uint8_t getPayloadLen(NRF24_packet_t* p)
{
  return (p->packet[RF_MAX_ADDR_WIDTH-RF_ADDR_WIDTH] & 0xFC) >> 2; 
}

typedef struct _Serial_header_t
{
  uint32_t timestamp;
  uint8_t  packetsLost;
  uint8_t  address[RF_ADDR_WIDTH];    // Lowest RF_MAX_ADDR_WIDTH-RF_ADDR_WIDTH byte(s) come first in data.
} Serial_header_t;

#endif // NRF24_sniff_types_h
