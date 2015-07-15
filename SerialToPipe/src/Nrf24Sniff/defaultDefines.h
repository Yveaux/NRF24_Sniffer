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

#ifndef DEFAULTDEFINES_H
#define	DEFAULTDEFINES_H

#define DEFAULT_BAUDRATE                (115200)
#define DEFAULT_RF_CHANNEL              (76)
#define DEFAULT_RF_DATARATE             (0)
#define DEFAULT_RF_ADDRESS_LEN          (5)
#define DEFAULT_RF_ADDRESS_PROMISC_LEN  (4)
#define DEFAULT_RF_BASE_ADDRESS         ((uint64_t)0xA8A8E1FC00ULL)
#define DEFAULT_RF_CRC_LEN              (2)
#define DEFAULT_RF_PAYLOAD_LEN          (32)

//Precompiler can only compare numbers... WINDOWS=0 LINUX=1
#if OS == 0
#define DEFAULT_PIPENAME                "\\\\.\\pipe\\wireshark"
#define DEFAULT_COMPORT                 "0"
#elif OS == 1
#define DEFAULT_PIPENAME                "/tmp/wireshark"
#define DEFAULT_COMPORT                 "/dev/ttyUSB0"
#endif

#endif	/* DEFAULTDEFINES_H */

