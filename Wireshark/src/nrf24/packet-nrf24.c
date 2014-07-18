/* packet-nrf24.c
 * Nordic Semi. NRF24L01+ dissector for Enhanced Shockburst mode. 
 * 
 * Copyright (c) 2014, Ivo Pullens <info@emmission.nl>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <epan/packet.h>
#include <epan/expert.h>

#define BITS_TO_BYTES(x)  (((x)+7)>>3)
#define BYTES_TO_BITS(x)  ((x)<<3)

//#define BYTE_ALIGN_PCAP

#define MYSENSORS_MIN_PAYLOAD_LEN  (8)

#define NRF24_ADDRESS_LENGTH            (5)
#define NRF24_CONTROLFIELD_PAYLOAD_LENGTH_LENGTH_BITS  (6)
#define NRF24_CONTROLFIELD_PID_LENGTH_LENGTH_BITS      (2)
#define NRF24_CONTROLFIELD_NOACK_LENGTH_LENGTH_BITS    (1)
#define NRF24_CONTROLFIELD_LENGTH_BITS  (NRF24_CONTROLFIELD_PAYLOAD_LENGTH_LENGTH_BITS+NRF24_CONTROLFIELD_PID_LENGTH_LENGTH_BITS+NRF24_CONTROLFIELD_NOACK_LENGTH_LENGTH_BITS)
#define NRF24_CRC_LENGTH                (2)

#ifdef BYTE_ALIGN_PCAP
#define NRF24_CONTROLFIELD_SHIFT (7)
#else
#define NRF24_CONTROLFIELD_SHIFT (0)
#endif
#define NRF24_OFFSET_CONTROLFIELD_BITS (BYTES_TO_BITS(NRF24_ADDRESS_LENGTH)+NRF24_CONTROLFIELD_SHIFT)

#define NRF24_PAYLOADLENGTH_MASK ((((guint16)1)<<NRF24_CONTROLFIELD_PAYLOAD_LENGTH_LENGTH_BITS)-1)
#define NRF24_PID_MASK           ((((guint16)1)<<NRF24_CONTROLFIELD_PID_LENGTH_LENGTH_BITS)-1)
#define NRF24_NOACK_MASK         ((((guint16)1)<<NRF24_CONTROLFIELD_NOACK_LENGTH_LENGTH_BITS)-1)

#if NRF24_ADDRESS_LENGTH == 1
#define FT_NRF24_ADDRESS    FT_UINT8
#else
#if NRF24_ADDRESS_LENGTH == 2
#define FT_NRF24_ADDRESS    FT_UINT16
#else
#if NRF24_ADDRESS_LENGTH <= 4
#define FT_NRF24_ADDRESS    FT_UINT32
#else
#if NRF24_ADDRESS_LENGTH <= 8
#define FT_NRF24_ADDRESS    FT_UINT64
#else
#error "Unsupported NRF24 address length"
#endif
#endif
#endif
#endif

#if NRF24_CRC_LENGTH == 0
#undef FT_CRC_ADDRESS
#else
#if NRF24_CRC_LENGTH == 1
#define FT_CRC_ADDRESS    FT_UINT8
#else
#if NRF24_CRC_LENGTH == 2
#define FT_CRC_ADDRESS    FT_UINT16
#else
#error "Unsupported NRF24 crc length"
#endif
#endif
#endif

static heur_dissector_list_t heur_subdissector_list;

static int hf_nrf24_nodeaddress           = -1;
static int hf_nrf24_control               = -1;
static int hf_nrf24_control_payloadlength = -1;
static int hf_nrf24_control_pid           = -1;
static int hf_nrf24_control_noack         = -1;
static int hf_nrf24_crc                   = -1;
static int hf_nrf24_crc_valid             = -1;

static const int *control_fields[] = {
    &hf_nrf24_control_payloadlength,
    &hf_nrf24_control_pid,
    &hf_nrf24_control_noack,
    NULL
};
    
static int ett_nrf24              = -1;
static int ett_nrf24_control      = -1;
static gint proto_nrf24           = -1;
const guint encoding = ENC_LITTLE_ENDIAN;

static dissector_handle_t data_handle;


static const value_string noack_types[] = {
  { 0, "ACK" },
  { 1, "NO_ACK" },
  { 0, NULL }
};


#ifndef BYTE_ALIGN_PCAP
/* NRF24L01+ Product Spec:
      The CRC is the mandatory error detection mechanism in the packet. It is either 1 or 2 bytes and is calculated
      over the address, Packet Control Field and Payload.
      The polynomial for 1 byte CRC is X^8 + X^2 + X + 1. Initial value 0xFF.
      The polynomial for 2 byte CRC is X^16+ X^12 + X^5 + 1. Initial value 0xFFFF.  (==> equals CRC-16-CCITT polynomial)
*/
guint16 crc16(tvbuff_t *tvb, const guint16 len_bits)
{
  guint16 crc = 0xffff;
  if ((len_bits > 0) && (len_bits <= BYTES_TO_BITS(tvb_length(tvb))))
  {
    // The length of the data might not be a multiple of full bytes.
    // Therefore we proceed over the data bit-by-bit (like the NRF24 does) to
    // calculate the CRC.
    guint16 data;
    guint8 byte, shift;
    guint16 bitoffs = 0;

    // Get a new byte for the next 8 bits.
    byte = tvb_get_guint8(tvb, bitoffs>>3);
    while (bitoffs < len_bits)
    {
      shift = bitoffs & 7;
      // Shift the active bit to the position of bit 15 
      data = ((guint16)byte) << (8 + shift);
      // Assure all other bits are 0
      data &= 0x8000;
      crc ^= data;
      if (crc & 0x8000)
      {
        crc = (crc << 1) ^ 0x1021;      // 0x1021 = (1) 0001 0000 0010 0001 = x^16+x^12+x^5+1
      }
      else
      {
        crc = (crc << 1);
      }
      ++bitoffs;
      if (0 == (bitoffs & 7))
      {
        // Get a new byte for the next 8 bits.
        byte = tvb_get_guint8(tvb, bitoffs>>3);
      }
    }
  }
  return crc;
}
#else
#error CRC calculation not yet implemented/tested for byte aligned data...
/* For byte aligned data we could simply pass the start-bit and nr of bits and the generated CRC so far for each
   string of bits. Then just continue calculation for each partial string to get the final CRC */
#endif


static gchar* buildColInfo( packet_info *pinfo, guint64 nodeAddress, guint8 payloadLen, guint8 pid, gboolean noAck)
{
  static gchar buff[100];
  char *b = buff;
  guint8 i;
  
  b += sprintf(b, "Adr:0x");
  for (i = 0; i < NRF24_ADDRESS_LENGTH; ++i)
  {
    b += sprintf(b, "%02x", (guint8)(nodeAddress >> BYTES_TO_BITS(NRF24_ADDRESS_LENGTH-i-1)));
  }
  b += sprintf(b, ", Len:%d%s, Pid:%d, %s", payloadLen, payloadLen == 0 ? "(ack)" : "", pid, noAck ? "NoAck" : "Ack");
  return buff;
}

// content format
static void dissect_nrf24(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  // your variable definitions go here
  int bitoffset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "nrf24");
  col_add_fstr(pinfo->cinfo, COL_PACKET_LENGTH, "%d", tvb_length(tvb) );
  
  // Clear out stuff in the info column
  col_clear(pinfo->cinfo, COL_INFO);
  if (tree)
  {
    // in case that someone wants to know some details of our protocol
    // spawn a subtree and cut the sequence in readable parts
    proto_item *ti = NULL;
    proto_item *pi = NULL;
    proto_tree *nrf24_tree = NULL;
    gboolean crc_ok;
    guint64 nodeAddress;
    guint16 packetLenBits, calc_crc, packet_crc, controlField;
    guint8 payloadLen, pid, noAck;
    
    // Get control field (in lower NRF24_CONTROLFIELD_LENGTH_BITS bits) & extract payload length, pid & noack
    controlField = tvb_get_bits16(tvb, NRF24_OFFSET_CONTROLFIELD_BITS, NRF24_CONTROLFIELD_LENGTH_BITS, ENC_BIG_ENDIAN);
    payloadLen = (controlField >> (NRF24_CONTROLFIELD_PID_LENGTH_LENGTH_BITS+NRF24_CONTROLFIELD_NOACK_LENGTH_LENGTH_BITS))& NRF24_PAYLOADLENGTH_MASK;
    pid        = (controlField >> NRF24_CONTROLFIELD_NOACK_LENGTH_LENGTH_BITS) & NRF24_PID_MASK;
    noAck      = controlField & NRF24_NOACK_MASK;
    
    packetLenBits =  BYTES_TO_BITS(NRF24_ADDRESS_LENGTH)
                    +NRF24_CONTROLFIELD_LENGTH_BITS
                    +BYTES_TO_BITS(payloadLen)
                    +BYTES_TO_BITS(NRF24_CRC_LENGTH);

    ti = proto_tree_add_item(tree, proto_nrf24, tvb, 0 /*start*/, BITS_TO_BYTES(packetLenBits) /*end*/, ENC_NA);
    calc_crc = crc16(tvb, packetLenBits - BYTES_TO_BITS(NRF24_CRC_LENGTH));

    nrf24_tree = proto_item_add_subtree(ti, ett_nrf24);

    proto_tree_add_item(nrf24_tree, hf_nrf24_nodeaddress, tvb, BITS_TO_BYTES(bitoffset), NRF24_ADDRESS_LENGTH, ENC_NA);
    nodeAddress = tvb_get_ntoh64(tvb, 0);
    nodeAddress >>= BYTES_TO_BITS(sizeof(guint64)-NRF24_ADDRESS_LENGTH);
    bitoffset += BYTES_TO_BITS(NRF24_ADDRESS_LENGTH);

    proto_tree_add_bitmask(nrf24_tree, tvb, BITS_TO_BYTES(bitoffset), hf_nrf24_control, ett_nrf24_control, control_fields, ENC_BIG_ENDIAN);
    bitoffset += NRF24_CONTROLFIELD_LENGTH_BITS;
    
#ifdef FT_CRC_ADDRESS
    // CRC is located in last bits of packet
#ifdef BYTE_ALIGN_PCAP
    proto_tree_add_item(nrf24_tree, hf_nrf24_crc, tvb, BITS_TO_BYTES(bitoffset)+payloadLen, NRF24_CRC_LENGTH, ENC_NA);
#else
    proto_tree_add_bits_item(nrf24_tree, hf_nrf24_crc, tvb, bitoffset+BYTES_TO_BITS(payloadLen), BYTES_TO_BITS(NRF24_CRC_LENGTH), ENC_NA);
    packet_crc = tvb_get_bits16(tvb, bitoffset+BYTES_TO_BITS(payloadLen), BYTES_TO_BITS(NRF24_CRC_LENGTH), ENC_BIG_ENDIAN);
    crc_ok = calc_crc == packet_crc;
    pi = proto_tree_add_boolean(nrf24_tree, hf_nrf24_crc_valid, tvb, BITS_TO_BYTES(bitoffset), 8, crc_ok);
    PROTO_ITEM_SET_GENERATED(pi);
    if (!crc_ok)
    {
      // Color the CRC when invalid.
      expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_WARN, "Calculated CRC 0x%02x, packet CRC 0x%02x", calc_crc, packet_crc);
    }
//    proto_tree_add_debug_text(tree, "CRC packet=0x%04x, calculated=0x%04x", packet_crc, calc_crc);  
#endif
#endif
    if (crc_ok)
    {
      gchar* info = buildColInfo( pinfo, nodeAddress, payloadLen, pid, noAck != 0);
      col_add_str(pinfo->cinfo, COL_INFO, info );
      proto_item_append_text(ti, " - %s", info);
      col_add_str(pinfo->cinfo, COL_DEF_SRC, "?");
      col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%d", (guint8)nodeAddress);
    }
    else
    {
      col_add_str(pinfo->cinfo, COL_INFO, "CRC Error");
    }

    if (payloadLen > 0)
    {
      tvbuff_t* tvb_next;
#ifdef BYTE_ALIGN_PCAP
      tvb_next = tvb_new_subset(tvb, BITS_TO_BYTES(bitoffset), payloadLen, payloadLen);
#else
      tvb_next = tvb_new_octet_aligned(tvb, bitoffset, BYTES_TO_BITS(payloadLen));
#endif
//      proto_tree_add_debug_text(tree, "Payload offset=%d, len=%d", bitoffset, payloadLen<<3);  

      add_new_data_source(pinfo, tvb_next, "NRF24 Payload Data");
      // The NRF24 header contains no indication of the payload type. Therefore we
      // pass it on to a list of heuristic dissectors for NRF24 payloads, or display
      // it as data when none found.
      if (!crc_ok || !dissector_try_heuristic(heur_subdissector_list, tvb_next, pinfo, tree, NULL))
      {
        call_dissector(data_handle, tvb_next, pinfo, tree);
      }
    }
  }
}

#define PAYLOADLENGTH_MASK  (NRF24_PAYLOADLENGTH_MASK << (16-NRF24_CONTROLFIELD_SHIFT-NRF24_CONTROLFIELD_PAYLOAD_LENGTH_LENGTH_BITS))
#define PID_MASK            (NRF24_PID_MASK << (16-NRF24_CONTROLFIELD_SHIFT-NRF24_CONTROLFIELD_PAYLOAD_LENGTH_LENGTH_BITS-NRF24_CONTROLFIELD_PID_LENGTH_LENGTH_BITS))
#define NOACK_MASK          (NRF24_NOACK_MASK <<(16-NRF24_CONTROLFIELD_SHIFT-NRF24_CONTROLFIELD_PAYLOAD_LENGTH_LENGTH_BITS-NRF24_CONTROLFIELD_PID_LENGTH_LENGTH_BITS-NRF24_CONTROLFIELD_NOACK_LENGTH_LENGTH_BITS))

void proto_register_nrf24(void)
{
/*
  NRF24L01
  8bit        address
  7bit        fill
  9bit        packet control
        6bit  payload length
        2bit  PID
        1bite NO_ACK
  0..32bytes  Payload
  1-2bytes    CRC
*/
    static hf_register_info hf[] = {
        { &hf_nrf24_nodeaddress,            { "Node address",   "nrf24.node",       FT_NRF24_ADDRESS, BASE_HEX,  NULL, 0x0, NULL, HFILL } },
        { &hf_nrf24_control,                { "Control field",  "nrf24.ctrl",       FT_UINT16,        BASE_HEX,  NULL, 0x0, NULL, HFILL } },
        { &hf_nrf24_control_payloadlength,  { "Payload length", "nrf24.ctrl.len",   FT_UINT16,        BASE_DEC,  NULL,              PAYLOADLENGTH_MASK, NULL, HFILL } },
        { &hf_nrf24_control_pid,            { "PID",            "nrf24.ctrl.pid",   FT_UINT16,        BASE_DEC,  NULL,              PID_MASK, NULL, HFILL } },
        { &hf_nrf24_control_noack,          { "No ack",         "nrf24.ctrl.noack", FT_UINT16,        BASE_DEC,  VALS(noack_types), NOACK_MASK, NULL, HFILL } },
#ifdef FT_CRC_ADDRESS
        { &hf_nrf24_crc,                    { "CRC",            "nrf24.crc",        FT_CRC_ADDRESS,   BASE_HEX,  NULL, 0x0, NULL, HFILL } },
        { &hf_nrf24_crc_valid,              { "CRC Valid",      "nrf24.crcvalid",   FT_BOOLEAN,       BASE_NONE, NULL, 0x0, NULL, HFILL } },
#endif
      };
    static int *ett[] = {
        &ett_nrf24,           // subtree nrf24mysns
        &ett_nrf24_control    // subtree nrf24mysns control field
    };
 
    proto_nrf24 = proto_register_protocol (
        "NRF24",        // name
        "nrf24",             // short name
        "nrf24"              // abb ref
        );
    register_dissector("nrf24", dissect_nrf24, proto_nrf24);


    register_heur_dissector_list("nrf24", &heur_subdissector_list);

    proto_register_field_array(proto_nrf24, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
 }
    
/* Register Protocol handler */
void proto_reg_handoff_nrf24(void)
{
  static dissector_handle_t nrf24_handle;

  nrf24_handle = create_dissector_handle(dissect_nrf24, proto_nrf24);
  data_handle = find_dissector("data");
}
