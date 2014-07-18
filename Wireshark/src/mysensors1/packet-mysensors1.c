/* packet-mysensors1.c
 * MySensors wireless network dissector (v1.3, protocol 1)
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
#include <stdint.h>
#include <epan/packet.h>
#include <epan/expert.h>

#define MYSENSORS_ABBREV "mysensors1"

#define MYSENSORS_MSG_HEADER_LENGTH        (7)
#define MYSENSORS_MSG_HEADER_CRC_OFFSET    (0)
#define MYSENSORS_MSG_MAX_LENGTH           (33)   // Bug in MyMessage definition; MyMessage.data[MAX_PAYLOAD+1] makes 32+1 maximum size...
#define MYSENSORS_MSG_MAX_PAYLOAD_LENGTH   (MYSENSORS_MSG_MAX_LENGTH - MYSENSORS_MSG_HEADER_LENGTH)

static dissector_handle_t mysensors_handle;

static int hf_mysensors_crc = -1;        
static int hf_mysensors_crc_valid = -1;
static int hf_mysensors_version = -1;    
static int hf_mysensors_binary = -1;     
static int hf_mysensors_sender = -1;     
static int hf_mysensors_dest = -1;       
static int hf_mysensors_last = -1;       
static int hf_mysensors_sensor = -1;     
static int hf_mysensors_commandtype = -1;
static int hf_mysensors_type = -1;       

static int ett_mysensors       = -1;
static gint proto_mysensors    = -1;
const guint encoding = ENC_LITTLE_ENDIAN;

static dissector_handle_t data_handle;

typedef enum {
  V1_13 = 1,
  V2_14 = 2,
} MySensors_Version;

static const value_string version_types[] = {
  { V1_13, "v1.3" },
  { V2_14, "v1.4" },
  { 0, NULL }
};

typedef enum {
  C_PRESENTATION = 0,
  C_SET = 1,
  C_REQ = 2,
  C_ACK = 3,
  C_INTERNAL = 4
} MySensors_Command;

static const value_string command_types[] = {
  { C_PRESENTATION, "PRESENTATION" },
  { C_SET,          "SET" },
  { C_REQ,          "REQ" },
  { C_ACK,          "ACK" },
  { C_INTERNAL,     "INTERNAL" },
  { 0, NULL }
};

/* Variable types, used for messages of type C_SET, C_REQ or C_ACK */
static const value_string data_types[] = {
  { 0,  "TEMP" },
  { 1,  "HUM" },
  { 2,  "LIGHT" },
  { 3,  "DIMMER" },
  { 4,  "PRESSURE" },
  { 5,  "FORECAST" },
  { 6,  "RAIN" },
  { 7,  "RAINRATE" },
  { 8,  "WIND" },
  { 9,  "GUST" },
  { 10, "DIRECTION" },
  { 11, "UV" },
  { 12, "WEIGHT" },
  { 13, "DISTANCE" },
  { 14, "IMPEDANCE" },
  { 15, "ARMED" },
  { 16, "TRIPPED" },
  { 17, "WATT" },
  { 18, "KWH" },
  { 19, "SCENE_ON" },
  { 20, "SCENE_OFF" },
  { 21, "HEATER" },
  { 22, "HEATER_SW" },
  { 23, "LIGHT_LEVEL" },
  { 24, "VAR1" },
  { 25, "VAR2" },
  { 26, "VAR3" },
  { 27, "VAR4" },
  { 28, "VAR5" },
  { 29, "UP" },
  { 30, "DOWN" },
  { 31, "STOP" },
  { 32, "IR_SEND" },
  { 33, "IR_RECEIVE" },
  { 34, "FLOW" },
  { 35, "VOLUME" },
  { 36, "LOCK_STATUS" },
  { 0, NULL }
};

/* Internal types, used for messages of type C_INTERNAL */
static const value_string internal_types[] = {
  { 0,  "BATTERY_LEVEL" },
  { 1,  "BATTERY_DATE" },
  { 2,  "LAST_TRIP" },
  { 3,  "TIME" },
  { 4,  "VERSION" },
  { 5,  "REQUEST_ID" },
  { 6,  "INCLUSION_MODE" },
  { 7,  "RELAY_NODE" },
  { 8,  "LAST_UPDATE" },
  { 9,  "PING" },
  { 10, "PING_ACK" },
  { 11, "LOG_MESSAGE" },
  { 12, "CHILDREN" },
  { 13, "UNIT" },
  { 14, "SKETCH_NAME" },
  { 15, "SKETCH_VERSION" },
  { 0, NULL }
};

/* Sensor types, used for messages of type C_PRESENTATION */
static const value_string sensor_types[] = {
  { 0,  "DOOR" },
  { 1,  "MOTION" },
  { 2,  "SMOKE" },
  { 3,  "LIGHT" },
  { 4,  "DIMMER" },
  { 5,  "COVER" },
  { 6,  "TEMP" },
  { 7,  "HUM" },
  { 8,  "BARO" },
  { 9,  "WIND" },
  { 10, "RAIN" },
  { 11, "UV" },
  { 12, "WEIGHT" },
  { 13, "POWER" },
  { 14, "HEATER" },
  { 15, "DISTANCE" },
  { 16, "LIGHT_LEVEL" },
  { 17, "ARDUINO_NODE" },
  { 18, "ARDUINO_RELAY" },
  { 19, "LOCK" },
  { 20, "IR" },
  { 21, "WATER" },
  { 0, NULL }
};

static uint8_t crc8Message(tvbuff_t* tvb)
{
  uint8_t crc = 0x00;
  uint8_t loop_count;
  uint8_t bit_counter;
  uint8_t feedback_bit;
  uint8_t len = min(tvb_length(tvb), MYSENSORS_MSG_MAX_LENGTH);
  uint8_t message[MYSENSORS_MSG_MAX_LENGTH] = {0, };
  uint8_t *mp = message;
  // Pull a copy to work with
  (void)tvb_memcpy(tvb, &message, 0, len);

  // Must set crc to a constant value.
  message[MYSENSORS_MSG_HEADER_CRC_OFFSET] = 0;

  for (loop_count = 0; loop_count != sizeof(message); ++loop_count)
  {
    uint8_t data;
    data = *mp++;

    bit_counter = 8;
    do {
      feedback_bit = (crc ^ data) & 0x01;
      if ( feedback_bit == 0x01 )
      {
        crc = crc ^ 0x18;              //0X18 = X^8+X^5+X^4+X^0
      }
      crc = (crc >> 1) & 0x7F;
      if ( feedback_bit == 0x01 )
      {
        crc = crc | 0x80;
      }

      data = data >> 1;
      bit_counter--;
    } while (bit_counter > 0);
  }
  return crc;
}

static const gchar* typeToStr( MySensors_Command commandType, guint8 type )
{
  switch (commandType)
  {
    case C_PRESENTATION:
      return val_to_str(type, sensor_types, "%d"); 
    case C_SET:
    case C_REQ:
    case C_ACK:
      return val_to_str(type, data_types, "%d"); 
    case C_INTERNAL:
      return val_to_str(type, internal_types, "%d"); 
  }
  return "?";
}

static inline gchar toHexChar(guint8 v)
{
  v &= 0x0F;
  if (v < 10)
    return '0'+v;
    
  v -= 10;
  return 'A'+v;
}

static gchar* buildColInfo( packet_info *pinfo, guint8 payloadLen, gboolean binary, MySensors_Command commandType,
                            guint8 type, guint8 sensor, tvbuff_t* tvb_data )
{
  static gchar buff[100];
  gchar* s = buff;
  s += sprintf( s, "Msg:%s, Type:%s, ChildId:%d",
                 val_to_str(commandType, command_types, "%d"),
                 typeToStr(commandType, type),
                 sensor
               );
  if ((payloadLen > 0) && (payloadLen <= MYSENSORS_MSG_MAX_PAYLOAD_LENGTH))
  {
    if (binary)
    {
      static gchar hexbuff[MYSENSORS_MSG_MAX_PAYLOAD_LENGTH*3+1];
      gchar* p = hexbuff;
      guint8 i;
      for (i = 0; i < payloadLen; ++i)
      {
        guint8 v = tvb_get_guint8(tvb_data, i);
        *p++ = toHexChar(v >> 4);
        *p++ = toHexChar(v);
        *p++ = ' '; 
      }
      *(p-1) = 0;
      
      s += sprintf( s, ", Data:0x%s", hexbuff );
    }
    else
    {
      s += sprintf( s, ", Data:'%s'", tvb_format_text_wsp(tvb_data, 0, payloadLen) );
    }
  }
  return buff;
}

// Get a byte from a bit offset, where high nibble is at offset+12 and low nibble is at offset 0.
// E.g. btes 0xA0 02 == l. .h => 0x2A
#define TVB_GET_BYTE_SWAPPED(tvb,bitoffset,var)          \
{                                                        \
  guint16 v = tvb_get_bits16(tvb,bitoffset,16,encoding); \
  var = (guint8)((v << 4) | (v >> 12));                  \
}

// content format
static void dissect_mysensors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  // your variable definitions go here
  int bitoffset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "mysensors");
  
  // Clear out stuff in the info column
  col_clear(pinfo->cinfo,COL_INFO);
  if (tree)
  {
    // in case that someone wants to know some details of our protocol
    // spawn a subtree and cut the sequence in readable parts
    proto_item *pi = NULL;
    proto_item *ti = NULL;
    proto_tree *mysensors_tree = NULL;
    tvbuff_t* tvb_next;
    guint8 payload_crc, calc_crc, type, sender, last, dest, childid;
    MySensors_Command commandType;
    gboolean crc_ok, binary;
    gchar* info;
    guint8 payloadLen;
    
    ti = proto_tree_add_item(tree, proto_mysensors, tvb, 0 /*start*/, -1 /*to end*/, ENC_NA);
    mysensors_tree = proto_item_add_subtree(ti, ett_mysensors);

    /* --- HEADER FORMAT ---
      7 bytes:
      00 01 02 03 04 05 06 
      Aa Bb Cc Dd Ee Ff Gg
       
      Aa = CRC
      b  = binary << 3 | version
      cB = from
      dC = to
      eD = last
      fE = childId
      F  = messageType
      Gg = type
    */

    /* CRC - Calculate and compare to CRC in header*/
    calc_crc = crc8Message(tvb);

    proto_tree_add_item(mysensors_tree, hf_mysensors_crc, tvb, bitoffset>>3, 1, encoding);
    payload_crc = tvb_get_guint8(tvb, bitoffset>>3);
    crc_ok = calc_crc == payload_crc;
    pi = proto_tree_add_boolean(mysensors_tree, hf_mysensors_crc_valid, tvb, bitoffset>>3, 8, crc_ok);
    PROTO_ITEM_SET_GENERATED(pi);
    if (!crc_ok)
    {
      // Color the CRC when invalid.
      expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_WARN, "Calculated CRC 0x%02x, payload CRC 0x%02x", calc_crc, payload_crc);
    }
    bitoffset += 8;    

    /* Binary */
    proto_tree_add_bits_item(mysensors_tree, hf_mysensors_binary, tvb, bitoffset+4, 1, encoding);
    binary = tvb_get_bits8(tvb, bitoffset+4, 1);

    /* Version */
    proto_tree_add_bits_item(mysensors_tree, hf_mysensors_version, tvb, bitoffset+5, 3, encoding);

    /* From (sender) */
    TVB_GET_BYTE_SWAPPED(tvb, bitoffset, sender);
    proto_tree_add_uint(mysensors_tree, hf_mysensors_sender, tvb, bitoffset>>3, 2, sender);
    bitoffset += 8;

    /* To (dest) */
    TVB_GET_BYTE_SWAPPED(tvb, bitoffset, dest);
    proto_tree_add_uint(mysensors_tree, hf_mysensors_dest, tvb, bitoffset>>3, 2, dest);
    bitoffset += 8;

    /* Last (dest) */
    TVB_GET_BYTE_SWAPPED(tvb, bitoffset, last);
    proto_tree_add_uint(mysensors_tree, hf_mysensors_last, tvb, bitoffset>>3, 2, last);
    bitoffset += 8;

    /* ChildId */
    TVB_GET_BYTE_SWAPPED(tvb, bitoffset, childid);
    proto_tree_add_uint(mysensors_tree, hf_mysensors_sensor, tvb, bitoffset>>3, 2, childid);
    bitoffset += 8;

    /* MessageType (commandType) */
    proto_tree_add_bits_item(mysensors_tree, hf_mysensors_commandtype, tvb, bitoffset, 4, encoding);
    commandType = (MySensors_Command)tvb_get_bits8(tvb, bitoffset, 4);
    bitoffset += 8;

    /* Type */
    type = tvb_get_guint8(tvb, bitoffset>>3);
    proto_tree_add_uint_format_value(mysensors_tree, hf_mysensors_type, tvb, bitoffset>>3, 1, type, "%s (%d)", typeToStr(commandType, type), (guint8)type);
    bitoffset += 8;

    // Create tvb for the payload.
    payloadLen = tvb_length(tvb) - (bitoffset>>3);
    tvb_next = tvb_new_subset(tvb, bitoffset>>3, payloadLen, payloadLen);

    info = buildColInfo( pinfo, payloadLen, binary, commandType, type, childid, tvb_next );
    col_add_str(pinfo->cinfo, COL_INFO, info);
    proto_item_append_text(ti, " - %s", info);
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%d", sender);
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%d", dest);

    // Pass payload to generic data dissector
    call_dissector(data_handle, tvb_next, pinfo, mysensors_tree);
  }
}

static gboolean dissect_mysensors_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  guint8 version;

  /* 0) Test minimum packet length */
  if (tvb_length(tvb) < MYSENSORS_MSG_HEADER_LENGTH)
    return FALSE;

  /* 1) Test protocol verion -- only version 1 (1.3) currently supported */
  version = tvb_get_bits8(tvb, 13, 3);
  if (version != V1_13)
    return FALSE;

  dissect_mysensors(tvb, pinfo, tree);
    
  return TRUE;
}

void proto_register_mysensors(void)
{
    static hf_register_info hf[] = {
        { &hf_mysensors_crc,            { "CRC", MYSENSORS_ABBREV ".crc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_crc_valid,      { "CRC Valid", MYSENSORS_ABBREV ".crcvalid", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_version,        { "Version", MYSENSORS_ABBREV ".version", FT_UINT8, BASE_DEC, VALS(version_types), 0x0, NULL, HFILL } },
        { &hf_mysensors_binary,         { "Binary", MYSENSORS_ABBREV ".binary", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_sender,         { "Sender node", MYSENSORS_ABBREV ".sender", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_dest,           { "Destination node", MYSENSORS_ABBREV ".dest", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_last,           { "Last node", MYSENSORS_ABBREV ".last", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_sensor,         { "ChildID", MYSENSORS_ABBREV ".childid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_commandtype,    { "Message type", MYSENSORS_ABBREV ".msgtype", FT_UINT8, BASE_DEC, VALS(command_types), 0x0, NULL, HFILL } },
        { &hf_mysensors_type,           { "Sub type", MYSENSORS_ABBREV ".subtype", FT_UINT8, BASE_DEC, NULL /*representation differs with command*/, 0x0, NULL, HFILL } },
      };
    static int *ett[] = {
        &ett_mysensors    // subtree nrf24mysensors
    };
 
    proto_mysensors = proto_register_protocol (
        "MySensors1",      // name
        "mysensors1",      // short name
        MYSENSORS_ABBREV       // abbrev
        );
    register_dissector(MYSENSORS_ABBREV, dissect_mysensors, proto_mysensors);
 
    proto_register_field_array(proto_mysensors, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
 }
    
/* Register Protocol handler */
void proto_reg_handoff_mysensors(void)
{
  mysensors_handle = create_dissector_handle(dissect_mysensors, proto_mysensors);
  heur_dissector_add("nrf24" /*parent protocol*/, dissect_mysensors_heur, proto_mysensors);
  data_handle = find_dissector("data");
}
