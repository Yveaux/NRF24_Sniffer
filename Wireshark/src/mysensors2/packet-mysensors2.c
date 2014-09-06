/* packet-mysensors2.c
 * MySensors wireless network dissector (v1.4, protocol 2)
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

#define MYSENSORS_MSG_HEADER_LENGTH        (7)

static dissector_handle_t mysensors_handle;

static int hf_mysensors_version = -1;    
static int hf_mysensors_length = -1;     
static int hf_mysensors_commandtype = -1;
static int hf_mysensors_isack = -1;
static int hf_mysensors_reqack = -1;
static int hf_mysensors_datatype = -1;   
static int hf_mysensors_type = -1;       
static int hf_mysensors_sensor = -1;     
static int hf_mysensors_sender = -1;     
static int hf_mysensors_last = -1;       
static int hf_mysensors_dest = -1;       

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
  C_INTERNAL = 3,
  C_STREAM = 4
} MySensors_Command;

static const value_string command_types[] = {
  { C_PRESENTATION, "PRESENTATION" },
  { C_SET,          "SET" },
  { C_REQ,          "REQ" },
  { C_INTERNAL,     "INTERNAL" },
  { C_STREAM,       "STREAM" },
  { 0, NULL }
};

typedef enum {
  P_STRING = 0,
  P_BYTE,
  P_INT16,
  P_UINT16,
  P_LONG32,
  P_ULONG32,
  P_CUSTOM,
  P_FLOAT32,
} MySensors_PayloadType;

static const value_string payload_types[] = {
  { 0, "STRING" },
  { 1, "BYTE" },
  { 2, "INT16" },
  { 3, "UINT16" },
  { 4, "LONG32" },
  { 5, "ULONG32" },
  { 6, "CUSTOM" },
  { 7, "FLOAT32" },
  { 0, NULL }
};

/* Variable types, used for messages of type C_SET, C_REQ or C_SET_WITH_ACK */
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
  { 37, "DUST_LEVEL" },
  { 38, "VOLTAGE" },
  { 39, "CURRENT" },
  { 0, NULL }
};

/* Internal types, used for messages of type C_INTERNAL */
static const value_string internal_types[] = {
  { 0,  "BATTERY_LEVEL" },
  { 1,  "TIME" },
  { 2,  "VERSION" },
  { 3,  "ID_REQUEST" },
  { 4,  "ID_RESPONSE" },
  { 5,  "INCLUSION_MODE" },
  { 6,  "CONFIG" },
  { 7,  "FIND_PARENT" },
  { 8,  "FIND_PARENT_RESPONSE" },
  { 9,  "LOG_MESSAGE" },
  { 10, "CHILDREN" },
  { 11, "SKETCH_NAME" },
  { 12, "SKETCH_VERSION" },
  { 13, "REBOOT" },
  { 14, "GATEWAY_READY" },
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
  { 22, "AIR_QUALITY" },
  { 23, "CUSTOM" },
  { 24, "DUST" },
  { 25, "SCENE_CONTROLLER" },
  { 0, NULL }
};

/* Stream types, used for messages of type C_STREAM */
static const value_string stream_types[] = {
  { 0,  "FIRMWARE_CONFIG_REQUEST" },
  { 1,  "FIRMWARE_CONFIG_RESPONSE" },
  { 2,  "FIRMWARE_REQUEST" },
  { 3,  "FIRMWARE_RESPONSE" },
  { 4,  "SOUND" },
  { 5,  "IMAGE" },
  { 0, NULL }
};

static const value_string ack_types[] = {
  { 0, "NoAck" },
  { 1, "Ack" },
  { 0, NULL }
};

static const gchar* typeToStr( MySensors_Command commandType, guint8 type )
{
  switch (commandType)
  {
    case C_PRESENTATION:
      return val_to_str(type, sensor_types, "%d"); 
    case C_SET:
    case C_REQ:
      return val_to_str(type, data_types, "%d"); 
    case C_INTERNAL:
      return val_to_str(type, internal_types, "%d"); 
    case C_STREAM:
      return val_to_str(type, stream_types, "%d"); 
  }
  return "?";
}

static const gchar* payloadToStr( guint8 dataType, tvbuff_t* tvb_data, guint8 payloadLen )
{
  static gchar buff[100];
  switch(dataType)
  {
    case P_STRING:
      (void)sprintf(buff, "'%s'", tvb_format_text_wsp(tvb_data, 0, payloadLen));
      break;
    case P_BYTE:
      (void)sprintf(buff, "%u", tvb_get_guint8(tvb_data, 0));
      break;
    case P_INT16:
      (void)sprintf(buff, "%i", tvb_get_letohs(tvb_data, 0));
      break;
    case P_UINT16:
      (void)sprintf(buff, "%u", tvb_get_letohs(tvb_data, 0));
      break;
    case P_LONG32:
      (void)sprintf(buff, "%li", tvb_get_letohl(tvb_data, 0));
      break;
    case P_ULONG32:
      (void)sprintf(buff, "%lu", tvb_get_letohl(tvb_data, 0));
      break;
    case P_FLOAT32:
      (void)sprintf(buff, "%f", (float)tvb_get_letohl(tvb_data, 0));
      break;
    case P_CUSTOM:
    default:
      (void)sprintf(buff, "?");
      break;
  }
  return buff;
} 

static gchar* buildColInfo( packet_info *pinfo, guint8 payloadLen, guint8 dataType, MySensors_Command commandType,
                            guint8 reqack, guint8 isack, guint8 type, guint8 sensor, tvbuff_t* tvb_data )
{
  static gchar buff[100];
  gchar* s = buff;
  s += sprintf( s, "Cmd:%s, ReqAck:%d, IsAck:%d, Type:%s, Sns:%d",
                 val_to_str(commandType, command_types, "%d"),
                 reqack,
                 isack,
                 typeToStr(commandType, type),
                 sensor
               );
  if (payloadLen > 0)
  {
    s += sprintf( s, ", Data:%s [%s]",
                   payloadToStr(dataType, tvb_data, payloadLen),
                   val_to_str(dataType, payload_types, "%d")
                 );
  }
  return buff;
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
    guint8 payloadLen, dataType, type, sensor, sender, last, dest, reqack, isack;
    MySensors_Command commandType;
    gchar* info;
    
    ti = proto_tree_add_item(tree, proto_mysensors, tvb, 0 /*start*/, -1 /*to end*/, ENC_NA);
    mysensors_tree = proto_item_add_subtree(ti, ett_mysensors);
    
    proto_tree_add_item(mysensors_tree, hf_mysensors_last, tvb, bitoffset>>3, 1, encoding);
    last = tvb_get_guint8(tvb, bitoffset>>3);
    bitoffset += 8;
    proto_tree_add_item(mysensors_tree, hf_mysensors_sender, tvb, bitoffset>>3, 1, encoding);
    sender = tvb_get_guint8(tvb, bitoffset>>3);
    bitoffset += 8;
    proto_tree_add_item(mysensors_tree, hf_mysensors_dest, tvb, bitoffset>>3, 1, encoding);
    dest = tvb_get_guint8(tvb, bitoffset>>3);
    bitoffset += 8;

    proto_tree_add_bits_item(mysensors_tree, hf_mysensors_length, tvb, bitoffset, 5, encoding);
    payloadLen = tvb_get_bits8(tvb, bitoffset, 5);
    bitoffset += 5;
    proto_tree_add_bits_item(mysensors_tree, hf_mysensors_version, tvb, bitoffset, 3, encoding);
    bitoffset += 3;
    proto_tree_add_bits_item(mysensors_tree, hf_mysensors_datatype, tvb, bitoffset, 3, encoding);
    dataType = tvb_get_bits8(tvb, bitoffset, 3);  // Type of payload
    bitoffset += 3;
    proto_tree_add_bits_item(mysensors_tree, hf_mysensors_isack, tvb, bitoffset, 1, encoding);
    isack = (MySensors_Command)tvb_get_bits8(tvb, bitoffset, 1);
    bitoffset += 1;
    proto_tree_add_bits_item(mysensors_tree, hf_mysensors_reqack, tvb, bitoffset, 1, encoding);
    reqack = (MySensors_Command)tvb_get_bits8(tvb, bitoffset, 1);
    bitoffset += 1;
    proto_tree_add_bits_item(mysensors_tree, hf_mysensors_commandtype, tvb, bitoffset, 3, encoding);
    commandType = (MySensors_Command)tvb_get_bits8(tvb, bitoffset, 3);
    bitoffset += 3;

    type = tvb_get_guint8(tvb, bitoffset>>3);
    proto_tree_add_uint_format_value(mysensors_tree, hf_mysensors_type, tvb, bitoffset>>3, 1, type, "%s (%d)", typeToStr(commandType, type), (guint8)type);
    bitoffset += 8;
    proto_tree_add_item(mysensors_tree, hf_mysensors_sensor, tvb, bitoffset>>3, 1, encoding);
    sensor = tvb_get_guint8(tvb, bitoffset>>3);
    bitoffset += 8;

    // Create tvb for the payload.
    tvb_next = tvb_new_subset(tvb, bitoffset>>3, payloadLen, payloadLen);

    info = buildColInfo( pinfo, payloadLen, dataType, commandType, reqack, isack, type, sensor, tvb_next );
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

  /* 1) Test protocol verion -- only version 2 (1.4) currently supported */
  version = tvb_get_bits8(tvb, 3*8+5, 3);
  if (version != V2_14)
    return FALSE;

  dissect_mysensors(tvb, pinfo, tree);
    
  return TRUE;
}

void proto_register_mysensors(void)
{
    static hf_register_info hf[] = {
        { &hf_mysensors_last,           { "Last node", "mysensors.last", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_sender,         { "Sender node", "mysensors.sender", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_dest,           { "Destination node", "mysensors.dest", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_length,         { "Length", "mysensors.paylen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_mysensors_version,        { "Version", "mysensors.version", FT_UINT8, BASE_DEC, VALS(version_types), 0x0, NULL, HFILL } },
        { &hf_mysensors_datatype,       { "Data type", "mysensors.datatype", FT_UINT8, BASE_DEC, VALS(payload_types), 0x0, NULL, HFILL } },
        { &hf_mysensors_commandtype,    { "Command type", "mysensors.cmdtype", FT_UINT8, BASE_DEC, VALS(command_types), 0x0, NULL, HFILL } },
        { &hf_mysensors_isack,          { "IsAck", "mysensors.isack", FT_UINT8, BASE_DEC, VALS(ack_types), 0x0, NULL, HFILL } },
        { &hf_mysensors_reqack,         { "ReqAck", "mysensors.reqack", FT_UINT8, BASE_DEC, VALS(ack_types), 0x0, NULL, HFILL } },
        { &hf_mysensors_type,           { "Type", "mysensors.type", FT_UINT8, BASE_DEC, NULL /*representation differs with command*/, 0x0, NULL, HFILL } },
        { &hf_mysensors_sensor,         { "Sensor", "mysensors.sensor", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      };
    static int *ett[] = {
        &ett_mysensors    // subtree nrf24mysensors
    };
 
    proto_mysensors = proto_register_protocol (
        "MySensors2",        // name
        "mysensors2",        // short name
        "mysensors2"         // abbref
        );
    register_dissector("mysensors2", dissect_mysensors, proto_mysensors);
 
    proto_register_field_array(proto_mysensors, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
 }
    
/* Register Protocol handler */
void proto_reg_handoff_mysensors(void)
{
  mysensors_handle = create_dissector_handle(dissect_mysensors, proto_mysensors);
  heur_dissector_add("nrf24" /*parent protocol*/, dissect_mysensors_heur, proto_mysensors);
  heur_dissector_add("rhmesh" /*parent protocol*/, dissect_mysensors_heur, proto_mysensors);
  data_handle = find_dissector("data");
}
