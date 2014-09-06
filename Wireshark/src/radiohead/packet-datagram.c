/* packet-radiohead.c
 * Dissector for RadioHead wireless networking stack. 
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

// Flags -- RHReliableDatagram.h
#define RH_FLAGS_ACK_BIT  (7)
#define RH_FLAGS_ACK_MASK (((guint16)1)<<RH_FLAGS_ACK_BIT)

#define RH_DATAGRAM_MSG_HEADER_LENGTH  (4)

#define BITS_TO_BYTES(x)  (((x)+7)>>3)
#define BYTES_TO_BITS(x)  ((x)<<3)

static const guint encoding = ENC_LITTLE_ENDIAN;

static dissector_handle_t radiohead_datagram_handle;

static heur_dissector_list_t heur_subdissector_list;

static int hf_radiohead_datagram_to          = -1;
static int hf_radiohead_datagram_from        = -1;
static int hf_radiohead_datagram_id          = -1;
static int hf_radiohead_datagram_flags       = -1;
static int hf_radiohead_datagram_flags_ack   = -1;

static const int *flags_field[] = {
    &hf_radiohead_datagram_flags_ack,
    NULL
};

static int ett_radiohead_datagram       = -1;
static int ett_radiohead_datagram_flags = -1;
static gint proto_radiohead_datagram    = -1;

static dissector_handle_t data_handle;


static const value_string ack_types[] = {
  { 0, "NO_ACK" },
  { 1, "ACK" },
  { 0, NULL }
};

static gchar* radiohead_datagram_buildColInfo( packet_info *pinfo, /*const guint8 to, const guint8 from,*/ const guint8 id, const guint8 flags)
{
  static gchar buff[100];
  gchar* s = buff;
  s += sprintf( s, "Id:%d", id);
  s += sprintf( s, ", Flags:%s", val_to_str((flags & RH_FLAGS_ACK_MASK)>>RH_FLAGS_ACK_BIT, ack_types, "%d") );
  return buff;
}

// content format
static void dissect_radiohead_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  // your variable definitions go here
  int offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "rhdatagram");
  col_add_fstr(pinfo->cinfo, COL_PACKET_LENGTH, "%d", tvb_length(tvb) );
  
  // Clear out stuff in the info column
  col_clear(pinfo->cinfo, COL_INFO);
  if (tree)
  {
    // in case that someone wants to know some details of our protocol
    // spawn a subtree and cut the sequence in readable parts
    proto_item *ti = NULL;
    proto_item *pi = NULL;
    proto_tree *radiohead_tree = NULL;
    guint8 to, from, id, flags;
    guint length;
    gchar* info;

    ti = proto_tree_add_item(tree, proto_radiohead_datagram, tvb, 0 /*start*/, -1 /*end*/, encoding);
    radiohead_tree = proto_item_add_subtree(ti, ett_radiohead_datagram);

    length = tvb_length(tvb);

    proto_tree_add_item(radiohead_tree, hf_radiohead_datagram_to, tvb, offset, 1, encoding);
    to = tvb_get_guint8(tvb, offset);
    offset++;
    proto_tree_add_item(radiohead_tree, hf_radiohead_datagram_from, tvb, offset, 1, encoding);
    from = tvb_get_guint8(tvb, offset);
    offset++;
    proto_tree_add_item(radiohead_tree, hf_radiohead_datagram_id, tvb, offset, 1, encoding);
    id = tvb_get_guint8(tvb, offset);
    offset++;
    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(radiohead_tree, tvb, offset, hf_radiohead_datagram_flags, ett_radiohead_datagram_flags, flags_field, encoding);
    offset++;

    info = radiohead_datagram_buildColInfo( pinfo, /*to, from,*/ id, flags);
    col_add_str(pinfo->cinfo, COL_INFO, info);
    proto_item_append_text(ti, " - %s", info);
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%d", from);
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%d", to);

    if (tvb_length_remaining(tvb, offset /*TODO: bits or bytes?*/) > 0)
    {
      tvbuff_t* tvb_next;
      tvb_next = tvb_new_subset(tvb, offset/*start*/, -1 /*to end*/, -1/*reported length*/ );

      add_new_data_source(pinfo, tvb_next, "RadioHead Datagram Payload Data");
      // The radiohead header contains no indication of the payload type. Therefore we
      // pass it on to a list of heuristic dissectors for radiohead payloads, or display
      // it as data when none found.
      if (!dissector_try_heuristic(heur_subdissector_list, tvb_next, pinfo, tree, NULL))
      {
        call_dissector(data_handle, tvb_next, pinfo, tree);
      }
    }
  }
}

static gboolean dissect_radiohead_datagram_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  /* 0) Test minimum packet length */
  if (tvb_length(tvb) < RH_DATAGRAM_MSG_HEADER_LENGTH)
    return FALSE;

  /* 1) ... */

  dissect_radiohead_datagram(tvb, pinfo, tree);
    
  return TRUE;
}

void proto_register_radiohead_datagram(void)
{
/*
  RadioHead 1.32
  RHDatagram:
    -TO The node address that the message is being sent to (broadcast RH_BROADCAST_ADDRESS (255) is permitted)
    -FROM The node address of the sending node
    -ID A message ID, distinct (over short time scales) for each message sent by a particilar node
    -FLAGS A bitmask of flags. The most significant 4 bits are reserved for use by RadioHead. The least significant 4 bits are reserved for applications.

  RHReliableDatagram:
      RHDatagram header, RH_FLAGS_ACK bit set,
    - 1 octet of payload containing ASCII '!' (since some drivers cannot handle 0 length payloads)
*/

    static hf_register_info hf[] = {
        //                                       Name     Abbrev                          Type      Display    Strings          Bitmask            Blurb  DontTouch
        { &hf_radiohead_datagram_to,           { "To",    "radiohead.datagram.to",        FT_UINT8, BASE_DEC,  NULL,            0,                 NULL, HFILL } },
        { &hf_radiohead_datagram_from,         { "From",  "radiohead.datagram.from",      FT_UINT8, BASE_DEC,  NULL,            0,                 NULL, HFILL } },
        { &hf_radiohead_datagram_id,           { "Id",    "radiohead.datagram.id",        FT_UINT8, BASE_DEC,  NULL,            0,                 NULL, HFILL } },
        { &hf_radiohead_datagram_flags,        { "Flags", "radiohead.datagram.flags",     FT_UINT8, BASE_HEX,  NULL,            0,                 NULL, HFILL } },
        { &hf_radiohead_datagram_flags_ack,    { "Ack",   "radiohead.datagram.flags.ack", FT_UINT8, BASE_DEC,  VALS(ack_types), RH_FLAGS_ACK_MASK, NULL, HFILL } },
      };
    static int *ett[] = {
        &ett_radiohead_datagram,            // subtree radiohead
        &ett_radiohead_datagram_flags       // subtree radiohead flags field
    };
 
    proto_radiohead_datagram = proto_register_protocol (
        "RadioHeadDatagram",        // name
        "rhdatagram",        // short name
        "rhdatagram"         // abbrev
        );
    register_dissector("rhdatagram", dissect_radiohead_datagram, proto_radiohead_datagram);
    register_heur_dissector_list("rhdatagram", &heur_subdissector_list);

    proto_register_field_array(proto_radiohead_datagram, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* Register Protocol handler */
void proto_reg_handoff_radiohead_datagram(void)
{
  radiohead_datagram_handle = create_dissector_handle(dissect_radiohead_datagram, proto_radiohead_datagram);
  heur_dissector_add("nrf24" /*parent protocol*/, dissect_radiohead_datagram_heur, proto_radiohead_datagram);
  data_handle = find_dissector("data");
}
