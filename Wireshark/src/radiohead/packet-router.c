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

#define RH_ROUTER_MSG_HEADER_LENGTH  (5)

#define BITS_TO_BYTES(x)  (((x)+7)>>3)
#define BYTES_TO_BITS(x)  ((x)<<3)

static const guint encoding = ENC_LITTLE_ENDIAN;

static dissector_handle_t radiohead_router_handle;

static heur_dissector_list_t heur_subdissector_list;

static int hf_radiohead_router_dest    = -1;
static int hf_radiohead_router_source  = -1;
static int hf_radiohead_router_hops    = -1;
static int hf_radiohead_router_id      = -1;
static int hf_radiohead_router_flags   = -1;

static int ett_radiohead_router        = -1;
static gint proto_radiohead_router     = -1;

static dissector_handle_t data_handle;

static gchar* radiohead_router_buildColInfo( packet_info *pinfo, const guint8 hops, const guint8 id, const guint8 flags)
{
  static gchar buff[100];
  gchar* s = buff;
  s += sprintf( s, "Id:%d", id);
  s += sprintf( s, ", Hops:%d", hops);
  s += sprintf( s, ", Flags:%d", flags);
  return buff;
}

// content format
static void dissect_radiohead_router(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  // your variable definitions go here
  int offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "rhrouter");
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
    guint8 dest, source, hops, id, flags;
    guint length;
    gchar* info;

    ti = proto_tree_add_item(tree, proto_radiohead_router, tvb, 0 /*start*/, -1 /*end*/, encoding);
    radiohead_tree = proto_item_add_subtree(ti, ett_radiohead_router);

    length = tvb_length(tvb);

    proto_tree_add_item(radiohead_tree, hf_radiohead_router_dest, tvb, offset, 1, encoding);
    dest = tvb_get_guint8(tvb, offset);
    offset++;
    proto_tree_add_item(radiohead_tree, hf_radiohead_router_source, tvb, offset, 1, encoding);
    source = tvb_get_guint8(tvb, offset);
    offset++;
    proto_tree_add_item(radiohead_tree, hf_radiohead_router_hops, tvb, offset, 1, encoding);
    hops = tvb_get_guint8(tvb, offset);
    offset++;
    proto_tree_add_item(radiohead_tree, hf_radiohead_router_id, tvb, offset, 1, encoding);
    id = tvb_get_guint8(tvb, offset);
    offset++;
    proto_tree_add_item(radiohead_tree, hf_radiohead_router_flags, tvb, offset, 1, encoding);
    flags = tvb_get_guint8(tvb, offset);
    offset++;

    info = radiohead_router_buildColInfo( pinfo, hops, id, flags);
    col_add_str(pinfo->cinfo, COL_INFO, info);
    proto_item_append_text(ti, " - %s", info);
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%d", source);
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%d", dest);

    if (tvb_length_remaining(tvb, offset /*TODO: bits or bytes?*/) > 0)
    {
      tvbuff_t* tvb_next;
      tvb_next = tvb_new_subset(tvb, offset/*start*/, -1 /*to end*/, -1/*reported length*/ );

      add_new_data_source(pinfo, tvb_next, "RadioHead Router Payload Data");
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

static gboolean dissect_radiohead_router_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  /* 0) Test minimum packet length */
  if (tvb_length(tvb) < RH_ROUTER_MSG_HEADER_LENGTH)
    return FALSE;

  /* 1) ... */

  dissect_radiohead_router(tvb, pinfo, tree);
    
  return TRUE;
}

void proto_register_radiohead_router(void)
{
/*
  RadioHead 1.32
  RHRouter:
    - 1 octet DEST, the destination node address (ie the address of the final destination node for this message)
    - 1 octet SOURCE, the source node address (ie the address of the originating node that first sent the message).
    - 1 octet HOPS, the number of hops this message has traversed so far.
    - 1 octet ID, an incrementing message ID for end-to-end message tracking for use by subclasses. Not used by RHRouter.
    - 1 octet FLAGS, a bitmask for use by subclasses. Not used by RHRouter.
    - 0 or more octets DATA, the application payload data. The length of this data is implicit in the length of the entire message.
*/

    static hf_register_info hf[] = {
        //                                     Name      Abbrev                     Type      Display    Strings  Bitmask  Blurb  DontTouch
        { &hf_radiohead_router_dest,         { "Dest",   "radiohead.router.dest",   FT_UINT8, BASE_DEC,  NULL,    0,       NULL,  HFILL } },
        { &hf_radiohead_router_source,       { "Source", "radiohead.router.source", FT_UINT8, BASE_DEC,  NULL,    0,       NULL,  HFILL } },
        { &hf_radiohead_router_hops,         { "Hops",   "radiohead.router.hops",   FT_UINT8, BASE_DEC,  NULL,    0,       NULL,  HFILL } },
        { &hf_radiohead_router_id,           { "Id",     "radiohead.router.id",     FT_UINT8, BASE_DEC,  NULL,    0,       NULL,  HFILL } },
        { &hf_radiohead_router_flags,        { "Flags",  "radiohead.router.flags",  FT_UINT8, BASE_HEX,  NULL,    0,       NULL,  HFILL } },
      };
    static int *ett[] = {
        &ett_radiohead_router             // subtree radiohead
    };
 
    proto_radiohead_router = proto_register_protocol (
        "RadioHeadRouter",        // name
        "rhrouter",        // short name
        "rhrouter"         // abbrev
        );
    register_dissector("rhrouter", dissect_radiohead_router, proto_radiohead_router);
    register_heur_dissector_list("rhrouter", &heur_subdissector_list);

    proto_register_field_array(proto_radiohead_router, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* Register Protocol handler */
void proto_reg_handoff_radiohead_router(void)
{
  radiohead_router_handle = create_dissector_handle(dissect_radiohead_router, proto_radiohead_router);
  heur_dissector_add("rhdatagram" /*parent protocol*/, dissect_radiohead_router_heur, proto_radiohead_router);
  data_handle = find_dissector("data");
}
