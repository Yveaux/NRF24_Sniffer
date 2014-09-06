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

/* RHMesh.h */
#define RH_MESH_MESSAGE_TYPE_MIN                            RH_MESH_MESSAGE_TYPE_APPLICATION
#define RH_MESH_MESSAGE_TYPE_APPLICATION                    0
#define RH_MESH_MESSAGE_TYPE_ROUTE_DISCOVERY_REQUEST        1
#define RH_MESH_MESSAGE_TYPE_ROUTE_DISCOVERY_RESPONSE       2
#define RH_MESH_MESSAGE_TYPE_ROUTE_FAILURE                  3
#define RH_MESH_MESSAGE_TYPE_MAX                            RH_MESH_MESSAGE_TYPE_ROUTE_FAILURE


#define RH_MESH_MSG_HEADER_LENGTH  (1)

#define BITS_TO_BYTES(x)  (((x)+7)>>3)
#define BYTES_TO_BITS(x)  ((x)<<3)

static const guint encoding = ENC_LITTLE_ENDIAN;

static dissector_handle_t radiohead_mesh_handle;

static heur_dissector_list_t heur_subdissector_list;

static int hf_radiohead_mesh_type               = -1;
static int hf_radiohead_mesh_routedisc_destlen  = -1;
static int hf_radiohead_mesh_routedisc_dest     = -1;
static int hf_radiohead_mesh_routedisc_route    = -1;
static int hf_radiohead_mesh_routefail_dest     = -1;

static int ett_radiohead_mesh        = -1;
static int ett_radiohead_routedisc   = -1;
static int ett_radiohead_routefail   = -1;
static gint proto_radiohead_mesh     = -1;

static dissector_handle_t data_handle;
static dissector_handle_t mesh_route_discovery_handle;
static dissector_handle_t mesh_route_fail;

static const value_string msgtype_types[] = {
  { RH_MESH_MESSAGE_TYPE_APPLICATION,              "APPLICATION" },
  { RH_MESH_MESSAGE_TYPE_ROUTE_DISCOVERY_REQUEST,  "ROUTE_DISCOVERY_REQUEST" },
  { RH_MESH_MESSAGE_TYPE_ROUTE_DISCOVERY_RESPONSE, "ROUTE_DISCOVERY_RESPONSE" },
  { RH_MESH_MESSAGE_TYPE_ROUTE_FAILURE,            "ROUTE_FAILURE" },
  { 0, NULL }
};


static gchar* radiohead_mesh_buildColInfo( packet_info *pinfo, const guint8 type)
{
  static gchar buff[100];
  gchar* s = buff;
  s += sprintf( s, "Type:%s", val_to_str(type, msgtype_types, "%d") );
  return buff;
}

// content format
static void dissect_radiohead_mesh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  // your variable definitions go here
  int offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "rhmesh");
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
    guint8 type;
    guint length;
    gchar* info;

    ti = proto_tree_add_item(tree, proto_radiohead_mesh, tvb, 0 /*start*/, -1 /*end*/, encoding);
    radiohead_tree = proto_item_add_subtree(ti, ett_radiohead_mesh);

    length = tvb_length(tvb);

    pi = proto_tree_add_item(radiohead_tree, hf_radiohead_mesh_type, tvb, offset, 1, encoding);
    type = tvb_get_guint8(tvb, offset);
    offset++;

    info = radiohead_mesh_buildColInfo( pinfo, type);
    col_add_str(pinfo->cinfo, COL_INFO, info);
    proto_item_append_text(ti, " - %s", info);

    if (tvb_length_remaining(tvb, offset) > 0)
    {
      proto_tree *pt = NULL;
      gint len;
      switch( type )
      {
        case RH_MESH_MESSAGE_TYPE_ROUTE_DISCOVERY_REQUEST:  /*fallthrough*/
        case RH_MESH_MESSAGE_TYPE_ROUTE_DISCOVERY_RESPONSE:
          pt = proto_item_add_subtree (pi, ett_radiohead_routedisc);
          proto_tree_add_item(pt, hf_radiohead_mesh_routedisc_destlen, tvb, offset, 1, encoding);
          offset++;
          proto_tree_add_item(pt, hf_radiohead_mesh_routedisc_dest, tvb, offset, 1, encoding);
          offset++;
          len = tvb_length_remaining(tvb, offset);
          if (len > 0)
          {
            proto_tree_add_item(pt, hf_radiohead_mesh_routedisc_route, tvb, offset, len, encoding);
            offset += len;
          }
          break;
        case RH_MESH_MESSAGE_TYPE_ROUTE_FAILURE:
          pt = proto_item_add_subtree (pi, ett_radiohead_routefail);
          proto_tree_add_item(pt, hf_radiohead_mesh_routedisc_dest, tvb, offset, 1, encoding);
          offset++;
          break;
        case RH_MESH_MESSAGE_TYPE_APPLICATION:  /*fallthrough*/
        default:
          {
            tvbuff_t* tvb_next = tvb_new_subset(tvb, offset/*start*/, -1 /*to end*/, -1/*reported length*/ );
            add_new_data_source(pinfo, tvb_next, "RadioHead Mesh Payload Data");
            if (!dissector_try_heuristic(heur_subdissector_list, tvb_next, pinfo, tree, NULL))
            {
              call_dissector(data_handle, tvb_next, pinfo, tree);
            }
          }
          break;
      }
    }
  }
}


static gboolean dissect_radiohead_mesh_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  gint8 type;
  
  /* 0) Test minimum packet length */
  if (tvb_length(tvb) < RH_MESH_MSG_HEADER_LENGTH)
    return FALSE;

  /* 1) First octet must contain a valid RH_MESH_MESSAGE_TYPE_* type */
  type = tvb_get_guint8(tvb, 0);
  if ((type < RH_MESH_MESSAGE_TYPE_MIN) || (type > RH_MESH_MESSAGE_TYPE_MAX))
    return FALSE;
 
  dissect_radiohead_mesh(tvb, pinfo, tree);
  return TRUE;
}

void proto_register_radiohead_mesh(void)
{
/*
  RadioHead 1.32
  RHMesh:
    - MeshMessageHeader
      - 1 octet MSGTYPE
  
      * MeshApplicationMessage (message type RH_MESH_MESSAGE_TYPE_APPLICATION). Carries an application layer message for the caller of RHMesh
        - 0..n octets DATA
      * MeshRouteDiscoveryMessage (message types RH_MESH_MESSAGE_TYPE_ROUTE_DISCOVERY_REQUEST and RH_MESH_MESSAGE_TYPE_ROUTE_DISCOVERY_RESPONSE). Carries Route Discovery messages (broadcast) and replies (unicast).
        - 1 octet DESTLEN. Reserved (must be 1)
        - 1 octet DEST. The address of the destination node whose route is being sought. 
        - 0..n octets ROUTE. List of node addresses visited so far. Length is implcit. 
      * MeshRouteFailureMessage (message type RH_MESH_MESSAGE_TYPE_ROUTE_FAILURE) Informs nodes of route failures.
        - 1 octet DEST. The address of the destination towards which the route failed. 
*/
    static hf_register_info hf[] = {
        //                                     Name              Abbrev                                  Type       Display    Strings              Bitmask  Blurb  DontTouch
        { &hf_radiohead_mesh_type,              { "Type",            "radiohead.mesh.type",              FT_UINT8,  BASE_DEC,  VALS(msgtype_types), 0,       NULL,  HFILL } },
        { &hf_radiohead_mesh_routedisc_destlen, { "Dest len",        "radiohead.mesh.routedisc.destlen", FT_UINT8,  BASE_DEC,  0,                   0,       NULL,  HFILL } },
        { &hf_radiohead_mesh_routedisc_dest,    { "Dest",            "radiohead.mesh.routedisc.dest",    FT_UINT8,  BASE_DEC,  0,                   0,       NULL,  HFILL } },
        { &hf_radiohead_mesh_routedisc_route,   { "Route",           "radiohead.mesh.routedisc.route",   FT_BYTES,  BASE_NONE, 0,                   0,       NULL,  HFILL } },
        { &hf_radiohead_mesh_routefail_dest,    { "Dest",            "radiohead.mesh.routefail.dest",    FT_UINT8,  BASE_DEC,  0,                   0,       NULL,  HFILL } },
    };
    static int *ett[] = {
        &ett_radiohead_mesh,             // subtree radiohead
        &ett_radiohead_routedisc,
        &ett_radiohead_routefail
    };
 
    proto_radiohead_mesh = proto_register_protocol (
        "RadioHeadMesh", // name
        "rhmesh",        // short name
        "rhmesh"         // abbrev
        );
    register_dissector("rhmesh", dissect_radiohead_mesh, proto_radiohead_mesh);
    register_heur_dissector_list("rhmesh", &heur_subdissector_list);

    proto_register_field_array(proto_radiohead_mesh, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* Register Protocol handler */
void proto_reg_handoff_radiohead_mesh(void)
{
  radiohead_mesh_handle = create_dissector_handle(dissect_radiohead_mesh, proto_radiohead_mesh);
  heur_dissector_add("rhrouter" /*parent protocol*/, dissect_radiohead_mesh_heur, proto_radiohead_mesh);
  data_handle = find_dissector("data");
}
