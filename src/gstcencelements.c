/* GStreamer ISO MPEG DASH common encryption decryptor
 * Copyright (C) 2013 YouView TV Ltd. <alex.ashley@youview.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Suite 500,
 * Boston, MA 02110-1335, USA.
 */


#define PACKAGE "CENCWIDEVINECENC"
#include <printf.h>
#include "gstcencdec.h"

#define VERSION "0.0.1"

#define PACKAGE_NAME "The widevinecenc decryptor"

static gboolean
plugin_init (GstPlugin * plugin)
{
    
  printf("Registering cencdec plugin\n");
  
  return gst_element_register (plugin, "cencwidevinedec", GST_RANK_PRIMARY,
      GST_TYPE_CENC_DECRYPT);
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    cencwidevinedec,
    "ISOBMFF common encryption element",
    plugin_init,
    VERSION,
    "LGPL",
    PACKAGE_NAME,
    "https://github.com/bruni68510/gst-cencwidevinedec.git");
