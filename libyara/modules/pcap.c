/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <jansson.h>

#include <yara/modules.h>

#define MODULE_NAME pcap

begin_declarations;

  declare_string("greeting");

  declare_integer("number_of_packets");

  begin_struct_array("packets");
    begin_struct("tcp");
        declare_integer("srcport");
        declare_integer("dstport");
    end_struct("tcp");
    begin_struct("ip");
        declare_integer("src");
        declare_integer("dst");
    end_struct("ip");
  end_struct_array("packets");

end_declarations;


int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  set_string("Hello PCAP World!", module_object, "greeting");

  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  json_error_t json_error;
  json_t* json;

  // printf("len: %ld, %s\n", module_data_size, (const char*) module_data);

  foreach_memory_block(iterator, block)
  {
    const char* block_data = block->fetch_data(block);

    json = json_loads(
        (const char*) block_data,
        #if JANSSON_VERSION_HEX >= 0x020600
        JSON_ALLOW_NUL,
        #else
        0,
        #endif
        &json_error);

    if (json == NULL)
    {
      fputs(json_error.text, stderr);
      fputs("\n", stderr);
      return ERROR_INVALID_FILE;
    }

    module_object->data = (void*) json;

    size_t num_packets = json_array_size(json);
    set_integer(num_packets, module_object, "number_of_packets");

    json_t* packet;
    int i;
    json_array_foreach(json, i, packet) {
      json_t* tcp_srcport = json_object_get(packet, "tcp.srcport");
      json_t* tcp_dstport = json_object_get(packet, "tcp.dstport");
      if(tcp_srcport && tcp_dstport)
      {      
        // // printf("tcp.srcport = %" JSON_INTEGER_FORMAT " , tcp.dstport = %" JSON_INTEGER_FORMAT "\n", 
        // printf("[%d] tcp.srcport = %d, tcp.dstport = %d\n", 
        //   i,
        //   atoi(json_string_value(tcp_srcport)),
        //   atoi(json_string_value(tcp_dstport))
        //   );
        set_integer(atoi(json_string_value(tcp_srcport)), module_object, "packets[%i].tcp.srcport", i);
        set_integer(atoi(json_string_value(tcp_dstport)), module_object, "packets[%i].tcp.dstport", i);
      }
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
