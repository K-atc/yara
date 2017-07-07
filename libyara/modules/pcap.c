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


#define METHOD_GET    0x01
#define METHOD_POST   0x02

uint64_t pcap_http_request(
    YR_OBJECT* network_obj,
    RE* uri_regexp,
    int methods)
{
  json_t* json = (json_t*) network_obj->data;
  json_t* packet;

  uint64_t result = 0;
  size_t i;

  const char* method;
  const char* full_uri;

  json_array_foreach(json, i, packet) {
    json_t* layers = json_object_get(json_object_get(packet, "_source"), "layers");
    json_t* http = json_object_get(layers, "http");
    if(http)
    {
      void *iter = json_object_iter(http);
      if(iter)
      {
        json_t* value = json_object_iter_value(iter);
        json_t* obj_method = json_object_get(value, "http.request.method");
        if(obj_method)
        {
          method = json_string_value(obj_method);
        }
        else
        {
          method = "get";
        }
      }
      else
      {
        method = "get";
      }
      json_t* obj_full_uri = json_object_get(http, "http.request.full_uri");
      if(obj_full_uri)
      {
        full_uri = json_string_value(obj_full_uri);
        if (((methods & METHOD_GET && strcasecmp(method, "get") == 0) ||
             (methods & METHOD_POST && strcasecmp(method, "post") == 0)) &&
             yr_re_match(uri_regexp, full_uri) > 0)
        {
          result = 1;
          break;
        }        
      }

    }
  }

  return result;
}

define_function(check_http_request)
{
  return_integer(
      pcap_http_request(
          parent(),
          regexp_argument(1),
          METHOD_GET | METHOD_POST));
}


define_function(check_http_get)
{
  return_integer(
      pcap_http_request(
          parent(),
          regexp_argument(1),
          METHOD_GET));
}


define_function(check_http_post)
{
  return_integer(
      pcap_http_request(
          parent(),
          regexp_argument(1),
          METHOD_POST));
}


begin_declarations;

  declare_string("greeting");

  declare_integer("number_of_packets");

  begin_struct("check");
    declare_function("http_get", "r", "i", check_http_get);
    declare_function("http_post", "r", "i", check_http_post);
    declare_function("http_request", "r", "i", check_http_request);
  end_struct("check");

  begin_struct_array("packets");

    begin_struct("tcp");
      declare_integer("srcport");
      declare_integer("dstport");
    end_struct("tcp");
  
    begin_struct("ip");
      declare_integer("src");
      declare_integer("dst");
    end_struct("ip");
  
    begin_struct("http");
      begin_struct("request");
        declare_string("method");
        declare_string("uri");
        declare_string("host");
        declare_string("full_uri");
      end_struct("request");
    end_struct("http");
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

    // FIX ME: Not so good idea
    module_object->data = (void*) json;
    YR_OBJECT* check_object = get_object(module_object, "check");
    check_object->data = (void*) json;

    size_t num_packets = json_array_size(json);
    set_integer(num_packets, module_object, "number_of_packets");

    json_t* packet;
    int i;
    json_array_foreach(json, i, packet) {
      json_t* layers = json_object_get(json_object_get(packet, "_source"), "layers");
      json_t* tcp = json_object_get(layers, "tcp");
      json_t* tcp_srcport = json_object_get(tcp, "tcp.srcport");
      json_t* tcp_dstport = json_object_get(tcp, "tcp.dstport");
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
      json_t* http = json_object_get(layers, "http");
      if(http)
      {
        json_t* host = json_object_get(http, "http.host");
        if(host)
        {
          set_string(json_string_value(host), module_object, "packets[%i].http.request.host", i);
        }
        json_t* full_uri = json_object_get(http, "http.request.full_uri");
        if(full_uri)
        {
          // printf("[%d] full_uri = %s\n", i, json_string_value(full_uri));
          set_string(json_string_value(full_uri), module_object, "packets[%i].http.request.full_uri", i);
        }

        void *iter = json_object_iter(http);
        if(iter)
        {
          json_t* value = json_object_iter_value(iter);
          json_t* method = json_object_get(value, "http.request.method");
          if(method)
          {
            set_string(json_string_value(method), module_object, "packets[%i].http.request.method", i);
          }
          json_t* uri = json_object_get(value, "http.request.uri");
          if(uri){
            set_string(json_string_value(uri), module_object, "packets[%i].http.request.uri", i);
          }
        }
      }
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
  if (module->data != NULL)
    json_decref((json_t*) module->data);

  return ERROR_SUCCESS;
}
