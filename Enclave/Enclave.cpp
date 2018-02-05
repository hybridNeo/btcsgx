/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <secp256k1.h>
#include <string>
#include <vector>
#include <stdint.h>	
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <ios>
#include <bitcoin/consensus.hpp>
#define CONSENSUS_SCRIPT_VERIFY_PREVOUT_SCRIPT "76a914c564c740c6900b93afc9f1bdaef0a9d466adf6ee88ac"
using namespace libbitcoin::consensus;

typedef std::vector<uint8_t> data_chunk;

static unsigned from_hex(const char ch)
{
    if ('A' <= ch && ch <= 'F')
        return 10 + ch - 'A';

    if ('a' <= ch && ch <= 'f')
        return 10 + ch - 'a';

    return ch - '0';
}

static bool decode_base16_private(uint8_t* out, size_t size, const char* in)
{
    for (size_t i = 0; i < size; ++i)
    {
        if (!isxdigit(in[0]) || !isxdigit(in[1]))
            return false;

        out[i] = (from_hex(in[0]) << 4) + from_hex(in[1]);
        in += 2;
    }

    return true;
}


static bool decode_base16(data_chunk& out, const std::string& in)
{
    // This prevents a last odd character from being ignored:
    if (in.size() % 2 != 0)
        return false;

    data_chunk result(in.size() / 2);
    if (!decode_base16_private(result.data(), result.size(), in.data()))
        return false;

    out = result;
    return true;
}

static verify_result test_verify(const std::string& transaction,
    const std::string& prevout_script, uint64_t prevout_value=0,
    uint32_t tx_input_index=0, const uint32_t flags=verify_flags_p2sh,
    int32_t tx_size_hack=0)
{
    data_chunk tx_data, prevout_script_data;
    decode_base16(tx_data, transaction);
    decode_base16(prevout_script_data, prevout_script);
    return verify_script(&tx_data[0], tx_data.size() + tx_size_hack,
        &prevout_script_data[0], prevout_script_data.size(), prevout_value,
        tx_input_index, flags);
}

void libconsensus_tester(){
	// const unsigned char str[20] = {0};

	// size_t size =1;
	// verify_result_type res;
 //  	data_chunk prevout_script_data;
	// decode_base16(prevout_script_data, CONSENSUS_SCRIPT_VERIFY_PREVOUT_SCRIPT);
	 const verify_result result = test_verify("42", "42");
}


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    unsigned char s_one[32] = { 0 };
       // throw std::invalid_argument("121");

   	// secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
   	// secp256k1_pubkey point;

   	// s_one[31] = 1;
   	// secp256k1_ec_pubkey_create(ctx, &point, s_one);
   	// char* S1 = reinterpret_cast<char*>(&point);
   	// //libconsensus_tester();
   	//ocall_print_string(S1);
    ocall_print_string(buf);
}
