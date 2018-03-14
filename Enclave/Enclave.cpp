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
#define CONSENSUS_SCRIPT_VERIFY_TX \
    "01000000017d01943c40b7f3d8a00a2d62fa1d560bf739a2368c180615b0a7937c0e883e7c000000006b4830450221008f66d188c664a8088893ea4ddd9689024ea5593877753ecc1e9051ed58c15168022037109f0d06e6068b7447966f751de8474641ad2b15ec37f4a9d159b02af68174012103e208f5403383c77d5832a268c9f71480f6e7bfbdfa44904becacfad66163ea31ffffffff01c8af0000000000001976a91458b7a60f11a904feef35a639b6048de8dd4d9f1c88ac00000000"
#define CONSENSUS_SCRIPT_VERIFY_PREVOUT_SCRIPT \
    "76a914c564c740c6900b93afc9f1bdaef0a9d466adf6ee88ac"

// Test case derived from first witness tx:
#define CONSENSUS_SCRIPT_VERIFY_WITNESS_TX \
    "010000000001015836964079411659db5a4cfddd70e3f0de0261268f86c998a69a143f47c6c83800000000171600149445e8b825f1a17d5e091948545c90654096db68ffffffff02d8be04000000000017a91422c17a06117b40516f9826804800003562e834c98700000000000000004d6a4b424950313431205c6f2f2048656c6c6f20536567576974203a2d29206b656570206974207374726f6e6721204c4c415020426974636f696e20747769747465722e636f6d2f6b6873396e6502483045022100aaa281e0611ba0b5a2cd055f77e5594709d611ad1233e7096394f64ffe16f5b202207e2dcc9ef3a54c24471799ab99f6615847b21be2a6b4e0285918fd025597c5740121021ec0613f21c4e81c4b300426e5e5d30fa651f41e9993223adbe74dbe603c74fb00000000"
#define CONSENSUS_SCRIPT_VERIFY_WITNESS_PREVOUT_SCRIPT \
"a914642bda298792901eb1b48f654dd7225d99e5e68c87"
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
void result_insepector(verify_result res){
    if(res == verify_result_eval_false){
        printf("Verify Result eval false \n");
    }else if(res == verify_result_eval_true){
        printf("Verify Result eval true\n");
    }else if(res == verify_result_script_size){
        printf("Verify result script size\n");
    }else if(res == verify_result_push_size){
        printf("Verify result push size \n");
    }else if(res == verify_result_op_count){
        printf("Verify result op count\n");
    }else if(res == verify_result_stack_size){
        printf("Verify result stack size\n");
    }else if(res == verify_result_sig_count){
        printf("Verify result sig count\n");
    }else if(res == verify_result_pubkey_count){
        printf("Verify result pubkey count\n");
    }else if(res == verify_result_verify){
        printf("Verify result failed verify \n");
    }else if(res == verify_result_equalverify){
        printf("Verify result failed equal verify\n");
    }else if(res == verify_result_checkmultisigverify){
        printf("Verify result failed checkmultisigverify\n");
    }else if(res == verify_result_checksigverify){
        printf("Verify result failed checksigverify\n");
    }else if(res == verify_result_numequalverify){
        printf("Verify result failed numequalverify \n");
    }else if(res == verify_result_bad_opcode ){
        printf("Verify result failed bad opcode \n");
    }else if(res == verify_result_disabled_opcode){
        printf("Verify result failed disabled opcode \n");
    }else if(res == verify_result_invalid_stack_operation){
        printf("Verify result failed invalid stack operation\n");
    }
    else{
        printf("Some other output\n");
    }
}
void case1(){
    const verify_result result = test_verify("42", "42");
    result_insepector(result);
    if(result ==  verify_result_tx_invalid){
        printf("CASE 1 : Test Case passed\n");
    }else{
        printf("CASE 1 : Test Case failed \n");
    }
}
void case2(){
    const verify_result result = test_verify(CONSENSUS_SCRIPT_VERIFY_TX, "76a914c564c740c6900b93afc9f1bdaef0a9d466adf6ef88ac");
    result_insepector(result);
    if(result == verify_result_equalverify){
        printf("CASE 2 : Test Case passed\n");
    }else{
        printf("CASE 2 : Test Case failed \n");
    }
}
void case3(){
    const verify_result result = test_verify(CONSENSUS_SCRIPT_VERIFY_TX, CONSENSUS_SCRIPT_VERIFY_PREVOUT_SCRIPT);
    if(result == verify_result_eval_true){
        printf("CASE 3: Test Case passed\n");
    }else{
        printf("CASE 3 : Test Case failed \n");
    }
    result_insepector(result);
}

void case4(){
    static const auto index = 0u;
    static const auto value = 500000u;
    static const uint32_t flags =
        verify_flags_p2sh |
        verify_flags_dersig |
        verify_flags_nulldummy |
        verify_flags_checklocktimeverify |
        verify_flags_checksequenceverify |
        verify_flags_witness;

    const verify_result result = test_verify(CONSENSUS_SCRIPT_VERIFY_WITNESS_TX, CONSENSUS_SCRIPT_VERIFY_WITNESS_PREVOUT_SCRIPT, value, index, flags);
    if(result == verify_result_eval_true){
        printf("CASE 4: test passed\n");
    }else{
        printf("CASE 4: test failed\n");
    }
    result_insepector(result);
}
void ecall_libconsensus_tester(){
    case1();
    case2();
    case3();
    case4();
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
    ocall_print_string(buf);
}
