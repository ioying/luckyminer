#!/usr/bin/env python3 
# -*- coding: utf-8 -*-
#
# special thanks:
# forked from vsergeev/ntgbtminer       https://github.com/vsergeev/ntgbtminer
# repaired bad-txnmrklroot references   https://github.com/FACT0RN/factoring/issues/6
#                                       https://github.com/FACT0RN/factoring/pull/10/files
# https://developer.bitcoin.org/reference/rpc/getblocktemplate.html
#
# Todo
#    default_witness_commitment for each transactions
#    using stratum

import base64
import hashlib
import json
import multiprocessing
import random
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from luckyMiner.func import *
from luckyMiner.luckyminer_func import *
import luckyMiner.config as C


def genBlockTo(n):
    # generatetoaddress to nblock, for regtest only
    # Submission Error bad-cb-height when height under ~500
    nowHeight = 0    
    while nowHeight < n:
        res = rpc_getblocktemplate()
        print("nowheight:",res['height'] , "/" ,n, time.asctime( time.localtime(time.time())))
        nowHeight = int(res['height'])
        rpc_generatetoaddress(10)
        time.sleep(0.5)

def testHash():
    target_hash = b'\x00\x00\x00\x00\xff\x00\x00\x00&;\x96\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    block_template = {'capabilities': ['proposal'], 'version': 536870912, 'rules': ['csv', '!segwit', 'testdummy', 'taproot'], 'vbavailable': {}, 'vbrequired': 0, 
                      'previousblockhash': '661987eb9cf33f7d1aedb6e84ddd022f077c45895556b8b6dbc0df4584dfa59c', 'transactions': [], 'coinbaseaux': {}, 'coinbasevalue': 0, 
                      'longpollid': '661987eb9cf33f7d1aedb6e84ddd022f077c45895556b8b6dbc0df4584dfa59c7996', 'target': '7fffff0000000000000000000000000000000000000000000000000000000000', 
                      'mintime': 1674453456, 'mutable': ['time', 'transactions', 'prevblock'], 'noncerange': '00000000ffffffff', 'sigoplimit': 80000, 'sizelimit': 4000000, 
                      'weightlimit': 4000000, 'curtime': 1674454754, 'bits': '207fffff', 'height': 200022, 
                      'default_witness_commitment': '6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9'} 
    coinbase_message ="6c75636b794d696e6572536f6c6f5f414d4435363030485f3030395f72656774657374"
    extranonce_start = 0 
    address = "bcrt1qxmt29vfzghjczh5y6dsjtrrcks766xfvxk2r9x"
    print(block_mine(block_template, coinbase_message, extranonce_start, address, target_hash))
    
def testGetBlockTemplate():
    # not real time, result changed every 2~5 sec.
    time_start = time.time()
    for i in range(100):
        res = rpc_getblocktemplate()
        print(i,len(res['transactions']),res['default_witness_commitment'])
        time.sleep(1)
    print(time.time() - time_start)
    
if __name__ == "__main__":
    ###
    #testGetBlockTemplate()
    #sys.exit(1)
    ###
    
    multiproce = 6; 
    '''
    e.g. 6 Cores 12 Logical processors CPU Utilzation: 
     1 :  20%,   700KH/s hashrate
     5 :  56%,  2600KH/s hashrate
    12 : 100%,  5400KH/s hashrate
    '''
    mPrint(sys.argv[0], 2, C.CONFIG[C.testnet]["coinBaseMessage"], C.CONFIG[C.testnet]["blockRewardAddress"] , C.CONFIG[C.testnet]["NET_TYPE"],"multiprocessing:",multiproce)

    ### get scriptPubKey from rpc !important 
    C.CONFIG[C.testnet]["scriptPubKey"] = rpc_getScriptPubKey(C.CONFIG[C.testnet]["blockRewardAddress"])
    print("scriptPubKey:", C.CONFIG[C.testnet]["scriptPubKey"])

    ### multiprocessing 

    manager = multiprocessing.Manager()
    C_hash_rate = manager.dict()
    process_list = []
    for i in range(multiproce):
        C_hash_rate['p'+str(i)] = C.real_hash_rate+i;
        p = multiprocessing.Process(target=standalone_miner_c, args=(C.CONFIG[C.testnet]["coinBaseMessage"], C.CONFIG[C.testnet]["blockRewardAddress"], b'\x00\x00\x00\x00\xff','p'+str(i),C_hash_rate));
        p.start();
        process_list.append(p)
    try:
        for proc in process_list:
            proc.join()
    except Exception as e:
        mPrint("*** multiprocessing join error：",2,e)

