#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

import base64
import binascii 
import hashlib
import json
import os
import requests
import random
import struct
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

from multiprocessing import Process
import luckyMiner.config as C
from luckyMiner.func import *

MINE_TIMEOUT       = C.CONFIG[C.testnet]["MINE_TIMEOUT"]
RPC_URL            = C.CONFIG[C.testnet]["RPC_URL"] 
RPC_USER           = C.CONFIG[C.testnet]["RPC_USER"] 
RPC_PASS           = C.CONFIG[C.testnet]["RPC_PASS"] 
coinBaseMessage    = C.CONFIG[C.testnet]["coinBaseMessage"] 
blockRewardAddress = C.CONFIG[C.testnet]["blockRewardAddress"] 

#################################################
# Utility function to submit an RPC method call
# to a bitcoin server
# copy from \backup\python\miner\bm\btc\utils.py
#################################################

def rpcCall(method, params = None, port=18444, host="localhost", user="user", password="password"):
    #
    # Create request header
    #
    headers = {'content-type': 'application/json'}
    #
    # Build URL from host and port information
    #
    #url = "http://" + host + ":" + str(port)
    url = host
    #
    # Assemble payload as a Python dictionary
    
    #payload = {"method": method, "params": params, "jsonrpc": "2.0", "id": random.getrandbits(32)}        
    payload = {"id": random.getrandbits(32), "method": method, "params": params } 
    #
    # Create and send POST request
    #
    #print("rpcCall:", payload, "host:", host, url ) user, password
    r = requests.post(url, json=payload, headers=headers, auth=(RPC_USER, RPC_PASS))
    #
    # and interpret result
    #
    json = r.json()
    if 'result' in json and json['result'] != None:
        return json['result']
    elif 'error' in json and json['error'] != None:
        #raise ConnectionError("Request failed with RPC error", json['error'])
        print("Request failed with RPC error", json['error'])
        time.sleep(5)
    if r.status_code != 200:
        #raise ConnectionError("Request failed with HTTP status code ", r.status_code)
        print("Request failed with HTTP status code ", r.status_code)
        time.sleep(5)
    #
    # Might be perfectly valid to get here as some calls like submitblock do
    # not return anything
    #
    return None

################################################################################
# Bitcoin Daemon JSON-HTTP RPC
################################################################################

# JSON-HTTP RPC Configuration
# This will be particular to your local ~/.bitcoin/bitcoin.conf
def rpc(method, params=None):
    """
    Make an RPC call to the Bitcoin Daemon JSON-HTTP server.

    Arguments:
        method (string): RPC method
        params: RPC arguments

    Returns:
        object: RPC response result.
    """

    rpc_id = random.getrandbits(32)
    data = json.dumps({"id": rpc_id, "method": method, "params": params}).encode()
    auth = base64.encodebytes((RPC_USER + ":" + RPC_PASS).encode()).decode().strip()
    try:
        request = urllib.request.Request(RPC_URL, data, {"Authorization": "Basic {:s}".format(auth)})
    except Exception as e:
        traceback.print_exc()        
        mPrint("*** rpc_error",2,e)  

    with urllib.request.urlopen(request) as f:
        response = json.loads(f.read())

    if response['id'] != rpc_id:
        raise ValueError("Invalid response id: got {}, expected {:u}".format(response['id'], rpc_id))
    elif response['error'] is not None:
        raise ValueError("RPC error: {:s}".format(json.dumps(response['error'])))

    return response['result']

################################################################################
# Bitcoin Daemon RPC Call Wrappers
################################################################################

#{"id": 0, "method": "getblocktemplate", "params": [{
#    "capabilities": ["coinbasetxn", "workid", "coinbase/append"],
#    "longpollid": "some gibberish",
#}]}

def rpc_getblocktemplate():
    try:
        return rpcCall(method="getblocktemplate", params =[{"rules": ["segwit"]}],host = C.CONFIG[C.testnet]["RPC_URL"])
        #return rpc("getblocktemplate", [{"rules": ["segwit"]}])
    except ValueError:
        return {}


def rpc_submitblock(block_submission):
    #response = rpc("submitblock", [block_submission])
    response = rpcCall(method="submitblock", params =[block_submission], host = C.CONFIG[C.testnet]["RPC_URL"])
    if response is not None :
        if response == "high-hash":
            pass
        else:
            mPrint("Submitting：",3, "Submission Error: {}".format(response), block_submission)
        return response
    else:
        mPrint("Submitting：",3, "response is NONE")
        return response

def rpc_getblock(hash, verbosity=2 ):
    return rpc("getblock", [hash, verbosity])  

#generatetoaddress 10000 bcrt1qxmt29vfzghjczh5y6dsjtrrcks766xfvxk2r9x    
#regtest mode only
def rpc_generatetoaddress(nblocks=1000, addr="bcrt1qxmt29vfzghjczh5y6dsjtrrcks766xfvxk2r9x"):
    return rpc("generatetoaddress", [nblocks, addr])
    
# get scriptPubKey     
def rpc_getScriptPubKey(address = ""):
    walletList = rpcCall(method="listwallets", params =[],host = C.CONFIG[C.testnet]["RPC_URL"])
    result = rpcCall(method="getaddressinfo", params =[C.CONFIG[C.testnet]["blockRewardAddress"]],host = C.CONFIG[C.testnet]["RPC_URL"]+"/wallet/"+ walletList[0])
    if 'scriptPubKey' in result:
        return result['scriptPubKey']
    return false

################################################################################
# Representation Conversion Utility Functions
################################################################################


def int2lehex(value, width):
    """
    Convert an unsigned integer to a little endian ASCII hex string.

    Args:
        value (int): value
        width (int): byte width

    Returns:
        string: ASCII hex string
    """

    return value.to_bytes(width, byteorder='little').hex()


def int2varinthex(value):
    """
    Convert an unsigned integer to little endian varint ASCII hex string.

    Args:
        value (int): value

    Returns:
        string: ASCII hex string
    """

    if value < 0xfd:
        return int2lehex(value, 1)
    elif value <= 0xffff:
        return "fd" + int2lehex(value, 2)
    elif value <= 0xffffffff:
        return "fe" + int2lehex(value, 4)
    else:
        return "ff" + int2lehex(value, 8)

#   ok!  test by ioying 01/17/2023  
#   useless 
def bitcoinaddress2hash160(addr):
    """
    Convert a Base58 Bitcoin address to its Hash-160 ASCII hex string.
    Args:
        addr (string): Base58 Bitcoin address
    Returns:
        string: Hash-160 ASCII hex string
    """
#    e.g. decode('mvm74FACaagz94rjWbNmW2EmhJdmEGcxpa')  
#         #>> a73706385fffbf18855f2aee2a6168f29dbb597e    
#    test by ioying 01/17/2023 

    table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    #print("addr:", addr)
    hash160 = 0
    addr = addr[::-1]
    for i, c in enumerate(addr):
        hash160 += (58 ** i) * table.find(c)
    print("hash160:", hash160)
    # Convert number to 50-byte ASCII Hex string
    hash160 = "{:050x}".format(hash160)
    #print("hash160 format:", hash160)
    # Discard 1-byte network byte at beginning and 4-byte checksum at the end
    print("base58Encode(s)", base58Encode(bytes(addr.encode())))
    print("hash160[2:50 - 8]", hash160[2:50 - 8], hash160 , addr) 
    
    #time.sleep(10)
    return hash160[2:50 - 8]


Base58Alphabet    = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#RIPPLE_ALPHABET = b'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'

# input str 
# YzQaNtgo1vimyTKC6CMCcFsv25RCVaWCcx7rKiVFsjcGpnRqz8ycFXpPw2oy
def base58decode(data):
    """
    base58  decoder
    :param data: str
    :return:
    """
    result = 0

    for d in data:
        charIndex = Base58Alphabet.find(d)
        result = result * len(Base58Alphabet)
        result = result + charIndex
        #print(d, charIndex, result)
    decoded = hex(result)

    # if data[0] == Base58Alphabet[0]:
    #     decoded = str(0x0) + decoded

    return decoded


#   input str address or Hexadecimal Values  
#  "0x2025d153341905727a46f0e7c511703d176862cc495ea324557cb6f1487cdae63"
#  "bcrt1qxmt29vfzghjczh5y6dsjtrrcks766xfvxk2r9x"
def base58encode(data):
    print(type(data))
    if isinstance(data, str):
        x = int(data.encode('utf-8').hex(), 16)
        # bytes(data, encoding="utf-8")   #  
    else:
        x = int(data, 16)
    print('data 16:',x)    
    result = []

    #x = int(data, 16)
    base = 58

    zero = 0

    while x != zero:
        x, mod = divmod(x, base)
        result.append(Base58Alphabet[mod])

    # if data[0] == str(0x0):
    #     result.append(Base58Alphabet[0])
    return "".join(result[::-1])




################################################################################
# Transaction Coinbase and Hashing Functions
################################################################################


def tx_encode_coinbase_height(height):
    """
    Encode the coinbase height, as per BIP 34:
    https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki

    Arguments:
        height (int): height of the mined block

    Returns:
        string: encoded height as an ASCII hex string
    """

    width = (height.bit_length() + 7) // 8

    return bytes([width]).hex() + int2lehex(height, width)



# https://github.com/FACT0RN/factoring/pull/10/files  fix Submission Error: bad-txnmrklroot
def tx_make_coinbase(coinbase_script, address, value, height, wit_commitment):
    """
    Create a coinbase transaction.

    Arguments:
        coinbase_script (string): arbitrary script as an ASCII hex string
        address (string): Base58 Bitcoin address
        value (int): coinbase value
        height (int): mined block height

    Returns:
        string: coinbase transaction as an ASCII hex string
    """

    # See https://en.bitcoin.it/wiki/Transaction

    coinbase_script = tx_encode_coinbase_height(height) + coinbase_script
    ####wrong result , using rpc_getScriptPubKey replace ###############################
    # Create a pubkey script 
    # OP_DUP OP_HASH160 <len to push> <pubkey> OP_EQUALVERIFY OP_CHECKSIG
    # pubkey_script = "76" + "a9" + "14" + bitcoinaddress2hash160(address) + "88" + "ac"
    ####################################################################################
    pubkey_script = C.CONFIG[C.testnet]["scriptPubKey"]
    #print(bitcoinaddress2hash160(address), pubkey_script )
    #return
    #print("pubkey_script", pubkey_script)
    tx = ""
    # version
    tx += "01000000"
    # in-counter
    tx += "01"
    # input[0] prev hash
    tx += "0" * 64
    # input[0] prev seqnum
    tx += "ffffffff"
    # input[0] script len
    tx += int2varinthex(len(coinbase_script) // 2)
    # input[0] script
    tx += coinbase_script
    # input[0] seqnum
    tx += "ffffffff"
    # out-counter
    tx += "02"
    # output[0] value
    tx += int2lehex(value, 8)
    # output[0] script len
    tx += int2varinthex(len(pubkey_script) // 2)
    # output[0] script
    tx += pubkey_script
    # witness commitment value
    tx += int2lehex(0, 8)
    # witness commitment script len
    tx += int2varinthex(len(wit_commitment) // 2)
    # witness commitment script
    tx += wit_commitment
    # lock-time
    tx += "00000000"
    #print("tx:",tx)
    return tx

def tx_compute_hash(tx):
    """
    Compute the SHA256 double hash of a transaction.

    Arguments:
        tx (string): transaction data as an ASCII hex string

    Return:
        string: transaction hash as an ASCII hex string
    """
    #print("tx_compute_hash tx:",tx)
    return hashlib.sha256(hashlib.sha256(bytes.fromhex(tx)).digest()).digest()[::-1].hex()

######################################################################################
# https://github.com/CyberGX/MerkleRootCalculator/blob/master/MerkleRootCalculator.py
# other merkleCalculator 
# CalculatedMerkleRoot = str(merkleCalculator(txHashes), 'utf-8')
######################################################################################
def hashIt(firstTxHash, secondTxHash):
    # Reverse inputs before and after hashing
    # due to big-endian
    unhex_reverse_first = binascii.unhexlify(firstTxHash)[::-1]
    unhex_reverse_second = binascii.unhexlify(secondTxHash)[::-1]

    concat_inputs = unhex_reverse_first+unhex_reverse_second
    first_hash_inputs = hashlib.sha256(concat_inputs).digest()
    final_hash_inputs = hashlib.sha256(first_hash_inputs).digest()
    # reverse final hash and hex result
    return binascii.hexlify(final_hash_inputs[::-1])
 
 # Hash pairs of items recursively until a single value is obtained
def merkleCalculator(hashList):
    if len(hashList) == 1:
        return hashList[0]
    newHashList = []
    # Process pairs. For odd length, the last is skipped
    for i in range(0, len(hashList)-1, 2):
        newHashList.append(hashIt(hashList[i], hashList[i+1]))
    if len(hashList) % 2 == 1: # odd, hash last item twice
        newHashList.append(hashIt(hashList[-1], hashList[-1]))
    return merkleCalculator(newHashList)
###########################################

def tx_compute_merkle_root(tx_hashes):
    """
    Compute the Merkle Root of a list of transaction hashes.

    Arguments:
        tx_hashes (list): list of transaction hashes as ASCII hex strings

    Returns:
        string: merkle root as a big endian ASCII hex string
    """

    # Convert list of ASCII hex transaction hashes into bytes
    tx_hashes = [bytes.fromhex(tx_hash)[::-1] for tx_hash in tx_hashes]

    # Iteratively compute the merkle root hash
    while len(tx_hashes) > 1:
        # Duplicate last hash if the list is odd
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])

        tx_hashes_new = []

        for i in range(len(tx_hashes) // 2):
            # Concatenate the next two
            concat = tx_hashes.pop(0) + tx_hashes.pop(0)
            # Hash them
            concat_hash = hashlib.sha256(hashlib.sha256(concat).digest()).digest()
            # Add them to our working list
            tx_hashes_new.append(concat_hash)

        tx_hashes = tx_hashes_new

    # Format the root in big endian ascii hex
    #print("merkle_root:" , tx_hashes[0][::-1].hex())
    #time.sleep(10)
    return tx_hashes[0][::-1].hex()


################################################################################
# Block Preparation Functions
################################################################################


def block_make_header(block):
    """
    Make the block header.

    Arguments:
        block (dict): block template

    Returns:
        bytes: block header
    """

    header = b""

    # Version
    header += struct.pack("<L", block['version'])
    # Previous Block Hash
    header += bytes.fromhex(block['previousblockhash'])[::-1]
    # Merkle Root Hash
    header += bytes.fromhex(block['merkleroot'])[::-1]
    
    # Time
    header += struct.pack("<L", block['curtime'])
    # Target Bits
    header += bytes.fromhex(block['bits'])[::-1]
    # Nonce
    header += struct.pack("<L", block['nonce'])
    #print("header:", header)
    return header


def block_compute_raw_hash(header):
    """
    Compute the raw SHA256 double hash of a block header.

    Arguments:
        header (bytes): block header

    Returns:
        bytes: block hash
    """

    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]


def block_bits2target(bits):
    """
    Convert compressed target (block bits) encoding to target value.

    Arguments:
        bits (string): compressed target as an ASCII hex string

    Returns:
        bytes: big endian target
    """

    # Bits: 1b0404cb
    #       1b          left shift of (0x1b - 3) bytes
    #         0404cb    value
    bits = bytes.fromhex(bits)
    shift = bits[0] - 3
    value = bits[1:]

    # Shift value to the left by shift
    target = value + b"\x00" * shift
    # Add leading zeros
    target = b"\x00" * (32 - len(target)) + target

    return target


def block_make_submit(block):
    """
    Format a solved block into the ASCII hex submit format.

    Arguments:
        block (dict): block template with 'nonce' and 'hash' populated

    Returns:
        string: block submission as an ASCII hex string
    """

    submission = ""

    # Block header
    submission += block_make_header(block).hex()
    # Number of transactions as a varint
    submission += int2varinthex(len(block['transactions']))
    # Concatenated transactions data
    for tx in block['transactions']:
        submission += tx['data']

    return submission
    
##################################################################################
#   by openAI GPT
#   tx_make_coinbase(coinbase_script, address, block_template['coinbasevalue'], block_template['height'])
def create_coinbase_tx_(message, reward_address, coinbasevalue, block_height):
    """
    Creates a coinbase transaction that rewards the miner to the provided address.

    :param reward_address: The address to reward the miner
    :param block_height: The height of the block in the blockchain
    :return: The serialized coinbase transaction
    """
    # Arbitrary message used to distinguish coinbase transactions
    #message = "Coinbase transaction for block height {}".format(block_height)
    
    # Hash the message to create the scriptSig
    script_sig = hashlib.sha256(message.encode()).hexdigest()
    # Build the transaction outputs
    #
    #outputs = [{"value": 50, "address": reward_address}]
    outputs = [{"value": 6.47920263, "address": reward_address}]
    # Build the transaction inputs
    inputs = [{"script_sig": script_sig}]
    # Serialize the transaction
    transaction = {"inputs": inputs, "outputs": outputs}
    return transaction
    
#   by openAI GPT    
def create_coinbase_tx(reward, address):
    # Create a coinbase transaction with the specified reward
    # and send it to the specified address
    tx = {
        'inputs': [],
        'outputs': [{
            'address': address,
            'amount': reward
        }]
    }
    return tx
    
#   by openAI GPT
def compute_tx_hash(tx):
    # Compute the hash of the transaction by serializing its data
    # and computing the SHA-256 hash of the result
    tx_data = str(tx).encode()
    tx_hash = hashlib.sha256(tx_data).hexdigest()
    return tx_hash
    
##  openAI GPT end  #################################################################################


################################################################################
# Block Miner
################################################################################

def block_mine_c(block_template, coinbase_message, extranonce_start, address, target_hash = b'\xff\xff\xff', process='', C_hash_rate={}):
    if process not in C_hash_rate:
        C_hash_rate[process] = 0 
    """
    Mine a block.

    Arguments:
        block_template (dict): block template
        coinbase_message (bytes): binary string for coinbase script
        extranonce_start (int): extranonce offset for coinbase script
        address (string): Base58 Bitcoin address for block reward

    Timeout:
        timeout (float): timeout in seconds
        debugnonce_start (int): nonce start for testing purposes

    Returns:
        (block submission, hash rate) on success,
        (None, hash rate) on timeout or nonce exhaustion.
    """

    

    # Add an empty coinbase transaction to the block template transactions
    coinbase_tx = {}

    block_template['transactions'].insert(0, coinbase_tx)


    # Add a nonce initialized to zero to the block template
    block_template['nonce'] = 0
    real_target_hash = block_bits2target(block_template['bits'])
    # Compute the target hash
    if C.testnet == 0 and target_hash == b'\xff\xff\xff' :
        target_hash = block_bits2target(block_template['bits'])
    #else:
        #target_hash = b'\x00\x00\x00\xff\xff\x00\x00\x00\x00&;\x96\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


    time_start = time.time()

    # Initialize our running average of hashes per second
    hash_rate, hash_rate_count = 0.0, 0
    # Loop through the extranonce
    extranonce = random.getrandbits(32)
    while extranonce <= 0xffffffff:
        if C_hash_rate[process] < 200000:
            C_hash_rate[process] = C.real_hash_rate
        time_start = time.time()
        # Update the coinbase transaction with the new extra nonce
        coinbase_script = coinbase_message + int2lehex(extranonce, 4)
        coinbase_tx['data'] = tx_make_coinbase(coinbase_script, address, block_template['coinbasevalue'], block_template['height'], block_template['default_witness_commitment'])
        coinbase_tx['txid'] = tx_compute_hash(coinbase_tx['data'])        
        # Recompute the merkle root
        block_template['merkleroot'] = tx_compute_merkle_root([tx['txid'] for tx in block_template['transactions']])
        # other merkle method
        # Reform the block header
        block_header = block_make_header(block_template)
        #print("block_header", block_header)
        time_stamp = 0 
        # Loop through the nonce
        #nonce = 0  
        nonceStart = random.getrandbits(32)
        
        nonceEnd = nonceStart + C_hash_rate[process] * MINE_TIMEOUT if nonceStart + C_hash_rate[process] * MINE_TIMEOUT < 0xffffffff else 0xffffffff
        
        for nonce in range(nonceStart, nonceEnd): 
        
            # Update the block header with the new 32-bit nonce
            block_header = block_header[0:76] + nonce.to_bytes(4, byteorder='little')

            # Recompute the block hash
            block_hash = block_compute_raw_hash(block_header)

            # Check if it the block meets the target hash

            if block_hash < target_hash:   # or C.testnet == 2: (regtest mode)
                block_template['nonce'] = nonce
                block_template['hash'] = block_hash.hex()
                submission = block_make_submit(block_template)
                response = rpc_submitblock(submission)
                #sys.stdout.write("lucky miner:                            %s\r" % (block_hash.hex()[0:19]))
                #re.sub(r'00+','_'+str(len(re.findall(r'00+', st)[0]))+"_",st) ### count consecutive "0" and replace it 
                mPrint("lucky miner           real_target: %s, %s:%s @%s" % (real_target_hash.hex().replace("00000",".")[0:19], block_hash.hex().replace("00000","_")[0:19],response, process)) 
                if response is not None:
                    #print(response)
                    #return
                    pass
                else:
                    break
        time_count = (time.time() - time_start) if (time.time() - time_start) >1 else 1   # ZeroDivisionError: float division by zero
        hash_rate_m = nonceEnd  - nonceStart
        C_hash_rate[process] = int(hash_rate_m / time_count);
        mPrint("block_mine",1,process,"time:{:.2f}".format(time_count), 'sec. hash：', C_hash_rate[process], str(int(C_hash_rate[process] / 1000.0)) + "KH/s", " nonce:", nonceEnd, " extranonce:",extranonce)    
        extranonce += 1
        return (None, C_hash_rate[process], process,'n')  
    return (None, C_hash_rate[process], process,'e')
    
def test_lib():
    block_template = rpc_getblocktemplate()
    for x in block_template['transactions'] :
        print("block_template['transactions']:",x)
        
def returnSum(myDict): 
    sumIt = 0
    for i in myDict: 
        sumIt = sumIt + myDict[i] 
    return sumIt
    

################################################################################
# Standalone Bitcoin Miner, Single-threaded
################################################################################

 
def standalone_miner_c(coinbase_message = coinBaseMessage, address = blockRewardAddress, target_hash = b'\xff\xff\xff',process='',C_hash_rate=''):

    while True:
        # retry if connect request failed until get block_template.
        while True:
            try:
                block_template = rpc_getblocktemplate()
                if block_template == None:
                    time.sleep(5)
                    pass
                else:
                    break
            except Exception as e:
                mPrint("*** rpc_getblocktemplate",1,e)
                time.sleep(5)
                
        ### save template to file if necessary
        #saveBlock(block_template, transactions=1, once = 0)
        
        ##### todo 
        #       done : try to delete all transactions  response  "Submission Error: bad-cb-amount"
        
        #### try delete low value transaction
        #### Witnesses  A list of witnesses, 1 for each input, omitted if flag above is missing 
        #### bad-witness-merkle-match
        #print(block_template['coinbasevalue'], block_template['default_witness_commitment'])
        #for x in block_template['transactions'][:]:
            #print(x['fee']) 
            #if x['fee'] < 5000:
                #block_template['coinbasevalue'] -=  x['fee']
                #block_template['transactions'].remove(x)

        #print(block_template['coinbasevalue'], block_template['default_witness_commitment'])    
        #return
        
        try:
            mined_block, hash_rate, nowProcess, mark = block_mine_c(block_template, coinbase_message.encode().hex(), 0, address, target_hash,process)   # timeout=MINE_TIMEOUT)
        except Exception as e:
            traceback.print_exc()
            mPrint("*** standalone_miner error",2,e)  
            time.sleep(9)

        C_hash_rate[nowProcess] = hash_rate;
        mPrint("luckyMiner",1, str(int(hash_rate / 1000.0)) + "KH/s, Total:",str(int(sum(C_hash_rate.values())/ 1000.0)), "KH/s  height:"+ str(block_template['height']),"trans:",len(block_template['transactions']),time.asctime( time.localtime(time.time())),mark)
        #sys.stdout.write("lucky miner: %s,%s,%s,%s/r," % (str(int(hash_rate / 1000.0)) + "KH/s, Total:",str(int(sum(C_hash_rate.values())/ 1000.0)), "KH/s  height:"+ str(block_template['height']),time.asctime(time.localtime(time.time()))))
        time.sleep(0.5)    

