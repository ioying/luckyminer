import platform
if platform.system() != 'Linux':
    DATA_PATH = '.\\data\\'
    LOG_PATH = '.\\log\\' 
else:
    LOG_PATH = '/usr/local/luckyminer/log/'
    DATA_PATH = '/usr/local/luckyminer/data/'

####################################
# 0: mainnet  1: testnet  2: regtest
testnet = 0   
####################################

#default CPU one Logical processors hashrate 
real_hash_rate = 600000 
hash_rate={};  

# use rpc_getScriptPubKey(blockRewardAddress) to get scriptPubKey 
CONFIG = [{"RPC_URL" : "http://127.0.0.1:8332" ,
           "RPC_USER": "luck_nonce" ,
           "RPC_PASS": "*your*password*here*",
           "blockRewardAddress" : "bc1qmaq2ct9929hwuy8v74zq6r2h2hkcv93kwxnqcw",
           "scriptPubKey"    : "",
           "coinBaseMessage" : "luckyMinerSolo_Lele_0909",
           "MINE_TIMEOUT"    : 3,
           "NET_TYPE":"mainnet"},
           # testnet
          {"RPC_URL" : "http://127.0.0.1:18332" ,
           "RPC_USER": "luck_nonce" ,
           "RPC_PASS": "*your*password*here*",
           "blockRewardAddress" : "tb1qplqmx4da9am4q63a6xcseksynnpr6eeqzz5skl",
           "scriptPubKey"    : "00140fc1b355bd2f77506a3dd1b10cda049cc23d6720",
           "coinBaseMessage" : "luckyMinerSolo_AMD5600H_0909_testnet",
           "MINE_TIMEOUT"    : 6,
           "NET_TYPE":"testnet"},
           # regtest
           {"RPC_URL" : "http://127.0.0.1:18444" ,
           "RPC_USER": "luck_nonce" ,
           "RPC_PASS": "*your*password*here*",
           "blockRewardAddress" : "bcrt1qxmt29vfzghjczh5y6dsjtrrcks766xfvxk2r9x", #bcrt1qdq6f6zdww33sejpgaq9290gz6d2g2wkkna2xhl",
           "scriptPubKey"    : "001436d6a2b12245e5815e84d361258c78b43dad192c",
           "coinBaseMessage" : "luckyMinerSolo_AMD5600H_0909_regtest",
           "MINE_TIMEOUT"    : 6,
           "NET_TYPE":"regtest"}]
