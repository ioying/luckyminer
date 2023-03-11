# luckyminer

  Getblocktemplate Bitcoin Miner.
  
  
AMD Ryzen 5 5600H with Radeon Graphics 3.30 GHz 

6 Cores 12 Logical processors CPU Utilzation: 

  1  :  20%,  700KH/s 
  
  5  :  56%, 2600KH/s
  
  12 : 100%, 5400KH/s

  3k years can solve a block ! GOOD LUCK!


# Todo

  default_witness_commitment for each transactions
  
  using stratum


## Usage

 .Configure config.py change to your block_Reward_Address and coinBaseMessage
 
 .Configure `rpcuser` and `rpcpass` in `~/.bitcoin/bitcoin.conf`
 
 .Start bitcoind
 
 .python3 luckyminer.py 


# Special thanks:
forked from [vsergeev/ntgbtminer](https://github.com/vsergeev/ntgbtminer)

repaired bad-txnmrklroot references   (https://github.com/FACT0RN/factoring/issues/6) (                                 https://github.com/FACT0RN/factoring/pull/10/files)
                                      
[bitcoin developer DOC](https://developer.bitcoin.org/reference/rpc/getblocktemplate.html)

# Contributions

Any help more than welcome.

