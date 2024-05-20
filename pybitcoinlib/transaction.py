import json
import requests
from io import BytesIO
from hash import *
from util import *
from script import *

class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return "https://testnet.programmingbitcoin.com"
        else:
            return "https://mainnet.programmingbitcoin.com"
        
    @classmethod
    def fetch(cls, txid, testnet=False, fresh=False):
        if fresh or (txid not in cls.cache):
            url = "{}/tx/{}.hex".format(cls.get_url(testnet), txid)
            response = requests.get(url)

            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError("fail: {}".format(response.text))
            
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)

            if tx.id() != txid:
                raise ValueError("different id's: {} != {}".format(tx.id(), txid))
            
            cls.cache[txid] = tx
        
        cls.cache[txid].testnet = testnet

        return cls.cache[txid]
    
    @classmethod
    def load_cache(cls, filename):
        with open(filename, 'r') as file:
            disk_cache = json.loads(file.read())
            
        for k, raw_hex in disk_cache.items():
            raw = bytes.fromhex(raw_hex)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw))
            cls.cache[k] = tx

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)

class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index

        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        
        self.sequence = sequence
    
    def __repr__(self):
        return "{}:{}".format(self.prev_tx.hex(), self.prev_index)
    
    @classmethod
    def parse(cls, stream):
        '''reads a byte stream, parses it into a transaction input and returns a TxIn object'''

        prev_tx = stream.read(32)[::-1]
        prev_index = little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = little_endian_to_int(stream.read(4))

        return cls(prev_tx, prev_index, script_sig, sequence)
    
    def serialize(self):
        '''TxIn object into byte array'''
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)

        return result
    
    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount
    
    def script_pubkey(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey

class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return "{}:{}".format(self.amount, self.script_pubkey)
    
    @classmethod
    def parse(cls, stream):
        '''reads a byte stream, parses it into a transaction output and returns a TxOut object'''
        amount = little_endian_to_int(stream.read(8))
        script_pubkey = Script.parse(stream)

        return cls(amount, script_pubkey)
    
    def serialize(self):
        '''TxOut object into byte array'''
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()

        return result


class Tx:
    command = b"tx"

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False, segwit=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None

    def __repr__(self):
        tx_ins = ""
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + "\n"

        tx_outs = ""
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + "\n"

        return \
            "tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}" \
            .format(self.id(), 
                    self.version,
                    tx_ins, 
                    tx_outs, 
                    self.locktime
            )
    
    def id(self):
        '''human-readable hex of transaction hash'''
        return self.hash().hex()
    
    def hash(self):
        '''binary hash of the legacy serialization'''
        return hash256(self.serialize_legacy())[::-1]
    
    @classmethod
    def parse(cls, s, testnet=False):
        s.read(4)
        if s.read(1) == b"\x00":
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        s.seek(-5, 1)
        return parse_method(s, testnet=testnet)
    
    @classmethod
    def parse_legacy(cls, s, testnet=False):
        version = little_endian_to_int(s.read(4))

        inputs = []
        num_inputs = read_varint(s)
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        
        outputs = []
        num_outputs = read_varint(s)
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        
        locktime = little_endian_to_int(s.read(4))
        
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=False)
    
    @classmethod
    def parse_segwit(cls, s, testnet=False):
        version = little_endian_to_int(s.read(4))

        marker = s.read(2)
        if marker != b'\x00\x01':
            raise RuntimeError('Not a segwit transaction {}'.format(marker))
        
        inputs = []
        num_inputs = read_varint(s)
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))

        outputs = []
        num_outputs = read_varint(s)
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))

        for tx_in in inputs:
            items = []
            num_items = read_varint(s)
            for _ in range(num_items):
                item_len = read_varint(s)
                if item_len == 0:
                    items.append(0)
                else:
                    items.append(s.read(item_len))
                tx_in.witness = items

        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=True)

    
    def serialize(self):
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()
    
    def serialize_legacy(self):
        result = int_to_little_endian(self.version, 4)

        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()

        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        
        result += int_to_little_endian(self.locktime, 4)

        return result
    
    def serialize_segwit(self):
        result = int_to_little_endian(self.version, 4)

        result += b'\x00\x01'

        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()

        for tx_in in self.tx_ins:
            result += int_to_little_endian(len(tx_in.witness), 1)
            for item in tx_in.witness:
                if type(item) == int:
                    result += int_to_little_endian(item, 1)
                else:
                    result += encode_varint(len(item)) + item

        result += int_to_little_endian(self.locktime, 4)

        return result

    def fee(self, testnet=False):
        input_sum, output_sum = 0, 0

        for tx_in in self.tx_ins:
            input_sum += tx_in.value(testnet=testnet)

        for tx_out in self.tx_outs:
            output_sum += tx_out.amount

        return (input_sum - output_sum)

    def sig_hash(self, input_index, redeem_script=None):
        s = int_to_little_endian(self.version, 4)

        s += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                if redeem_script:
                    script_sig = redeem_script
                else:
                    script_sig = tx_in.script_pubkey(self.testnet)
            else:
                script_sig = None

            s += TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                sequence=tx_in.sequence,
            ).serialize()

        s += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)

        h256 = hash256(s)

        return int.from_bytes(h256, "big")
    
    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # grab the previous ScriptPubKey
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        # check to see if the ScriptPubkey is a p2sh
        if script_pubkey.is_p2sh_script_pubkey():
            # the last cmd has to be the RedeemScript to trigger
            cmd = tx_in.script_sig.cmds[-1]
            # parse the RedeemScript
            raw_redeem = int_to_little_endian(len(cmd), 1) + cmd
            redeem_script = Script.parse(BytesIO(raw_redeem))
            # the RedeemScript might be p2wpkh or p2wsh
            if redeem_script.is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index, redeem_script)
                witness = tx_in.witness
            elif redeem_script.is_p2wsh_script_pubkey():
                cmd = tx_in.witness[-1]
                raw_witness = encode_varint(len(cmd)) + cmd
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(input_index, witness_script=witness_script)
                witness = tx_in.witness
            else:
                z = self.sig_hash(input_index, redeem_script)
                witness = None
        else:
            # ScriptPubkey might be a p2wpkh or p2wsh
            if script_pubkey.is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index)
                witness = tx_in.witness
            elif script_pubkey.is_p2wsh_script_pubkey():
                cmd = tx_in.witness[-1]
                raw_witness = encode_varint(len(cmd)) + cmd
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(input_index, witness_script=witness_script)
                witness = tx_in.witness
            else:
                z = self.sig_hash(input_index)
                witness = None
        # combine the current ScriptSig and the previous ScriptPubKey
        combined = tx_in.script_sig + script_pubkey
        # evaluate the combined script
        return combined.evaluate(z, witness)
    
    def sign_input(self, input_index, privkey):
        z = self.sig_hash(input_index)
        der = privkey.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, "big")
        sec = privkey.point.sec()
        self.tx_ins[input_index].script_sig = Script([sig, sec])

        return self.verify_input(input_index)
    
    def is_coinbase(self):
        if len(self.tx_ins) != 1:
            return False
        
        if self.tx_ins[0].prev_tx != 0x0000000000000000000000000000000000000000000000000000000000000000:
            return False
        
        if self.tx_ins[0].prev_index != 0xffffffff:
            return False
        
        return True
    
    def coinbase_height(self):
        return little_endian_to_int(self.tx_ins[0].script_sig.cmds[0])
