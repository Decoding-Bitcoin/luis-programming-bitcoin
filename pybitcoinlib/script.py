from io import BytesIO

from util import *
from op import *

class Script:
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s):
        lenght = read_varint(s)
        cmds = []
        count = 0

        while count < lenght:
            current = s.read(1)
            count += 1
            current_byte = current[0]

            # <elem> (size of 1 to 75 bytes)
            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            # OP_PUSHDATA1 <elem> (size of 76 to 255 bytes)
            elif current_byte == 76:
                data_lenght = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_lenght))
                count += data_lenght + 1
            # OP_PUSHDATA2 <elem> (size of 256 to 520 bytes)
            elif current_byte == 77:
                data_lenght = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_lenght))
                count += data_lenght + 1
            # otherwise it's an operation and not an <elem>
            else:
                op_code = current_byte
                cmds.append(op_code)

        # lenghts must match
        if count != lenght:
            raise SyntaxError("script parsing failed")
        
        return cls(cmds=cmds)
    

    def raw_serialize(self):
        result = b""

        for cmd in self.cmds:
            # OP code
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)
            # <elem>
            else:
                length = len(cmd)

                if length < 75:
                    result += int_to_little_endian(length, 1)

                elif length >= 75 and length < 256:
                    result += int_to_little_endian(76, 1) # OP_PUSHDATA1
                    result += int_to_little_endian(length, 1)
                
                elif length >= 256 and length <= 520:
                    result += int_to_little_endian(77, 1) # OP_PUSHDATA2
                    result += int_to_little_endian(length, 2)
                
                else:
                    raise ValueError("command is too long")
                
                result += cmd
            
        return result
    
    def serialize(self):
        result = self.raw_serialize()
        total = len(result)

        return encode_varint(total) + result
    
    # evals a Script (ScriptSig + ScriptPubKey)
    def evaluate(self, z):
        cmds = self.cmds[:]
        stack = []
        altstack = []

        while len(cmds) > 0:
            cmd = cmds.pop(0)

            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]

                if cmd in (99,100):
                    if not operation(stack, cmds):
                        return False

                elif cmd in (107,108):
                    if not operation(stack, altstack):
                        return False
                
                elif cmd in (172,173,174,175):
                    if not operation(stack, z):
                        return False
                
                else:
                    if not operation(stack):
                        return False
            
            else:
                stack.append(cmd)
                if len(cmds) == 3 and cmds[0] == 0xa9 \
                    and type(cmds[1]) == bytes and len(cmds[1]) == 20 \
                    and cmds[2] == 0x87:
                    cmds.pop()
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):
                        return False
                    
                    stack.append(h160)

                    if not op_equal(stack):
                        return False
                    if not op_verify(stack):
                        return False
                    
                    redeem_script = encode_varint(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds) 

        # an empty stack evals to false
        if len(stack) == 0:
            return False
        if stack.pop() == b"":
            return False

        return True
    
def p2pkh_script(h160):
    '''Takes a pubkey hash and returns the p2pkh ScriptPubKey'''
    return Script([0x76, 0xa9, h160, 0x88, 0xac])
        
