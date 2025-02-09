def strdec(offset):
    enc_str_addr = 0x0040b898
    enc_str_size = 0x373b
    enc_str = bv.read(enc_str_addr, enc_str_size)
    xor_key_addr = 0x00410130
    xor_key_size = 0x40
    xor_key = bv.read(xor_key_addr, xor_key_size)
    dec = ""
    if offset < enc_str_size - 1:
        temp = offset
        while temp < enc_str_size - 1:
            if xor_key[temp & 0x3f] == enc_str[temp]:
                length = temp - offset
                break
            temp += 1
    for i in range(length):
        dec += chr(xor_key[(offset + i) & 0x3f] ^ enc_str[offset + i])
    log_info(f"Decrypted string: {dec} at offset {offset}")
    return dec

func = bv.get_functions_by_name("str_decrypt2")[0]
caller_sites = [cs for cs in func.caller_sites]
decs = []

for cs in caller_sites:
    offset = cs.mlil.params[0]
    # At some callsites, the offset is a constant, at others it is a variable
    if offset.operation == MediumLevelILOperation.MLIL_CONST:
        offset = offset.constant
        decs.append((strdec(offset), offset))
    else:
        log_info(f"Failed to decrypt string at {hex(cs.address)} because offset is not a constant ({offset.operation})")


#### create enum for decs and add them to the enum ###
bv.begin_undo_actions()

dec_members = []
for dec in decs:
    dec_members.append((dec[0], dec[1]))

# Anonymous enum
enum = Type.enumeration(arch=bv.arch, members=dec_members, width=4)

# Enum building
builder = TypeBuilder.enumeration()
for member in enum.members:
    builder.append(member.name, member.value)
registered_name = bv.define_user_type("dec_enum", builder.immutable_copy())
enum_type = bv.get_type_by_name(registered_name)
bv.commit_undo_actions()