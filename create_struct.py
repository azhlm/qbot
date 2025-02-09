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

def count_structs(buffer):
    struct_size = struct.calcsize("3I")  # Each struct has 3 unsigned 4-byte integers
    count = 0
    for i in range(0, len(buffer), struct_size):
        if i + struct_size > len(buffer):  # Ensure we don't read beyond the buffer
            break
        first, second, third = struct.unpack_from("3I", buffer, i)
        if first == 0:  # Stop condition
            break
        count += 1
    return count

def update_dec_enum(name, offset):
    enum_t = bv.types['dec_enum'].mutable_copy()
    enum_t.append(name, offset)
    bv.define_user_type("dec_enum", enum_t)

def update_member(arg):
    try:
        offset = arg.value
        decrypted = strdec(offset)
        update_dec_enum(decrypted, offset)
    except:
        offset = arg.value.value
        decrypted = strdec(offset)
    return decrypted

func = bv.get_functions_by_name("mw_resolve_api_struct")[0]
caller_sites = [cs for cs in func.caller_sites]
structs_array = []
size = 0x1000

bv.begin_undo_actions()
for cs in caller_sites:
    addr = cs.mlil.params[0].constant
    structs_array.append(addr)
    buffer = bv.read(addr, size)
    count = count_structs(buffer)
    log_info(f"Found {count} structs at {hex(addr)}")
    bv.define_user_data_var(addr, f"api_struct [{count}]")

bv.update_analysis_and_wait()
for structs in structs_array:
    structs = bv.get_data_var_at(structs)
    for structure in structs:
        api_addr = structure['api_addr'].value
        api_name = update_member(structure['api_name'])
        dll_name = update_member(structure['dll_name'])
        bv.define_user_data_var(api_addr, "void*")
        var = bv.get_data_var_at(api_addr)
        var.name = "mw_" + api_name
        log_info(f"Decrypted API name: {api_name} at {hex(api_addr)}")
        log_info(f"Decrypted DLL name: {dll_name} at {hex(api_addr)}")

log_info("Structs created successfully")
bv.commit_undo_actions()