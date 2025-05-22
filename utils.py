import ida_hexrays
import ida_lines
import ida_name
import ida_idaapi
import ida_bytes
import ida_nalt
import ida_typeinf
import ida_kernwin
import idaapi

import subprocess
import sys
import tempfile
import functools


def main_thread(func):
    """
    Decorator to run a function in the main thread of IDA Pro.
    Args:
        func (callable): The function to run in the main thread.
    Returns:
        callable: A wrapper function that runs the original function in the main thread.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = [None]
        def run():
            result[0] = func(*args, **kwargs)
        idaapi.execute_sync(run, idaapi.MFF_READ)
        return result[0]
    return wrapper


@main_thread
def get_code(func_name: str) -> str:
    """
    Get the decompiled code of a function in IDA Pro.
    Args:
        func_name (str): The name or address (hex starting with 0x) of the function to decompile.
    Returns:
        str: The decompiled code of the function, or an error message.
    """
    print(f"Decompiling function: {func_name}")
    cfunc = ida_hexrays.decompile(int(func_name, 16) if func_name.startswith("0x") else ida_name.get_name_ea(0, func_name))
    if cfunc is None:
        return "Function not found"
    return "\n".join(ida_lines.tag_remove(l.line) for l in cfunc.get_pseudocode())


def execute_code(ask: bool = True):
    @main_thread
    def execute_code(code: str) -> str:
        """
        Execute Python code in a temporary file if the user agrees.
        Args:
            code (str): The Python code to execute.
        Returns:
            str: The output of the executed code.
        """
        if ask and ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, f"Do you want to execute this code?\n\n{code}") != ida_kernwin.ASKBTN_YES:
            return "Execution cancelled by user."
        print(f"Executing code: {code}")
        with tempfile.NamedTemporaryFile(delete=True, suffix=".py") as temp_file:
            temp_file.write(code.encode("utf-8"))
            temp_file.flush()
            try:
                result = subprocess.run([sys.executable, temp_file.name], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout
                else:
                    return f"Error executing code: {result.stderr}"
            except Exception as e:
                return f"Execution failed: {str(e)}"
    return execute_code


@main_thread
def get_string(var_name: str) -> str:
    """
    Get the string representation of a global variable in IDA Pro.
    Args:
        var_name (str): The name of the global variable to get.
    Returns:
        str: The string representation of the variable, or an error message.
    """
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, var_name)
    if ea == ida_idaapi.BADADDR:
        return f"Variable '{var_name}' not found."

    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_strlit(flags):
        str_data = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
        if str_data is not None:
            return str_data.decode("utf-8", "backslashreplace")
    
    return f"Variable '{var_name}' is not a string."


@main_thread
def get_bytes(var_name: str, size: int) -> str:
    """
    Get the byte representation of a global variable in IDA Pro.
    Args:
        var_name (str): The name of the global variable to get.
        size (int): The number of bytes to read.
    Returns:
        str: The byte representation of the variable, or an error message.
    """
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, var_name)
    if ea == ida_idaapi.BADADDR:
        return f"Variable '{var_name}' not found."

    raw_bytes = ida_bytes.get_bytes(ea, size)
    if raw_bytes is not None:
        return raw_bytes.hex()
    
    return f"Failed to read bytes from variable '{var_name}'."


@main_thread
def get_global_data(var_name: str) -> str:
    """
    Get the address, type, and data of a global variable in IDA Pro.
    Args:
        var_name (str): The name of the global variable to get.
    Returns:
        str: A string describing the variable, or an error message.
    """
    print(f"Getting global data for variable: {var_name}")
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, var_name)
    if ea == ida_idaapi.BADADDR:
        return f"Variable '{var_name}' not found."

    type_str = "Unknown type"
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, tif, var_name, '')
        if not type_str:
            type_str = tif.dstr()
        if not type_str:
             type_str = "Type info found but could not be represented as string"
    else:
        pass # Stays "Unknown type"

    value_representation = ""
    try:
        flags = ida_bytes.get_flags(ea)
        item_size = ida_bytes.get_item_size(ea)

        if ida_bytes.is_strlit(flags):
            str_data = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
            if str_data is not None:
                value_representation = f'"{str_data.decode("utf-8", "backslashreplace")}"'
        
        if not value_representation and item_size > 0 :
            if tif.is_char() or tif.is_uchar() or item_size == 1:
                val = ida_bytes.get_byte(ea)
                char_representation = chr(val) if 32 <= val <= 126 else '.'
                value_representation = f"0x{val:02X} ('{char_representation}')"
            elif tif.is_int16() or tif.is_uint16() or item_size == 2:
                val = ida_bytes.get_word(ea)
                value_representation = f"0x{val:04X} ({val})"
            elif tif.is_int32() or tif.is_uint32() or item_size == 4:
                val = ida_bytes.get_dword(ea)
                value_representation = f"0x{val:08X} ({val})"
            elif tif.is_int64() or tif.is_uint64() or item_size == 8:
                val = ida_bytes.get_qword(ea)
                value_representation = f"0x{val:016X} ({val})"

        if not value_representation and item_size > 0:
            display_size = min(item_size, 64)
            raw_bytes = ida_bytes.get_bytes(ea, display_size)
            if raw_bytes:
                value_representation = f"Bytes: {raw_bytes.hex()}"
                if item_size > display_size:
                    value_representation += f"... (total {item_size} bytes)"
            else:
                value_representation = "(Failed to read bytes)"
        elif not value_representation and item_size == 0:
             if ida_nalt.is_public_name(ea) and ida_nalt.is_extern_name(ea):
                 value_representation = "(Extern symbol, data not available in this file)"
             else:
                value_representation = "(Zero size or data not defined)"

    except Exception as e:
        value_representation = f"(Error reading data: {str(e)})"

    return f"Name: {var_name}, Address: 0x{ea:X}, Type: {type_str if type_str else 'N/A'}, Value: {value_representation if value_representation else 'N/A'}"
