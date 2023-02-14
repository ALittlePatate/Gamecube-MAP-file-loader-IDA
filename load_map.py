import ida_search
import idc
import tkinter.filedialog

def rename_func(addr, function_name) : 
    if addr == idc.BADADDR :
        print("Bad address")
        return
    
    if not idc.set_name(int(addr, 16), function_name, 0x800) : #the 0x800 flag is for "FORCE", so it will rename the function even if it already has a name.
        print("Rename address failed")
        return
    
    print(f"{addr} --> {function_name}")
    
def read_map(file_path) :
    with open(file_path, 'r') as f :
        in_section = False
        for line in f.readlines() :
            if "  -----------------------" in line :
                in_section = True

            elif in_section :
                if line == "\n" :
                    in_section = False
                    continue

                line = line[18:] #8040e570  4 @354 	JSystem.a JALCalc.cpp
                data = line.split(" ")
                addr = data[0]
                name = data[3]

                if "." in addr : continue

                rename_func(addr, name)

print("[+] Starting...")
file_path = filedialog.askopenfilename()

print("[+] Scanning map file")
read_map(file_path)
print("[+] Done !")
