#!/usr/bin/python
import queue
import threading
import time
import sys, os, getopt

from subprocess import Popen, PIPE

queue = queue.Queue()
start = time.time()

dump_plugins = []
#dump_plugins = ["windows.dumpcerts", "windows.dumpregistry", "windows.dumpfiles", "windows.dumpregistry", "windows.servicediff"]

plugins = [ "windows.malfind", "windows.cmdline", "windows.pstree", "windows.netscan", "windows.netstat", "windows.callbacks"]
#plugins = ["amcache", "auditpol", "cachedump", "clipboard", "windows.cmdline", "cmdscan", "connections", "connscan", "consoles", "deskscan", "devicetree", "dlllist",
#            "envars", "getservicesids", "handles", "hashdump", "hibinfo", "hivelist", "hivescan", "iehistory", "ldrmodules", "lsadump", "malfind", "mbrparser", "memmap", "mftparser", "modules", "notepad", 
#            "privs", "pslist", "windows.psscan", "pstree", "psxview", "qemuinfo", "servicediff", "sessions", "sockets", "sockscan", "ssdt", "strings", "svcscan", "symlinkscan", "thrdscan", "verinfo", "windows", "wintree"]

plugins_all = [ "windows.malfind", "windows.cmdline", "windows.pstree", "windows.netscan", "windows.netstat", "windows.callbacks"]
#plugins_all = [ "amcache", "apihooks", "atoms", "atomscan", "auditpol", "bigpools", "bioskbd", "cachedump", "callbacks", "clipboard", "cmdline", "cmdscan", "connections", "connscan", "consoles", "crashinfo",
#                "deskscan", "devicetree", "dlldump", "dlllist", "driverirp", "drivermodule", "driverscan", "editbox", "envars", "eventhooks", "evtlogs", "filescan", 
#                "gahti", "gditimers", "gdt", "getservicesids", "getsids", "handles", "hashdump", "hibinfo", "hivelist", "hivescan", "hpakextract", "hpakinfo", "idt", "iehistory", "imagecopy", "imageinfo",
#                "joblinks", "kdbgscan", "kpcrscan", "ldrmodules", "lsadump", "malfind", "mbrparser", "memdump", "memmap", "messagehooks", "mftparser", "moddump", "modscan", "modules", "multiscan", "mutantscan",
#                "notepad", "objtypescan", "patcher", "printkey", "privs", "procdump", "pslist", "psscan", "pstree", "psxview", "qemuinfo", "raw2dmp", "sessions", "shellbags", "shimcache",
#                "shutdowntime", "sockets", "sockscan", "ssdt", "strings", "svcscan", "symlinkscan", "thrdscan", "threads", "timeliner", "timers", "truecryptmaster", "truecryptpassphrase", "truecryptsummary",
#                "unloadedmodules", "userassist", "userhandles", "vaddump", "vadinfo", "vadtree", "vadwalk", "vboxinfo", "verinfo", "vmwareinfo", "windows", "wintree", "wndscan"]

dump_noDir = ["hashdump"]

class ThreadVol(threading.Thread):
    """Threaded Volatility"""
    def __init__(self, queue, out_dir, memfile, vol_path):
        threading.Thread.__init__(self)
        self.queue = queue
        self.out_dir = out_dir
        self.memfile = memfile
        self.profile = ""
        self.vol_path = vol_path

    def run(self):
        while True:
            #grabs plugin from queue
            plugin = self.queue.get()

            # Create plugin dir
            plugin_dir = self.out_dir
            if not os.path.exists(plugin_dir):
                os.makedirs(plugin_dir)
            
            # Run volatility
            if ("dump" in plugin and not plugin in dump_noDir) or (plugin in dump_plugins):
                cmd = self.vol_path+" -f "+ self.memfile+" "+plugin+"  --dump-dir="+plugin_dir
            else:
                cmd = self.vol_path+" -f "+ self.memfile+" "+plugin
            print(cmd)
            pw = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
            stdout,stderr = pw.communicate()
            if stderr: print(stderr)

            # Write the output
            with open(plugin_dir+"/"+plugin+".txt",'wb') as f:
                f.write(stdout)

            #signals to queue job is done
            self.queue.task_done()






def main(argv):
    global plugins, plugins_all
    hlp = "autoVol.py -f MEMFILE -d DIRECTORY [-e VOLATILITY-PATH] [-a] [-p PROFILE] [-c 'plugin1,plugin2,plugin3']"
    try:
        opts, args = getopt.getopt(argv,"hf:d:p:c:ae:t:",["help","file","directory=","profile=","console=","all", "volatility-path=", "threads="])
    except getopt.GetoptError as err:
        print("~ %s" % str(err))
        print(hlp)
        sys.exit(2)

    memfile, console, directory, profile, use_all, vol_path, threads = "", "", "", "", False, "volatility", 8

    for opt, arg in opts:
        if opt == '-h':
            print(hlp)
            sys.exit()

        elif opt in ("-f","--file"):
            memfile = arg
            if not os.path.exists(memfile):
                print("File in path "+memfile+" does not exists")
                sys.exit()
        
        elif opt in ("-d","--directory"):
            directory = arg
            if not os.path.exists(directory):
                try: 
                    os.makedirs(directory)
                except:
                    print("Not a directory or not enough permissions: "+directory)
                    sys.exit()
            if not os.path.isdir(directory) or not os.access(directory, os.W_OK):
                print("Not a directory or not enough permissions: "+directory)
                sys.exit()



        elif opt in ("-c", "--console"):
            console = arg
        
        elif opt in ("-a", "--all"):
            use_all = True

        elif opt in ("-e", "--volatility-path"):
            vol_path = arg
        
        elif opt in ("-t", "--threads"):
            threads = int(arg)



    if not directory:
        print("Set a directory using the option -d")
        print(hlp)    
        sys.exit()


    #populate queue with data
    if console == "": # If not console, default plugins
        for plugin in dump_plugins:
            queue.put(plugin)

        if use_all:
            for plugin in plugins_all:
                queue.put(plugin)
        else:
            for plugin in plugins:
                queue.put(plugin)
    
    else: #If console, only pllugins defined in console
        plugins = console.split(",")
        for plugins in plugin:
            queue.put(plugin)

    #run X threads
    for i in range(threads):
        t = ThreadVol(queue, directory, memfile, vol_path)
        t.daemon = True
        t.start()
        time.sleep(0.1)



    #wait on the queue until everything has been processed     
    queue.join()
    print("Elapsed Time: %s" % (time.time() - start))


    

if __name__ == "__main__":
    main(sys.argv[1:])
