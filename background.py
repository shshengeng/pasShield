
import os
import threading
import time


def runEgoServer():
    cmd = "ego run ~/Desktop/ego/samples/azure_attestation/server"
    os.system(cmd)


#stop_threads = False
while True:
    #stop_threads = False
    thread1 = threading.Thread(target=runEgoServer)
    thread1.start()
    time.sleep(60*60*2)
    os.system("kill `lsof -t -i:8080`")
    time.sleep(10)



