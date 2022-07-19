import subprocess
import re
import time
import matplotlib
import matplotlib.pyplot as plt
version = "-4"
data =[]
RTT = []
ttl=1

def plot(data,RTT):
    plt.plot(data,RTT)
    plt.ylabel("Round Trip Time")
    plt.xlabel("Number of Hops")

    plt.savefig("TTL vs RTT.png")
    plt.show()


def run():
    ttl=1
    # RTT=[]
    while(ttl<31):
    # for ttl in range(1, 31)
    #     bashCmd = ["ping", version, "-i", str(ttl),destination]
        process = subprocess.Popen(["ping", version, "-i", str(ttl),destination], stdout = subprocess.PIPE)
        output, error =  process.communicate()
        output=output.split(b"\n")
        process.kill()
        # output = output.split(b"\n")
        l=[]
        for i in output:
            l.append(i.decode('utf-8'))
        output=l
        # output = [i.decode('utf-8') for i in output]
        print("TTL = ", ttl,flush = True)
        s = None
        i=2
        # l=graph(s,output,ttl)

        while (i<5):
        # for i in range(2, 5):
            if(output[i].find('timed out') == -1):
                if(output[i].find('expired') == -1):
                    RTT.append(int(output[i].split()[4].split("=")[1][:-2]))
                    print(output[i], flush=True)
                    data.append(ttl)
                    print(output[i].split()[4].split("=")[1][:-2], flush=True)


                    plot(data, RTT)

                    return
                else:
                    s = output[i]
            i=i+1



        if(s!=None):
            s = s.split()
            # bashCmd = ["ping", version, s[2][:-1]]
            print(s[2][:-1])
            process = subprocess.Popen(["ping", version, s[2][:-1]], stdout = subprocess.PIPE)
            output, error =  process.communicate()

            output = output.split(b"\n")
            process.kill()
            l=[]
            for i in output:
                l.append(i.decode('utf-8'))
            output=l
            # output = [i.decode('utf-8') for i in output]
            cnt = 0
            time = 0
            i=2
            while(i<5):
            # for i in range(2, 5):
                if(output[i].find('expired')==-1):
                    if(output[i].find('timed out') == -1):
                       cnt+=1
                       s= output[i].split()[4]
                       st = s.split("=")[1][:-2]
                       time+=int(st)
                       print(st, "ms",end = ' ',flush = True)


                else:
                    print("*",end = ' ',flush = True)
                i=i+1


            if(cnt!=0):
                data.append(ttl)
            if(cnt!=0):
                RTT.append(time/cnt)
            if(cnt!=0):
                print("RTT = ", time/cnt,flush = True)
            else:
                data.append(ttl)
                RTT.append(0)
                print("RTT = 0 due to ping failure", flush=True)
        else:
           RTT.append(0.0)
           data.append(ttl)
           print("*   *    *  RTTT = 0 due to timeout", flush=True)
        ttl=ttl+1
print("Enter the destination to Traceroute: ",flush =True)
url = input().split()[0]
print("Tracing route to ", url,flush = True)
destination=url
count=0


run()