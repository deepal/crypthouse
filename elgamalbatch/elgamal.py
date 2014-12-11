#! /usr/bin/python2

import utils, hashlib, time, random
from math import ceil

class ElGamalSignature(object):

    def __init__(self, p = None, x = None, g = None):

        if p == None and x == None:
                pass
        self.g = g
        self.p = p
        self.y = pow(self.g, x, self.p)			# Calculate g^x (mod p)

        self.pub = (self.p, self.g, self.y)		# Public key is (p, g, y)
        self.priv = x								# Private key is 'x'

    def sign(self, m, k):

        md5obj = hashlib.md5()
        md5obj.update(str(m))
        digest = md5obj.hexdigest()
        mhash = int(digest,16)
        
        r = pow(self.g, k, self.p)
        s = ((mhash - self.priv * r) * utils.inv_modulo(k, self.p - 1)) % (self.p - 1)
        return (r, s)

    def verify(self, m, sig):

        r = sig[0]
        s = sig[1]
        
        md5obj = hashlib.md5()
        md5obj.update(str(m))
        digest = md5obj.hexdigest()
        mhash = int(digest,16)  
        
        return (pow(self.y, r) * pow(r, s)) % self.p == pow(self.g, mhash, self.p)
        
    def batchVerify(self, msglist, siglist, batchSize=10):

        listverified = True
        mlist = []

        for msg in msglist:
            md5obj = hashlib.md5()
            md5obj.update(str(msg))
            digest = md5obj.hexdigest()
            mhash = int(digest,16)
            mlist.append(mhash)
        
         
        for j in range(int(ceil(float(len(msglist))/batchSize))):
            msgbatch = []
            sigbatch = []
            rlist = []
            slist = []
            rsmul = 1
            
            mlistbound = min(10, len(mlist))
            
            for i in range(0, mlistbound):
                index = random.randint(0,mlistbound-1)
                msgbatch.append(mlist.pop(index))
                sigbatch.append(siglist.pop(index))
                mlistbound = min(10, len(mlist))
        
            for sig in sigbatch:
                rlist.append(sig[0])
                slist.append(sig[1])
                rsmul = rsmul * pow(sig[0], sig[1])
    
            hashSum = sum(msgbatch)
            rSum = sum(rlist)
            listverified = listverified & ((pow(self.y,rSum)*rsmul) % self.p == pow(self.g, hashSum, self.p));
        
        return listverified
    

    def singleVerify(self, msglist, siglist):
        listverified = True
        
        mlist = []

        for msg in msglist:
            md5obj = hashlib.md5()
            md5obj.update(str(msg))
            digest = md5obj.hexdigest()
            mhash = int(digest,16)
            mlist.append(mhash)		

        if len(mlist) == len(siglist):
            for i in range(len(mlist)):
                listverified = listverified & ((pow(self.y, siglist[i][0]) * pow(siglist[i][0], siglist[i][1])) % self.p == pow(self.g, mlist[i], self.p))
        else:
            print "Message list and the signatures list size does not match !!"
            exit()

        return listverified


    def __str__(self):
        return """Public key: %s\nPrivate key: %s""" % (self.pub, self.priv)

if __name__ == "__main__":

    msglist = []
    el = ElGamalSignature(23, 6, 7)
    print "\n",el
    fp = open("/home/deepal/Desktop/elgamaloutput.txt","a+")

    for i in range(20):
        msglist.append(random.getrandbits(128))
            
    siglist = []
    
    for msg in msglist:
        siglist.append(el.sign(msg, 5))
    
    timestartsingleverify = time.time()
    print "Verfication (single mode) :", el.singleVerify(msglist, siglist)
    timestopsingleverify = time.time()
    singleverifytime = (timestopsingleverify-timestartsingleverify)*1000000
    
    print "Elapsed time for single verification: ",singleverifytime," microseconds\n"
    
    timestartbatchverify = time.time()
    print "Verfication (batch mode) :", el.batchVerify(msglist, siglist, 10)
    timestopbatchverify = time.time()
    batchverifytime = (timestopbatchverify-timestartbatchverify)*1000000
    
    print "Elapsed time for batch verification: ",batchverifytime," microseconds\n"
    
    fp.write(str(singleverifytime)+"\n")
    fp.write(str(batchverifytime)+"\n")     

    fp.close()    
    exit()
    

