import requests
import argparse


#tsreq = "MDQCAQEwITAJBgUrDgMCGgUABBTd45YiWW5cCvuKDwcKJ4yFoJgESAIJALmkGdR0+/AKAQH/"
url = "http://dse200.ncipher.com/TSS/HttpTspServer"


#r = requests.post(url,tsreq)
#print r.text

parser = argparse.ArgumentParser(description='Short sample app')
parser.add_argument("-in", action="store", dest="tsreq", required=True)
parser.add_argument("-out", action="store", dest="tsresp", required=True)

#print parser.parse_args().tsreq

fIn = open(parser.parse_args().tsreq, "r")
req = fIn.read()


r = requests.post(url,req)

out = open(parser.parse_args().tsresp,"wb")
out.write(r.text)
#print r.text