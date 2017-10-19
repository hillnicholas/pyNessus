#!/usr/bin/env python

# Simple wrapper of the requests library catered towards the Nessus scanner web interface.


import requests, getpass

HOST = "127.0.0.1"
PORT = "8834"
URL = "https://" + HOST + ":" + PORT
PROXY = dict( http = "socks5://localhost:8080", https = "socks5://localhost:8080" )


class Nessus():

    def __init__( self, host , port = None ):
        
        self.session = requests.Session()
        self.proxies = None
        self.verify = False
        self.host = host

        if port:
            port = ":" + port
        else:
            port = ""

        self.url = "https://" + host + port
        self.is_logged_in = False
        
    
    
    # logs user into the Nessus object
    def login(self, username, password ):
        response = self.session.post( URL + "/session" , proxies = PROXY, verify = False,
                   json={
                       "username": username,
                       "password": password
                       }
                     )
        # collect the token
        self.TOKEN = response.json()["token"]
        self.session.headers["X-Cookie"] = "token=" + self.TOKEN.encode("utf-8")
        self.is_logged_in = True



    # send a GET request.
    def get( self, path, params = None ):
        if self.is_logged_in:
            return self.session.get( URL + "/" + path, params = params, proxies = self.proxies , verify = self.verify )
        else:
            print "Not logged in."



    # send a POST request.
    def post( self, path, params = None, json = None ):
        if self.is_logged_in:
            return self.session.post( URL + "/" + path, params = params, json = json, proxies = self.proxies , verify = self.verify )
        else:
            print "Not logged in."





if __name__ == "__main__":
	# create Nessus scanner object
	scanner = Nessus("127.0.0.1")
	
	# set the proxies (probably not needed for your access)
	scanner.proxies =  PROXY
	
	# disable warnings for bad SSL certs
	scanner.verify = False

	# get scan configurations
	scans = scanner.get("scans").json()

	# get results of scan with ID 18
	scan_18 = scanner.get("scans/18").json()

