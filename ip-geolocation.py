#! /usr/bin/python

import os
import sys
import argparse
import logging
import sqlite3
import whois
import simplekml
import subprocess
import re
import socket
import pygeoip
import time
import os
import signal
import pandas
import requests
import csv
import pandas.io.sql as sqlio
from multiprocessing import Pool
from sqlalchemy import Column, Integer, Float, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from progressbar import ProgressBar

# SQLAlchemy Config

Base = declarative_base()

citylist = []
filename = "report.txt"
with open(filename, 'a') as rfile:
    rfile.write("***** IP Geolocation *****" + "\n")

logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)

#Database Classes

class ipRecord(Base):
    __tablename__ = 'ipgeolocation'

    id = Column(Integer,primary_key = True)
    url = Column(String)
    domainip = Column(String)
    whoisinfo = Column(String)
    nameserverips = Column(String)
    servermeta = Column(String)
    geodata = Column(String) 

    def __init__(self,url, domainip, whoisinfo, nameserverips, servermeta, geodata, **kwargs):
		self.url = url
		self.domainip = domainip 
                self.whoisinfo = whoisinfo
                self.nameserverips = nameserverips
		self.servermeta = servermeta
		self.geodata = geodata


class ipGeolocation(object):

    def __init__(self,url = ''):
        if url == '':
            raise Exception('No URL provided')

        self.url = url
        self.path = os.path.dirname(os.path.abspath(__file__))
        self.rawdata = pygeoip.GeoIP(self.path + '/GeoLiteCity.dat')
        self.clist = []
        self.pos = ()

        
            

        self.db = 'ipgeolocation.db'
        self.engine = create_engine('sqlite:///'+self.db, echo=False)
	Base.metadata.create_all(self.engine)

        session = sessionmaker(bind=self.engine)
	self.session = session()

    def signal_handler(self, signum, frame):
        print ('WHOIS timeout!',signum)
        raise Exception("Timed out!")
    
    def whoisLookup(self):
        #print self.url
        #signal.signal(signal.SIGALRM, self.signal_handler)
        #signal.alarm(10)
        #domain = subprocess.check_output(["whois", self.url, "|", "grep", "nameserver"])
        try:
            time.sleep(2)
            self.domain = whois.query(self.url)
            nameservers = (self.domain.name_servers)
            #print list(nameservers)
            #time.sleep(20)
            return list(nameservers)
            
        except Exception, error:
            nameservers = 'Not Found'
            pass

    def getsiteIP(self):
        try:
            self.siteip = socket.gethostbyname(self.url)
        except Exception, error:
            self.siteip = 'Not Found'
        
    def dnsLookup(self, nameservers):
        self.iplist = []
        try:
            for ns in nameservers:
                ip = socket.gethostbyname(ns)
                self.iplist.append(ip)
            return self.iplist
        except Exception, error:
            self.iplist.append('Not Found')
            pass
            
                                             
    def serverFingerprint(self):
        try:
            req = requests.get('http://' + self.url)
            headers = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Country-Code']
            self.sermeta = req.headers
            self.serverInfo = req.headers['Server']
            self.serverDate = req.headers['Date']
            self.serverXP = req.headers['X-Powered-By']
            for header in headers:
                try:
                    self.result = req.headers[header]
                    self.r = '%s: %s' % (header, self.result)
                except Exception, error:
                    self.r = '%s: Not found' % header
        except Exception, error:
            self.serverXP = 'Not found'
            pass

    def gpsData(self, iplist):
        try:
            for ip in iplist:
                data = self.rawdata.record_by_name(ip)
                self.city = data['city']
                self.lat = data['latitude']
                self.longi = data['longitude']
                self.pos = (self.city, self.lat, self.longi)
                self.clist.append(self.pos)
            #print self.clist
            return (self.clist)
                
        except Exception, error:
            self.clist.append('Not Found')
            pass

    def genKML(self, pos):
        try:
            for p in pos:
                citylist.append(p)
                kml = simplekml.Kml(open = 1)
                sp = kml.newpoint(name='The World', coords=[(0.0, 0.0)])
                for city, latu, longy in citylist:
                    pnt = kml.newpoint()
                    pnt.name = city
                    pnt.coords = [(longy,latu )]
                    
                kml.save('geodata.kml', format = False)
        
        except:
            pass

    def saveToDatabse(self):
        try:
            self.saveSQL(ipRecord(self.url, self.siteip, str(self.domain.__dict__), str(self.iplist), str(self.sermeta), str(self.clist)))

            with open(filename,'a') as rfile:
                rfile.write("[+]URL: " + self.url + "\n")
                rfile.write("[+]Domain IP: " + str(self.siteip) + "\n")
                rfile.write("[+]Domian Registrar: " + str(self.domain.registrar) + "\n")
                rfile.write("[+]Name Servers: " + str(self.domain.name_servers) + "\n")
                rfile.write("[+]Name Server IPs: " + str(self.iplist) + "\n")
                rfile.write("[+]Server Info: " + self.serverInfo + "\n")
                rfile.write("[+]Server Date: " + self.serverDate + "\n")
                try:
                    rfile.write("[+]Server X-Powered-By: " + self.serverXP + "\n")
                except Exception,error:
                    rfile.write("[+]Server X-Powered-By: Not Found" + self.serverXP + "\n")
                rfile.write("[+]Server Locations: " + str(self.clist) + "\n")
                rfile.write(" " + "\n")
        except:
            with open(filename, 'a') as rfile:
                rfile.write(" " + "\n")
            pass

    def saveSQL(self, row):
        try:
            self.session.add(row)
            self.session.commit()
        except:
            pass

    def convertcsv(self):
        try:
            con = sqlite3.connect(self.db)
            ipGeoRecord = sqlio.read_sql('select * from ipgeolocation', con)
            ipGeoRecord.to_csv('Database-Dump.csv')
        except:
            pass
        
        


def main(argv):
    parser = argparse.ArgumentParser(description='IP Geolocation')
    parser.add_argument('url',help='URL(s) to be analyzed; Ex.format:www.google.com; newline delimited text file or single URL')
    args=parser.parse_args()

    try:
        if os.path.isfile(args.url) and os.path.splitext(os.path.basename(args.url))[1] == '.txt':
	    with open(args.url) as ifile:
                lines = ifile.read()
                lines = lines.replace("http://","")
                lines = lines.replace("https://","")
                lines = lines.replace("www.", "") # May replace some false positives ('www.com') 
                urls = [url.split('/')[0] for url in lines.split()]
		urls = '\n'.join(urls)
                urls = urls.splitlines()
	else:
	    raise Exception('')
    except:
	try:
	    urls = [url for url in args.url.split(',')]
	except:
	    urls = args.url


    pbar = ProgressBar()

    for url in pbar(urls):
        c = url.count('.')
        if c > 1:
            url = url.split('.', c-1)[c-1]
        else:
            url = url
        ipgl = ipGeolocation(url)
        nameservers = ipgl.whoisLookup()
        iplist = ipgl.dnsLookup(nameservers)
        loc = ipgl.gpsData(iplist)
        ipgl.getsiteIP()
        ipgl.genKML(loc)
        ipgl.serverFingerprint()
        ipgl.saveToDatabse()
        ipgl.convertcsv()
        

    print 'All URLs analyzed. URL and IP information stored in `ipgeolocation.db`'

if __name__ == '__main__':
	main(sys.argv)
        
    
        
        
    

