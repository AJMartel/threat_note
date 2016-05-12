import hashlib
import random

from database import Base
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import ForeignKey


class User(Base):
    __tablename__ = 'users'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    user = Column('user', String)
    email = Column('email', String)
    password = Column('password', String)
    apikey = Column('apikey', String)

    def __init__(self, user, password, email):
        self.user = user.lower()
        self.password = hashlib.md5(password.encode('utf-8')).hexdigest()
        self.email = email
        self.apikey = hashlib.md5(user + str(random.random()).encode('utf-8')).hexdigest()

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self._id

    def get_apikey(self):
        return self.apikey

    def __repr__(self):
        return '<User %r>' % (self.user)


class Setting(Base):
    __tablename__ = 'settings'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    apikey = Column('apikey', String)
    odnskey = Column('odnskey', String)
    vtinfo = Column('vtinfo', String)
    whoisinfo = Column('whoisinfo', String)
    odnsinfo = Column('odnsinfo', String)
    httpproxy = Column('httpproxy', String)
    httpsproxy = Column('httpsproxy', String)
    threatcrowd = Column('threatcrowd', String)
    vtfile = Column('vtfile', String)
    circlinfo = Column('circlinfo', String)
    circlusername = Column('circlusername', String)
    circlpassword = Column('circlpassword', String)
    circlssl = Column('circlssl', String)
    pt_pdns = Column('pt_pdns', String)
    pt_whois = Column('pt_whois', String)
    pt_pssl = Column('pt_pssl', String)
    pt_host_attr = Column('pt_host_attr', String)
    pt_username = Column('pt_username', String)
    pt_api_key = Column('pt_api_key', String)
    cuckoo = Column('cuckoo', String)
    cuckoohost = Column('cuckoohost', String)
    cuckooapiport = Column('cuckooapiport', String)
    farsightinfo = Column('farsightinfo', String)
    farsightkey = Column('farsightkey', String)
    shodaninfo = Column('shodaninfo', String)
    shodankey = Column('shodankey', String)

    def __init__(self, vtinfo, whoisinfo, odnsinfo, circlinfo, farsightinfo,
                    shodaninfo, circlssl, threatcrowd, vtfile,
                    pt_pdns, pt_whois, pt_pssl, pt_host_attr, pt_username, pt_api_key,
                    apikey, odnskey, circlusername, circlpassword, farsightkey,
                    cuckoo, cuckoohost, cuckooapiport, httpproxy, httpsproxy, shodankey):
        self.apikey = apikey
        self.odnskey = odnskey
        self.vtinfo = vtinfo
        self.whoisinfo = whoisinfo
        self.odnsinfo = odnsinfo
        self.httpproxy = httpproxy
        self.httpsproxy = httpsproxy
        self.threatcrowd = threatcrowd
        self.vtfile = vtfile
        self.circlinfo = circlinfo
        self.circlusername = circlusername
        self.circlpassword = circlpassword
        self.circlssl = circlssl
        self.pt_pdns = pt_pdns
        self.pt_whois = pt_whois
        self.pt_pssl = pt_pssl
        self.pt_host_attr = pt_host_attr
        self.pt_username = pt_username
        self.pt_api_key = pt_api_key
        self.cuckoo = cuckoo
        self.cuckoohost = cuckoohost
        self.cuckooapiport = cuckooapiport
        self.farsightinfo = farsightinfo
        self.farsightkey = farsightkey
        self.shodaninfo = shodaninfo
        self.shodankey = shodankey


class Indicator(Base):
    __tablename__ = 'indicators'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    indicator = Column('indicator', String)
    type = Column('type', String)
    firstseen = Column('firstseen', String)
    lastseen = Column('lastseen', String)
    diamondmodel = Column('diamondmodel', String)
    attack_id = Column('attack_id',  Integer, ForeignKey("attacks._id"), nullable=False)
    confidence = Column('confidence', String)
    notes = Column('notes', String)
    tags = Column('tags', String)
    relationships = Column('relationships', String)

    def __init__(self, indicator, _id, attack_id, type, firstseen, lastseen, diamondmodel, confidence,
                 notes, tags, relationships):
        self.   _id = _id
        self.indicator = indicator
        self.attack_id = attack_id
        self.type = type
        self.firstseen = firstseen
        self.lastseen = lastseen
        self.diamondmodel = diamondmodel
        self.confidence = confidence
        self.notes = notes
        self.tags = tags
        self.relationships = relationships


class Attack(Base):
    __tablename__ = 'attacks'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    campaign_id = Column('campaign_id', Integer, ForeignKey("campaigns._id"), nullable=False)
    description = Column('description', String)
    notes = Column('notes', String)
    tags = Column('tags', String)

    def __init__(self, attack_id, campaign_id, description, notes, tags):
        self.attack_id = attack_id
        self.campaign_id = campaign_id
        self.description = description
        self.notes = notes
        self.tags = tags


class Campaign(Base):
    __tablename__ = 'campaigns'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    name = Column('name', String)
    adversary_id = Column('adversary_id', Integer, ForeignKey("adversaries._id"), nullable=False)
    notes = Column('notes', String)
    tags = Column('tags', String)

    def __init__(self, _id, name, adversary_id, notes, tags):
        self._id = _id
        self.name = name
        self.adversary_id = adversary_id
        self.notes = notes
        self.tags = tags


class Adversary(Base):
    __tablename__ = 'adversaries'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    name = Column('name', String)
    ttps = Column('ttps', String)
    notes = Column('notes', String)
    tags = Column('tags', String)

    def __init__(self, adversary_id, name, ttps, notes, tags):
        self.adversary_id = adversary_id
        self.name = name
        self.ttps = ttps
        self.notes = notes
        self.tags = tags


'''
class Indicator(Base):
    __tablename__ = 'indicators'
    _id = Column('_id', Integer, primary_key=True, autoincrement=True)
    object = Column('object', String)
    type = Column('type', String)
    firstseen = Column('firstseen', String)
    lastseen = Column('lastseen', String)
    diamondmodel = Column('diamondmodel', String)
    campaign = Column('campaign', String)
    confidence = Column('confidence', String)
    comments = Column('comments', String)
    tags = Column('tags', String)
    relationships = Column('relationships', String)

    def __init__(self, object, type, firstseen, lastseen, diamondmodel, campaign, confidence, comments, tags,
                 relationships):
        self.object = object
        self.type = type
        self.firstseen = firstseen
        self.lastseen = lastseen
        self.diamondmodel = diamondmodel
        self.campaign = campaign
        self.confidence = confidence
        self.comments = comments
        self.tags = tags
        self.relationships = relationships
'''
