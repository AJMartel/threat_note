import hashlib
import random
from app import db


class User(db.Model):
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String)
    email = db.Column(db.String)
    password = db.Column(db.String)
    apikey = db.Column(db.String)

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


class Setting(db.Model):
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    apikey = db.Column(db.String)
    odnskey = db.Column(db.String)
    vtinfo = db.Column(db.String)
    whoisinfo = db.Column(db.String)
    odnsinfo = db.Column(db.String)
    httpproxy = db.Column(db.String)
    httpsproxy = db.Column(db.String)
    threatcrowd = db.Column(db.String)
    vtfile = db.Column(db.String)
    circlinfo = db.Column(db.String)
    circlusername = db.Column(db.String)
    circlpassword = db.Column(db.String)
    circlssl = db.Column(db.String)
    pt_pdns = db.Column(db.String)
    pt_whois = db.Column(db.String)
    pt_pssl = db.Column(db.String)
    pt_host_attr = db.Column(db.String)
    pt_username = db.Column(db.String)
    pt_api_key = db.Column(db.String)
    cuckoo = db.Column(db.String)
    cuckoohost = db.Column(db.String)
    cuckooapiport = db.Column(db.String)
    farsightinfo = db.Column(db.String)
    farsightkey = db.Column(db.String)
    shodaninfo = db.Column(db.String)
    shodankey = db.Column(db.String)

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


class Indicator(db.Model):
    _id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(250))
    indicator_type = db.Column(db.String(50))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign._id'))
    campaign = db.relationship('Campaign', backref=db.backref('indicator', lazy='dynamic'))
    firstseen = db.Column(db.String(10))  #TODO: db.DateTime
    lastseen = db.Column(db.String(10))  #TODO: db.DateTime
    diamondmodel = db.Column(db.String(20))
    confidence = db.Column(db.String(10))
    notes = db.Column(db.Text)
    tags = db.Column(db.String(50))
    relationships = db.Column(db.String(250))

    def __init__(self, indicator, indicator_type, firstseen, lastseen, diamondmodel, confidence, notes, tags, relationships, campaign=None):

        self.indicator = indicator
        self.campaign = campaign
        self.indicator_type = indicator_type
        self.firstseen = firstseen
        self.lastseen = lastseen
        self.diamondmodel = diamondmodel
        self.confidence = confidence
        self.notes = notes
        self.tags = tags
        self.relationships = relationships

    def get_id(self):
        return self._id


class Campaign(db.Model):
    _id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    notes = db.Column(db.Text)
    tags = db.Column(db.String(50))
    #indicator_ids = db.Column(db.Integer, db.ForeignKey('indicator._id'))
    #iocs = db.relationship('Indicator', backref=db.backref('campaign', lazy='dynamic'))
    #adversary_id = db.Column(db.Integer, db.ForeignKey("adversaries._id"), nullable=False)

    def __init__(self, name, notes, tags, ):
        self.name = name
        self.notes = notes
        self.tags = tags
        #self.iocs = iocs

    def get_id(self):
        return self._id





'''
class Attack(db.Model):
    __tablename__ = 'attacks'
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns._id"), nullable=False)
    description = db.Column(db.String)
    notes = db.Column(db.String)
    tags = db.Column(db.String)

    def __init__(self, attack_id, campaign_id, description, notes, tags):
        self.attack_id = attack_id
        self.campaign_id = campaign_id
        self.description = description
        self.notes = notes
        self.tags = tags

    def get_id(self):
        return self._id


class Adversary(db.Model):
    __tablename__ = 'adversaries'
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    ttps = db.Column(db.String)
    notes = db.Column(db.String)
    tags = db.Column(db.String)

    def __init__(self, adversary_id, name, ttps, notes, tags):
        self.adversary_id = adversary_id
        self.name = name
        self.ttps = ttps
        self.notes = notes
        self.tags = tags

    def get_id(self):
        return self._id
'''
