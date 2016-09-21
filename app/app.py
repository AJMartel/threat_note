

import csv
import io
import re
import time
import hashlib
import random


from libs import circl
from libs import cuckoo
from libs import farsight
from libs import helpers
from libs import opendns
from libs import passivetotal
from libs import shodan
from libs import virustotal
from libs import whoisinfo
from threat_note.models import Indicator
from threat_note.models import Campaign
from threat_note.models import Setting
from threat_note.models import User

from werkzeug.datastructures import ImmutableMultiDict








@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = db.query(User).filter_by(user=form.user.data.lower()).first()
        if user:
            flash('User exists.')
        else:
            # user = User(form.user.data.lower(), form.key.data, form.email.data)
            user = User('a', 'a', 'a')
            db.add(user)

            # Set up the settings table when the first user is registered.
            if not Setting.query.filter_by(_id=1).first():
                settings = Setting('off', 'off', 'off', 'off', 'off', 'off', 'off', 'off', 'off', 'off', 'off', 'off',
                                   'off', '', '', '', '', '', '', '', '', '', '', '', '', '')
                db.add(settings)
            # Commit all database changes once they have been completed
            db.commit()
            login_user(user)

    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('register.html', form=form, title='Register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = form.get_user()
        if not user:
            flash('Invalid User or Key.')
        else:
            login_user(user)

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    return render_template('login.html', form=form, title='Login')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/', methods=['GET'])
@login_required
def home():
    try:
        counts = Indicator.query.distinct(Indicator.indicator).count()
        types = Indicator.query.group_by(Indicator.indicator_type).all()
        #network = Indicator.query.order_by(Indicator.indicator.desc()).limit(5).all()
        campaigns = Campaign.query.group_by(Campaign.name).all()
        taglist = Indicator.query.distinct(Indicator.tags).all()

        network = Indicator.query.join(Campaign, Indicator.campaign_id == Campaign._id).order_by(Indicator._id.desc()).limit(5).all()
        for i in network:
            print i.name
        # Generate Tag Cloud
        tags = set()
        for indicator in taglist:
            if indicator.tags == "":
                pass
            else:
                for tag in indicator.tags.split(","):
                    tags.add(tag.strip())

        dictcount = {}
        dictlist = []
        typecount = {}
        typelist = []

        # Generate Campaign Statistics Graph
        for campaign in campaigns:
            c = Indicator.query.filter_by(campaign_id=campaign.get_id()).count()
            if campaign.name == '':
                dictcount["category"] = "Unknown"
                tempx = (float(c) / float(counts)) * 100
                dictcount["value"] = round(tempx, 2)
            else:
                dictcount["category"] = campaign.name
                tempx = (float(c) / float(counts)) * 100
                dictcount["value"] = round(tempx, 2)

            dictlist.append(dictcount.copy())

        # Generate Indicator Type Graph
        for t in types:
            c = Indicator.query.filter_by(indicator_type=t.indicator_type).count()
            typecount["category"] = t.indicator_type
            tempx = float(c) / float(counts)
            newtemp = tempx * 100
            typecount["value"] = round(newtemp, 2)
            typelist.append(typecount.copy())
        favs = []

        # Add Import from Cuckoo button to Dashboard page
        settings = Setting.query.filter_by(_id=1).first()
        if 'on' in settings.cuckoo:
            importsetting = True
        else:
            importsetting = False

        return render_template('dashboard.html', networks=dictlist, network=network, favs=favs, typelist=typelist,
                               taglist=tags, importsetting=importsetting)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/tags', methods=['GET'])
@login_required
def tags():
    try:
        # Grab tags
        taglist = dict()
        rows = Indicator.query.distinct(Indicator.tags).all()
        if rows:
            for row in rows:
                if row.tags:
                    for tag in row.tags.split(','):
                        taglist[tag.strip()] = list()
            # Match indicators to tags
            del rows, row
            for tag, indicators in taglist.iteritems():
                rows = Indicator.query.filter(Indicator.tags.like('%' + tag + '%')).all()
                tmp = {}
                for row in rows:
                    tmp[row.object] = row.indicator_type
                    indicators.append(tmp)

        return render_template('tags.html', tags=taglist)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/networks', methods=['GET'])
@login_required
def networks():
    try:
        # Grab only network indicators
        network = Indicator.query.filter(Indicator.indicator_type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()
        return render_template('indicatorlist.html', network=network, title='Network Indicators', links='network')
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/threatactors', methods=['GET'])
@login_required
def threatactors():
    try:
        # Grab threat actors
        threatactors = Indicator.query.filter(Indicator.indicator_type == 'Threat Actor').all()
        return render_template('indicatorlist.html', network=threatactors, title='Threat Actors', links='threatactors')
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/victims', methods=['GET'])
@login_required
def victims():
    try:
        # Grab victims
        victims = Indicator.query.filter(Indicator.diamondmodel == ('Victim')).all()
        return render_template('indicatorlist.html', network=victims, title='Victims', links='victims')
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/files', methods=['GET'])
@login_required
def files():
    try:
        # Grab files/hashes
        files = Indicator.query.filter(Indicator.indicator_type == ('Hash')).all()
        return render_template('indicatorlist.html', network=files, title='Files & Hashes', links='files')
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/campaigns', methods=['GET'])
@login_required
def campaigns():
    try:
        # Grab campaigns
        campaignents = dict()
        rows = Campaign.query.group_by(Campaign.name).all()
        for c in rows:
            if c.campaign == '':
                name = 'Unknown'
            else:
                name = c.campaign
            campaignents[name] = list()
        # Match indicators to campaigns
        for camp, indicators in campaignents.iteritems():
            if camp == 'Unknown':
                camp = ''
            rows = Indicator.query.filter(Indicator.campaign == camp).all()
            tmp = {}
            for i in rows:
                tmp[i.object] = i.indicator_type
                indicators.append(tmp)
        return render_template('campaigns.html', campaignents=campaignents)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/settings', methods=['GET'])
@login_required
def settings():
    try:
        settings = Setting.query.filter_by(_id=1).first()
        user = User.query.filter(User.user == current_user).first
        return render_template('settings.html', records=settings, suser=user)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/campaign/<uid>/info', methods=['GET'])
@login_required
def campaignsummary(uid):
    try:
        http = Indicator.query.filter_by(object=uid).first()
        # Run ipwhois or domainwhois based on the type of indicator
        if str(http.indicator_type) == "IPv4" or str(http.indicator_type) == "IPv6" or str(
            http.indicator_type) == "Domain" or \
                str(http.indicator_type) == "Network":
            return redirect(url_for('objectsummary', uid=http.object))
        elif str(http.indicator_type) == "Hash":
            return redirect(url_for('filesobject', uid=http.object))
        else:
            return redirect(url_for('threatactorobject', uid=http.object))
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/newobject', methods=['GET'])
@login_required
def newindicator():
    try:
        currentdate = time.strftime("%Y-%m-%d")
        return render_template('newobject.html', currentdate=currentdate)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/insert/attack/', methods=['POST'])
@login_required
def addattack():
    try:
        imd = ImmutableMultiDict(request.form)
        inputs = helpers.convert(imd)
        attack = Attack(1, 'desc', 'note', None)
        db.add(attack)
        db.commit()
    except:
        print 'error adding attack'
        exit()

@app.route('/update/indicator/', methods=['POST'])
@app.route('/insert/object/', methods=['POST'])
@login_required
def newobject():
    try:
        imd = ImmutableMultiDict(request.form)
        records = helpers.convert(imd)

        # Import indicators from Cuckoo for the selected analysis task
        if 'type' in records and 'cuckoo' in records['type']:
            host_data, dns_data, sha1, firstseen = cuckoo.report_data(records['cuckoo_task_id'])
            if host_data and dns_data and sha1 and firstseen:
                # Import IP Indicators from Cuckoo Task
                for ip in host_data:
                    ip = ip['ip']
                    ind = Indicator.query.filter_by(object=ip).first()
                    if ind is None:
                        indicator = Indicator(ip.strip(), 'IPv4', firstseen, '', 'Infrastructure', records['campaign'],
                                              'Low', '', records['tags'], '')
                        db.add(indicator)
                        db.commit()

                    # Import Domain Indicators from Cuckoo Task
                    for dns in dns_data:
                        ind = Indicator.query.filter_by(object=dns['request']).first()
                        if ind is None:
                            indicator = Indicator(dns['request'], 'Domain', firstseen, '', 'Infrastructure',
                                                  records['campaign'], 'Low', '', records['tags'], '')
                            db.add(indicator)
                            db.commit()

                    # Import File/Hash Indicators from Cuckoo Task
                    ind = Indicator.query.filter_by(object=sha1).first()
                    if ind is None:
                        indicator = Indicator(sha1, 'Hash', firstseen, '', 'Capability',
                                              records['campaign'], 'Low', '', records['tags'], '')
                        db.add(indicator)
                        db.commit()

                # Redirect to Dashboard after successful import
                return redirect(url_for('home'))
            else:
                errormessage = 'Task is not a file analysis'
                return redirect(url_for('import_indicators'))

        row = Campaign.query.filter_by(name=records['inputcampaign']).first()
        if row:
            campaign_id = row.get_id()
        else:
            camp = Campaign(name=records['inputcampaign'], adversary_id=1, notes='', tags=records['tags'])
            db.add(camp)
            db.commit()

            row = Campaign.query.filter_by(name=records['inputcampaign']).first()
            campaign_id = row.get_id()

        if 'inputtype' in records:
            # Makes sure if you submit an IPv4 indicator, it's an actual IP
            # address.
            ipregex = re.match(
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', records['inputobject'])
            # Convert the inputobject of IP or Domain to a list for Bulk Add functionality.
            records['inputobject'] = records['inputobject'].split(',')
            for newobject in records['inputobject']:
                if records['inputtype'] == "IPv4":
                    if ipregex:
                        indicator = Indicator.query.filter_by(indicator=newobject).first()
                        if indicator is None:
                            ipv4_indicator = Indicator(indicator=newobject.strip(), campaign_id=campaign_id,
                                                       indicator_type=records['inputtype'],
                                                       firstseen=records['inputfirstseen'],
                                                       lastseen=records['inputlastseen'],
                                                       diamondmodel=records['diamondmodel'],
                                                       confidence=records['confidence'],
                                                       notes=records['comments'],
                                                       tags=records['tags'],
                                                       relationships=None)
                            db.add(ipv4_indicator)
                            db.commit()
                            # network = Indicator.query.filter(Indicator.indicator_type.in_(
                            #    ('IPv4', 'IPv6', 'Domain', 'Network'))).all()
                        else:
                            errormessage = "Entry already exists in database."
                            return render_template('newobject.html', errormessage=errormessage,
                                                   inputtype=records['inputtype'], inputobject=newobject,
                                                   inputfirstseen=records['inputfirstseen'],
                                                   inputlastseen=records['inputlastseen'],
                                                   inputcampaign=records['inputcampaign'],
                                                   comments=records['comments'],
                                                   diamondmodel=records['diamondmodel'],
                                                   tags=records['tags'])

                    else:
                        errormessage = "Not a valid IP Address."
                        return render_template('newobject.html', errormessage=errormessage,
                                               inputtype=records['inputtype'],
                                               inputobject=newobject, inputfirstseen=records['inputfirstseen'],
                                               inputlastseen=records['inputlastseen'],
                                               confidence=records['confidence'], inputcampaign=records['inputcampaign'],
                                               comments=records['comments'], diamondmodel=records['diamondmodel'],
                                               tags=records['tags'])
                else:
                    indicator = Indicator.query.filter_by(indicator=newobject).first()
                    if indicator is None:
                        indicator = Indicator(indicator=newobject.strip(), campaign_id=campaign_id,
                                              indicator_type=records['inputtype'],
                                              firstseen=records['inputfirstseen'],
                                              lastseen=records['inputlastseen'],
                                              diamondmodel=records['diamondmodel'],
                                              confidence=records['confidence'],
                                              notes=records['comments'],
                                              tags=records['tags'],
                                              relationships=None)
                        db.add(indicator)
                        db.commit()
                    else:
                        errormessage = "Entry already exists in database."
                        return render_template('newobject.html', errormessage=errormessage,
                                               inputtype=records['inputtype'], inputobject=newobject,
                                               inputfirstseen=records['inputfirstseen'],
                                               inputlastseen=records['inputlastseen'],
                                               inputcampaign=records['inputcampaign'],
                                               comments=records['comments'],
                                               diamondmodel=records['diamondmodel'],
                                               tags=records['tags'])

            if records['inputtype'] == "IPv4" or records['inputtype'] == "Domain" or records['inputtype'] == "Network" \
                or records['inputtype'] == "IPv6":
                network = Indicator.query.filter(
                    Indicator.indicator_type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()
                return render_template('indicatorlist.html', network=network, title='Network Indicators', links='network')

            elif records['diamondmodel'] == "Victim":
                victims = Indicator.query.filter(Indicator.diamondmodel == ('Victim')).all()
                return render_template('indicatorlist.html', network=victims, title='Victims', links='victims')

            elif records['inputtype'] == "Hash":
                files = Indicator.query.filter(Indicator.indicator_type == ('Hash')).all()
                return render_template('indicatorlist.html', network=files, title='Files & Hashes', links='files')

            else:
                threatactors = Indicator.query.filter(Indicator.indicator_type == ('Threat Actors')).all()
                return render_template('indicatorlist.html', network=threatactors, title='Threat Actors', links='threatactors')
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/edit/<uid>', methods=['POST', 'GET'])
@login_required
def editobject(uid):
    try:
        http = Indicator.query.filter_by(indicator=uid).first()
        newdict = helpers.row_to_dict(http)
        return render_template('editobject.html', entry=newdict)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/editcampaign/<uid>', methods=['POST', 'GET'])
@login_required
def editcampaign(uid):
    return render_template('error.html', error='Not Implemented')


@app.route('/update/settings/', methods=['POST'])
@login_required
def updatesettings():
    try:
        something = request.form
        imd = ImmutableMultiDict(something)
        newdict = helpers.convert(imd)

        # Query the first set of settings, could query custom settings for individual users
        settings = Setting.query.filter_by(_id=1).first()

        # Make sure we're updating the settings instead of overwriting them
        if 'threatcrowd' in newdict.keys():
            settings.threatcrowd = 'on'
        else:
            settings.threatcrowd = 'off'
        for pt_type in ['pt_pdns', 'pt_whois', 'pt_pssl', 'pt_host_attr']:
            auth = [newdict['pt_username'], newdict['pt_api_key']]
            if pt_type in newdict.keys() and ('' not in auth):
                setattr(settings, pt_type, 'on')
            else:
                setattr(settings, pt_type, 'off')
        if 'cuckoo' in newdict.keys():
            settings.cuckoo = 'on'
        else:
            settings.cuckoo = 'off'
        if 'vtinfo' in newdict.keys() and newdict['apikey'] is not '':
            settings.vtinfo = 'on'
        else:
            settings.vtinfo = 'off'
        if 'vtfile' in newdict.keys() and newdict['apikey'] is not '':
            settings.vtfile = 'on'
        else:
            settings.vtfile = 'off'
        if 'circlinfo' in newdict.keys() and newdict['circlusername'] is not '':
            settings.circlinfo = 'on'
        else:
            settings.circlinfo = 'off'
        if 'circlssl' in newdict.keys() and newdict['circlusername'] is not '':
            settings.circlssl = 'on'
        else:
            settings.circlssl = 'off'
        if 'whoisinfo' in newdict.keys():
            settings.whoisinfo = 'on'
        else:
            settings.whoisinfo = 'off'
        if 'farsightinfo' in newdict.keys() and newdict['farsightkey'] is not '':
            settings.farsightinfo = 'on'
        else:
            settings.farsightinfo = 'off'
        if 'shodaninfo' in newdict.keys() and newdict['shodankey'] is not '':
            settings.shodaninfo = 'on'
        else:
            settings.shodaninfo = 'off'
        if 'odnsinfo' in newdict.keys() and newdict['odnskey'] is not '':
            settings.odnsinfo = 'on'
        else:
            settings.odnsinfo = 'off'

        settings.farsightkey = newdict['farsightkey']
        settings.apikey = newdict['apikey']
        settings.odnskey = newdict['odnskey']
        settings.httpproxy = newdict['httpproxy']
        settings.httpsproxy = newdict['httpsproxy']
        settings.cuckoohost = newdict['cuckoohost']
        settings.cuckooapiport = newdict['cuckooapiport']
        settings.circlusername = newdict['circlusername']
        settings.circlpassword = newdict['circlpassword']
        settings.pt_username = newdict['pt_username']
        settings.pt_api_key = newdict['pt_api_key']
        settings.shodankey = newdict['shodankey']

        db.commit()
        settings = Setting.query.first()

        return render_template('settings.html', records=settings)
    except Exception as e:
        return render_template('error.html', error=e)

'''
@app.route('/update/indicator/', methods=['POST'])
@login_required
def updateobject():
    try:
        # Updates entry information
        something = request.form
        imd = ImmutableMultiDict(something)
        records = helpers.convert(imd)
        # taglist = records['tags'].split(",") - Unused
        # indicator = Indicator.query.filter_by(object=records['object']).first() - Unused


        # Campaign Name to Campign ID lookup
        row = Campaign.query.filter_by(name=records['inputcampaign']).first()
        if row:
            campaign_id = row.get_id()
        else:
            camp = Campaign(name=records['inputcampaign'], adversary_id=1, notes='', tags=records['tags'])
            #db.add(camp)
            #db.commit()

            row = Campaign.query.filter_by(name=records['inputcampaign']).first()
            campaign_id = row.get_id()

        try:
            Indicator.query.filter_by(indicator=records['indicator']).update(records)
        except Exception as e:
            # SQLAlchemy does not outright support altering tables.
            for k, v in records.iteritems():
                if Indicator.query.group_by(k).first() is None:
                    print 'ALTER Table'
                    # db.engine.execute("ALTER TABLE indicators ADD COLUMN " + k + " TEXT DEFAULT ''")

        db.commit()

        # db.execute('ALTER  TABLE indicators ADD COLUMN')

        # con = helpers.db_connection()
        # with con:
        #    cur = con.cursor()
        #    cur.execute(
        #        "ALTER TABLE indicators ADD COLUMN " + t + " TEXT DEFAULT ''")
        #    cur.execute("UPDATE indicators SET " + t + "= '" + records[
        #                t] + "' WHERE id = '" + records['id'] + "'")

        if records['type'] == "IPv4" or records['type'] == "IPv6" or records['type'] == "Domain" or \
                records['type'] == "Network":
            return redirect(url_for('objectsummary', uid=str(records['object'])))
        elif records['type'] == "Hash":
            return redirect(url_for('filesobject', uid=str(records['object'])))
        elif records['type'] == "Entity":
            return redirect(url_for('victimobject', uid=str(records['object'])))
        elif records['type'] == "Threat Actor":
            return redirect(url_for('threatactorobject', uid=str(records['object'])))
    except Exception as e:
        return render_template('error.html', error=e)
'''

@app.route('/insert/newfield/', methods=['POST'])
@login_required
def insertnewfield():
    try:
        something = request.form
        imd = ImmutableMultiDict(something)
        records = helpers.convert(imd)
        newdict = {}
        for i in records:
            if i == "inputnewfieldname":
                newdict[records[i]] = records['inputnewfieldvalue']
            elif i == "inputnewfieldvalue":
                pass
            else:
                newdict[i] = records[i]
        return render_template('editobject.html', entry=newdict)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/network/<uid>/info', methods=['GET'])
@app.route('/victims/<uid>/info', methods=['GET'])
@login_required
def objectdetails(uid):
    try:
        row = Indicator.query.filter_by(indicator=uid).first()
        records = helpers.row_to_dict(row)
        campaign_name = Campaign.query.filter_by(_id=row.campaign_id).first().name
        records['campaign'] = campaign_name
        settings = Setting.query.filter_by(_id=1).first()
        taglist = row.tags.split(",")

        temprel = {}
        if row.relationships:
            rellist = row.relationships.split(",")
            for rel in rellist:
                row = Indicator.query.filter_by(indicator=rel).first()
                temprel[row.object] = row.indicator_type

        reldata = len(temprel)
        jsonvt = ""
        whoisdata = ""
        odnsdata = ""
        circldata = ""
        circlssl = ""
        farsightdata = ""
        shodandata = ""
        pt_pdns_data = ""
        pt_whois_data = ""
        pt_pssl_data = ""
        pt_host_attr_data = ""

        # Run ipwhois or domainwhois based on the type of indicator
        if str(row.indicator_type) == "IPv4" or str(row.indicator_type) == "IPv6":
            if settings.vtinfo == "on":
                jsonvt = virustotal.vt_ipv4_lookup(str(row.indicator))
            if settings.whoisinfo == "on":
                whoisdata = whoisinfo.ipwhois(str(row.indicator))
            if settings.odnsinfo == "on":
                odnsdata = opendns.ip_investigate(str(row.indicator))
            if settings.circlinfo == "on":
                circldata = circl.circlquery(str(row.indicator))
            if settings.circlssl == "on":
                circlssl = circl.circlssl(str(row.indicator))
            if settings.pt_pdns == "on":
                pt_pdns_data = passivetotal.pt_lookup('dns', str(row.indicator))
            if settings.pt_whois == "on":
                pt_whois_data = passivetotal.pt_lookup('whois', str(row.indicator))
            if settings.pt_pssl == "on":
                pt_pssl_data = passivetotal.pt_lookup('ssl', str(row.indicator))
            if settings.pt_host_attr == "on":
                pt_host_attr_data = passivetotal.pt_lookup('attributes', str(row.indicator))
            if settings.farsightinfo == "on":
                farsightdata = farsight.farsightip(str(row.indicator))
            if settings.shodaninfo == "on":
                shodandata = shodan.shodan(str(row.indicator))

        elif str(row.indicator_type) == "Domain":
            if settings.whoisinfo == "on":
                whoisdata = whoisinfo.domainwhois(str(row.indicator))
            if settings.vtinfo == "on":
                jsonvt = virustotal.vt_domain_lookup(str(row.indicator))
            if settings.odnsinfo == "on":
                odnsdata = opendns.domains_investigate(str(row.indicator))
            if settings.circlinfo == "on":
                circldata = circl.circlquery(str(row.indicator))
            if settings.pt_pdns == "on":
                pt_pdns_data = passivetotal.pt_lookup('dns', str(row.indicator))
            if settings.pt_whois == "on":
                pt_whois_data = passivetotal.pt_lookup('whois', str(row.indicator))
            if settings.pt_pssl == "on":
                pt_pssl_data = passivetotal.pt_lookup('ssl', str(row.indicator))
            if settings.pt_host_attr == "on":
                pt_host_attr_data = passivetotal.pt_lookup('attributes', str(row.indicator))
            if settings.farsightinfo == "on":
                farsightdata = farsight.farsightdomain(str(row.indicator))
            if settings.shodaninfo == "on":
                shodandata = shodan.shodan(str(row.indicator))

        if settings.whoisinfo == "on":
            if whoisdata:
                if str(row.indicator_type) == "Domain":
                    address = str(whoisdata['city']) + ", " + str(whoisdata['country'])
                else:
                    address = str(whoisdata['nets'][0]['city']) + ", " + str(whoisdata['nets'][0]['country'])

        else:
            address = "Information about " + str(row.indicator)
        return render_template('indicatordetails.html', **locals())
    except Exception as e:
        return render_template('error.html', error=e)

@app.route('/threatactors/<uid>/info', methods=['GET'])
@app.route('/files/<uid>/info', methods=['GET'])
@login_required
def objectdetails1(uid):
    try:
        row = Indicator.query.filter(Indicator.indicator == uid).first()
        records = helpers.row_to_dict(row)
        campaign_name = Campaign.query.filter_by(_id=row.campaign_id).first().name
        records['campaign'] = campaign_name
        settings = Setting.query.filter_by(_id=1).first()
        taglist = row.tags.split(",")

        temprel = {}
        if row.relationships:
            rellist = row.relationships.split(",")
            for rel in rellist:
                reltype = Indicator.query.filter(Indicator.indicator == rel).first()
                temprel[reltype.object] = reltype.type

        reldata = len(temprel)
        if settings.vtfile == "on":
            jsonvt = virustotal.vt_hash_lookup(str(row))
        else:
            jsonvt = ""
        return render_template('indicatordetails.html', **locals())
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/relationships/<uid>', methods=['GET'])
@login_required
def relationships(uid):
    try:
        row = Indicator.query.filter_by(object=uid).first()
        indicators = Indicator.query.all()
        if row.relationships:
            rellist = row.relationships.split(",")
            temprel = {}
            for rel in rellist:
                reltype = Indicator.query.filter_by(object=rel).first()
                temprel[reltype.object] = reltype.indicator_type
        return render_template('addrelationship.html', records=row, indicators=indicators)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/addrelationship', methods=['GET', 'POST'])
@login_required
def addrelationship():
    try:
        something = request.form
        imd = ImmutableMultiDict(something)
        records = helpers.convert(imd)

        # Add Direct Relationship
        row = Indicator.query.filter_by(object=records['id']).first()

        if row.relationships:
            row.relationships = str(row.relationships) + ",{}".format(records['indicator'])
        else:
            row.relationships = str(records['indicator'])

        db.commit()

        # Add Reverse Relationship
        row = Indicator.query.filter_by(object=records['indicator']).first()

        if row.relationships:
            row.relationships = str(row.relationships) + ",{}".format(records['id'])
        else:
            row.relationships = str(records['id'])

        db.commit()

        if records['type'] == "IPv4" or records['type'] == "IPv6" or records['type'] == "Domain" or \
                records['type'] == "Network":
            return redirect(url_for('objectsummary', uid=str(records['id'])))
        elif records['type'] == "Hash":
            return redirect(url_for('filesobject', uid=str(records['id'])))
        elif records['type'] == "Entity":
            return redirect(url_for('victimobject', uid=str(records['id'])))
        elif records['type'] == "Threat Actor":
            return redirect(url_for('threatactorobject', uid=str(records['id'])))
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/delete/<uid>', methods=['GET'])
@login_required
def deletenetworkobject(uid):
    try:
        row = Indicator.query.filter(Indicator.indicator == uid).first()

        Indicator.query.filter_by(indicator=uid).delete()
        db.commit()

        if any(word in row.indicator_type for word in ['IPv4', 'IPv6', 'Domain', 'Network']):
            current_indicators = Indicator.query.filter(Indicator.indicator_type.in_(('IPv4', 'IPv6', 'Domain', 'Network'))).all()
            title = 'Network Indicators'
            links = 'network'
        elif row.indicator_type == 'Threat Actor':
            current_indicators = Indicator.query.filter_by(indicator_type='Threat Actor')
            title = 'Threat Actors'
            links = 'threatactors'
        elif row.diamondmodel == 'Victim':
            current_indicators = Indicator.query.filter_by(diamondmodel='Victim')
            title = 'Victims'
            links = 'victims'
        elif row.indicator_type == 'Hash':
            current_indicators = Indicator.query.filter_by(indicator_type='Hash')
            title = 'Files & Hashes'
            links = 'files'

        return render_template('indicatorlist.html', network=current_indicators, title=title, links=links)
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/apikey', methods=['POST'])
@login_required
def apiroll():
    print "Rolling API Key"
    try:
        print "Time to roll the key!"
        user = User.query.filter_by(user=current_user.user.lower()).first()
        user.apikey = hashlib.md5("{}{}".format(user, str(random.random())).encode('utf-8')).hexdigest()
        db.commit()
        return redirect(url_for('profile'))
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        user = User.query.filter_by(user=current_user.user.lower()).first()
        imd = ImmutableMultiDict(request.form)
        records = helpers.convert(imd)

        if 'currentpw' in records:
            if hashlib.md5(records['currentpw'].encode('utf-8')).hexdigest() == user.password:
                if records['newpw'] == records['newpwvalidation']:
                    user.password = hashlib.md5(records['newpw'].encode('utf-8')).hexdigest()
                    db.commit()
                    errormessage = "Password updated successfully."
                    return render_template('profile.html', errormessage=errormessage)
                else:
                    errormessage = "New passwords don't match."
                    return render_template('profile.html', errormessage=errormessage)
            else:
                errormessage = "Current password is incorrect."
                return render_template('profile.html', errormessage=errormessage)
        return render_template('profile.html')
    except Exception as e:
        return render_template('error.html', error=e)


@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_indicators():
    cuckoo_tasks = cuckoo.get_tasks()
    return render_template('import.html', cuckoo_tasks=cuckoo_tasks)


@app.route('/download/<uid>', methods=['GET'])
@login_required
def download(uid):
    if uid == 'Unknown':
        uid = ""
    rows = Indicator.query.filter_by(campaign=uid).all()

    # Lazy hack. This takes care of downloading indicators by Tags, could be put into its own app.route
    if not rows:
        rows = Indicator.query.filter(Indicator.tags.like('%' + uid + '%')).all()
    indlist = []
    for i in rows:
        indicator = helpers.row_to_dict(i)
        for key, value in indicator.iteritems():
            if value is None or value == "":
                indicator[key] = '-'
        indlist.append(indicator)
    out_file = io.BytesIO()
    fieldnames = indlist[0].keys()
    w = csv.DictWriter(out_file, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(indlist)

    response = make_response(out_file.getvalue())
    response.headers[
        "Content-Disposition"] = "attachment; filename=" + uid + "-campaign.csv"
    response.headers["Content-type"] = "text/csv"
    return response


@app.route('/about', methods=['GET'])
@login_required
def about():
    return render_template('about.html')


@app.teardown_appcontext
def shutdown_session(exception=None):
    db.remove()



