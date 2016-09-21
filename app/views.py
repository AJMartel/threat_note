from flask import flash
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user

from app import app, db, lm
from .forms import LoginForm, RegisterForm
from .models import User, Indicator, Campaign, Setting


@lm.user_loader
def load_user(id):
    return User.query.get(int(id))

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


@app.route('/settings', methods=['GET'])
@login_required
def settings():
    try:
        settings = Setting.query.filter_by(_id=1).first()
        user = User.query.filter(User.user == current_user).first
        return render_template('settings.html', records=settings, suser=user)
    except Exception as e:
        return render_template('error.html', error=e)

