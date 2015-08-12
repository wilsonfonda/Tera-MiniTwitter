# library for python web application framework
from flask import url_for, render_template, g, flash,\
    session, request, redirect, escape

# library for openID connect
import json
import httplib2
from apiclient import discovery
from oauth2client import client

# library to ahsh password
from passlib.hash import pbkdf2_sha256

# library to connect to S3
import boto
from boto.s3.key import Key

# library for other utilities
from datetime import datetime
from pytz import timezone
import math

# configuration parameter
from config import r_server, S3_BUCKET_NAME, S3_KEY_PREFIX,\
    ALLOWED_EXTENSIONS, CLIENT_ID, app, numitem

# setup boto to connect to S3
conn = boto.connect_s3()
bucket = conn.get_bucket(S3_BUCKET_NAME)

# setup SSL
context = ('ssl.crt', 'ssl.key')


# function to check whether uploaded file type is allowed
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


# funtion that is always executed before request
# check whether user has sign in or not
@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = r_server.hgetall('user:%s' % escape(session['user_id']))


# main page of the web
@app.route('/')
@app.route('/<userID>')
def index(userID=None):
    """ This is main function and page of the web application
    input:  without userID parameter, user will see his/her own timeline
            [userID] of a user to see a user's timeline
    return: user_id not in session will return user to index.html
            user_id in session will redirect user to timeline.html
    """
    error = None
    if not error and 'error' in request.args:
        error = request.args['error']
    if g.user:
        others = False
        followed = False
        if 'pagination' in request.args and int(
                request.args['pagination']) > 0:
            pagination = int(request.args['pagination'])
        else:
            pagination = 1
        if not userID or userID == session['user_id']:
            userID = session['user_id']
        else:
            if userID in r_server.lrange('following:%s' % escape(
                    session['user_id']), 0, 1000):
                followed = True
            others = True
        # upper and lower postID of post shown
        minimum = (pagination-1)*numitem
        maximum = pagination*numitem-1
        # list of shown postID
        posts = r_server.zrange('timeline:%s' % userID, minimum,
                                maximum, True)
        # get total length of existing post from user
        plen = int(math.ceil(int(r_server.zcard(
            'timeline:%s' % userID))/float(numitem)))
        # get the current accessed user Data
        userData = r_server.hgetall('user:%s' % userID)
        # posts to show in timeline
        postData = {}
        # profile of the user who post
        userPost = {}
        # number of follower from current user
        follower = r_server.llen(
            'followed:%s' % escape(session['user_id']))
        # number of following from current user
        following = r_server.llen(
            'following:%s' % escape(session['user_id']))
        # number of follower from userID
        followerO = r_server.llen('followed:%s' % userID)
        # number of following from userID
        followingO = r_server.llen('following:%s' % userID)
        for post in posts:
            postData[post] = r_server.hgetall('post:%s' % post)
            userPost[post] = r_server.hgetall('user:%s' %
                                              postData[post].get('userID'))
        return render_template('timeline.html', plen=plen,
                               pagination=pagination, followed=followed,
                               userData=userData, posts=posts,
                               postData=postData,
                               userPost=userPost, others=others,
                               follower=follower, following=following,
                               followerO=followerO, userID=userID,
                               followingO=followingO, error=error)
    else:
        posts = r_server.zrange('timeline:', 0, 100, True)
        postData = {}
        userPost = {}
        for post in posts:
            postData[post] = r_server.hgetall('post:%s' % post)
            userPost[post] = r_server.hgetall('user:%s' %
                                              postData[post].get('userID'))
        return render_template('index.html', CLIENT_ID=CLIENT_ID,
                               posts=posts,
                               postData=postData, userPost=userPost,
                               error=error)


# function to do sign in normally using email and password
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    """ This sign function allow user to use registered account to sign in
    input: post of user's email and password
    return: success: back to index function to render timeline.html
            failure: go back to sign in page in index.html and show
                     errors
    """
    if g.user:
        flash('you are already signed in')
        return redirect(url_for('index'))
    error = None
    user_id = None
    if request.method == 'POST':
        if not request.form['logEmail'] or '@' not in request.form['logEmail']:
            error = 'invalid email address'
            flash(error)
        else:
            user_id = r_server.hget('users', request.form['logEmail'].lower())
        if not request.form['logPassword']:
            error = 'invalid password'
            flash(error)
        if not user_id:
            error = 'invalid email'
            flash(error)
        else:
            if not pbkdf2_sha256.verify(
                    request.form['logPassword'], r_server.hget(
                        'user:%s' % user_id,
                        "password"
                    )
            ):
                error = 'invalid password'
                flash(error)
            if not error:
                session['user_id'] = user_id
                flash('successfully signed in')
                return redirect(url_for("index"))
    return redirect(url_for('index', error='Sign in'))


# function and page to do registration of new user
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """ This function will accept post form data about the user and
        increase next_userID for user if he is successfully registered
    input: user's first name, last name, email, and password
    return: success: user is registered, signed in, and redirected to index
                     to render timeline.html
            failure: user go back to the index.html with all of the error
                     shown to enable user to easily fix the problem

    """
    if g.user:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        if not request.form['inputFirstName']:
            error = 'You have to enter your first name'
            flash(error)
        if not request.form['inputLastName']:
            error = 'You have to enter your last name'
            flash(error)
        if not request.form['suEmail'] or '@' not in request.form['suEmail']:
            error = 'You have to enter a valid email address'
            flash(error)
        if not request.form['suPassword']:
            error = 'You have to enter a password'
            flash(error)
        elif len(
            request.form['suPassword']
        ) < 8 or len(
            request.form['suPassword']
        ) > 36:
            error = 'Your password must be between 8-36 character'
            flash(error)
        if r_server.hget('users', request.form['suEmail']) is not None:
            error = 'The email already exist'
            flash(error)
        if not error:
            r_server.incr('next_userID')
            user_id = r_server.get('next_userID')
            password = pbkdf2_sha256.encrypt(request.form['suPassword'],
                                             rounds=200000, salt_size=16)
            if r_server.hmset(
                    "user:%s" % user_id,
                    {
                        "firstName":
                        request.form['inputFirstName'].encode('utf8'),
                        "lastName":
                        request.form['inputLastName'].encode('utf8'),
                        "email": request.form['suEmail'].lower(),
                        "password": password, "userID": user_id
                    }
            ) and r_server.hset(
                "users", request.form['suEmail'].lower(),
                user_id
            ):
                session['user_id'] = user_id
                flash('successfully signed up')
                return redirect(url_for('index'))
            else:
                error = "sign up failure"
                flash(error)
                r_server.decr('next_userID')
    else:
        error = "please fill the sign up form correctly first"
        flash(error)
    return redirect(url_for('index', error='Sign up'))


# This function will delete user's session
@app.route('/signout')
def signout():
    """ This function will delete the user_id in the session and also
        credentials in session if the user sign in with google plus login
    return: success: deleted user_id and credentials in the session,
                     then go to index function
            failure: user credentials is not available or
                     user is not signed in
    """
    if not g.user:
        flash('you are not signed in')
        return redirect(url_for('index', error='Sign out Error'))
    """
    if 'credentials' not in session:
        session.pop('user_id', None)
        flash('successfully signed out')
        return redirect(url_for('index'))
    else:
        del session['credentials']
        session.pop('user_id', None)
        flash('successfully signed out')
        return redirect(url_for('index'))
    """
    # Only disconnect a connected user.
    if 'credentials' not in session:
        session.pop('user_id', None)
        flash('successfully signed out')
        return redirect(url_for('index'))
    credentials = session['credentials']
    # Execute HTTP GET request to revoke current token.
    access_token = json.loads(credentials)['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's session.
        del session['credentials']
        session.pop('user_id', None)
        flash('successfully signed out')
        return redirect(url_for('index'))
    else:
        # For whatever reason, the given token was invalid.
        flash('invalid token')
        del session['credentials']
        session.pop('user_id', None)
        return redirect(url_for('index'))


# function to login using google plus open ID
@app.route('/loginplus')
def loginplus():
    """ This function allow user to log in to Tera without registering
        this function will take user's data from the authenticated google
        plus user
    return: already registered email: login to the web application
            unregistered email: save the user's data into Redis and login
    """
    if 'credentials' not in session:
        flash('credential not in session')
        return redirect(url_for('oauth2callback'))
    credentials = client.OAuth2Credentials.from_json(session['credentials'])
    if credentials.access_token_expired:
        flash('credential expired')
        return redirect(url_for('oauth2callback'))
    else:
        flash('service built')
        http_auth = credentials.authorize(httplib2.Http())
        service = discovery.build('plus', 'v1', http_auth)
    try:
        person = service.people().get(userId='me').execute()
        user_id = r_server.hget('users', person['emails'][0]['value'].lower())
        if user_id:
            session['user_id'] = user_id
            flash('You sign in through google plus')
            return redirect(url_for('index'))
        else:
            r_server.incr('next_userID')
            user_id = r_server.get('next_userID')
            if r_server.hmset(
                    "user:%s" % user_id,
                    {
                        "firstName": person['name']['givenName'].capitalize(),
                        "lastName": person['name']['familyName'].capitalize(),
                        "email": person['emails'][0]['value'].lower(),
                        "userID": user_id
                    }
            ) and r_server.hset(
                "users", person['emails'][0]['value'].lower(),
                user_id
            ):
                session['user_id'] = user_id
                flash('You are registered using google plus')
                return redirect(url_for('index'))
            else:
                error = "sign up failure"
                flash(error)
                r_server.decr('next_userID')
    except client.AccessTokenRefreshError:
        error = 'The credentials have been revoked or expired, please re-run'
        error += 'the application to re-authorize.'
        flash(error)
    return redirect(url_for('index', error='Google Plus Login'))


# function to authenticate google plus user
@app.route('/oauth2callback', methods=['GET'])
def oauth2callback():
    """ This function will authenticate user and have the approval from user
        to user their data
    return: credentials and back to loginplus to continue the process
    """
    flow = client.flow_from_clientsecrets(
        'client_secrets.json',
        scope='email',
        redirect_uri=url_for('oauth2callback', _external=True))
    if 'code' not in request.args:
        auth_uri = flow.step1_get_authorize_url()
        return redirect(auth_uri)
    else:
        auth_code = request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        session['credentials'] = credentials.to_json()
        return redirect(url_for('loginplus'))


# function to create new post in the user's timeline and user's
# follower timeline
@app.route('/share', methods=['GET', 'POST'])
def share():
    """"This function will create new post in the user timeline and
        user's follower timeline if successfull,
        user can also attach the picture inside the post
    input: user's post content and image file
    return: success: add new post to user and user's follower timeline
            failure: return to timeline page and show error
    """
    if not g.user:
        error = 'You are not signed in'
        flash(error)
        return redirect(url_for('index', error='Share Error'))
    error = None
    filen = None
    if request.method == 'POST':
        if 'inputPost' not in request.form:
            error = 'Please write your thoughts first'
            flash(error)
        elif len(request.form['inputPost']) > 300:
            error = 'Your thought is too long'
            flash(error)
        try:
            if 'uploadImg' in request.files:
                filen = request.files['uploadImg']
                if filen and not allowed_file(filen.filename):
                    error = 'Please upload correct file'
                    flash(error)
        except IOError:
            error = 'File cannot be found'
            flash(error)
        if not error:
            r_server.incr('next_postID')
            postID = r_server.get('next_postID')
            if r_server.hmset(
                    "post:%s" % postID,
                    {
                        'content': request.form['inputPost'].encode('utf8'),
                        'userID': session['user_id'],
                        'datetime': datetime.now(timezone('UTC')).strftime(
                            "%Y-%m-%dT%H:%M:%S")
                    }
            ) and r_server.lpush(
                'posts:%s' % escape(session['user_id']),
                postID
            ) and r_server.zadd(
                'timeline:%s' % escape(
                    session['user_id']
                ),
                postID, postID
            ) and r_server.zadd(
                'timeline:', postID, postID
            ):
                for follower in r_server.lrange(
                    'followed:%s' % escape(
                        session['user_id']), 0, 1000):
                    r_server.zadd(
                        "timeline:%s" % follower, postID, postID
                    )
                try:
                    if filen:
                        fileType = filen.filename.rsplit('.', 1)[1]
                        k = Key(bucket)
                        k.key = S3_KEY_PREFIX+'post/'+postID
                        k.key += '.'+fileType
                        k.set_contents_from_file(filen)
                        k.make_public()
                        r_server.hset("post:%s" % postID,
                                      "imageURL",
                                      k.generate_url(0).split('?', 1)[0])
                        r_server.hset("post:%s" % postID,
                                      "fileType",
                                      fileType)
                except IOError:
                    error = 'File cannot be found'
                    flash(error)
                    r_server.decr('next_postID')
                    return redirect(url_for('index',
                                            error='Upload File Error'))
            else:
                r_server.decr('next_postID')
            return redirect(url_for('index'))
        else:
            error = "Your thought failed to be posted"
            flash(error)
    else:
        error = "your thought is abstract"
        flash(error)
    return redirect(url_for('index', error='Share Error'))


# function to delete user's post
@app.route('/deletepost', methods=['GET', 'POST'])
def deletePost():
    """ This function can be used to delete user's post,
        but user must have be the one who posted it
    input: post_ID
    return: success: delete post from the database
            failure: user doesn't have authority to delete the post
    """
    if not g.user:
        flash('You are not signed in')
        return redirect(url_for('index', error='Deletion Error'))
    error = None
    if request.method == 'POST':
        if 'inputPostID' not in request.form:
            error = "ID is unavailable"
            flash(error)
        elif request.form['inputPostID'] in r_server.lrange(
                'posts:%s' % escape(session['user_id']), 0, 1000):
            postID = request.form["inputPostID"]
            if r_server.hget('post:%s' % postID, 'fileType'):
                k = Key(bucket)
                k.key = S3_KEY_PREFIX+'post/'+postID
                k.key += '.'+r_server.hget('post:%s' % postID, 'fileType')
                bucket.delete_key(k)
            if r_server.lrem(
                    'posts:%s' % escape(session['user_id']),
                    int(postID), 0
            ) and r_server.delete(
                'post:%s' % postID
            ) and r_server.zrem(
                'timeline:%s' % escape(session['user_id']),
                postID
            ) and r_server.zrem('timeline:', postID):
                for follower in r_server.lrange(
                        'followed:%s' % escape(session['user_id']), 0, 1000):
                    r_server.zrem("timeline:%s" % follower, postID)
                flash('deletion successfull')
                return redirect(url_for('index'))
            else:
                flash('deletion failed')
                return redirect(url_for('index', error='delete error'))
        else:
            error = "you are not allowed to delete the post"
            flash(error)
    else:
        error = "you are not allowed to delete the post"
        flash(error)
    return redirect(url_for('index', error='Deletion Error'))


# Funtion to edit user's post
@app.route('/editpost', methods=['GET', 'POST'])
def editPost():
    """ This function can be used to edit the user's post, but user has
        to be the one who posted it
    input: editPostID
    return: success: post is updated and saved in the database
            failure: post cannot be edited because the user has no authority
    """
    if not g.user:
        error = 'You are not signed in'
        flash(error)
        return redirect(url_for('index', error='Edit Error'))
    error = None
    if request.method == 'POST':
        if 'editPostID' not in request.form:
            error = "ID is unavailable"
            flash(error)
        if 'inputEditPost' not in request.form:
            error = "You should put some thoughts"
            flash(error)
        if 'editImg' in request.files:
            filen = request.files['editImg']
        else:
            filen = None
        if filen and not allowed_file(filen.filename):
            error = "Picture format is wrong"
            flash(error)
        if not error and request.form['editPostID'] in r_server.lrange(
                'posts:%s' % escape(session['user_id']), 0, 1000):
            postID = request.form["editPostID"]
            r_server.hset('post:%s' % postID, 'content',
                          request.form['inputEditPost'].encode('utf8'))
            if filen:
                    k = Key(bucket)
                    k.key = S3_KEY_PREFIX+'post/'+postID
                    k.key += '.'+filen.filename.rsplit('.', 1)[1]
                    k.set_contents_from_file(filen)
                    k.make_public()
            flash("edit successfull")
            return redirect(url_for('index'))
        else:
            error = "you are not allowed to edit the post"
            flash(error)
    else:
        error = "you are not allowed to edit the post"
        flash(error)
    return redirect(url_for('index', error='Edit Error'))


# funtion to search other user
@app.route('/search', methods=['GET', 'POST'])
def search():
    """ This function is to search other available user
        according to the user's text input
        if user doesn't input anything, it will return all available user
    input: user search input
    return: list of all available user
    """
    if not g.user:
        flash("You are not signed in")
        return redirect(url_for('index'))
    matching = []
    if request.method == 'POST':
        for key in r_server.hkeys('users'):
            if key:
                currentUser = r_server.hgetall('user:%s' %
                                               r_server.hget('users', key))
            if currentUser:
                if request.form['inputSearch'].lower() in currentUser.get(
                        'firstName'
                ).lower() or request.form[
                    'inputSearch'].lower() in currentUser.get(
                    'lastName'
                ).lower() or request.form[
                    'inputSearch'].lower() in currentUser.get(
                    'email'
                ).lower():
                    if currentUser.get('email') not in g.user.get('email'):
                        matching.append(currentUser)
        return render_template('search.html', matching=matching)
    else:
        error = "Unable to search"
        flash(error)
    return redirect(url_for('index', error='Search Error'))


# function to follow other users
@app.route('/followuser', methods=['GET', 'POST'])
def follow():
    """ This function allow user to follow other users and
        have that other user's post appear in the timeline
        This has limitation of only taking the 100 latest post
        of the followed user at first time it follow
        input: userID to be followed
        return: timeline of other user is added to the logged in user
                and post from other user will also appear in the future
    """
    if not g.user:
        flash('You are not signed in')
        return redirect(url_for('index', error='Follow Error'))
    error = None
    if request.method == 'POST':
        if 'followUserID' not in request.form:
            error = 'Invalid account'
            flash(error)
        elif request.form['followUserID'] in r_server.lrange(
            'following:%s' % escape(session['user_id']), 0, 100
        ):
            error = "You already follow this person"
            flash(error)
        if not error:
            if r_server.lpush(
                    'following:%s' % escape(
                        session['user_id']
                    ), int(request.form['followUserID'])
            ) and r_server.lpush(
                'followed:%s' % request.form['followUserID'],
                int(session['user_id'])
            ):
                for post in r_server.lrange(
                        'posts:%s' % request.form['followUserID'], 0, 100
                ):
                    r_server.zadd(
                        "timeline:%s" % escape(
                            session['user_id']
                        ), int(post), post
                    )
                flash('successfully follow the account')
                return redirect(
                    url_for(
                        'index',
                        userID=request.form['followUserID']
                    )
                )
        else:
            error = "Failed to follow"
            flash(error)
    else:
        error = "Unable to follow"
        flash(error)
    return redirect(url_for('index', error='Follow Error'))


# function to unfollow user
@app.route('/unfollowuser', methods=['GET', 'POST'])
def unfollow():
    """ This function is used to unfollow other user.
        This function will delete 100 latest post from the other user
        and won't show post from the user in the future
    input: user ID to be unfollowed
    return: unfollow user ID and delete 100 latest posts from timeline
    """
    if not g.user:
        flash('You are not signed in')
        return redirect(url_for('index', error='Unfollow Error'))
    error = None
    if request.method == 'POST':
        if 'unfollowUserID' not in request.form:
            error = 'Invalid account'
            flash(error)
        elif request.form['unfollowUserID'] not in r_server.lrange(
            'following:%s' % escape(session['user_id']), 0, 100
        ):
            error = "You are not following this person"
            flash(error)
        if not error:
            if r_server.lrem(
                    'following:%s' % escape(
                        session['user_id']
                    ),
                    int(request.form['unfollowUserID']), 0
            ) and r_server.lrem(
                'followed:%s' % request.form['unfollowUserID'],
                int(session['user_id']), 0
            ):
                for post in r_server.lrange(
                        'posts:%s' % request.form['unfollowUserID'],
                        0, 100
                ):
                    r_server.zrem(
                        "timeline:%s" % escape(
                            session['user_id']
                        ), post
                    )
                flash('successfully unfollow the account')
                return redirect(
                    url_for(
                        'index',
                        userID=request.form['unfollowUserID']
                    )
                )
        else:
            error = "Failed to unfollow"
            flash(error)
    else:
        error = "Please choose who you want to unfollow"
        flash(error)
    return redirect(url_for('index', error="Unfollow Error"))


# debugging part of the web application when internal error server happen
if not app.debug:
    import logging
    from logging import FileHandler
    file_handler = FileHandler('log.txt')
    file_handler.setLevel(logging.WARNING)
    app.logger.addHandler(file_handler)

# run the program
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
    # debug=True, ssl_context=context, threaded=True)
