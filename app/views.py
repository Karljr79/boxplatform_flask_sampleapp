import requests
import os, time, json

from flask import Flask, render_template, session, escape, g, request, url_for, redirect, flash

from app import app

from boxsdk import Client, JWTAuth
from boxsdk.object.user import User
from boxsdk.network.logging_network import LoggingNetwork

# Setup Box Custom Logger
logging_network = LoggingNetwork()

# Helper function to store tokens, passed into JWTAuth call
def store_tokens(access_t, refresh_t):
    session['token_id'] = access_t
    return

# When any request comes in, initialize the object that will check the expiration of the token.
# This object will also refresh the token against the API if needed. Note, this is an admin token
# that we are caching.
@app.before_request
def load_auth_object_into_current_pageload_context():
    if "/static/" in request.path:
        return

    if "token_id" in session:
        print "ACCESS TOKEN FOUND: {0}".format(escape(session['token_id']))
        auth = JWTAuth(client_id=app.config['CLIENT_ID'],
            client_secret=app.config['CLIENT_SECRET'],
            enterprise_id=app.config['EID'],
            jwt_key_id=app.config['KEY_ID'],
            rsa_private_key_file_sys_path=os.path.join(os.path.dirname(__file__),'private_key.pem'),
            rsa_private_key_passphrase=app.config['PASSPHRASE'],
            store_tokens=store_tokens,
            access_token=escape(session['token_id']))# <-- This is the difference.  Uses the old token.
    else:
        auth = JWTAuth(client_id=app.config['CLIENT_ID'],
            client_secret=app.config['CLIENT_SECRET'],
            enterprise_id=app.config['EID'],
            jwt_key_id=app.config['KEY_ID'],
            rsa_private_key_file_sys_path=os.path.join(os.path.dirname(__file__),'private_key.pem'),
            rsa_private_key_passphrase=app.config['PASSPHRASE'],
            store_tokens=store_tokens)
    g.auth = auth


@app.route('/', methods=['GET'])
def index():
    return render_template("login.html",
                            callback=app.config['AUTH0_CALLBACK_URL'])

# Login Page
@app.route('/login', methods=['GET'])
def login():
    print '### Sending Login view ###'
    return render_template("login.html",
                            callback=app.config['AUTH0_CALLBACK_URL'])


@app.route('/user/<user_id>', methods=['GET'])
def user_detail(user_id):
    if 'profile' not in session:
        flash("You must be logged in", 'error')
        return render_template("login.html")
    else:
        print '### Sending user detail view ###'
        client = Client(g.auth, network_layer=logging_network)
        user = client.user(user_id=user_id).get()

        # As an admin, we can act on behalf of other users by creating new auth and client objects.
        # We should also be caching this token.  For the purposes of this quickstart
        # we only cache access for one user (the admin).
        print "AUTHENTICATING USER: " + user_id + " (" + user.name + ")"
        user_auth = JWTAuth(client_id=app.config['CLIENT_ID'],
                    client_secret=app.config['CLIENT_SECRET'],
                    enterprise_id=app.config['EID'],
                    jwt_key_id=app.config['KEY_ID'],
                    rsa_private_key_file_sys_path=os.path.join(os.path.dirname(__file__),'private_key.pem'),
                    rsa_private_key_passphrase=app.config['PASSPHRASE'])
        user_auth.authenticate_app_user(user) # <--- Authenticate as the user
        user_client = Client(user_auth)

        # Make API calls as the user by using the user_client object
        files = user_client.folder(folder_id='0').get_items(limit=100)

        # Build the preview links for the files belonging to this user
        for f in files:
            if f._item_type=="file":
                f.preview_url = f.get(fields=['expiring_embed_link']).expiring_embed_link['url']
                f.preview_url = f.preview_url + "?showAnnotations=true"

        # Pass the user access token to the page
        token = user_auth.access_token
        print token
        return render_template("user_detail.html",
                               user=user,
                               files_list=files,
                               token=token)


@app.route('/folder/<folder_id>', methods=['GET'])
def folder_detail(folder_id):
    client = Client(g.auth, network_layer=logging_network)
    user = client.user(user_id=session['box_id']).get()

    print "AUTHENTICATING USER: " + session['box_id']
    user_auth = JWTAuth(client_id=app.config['CLIENT_ID'],
                client_secret=app.config['CLIENT_SECRET'],
                enterprise_id=app.config['EID'],
                jwt_key_id=app.config['KEY_ID'],
                rsa_private_key_file_sys_path=os.path.join(os.path.dirname(__file__),'private_key.pem'),
                rsa_private_key_passphrase=app.config['PASSPHRASE'])
    user_auth.authenticate_app_user(user) # <--- Authenticate as the user
    user_client = Client(user_auth)
    token = user_auth.access_token

    folder = user_client.folder(folder_id=folder_id).get()
    files = folder.get_items(limit=100)

    # Build the preview links for the files belonging to this user
    for f in files:
        if f._item_type=="file":
            f.preview_url = f.get(fields=['expiring_embed_link']).expiring_embed_link['url']

    return render_template("folder_detail.html",
                           folder=folder,
                           files_list=files,
                           token=token)

@app.route('/folder/new', methods=['POST'])
def create_new_folder():
    client = Client(g.auth, network_layer=logging_network)
    user = client.user(user_id=session['box_id']).get()

    print "AUTHENTICATING USER: " + session['box_id']
    user_auth = JWTAuth(client_id=app.config['CLIENT_ID'],
                client_secret=app.config['CLIENT_SECRET'],
                enterprise_id=app.config['EID'],
                jwt_key_id=app.config['KEY_ID'],
                rsa_private_key_file_sys_path=os.path.join(os.path.dirname(__file__),'private_key.pem'),
                rsa_private_key_passphrase=app.config['PASSPHRASE'])
    user_auth.authenticate_app_user(user) # <--- Authenticate as the user
    user_client = Client(user_auth)

    folder = user_client.folder('0').get()
    folder.create_subfolder(request.form['foldername'])

    return redirect('/user/' + session['box_id'])

# Here we're using the /callback route.
@app.route('/callback')
def callback_handling():
    code = request.args.get('code')
    json_header = {'content-type': 'application/json'}
    token_url = "https://{domain}/oauth/token".format(domain=app.config['AUTH0_DOMAIN'])

    token_payload = {
    'client_id':     app.config['AUTH0_CLIENT_ID'],
    'client_secret': app.config['AUTH0_CLIENT_SECRET'],
    'redirect_uri':  app.config['AUTH0_CALLBACK_URL'],
    'code':          code,
    'grant_type':    'authorization_code'
    }

    token_info = requests.post(token_url, data=json.dumps(token_payload), headers = json_header).json()

    user_url = "https://{domain}/userinfo?access_token={access_token}" \
      .format(domain=app.config['AUTH0_DOMAIN'], access_token=token_info['access_token'])

    user_info = requests.get(user_url).json()

    # We're saving all user information into the session
    session['profile'] = user_info

    # Check to see if there is a Box App User associated with this login
    # if not, create one.
    if 'app_metadata' in user_info:
        session['box_id'] = user_info['app_metadata']['box_id']
        return redirect('/user/' + user_info['app_metadata']['box_id'])
    else:
        new_user = createNewBoxAppUser(user_info['name'])
        #update Auth0 metadata
        updateAuth0MetaData(auth0_id=user_info['user_id'], box_id=new_user['id'])

        return redirect(url_for('user_detail', user_id=new_user['id']))

# Helper function to create a new Box app user
def createNewBoxAppUser(name, job_title=None, phone=None, address=None):
    client = Client(g.auth, network_layer=logging_network)
    new_user = client.create_user(name=name,
                                  job_title=job_title,
                                  phone=phone,
                                  address=address)

    flash("Created new user: {0} ".format(name))
    session['box_id'] = new_user['id']
    return new_user

# Helper function to add Box app user id to Auth0 metadata
def updateAuth0MetaData(auth0_id, box_id):
    access_token = getAuth0AccessToken()

    # Assemble request
    metadata_url = "https://{domain}/api/users/{user_id}/metadata" \
      .format(domain=app.config['AUTH0_DOMAIN'], user_id=auth0_id)

    json_headers = {'content-type': 'application/json',
                   'Authorization': 'Bearer ' + access_token
    }

    params = { 'box_id': box_id }

    # Send the PUT request
    r = requests.put(url=metadata_url, data=json.dumps(params), headers=json_headers)


# Get Auth0 access token
def getAuth0AccessToken():
    json_headers = {'content-type': 'application/json'}
    token_url = "https://{domain}/oauth/token".format(domain=app.config['AUTH0_DOMAIN'])
    token_payload = {
    'client_id':     app.config['AUTH0_CLIENT_ID'],
    'client_secret': app.config['AUTH0_CLIENT_SECRET'],
    'grant_type':    'client_credentials'
    }
    access_token = requests.post(token_url, data=json.dumps(token_payload), headers = json_headers).json()
    return access_token['access_token']
