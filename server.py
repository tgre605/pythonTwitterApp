import cherrypy
import urllib
import json
import base64
import nacl.encoding
import nacl.signing
import time
import sqlite3
from jinja2 import Environment, FileSystemLoader
file_loader = FileSystemLoader('templates')
from config import myIP, myPort

class MainApp(object):
    # CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on': 'True',
                  }


    @cherrypy.expose
    def default(self):
        env = Environment(loader=file_loader)
        template = env.get_template('errorPage.html')
        output = template.render()
        cherrypy.response.status = 404
        return output


    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        env = Environment(loader=file_loader)
        try:
            template = env.get_template('home.html')
            output = template.render(username=cherrypy.session['username'])
            return output
        except:
            template = env.get_template('launch.html')# There is no username
            output = template.render()
            return output

    @cherrypy.expose
    def login(self):
        env = Environment(loader=file_loader)
        template = env.get_template('login.html')
        output = template.render()

        return output

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        cherrypy.session['myIP'] = myIP
        cherrypy.session['myPort'] = myPort
        apiKeyGen(username, password)
        makeKey(username)
        error = authoriseUserLogin(username)
        if error == 0:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            # backgroundTask = cherrypy.process.plugins.BackgroundTask(1, backgroundReport())
            # backgroundTask.start()
            listUsers(cherrypy.session['username'])
            getUsers()
            contentFilterDB()
            loginPubkey(cherrypy.session['username'])
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("delete from apiKey where username = ?", [username])
        conn.commit()
        conn.close()
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


    @cherrypy.expose
    def publicMessages(self):
        env = Environment(loader=file_loader)
        template = env.get_template('publicMessages.html')
        try:
            getPublicMessages()
            authoriseUserLogin(cherrypy.session['username'])
            output = template.render(messages=cherrypy.session['publicMessages'], users=cherrypy.session['users'])
            return output
        except Exception as error:
            print("Page failed, ", error)
            template = env.get_template('home.html')
            output = template.render(username=cherrypy.session['username'])
        return output


    @cherrypy.expose
    def publicMessagesFrom(self, otherUser):
        env = Environment(loader=file_loader)
        template = env.get_template('publicMessages.html')
        try:
            authoriseUserLogin(cherrypy.session['username'])
            getPublicMessagesFrom(otherUser)
            if len(cherrypy.session['publicMessages']) < 1:
                template = env.get_template('noPublicMessages.html')
                output = template.render(users=cherrypy.session['users'], otherUser=otherUser)
            else:
                output = template.render(messages=cherrypy.session['publicMessages'], users=cherrypy.session['users'], otherUser=otherUser)
            return output
        except Exception as error:
            print("Page failed, ", error)
            template = env.get_template('home.html')
            output = template.render(username=cherrypy.session['username'])
        return output


    @cherrypy.expose
    def onlineUsers(self):
        env = Environment(loader=file_loader)
        template = env.get_template('onlineUsers.html')
        listPing(cherrypy.session['username'])
        getAllInfo()
        cherrypy.session['allInfo']
        try:
            authoriseUserLogin(cherrypy.session['username'])
            output = template.render(users=cherrypy.session['allInfo'])
            return output
        except Exception as error:
            print("Page failed, ", error)
            template = env.get_template('home.html')
            output = template.render(username=cherrypy.session['username'])
        return output

    @cherrypy.expose
    def privateMessages(self):
        env = Environment(loader=file_loader)
        template = env.get_template('privateMessages.html')
        try:
            authoriseUserLogin(cherrypy.session['username'])
            getPrivateMessages()
            output = template.render(messages=cherrypy.session['privateMessages'], users=cherrypy.session['users'])
            return output
        except Exception as error:
            print("Page failed, ", error)
            template = env.get_template('home.html')
            output = template.render(username=cherrypy.session['username'])
        return output

    @cherrypy.expose
    def privateMessagesFrom(self, otherUser):
        env = Environment(loader=file_loader)
        template = env.get_template('privateMessages.html')
        try:
            authoriseUserLogin(cherrypy.session['username'])
            getPrivateMessagesFrom(otherUser)
            if len(cherrypy.session['privateMessages']) < 1:
                template = env.get_template('noMessages.html')
                output = template.render(users=cherrypy.session['users'], otherUser=otherUser)
            else:
                output = template.render(messages=cherrypy.session['privateMessages'], users=cherrypy.session['users'], otherUser=otherUser)
            return output
        except:  # There is no username
            template = env.get_template('noMessages.html')
            output = template.render(users=cherrypy.session['users'])
        return output

    @cherrypy.expose
    def sendBroadcast(self, message):
        env = Environment(loader=file_loader)
        template = env.get_template('sentBroadcast.html')
        try:
            authoriseUserLogin(cherrypy.session['username'])
            output = template.render()
            broadcast(cherrypy.session['username'], message)
        except Exception as error:
            print("Broadcast failed, ", error)
            template = env.get_template('home.html')
            output = template.render(username=cherrypy.session['username'])
        return output

    @cherrypy.expose
    def dm(self, message, user):
        env = Environment(loader=file_loader)
        try:
            authoriseUserLogin(cherrypy.session['username'])
            sent = sendPM(cherrypy.session['username'], user, message)
            if sent == 0:
                template = env.get_template('notSent.html')
            else:
                template = env.get_template('sentBroadcast.html')
            output = template.render(user=user)
            return output
        except Exception as error:  # There is no username
            print("Didn't Send,", error)
            template = env.get_template('home.html')
            output = template.render(username=cherrypy.session['username'])
            return output

    @cherrypy.expose
    def inputPM(self):
        listUsers(cherrypy.session['username'])
        getUsers()
        env = Environment(loader=file_loader)
        template = env.get_template('inputPM.html')
        try:
            authoriseUserLogin(cherrypy.session['username'])
            output = template.render(users=cherrypy.session['users'])
            return output
        except Exception as error:
            print("Page failed, ", error)
            template = env.get_template('home.html')
            output = template.render(username=cherrypy.session['username'])
            return output

    @cherrypy.expose
    def pingServer(self):
        authoriseUserLogin(cherrypy.session['username'])
        sPing(cherrypy.session['username'], cherrypy.session['pubkeyHex'])
        env = Environment(loader=file_loader)
        template = env.get_template('home.html')
        output = template.render(username=cherrypy.session['username'])
        return output


###
### Functions only after here
###


def apiKeyGen(username, password):
    url = "http://cs302.kiwi.land/api/load_new_apikey"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))

    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
    }
    payload = json.dumps(payload).encode()

    try:
        reply = response(url, payload, headers)
        dataIn = reply
        dbusername = username
        cherrypy.session['apiKey'] = dataIn['api_key']
        generatedAt = dataIn['api_key_generated_at']
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute(
            "create table if not exists apiKey(id integer primary key autoincrement not null,apiKey unique not null, generatedAt text not null, username text unique not null)")
        c.execute(
            "create table if not exists messages(id integer primary key autoincrement not null,loginServerRecord not null, message text not null, timeSent text not null, signature text not null)")
        c.execute("delete from apiKey where username = ?", [dbusername])
        c.execute("insert into apiKey(apiKey, generatedAt, username) values (?, ?, ?)",
                  (cherrypy.session['apiKey'], generatedAt, username))
        conn.commit()
        conn.close()
        return 0
    except Exception as error:
        print("Failed API key, ", error)
        return 1


def makeKey(username):
    url = "http://cs302.kiwi.land/api/add_pubkey"
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute(
        "create table if not exists users_login(id integer primary key autoincrement not null, username text unique not null, private_key unique)")
    c.execute("select username from users_login where username = ?", [username])
    rows = c.fetchall()
    conn.close()
    if len(rows) < 1:
        signing_key = nacl.signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')
        message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
        cherrypy.session['pubkeyHex'] = pubkey_hex_str
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        cherrypy.session['signingKey'] = signing_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
        c.execute("insert into users_login(username, private_key) values (?, ?)", (username, cherrypy.session['signingKey']))
        conn.commit()
        conn.close()
        cherrypy.session['serverRecord'] = loginServerRecord(username)
        headers = {
            'X-username': username,
            'X-apikey': cherrypy.session['apiKey'],
            'Content-Type': 'application/json; charset=utf-8',
        }

        payload = {
            "pubkey": pubkey_hex_str,
            "username": username,
            "signature": signature_hex_str,
        }
        payload = json.dumps(payload).encode()

        try:
            reply = response(url, payload, headers)
            cherrypy.session['serverRecord'] = reply["loginserver_record"]
            return 0
        except Exception as error:
            print("Make key failed, ", error)
            return 1

    else:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("select private_key from users_login where username = ?", [username])
        rows = c.fetchall()
        conn.close()
        cherrypy.session['signingKey'] = rows[0][0]

        signing_key = bytes.fromhex(cherrypy.session['signingKey'])
        signing_key = nacl.signing.SigningKey(signing_key)
        pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')
        message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
        cherrypy.session['pubkeyHex'] = pubkey_hex_str
        logServerRecord = loginServerRecord(username)
        cherrypy.session['serverRecord'] = logServerRecord['loginserver_record']



def listUsers(username):
    url = "http://cs302.kiwi.land/api/list_users"
    headers = {
        'X-username': username,
        'X-apikey': cherrypy.session['apiKey'],
        'Content-Type': 'application/json; charset=utf-8',
    }
    payload = {
    }
    payload = json.dumps(payload).encode()
    try:
        reply = response(url, payload, headers)
        cherrypy.session['users'] = reply['users']
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("create table if not exists users(id integer primary key autoincrement not null, username text unique not null, ip text not null, user_pubkey text not null, status text not null)")
        c.execute("delete from users")
        for otherUsername in cherrypy.session['users']:
            c.execute("insert into users (username, ip, user_pubkey, status) values (?, ?, ?, ?)", (otherUsername['username'], otherUsername['connection_address'], otherUsername['incoming_pubkey'], otherUsername['status']))
        conn.commit()
        conn.close()
        getInfo()
    except Exception as error:
        print("List did not work,", error)
        return 1


def listPing(username):
    listUsers(cherrypy.session['username'])
    userList = cherrypy.session['users']
    for otherUsername in userList:
        ping_check(username, otherUsername['connection_address'])
    return 1


def checkPubkey(username):
    headers = {
        'X-username': username,
        'X-apikey': cherrypy.session['apiKey'],
        'Content-Type': 'application/json; charset=utf-8',
    }
    record = loginServerRecord(username)
    recordFields = (record['loginserver_record'])
    firstComma = recordFields.find(',')
    secondComma = recordFields.index(',', firstComma + 1)
    userPub = recordFields[firstComma+1:secondComma]
    url = "http://cs302.kiwi.land/api/check_pubkey?pubkey=" + 'b9b4091cfc539bfdba25bee42fe9452f9b03ca0914108428959f81f5ba84815b'
    payload = {
    }
    try:
        reply = response(url, payload, headers)
        print(reply)
        return reply
    except Exception as error:
        print("Failed check pubkey, ", error)
        return 1


def loginPubkey(username):
    #makeKey(username)
    headers = {
        'X-username': username,
        'X-apikey': cherrypy.session['apiKey'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
    }
    url = "http://cs302.kiwi.land/api/loginserver_pubkey"
    try:
        reply = response(url, payload, headers)
        cherrypy.session['serverPub'] = reply
        return 0
    except Exception as error:
        print("Failed login pubkey, ", error)
        return 1


def loginServerRecord(username):
    url = "http://cs302.kiwi.land/api/get_loginserver_record"

    headers = {
        'X-username': username,
        'X-apikey': cherrypy.session['apiKey'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
    }
    payload = json.dumps(payload).encode()

    try:
        reply = response(url, payload, headers)
        return reply
    except Exception as error:
        print("Failed ping server record, ", error)
        return 1


def authoriseUserLogin(username):
    url = "http://cs302.kiwi.land/api/report"
    headers = {
        'X-username': username,
        'X-apikey': cherrypy.session['apiKey'],
        'Content-Type': 'application/json; charset=utf-8',
    }
    payload = {
        'connection_address': cherrypy.session['myIP'],
        'connection_location': cherrypy.session['myPort'],
        'incoming_pubkey': cherrypy.session['pubkeyHex']
    }

    payload = json.dumps(payload).encode()

    try:
        reply = response(url, payload, headers)
        print(reply)
        return 0
    except Exception as error:
        print("Auth User login error", error)
        return 1


def sPing(username, pubkey_hex_str):
    url = "http://cs302.kiwi.land/api/ping"
    headers = {
        'X-username': username,
        'X-apikey': cherrypy.session['apiKey'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey": pubkey_hex_str,
    }
    payload = json.dumps(payload).encode()

    try:
        reply = response(url, payload, headers)
        print(reply)
        return 0
    except Exception as error:
        print("Failed server ping, ", error)
        return 1


def broadcast(username, message):
    ctime = str(time.time())
    headers = {
        'X-username': username,
        'X-apikey': cherrypy.session['apiKey'],
        'Content-Type': 'application/json; charset=utf-8',
    }
    signing_key = bytes.fromhex(cherrypy.session['signingKey'])
    signing_key = nacl.signing.SigningKey(signing_key)
    message_bytes = bytes(cherrypy.session['serverRecord'] + message + ctime, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    payload = {
        'loginserver_record': cherrypy.session['serverRecord'],
        'message': message,
        'sender_created_at': ctime,
        'signature': signature_hex_str,
    }
    payload = json.dumps(payload).encode()
    getInfo()
    for ip in cherrypy.session['ips']:
        try:
            url = "http://" + ip[0] + "/api/rx_broadcast"
            reply = response(url, payload, headers)
            print(reply)
            print(ip[0])
        except Exception as error:
            print("Broadcast failed to ", ip[0], error)
    return 1


def getInfo():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("select ip from users")
    rows = c.fetchall()
    conn.close()
    cherrypy.session['ips'] = rows


def getAllInfo():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("select username, ip, status from users")
    rows = c.fetchall()
    conn.close()
    cherrypy.session['allInfo'] = {}
    for x in range(len(rows)):
        y = rows[x]
        cherrypy.session['allInfo'][x] = y


def getUsers():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("select username from users")
    rows = c.fetchall()
    conn.close()
    cherrypy.session['users'] = rows


def getPublicMessages():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("select loginServerRecord, message from messages order by timeSent desc ")
    rows = c.fetchall()
    conn.close()
    cherrypy.session['publicMessages'] = {}
    cherrypy.session['publicMessages'].clear()
    for x in range(len(rows)):
        y = rows[x]
        message = y[1]
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("select word, replaceWith from filter")
        filterWords = c.fetchall()
        conn.close()
        for j in range(len(filterWords)):
            if filterWords[j][0] in message:
                message = message.replace(filterWords[j][0], filterWords[j][1])

        otherUsername = y[0][0:7]
        data = [otherUsername, message]
        cherrypy.session['publicMessages'][x] = data


def getPublicMessagesFrom(otherUser):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("select loginServerRecord, message from messages order by timeSent desc ")
    rows = c.fetchall()
    conn.close()
    cherrypy.session['publicMessages'] = {}
    cherrypy.session['publicMessages'].clear()
    for x in range(len(rows)):
        if otherUser in rows[x][0]:
            y = rows[x]
            message = y[1]
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("select word, replaceWith from filter")
            filterWords = c.fetchall()
            conn.close()
            for j in range(len(filterWords)):
                if filterWords[j][0] in message:
                    message = message.replace(filterWords[j][0], filterWords[j][1])

            otherUsername = y[0][0:7]
            data = [otherUsername, message]
            cherrypy.session['publicMessages'][x] = data


def getPrivateMessagesFrom(otherUser):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("select loginServerRecord, encrypted_message, targetUsername, signature, timeSent from privatemessages order by timeSent desc ")
    rows = c.fetchall()
    conn.close()
    cherrypy.session['privateMessages'] = {}
    cherrypy.session['privateMessages'].clear()
    signing_key = bytes.fromhex(cherrypy.session['signingKey'])
    signing_key = nacl.signing.SigningKey(signing_key)
    privateKey = signing_key.to_curve25519_private_key()
    unseal_box = nacl.public.SealedBox(privateKey)
    for x in range(len(rows)):
        if cherrypy.session['username'] in rows[x][2] or cherrypy.session['username'] in rows[x][0]:
            if cherrypy.session['username'] in rows[x][0]:
                message = rows[x][1]
            else:
                try:
                    message = bytes(rows[x][1], encoding='utf-8')
                    message_decrypted = unseal_box.decrypt(message, encoder=nacl.encoding.HexEncoder)
                    message = message_decrypted.decode('utf-8')
                except:
                    message = rows[x][1]
            if otherUser in rows[x][0]:
                conn = sqlite3.connect("users.db")
                c = conn.cursor()
                c.execute("select word, replaceWith from filter")
                filterWords = c.fetchall()
                conn.close()
                for j in range(len(filterWords)):
                    if filterWords[j][0] in message.lower():
                        message = message.lower().replace(filterWords[j][0], filterWords[j][1])
                cherrypy.session['privateMessages'][x] = [message, otherUser, rows[x][2][0:7]]
        if cherrypy.session['username'] in rows[x][0] and otherUser in rows[x][2]:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("select word, replaceWith from filter")
            filterWords = c.fetchall()
            conn.close()
            for j in range(len(filterWords)):
                if filterWords[j][0] in message.lower():
                    message = message.lower().replace(filterWords[j][0], filterWords[j][1])
            cherrypy.session['privateMessages'][x] = [message, cherrypy.session['username'], rows[x][2][0:7]]


def getPrivateMessages():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("select loginServerRecord, encrypted_message, targetUsername from privatemessages order by timeSent desc ")
    rows = c.fetchall()
    conn.close()
    cherrypy.session['privateMessages'] = {}
    cherrypy.session['privateMessages'].clear()

    for x in range(len(rows)):
        if cherrypy.session['username'] in rows[x][2] or cherrypy.session['username'] in rows[x][0]:
            if cherrypy.session['username'] in rows[x][0]:
                message = rows[x][1]
            else:
                try:
                    message = bytes(rows[x][1], encoding='utf-8')
                    signing_key = bytes.fromhex(cherrypy.session['signingKey'])
                    signing_key = nacl.signing.SigningKey(signing_key)
                    privateKey = signing_key.to_curve25519_private_key()
                    unseal_box = nacl.public.SealedBox(privateKey)
                    message_decrypted = unseal_box.decrypt(message, encoder=nacl.encoding.HexEncoder)
                    message = message_decrypted.decode('utf-8')
                except:
                    message = rows[x][1]
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("select word, replaceWith from filter")
            filterWords = c.fetchall()
            conn.close()
            otherUsername = rows[x][0][0:7]
            for j in range(len(filterWords)):
                if filterWords[j][0] in message.lower():
                    message = message.lower().replace(filterWords[j][0], filterWords[j][1])
            cherrypy.session['privateMessages'][x] = [message, otherUsername, rows[x][2][0:7]]


def sendPM(username, otherUsername, message):
    ctime = str(time.time())
    headers = {
        'X-username': username,
        'X-apikey': cherrypy.session['apiKey'],
        'Content-Type': 'application/json; charset=utf-8',
    }
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    otherUsername = otherUsername
    c.execute("select ip, user_pubkey from users where username = ?", [otherUsername])
    rows = c.fetchall()
    conn.close()
    verifykey = nacl.signing.VerifyKey(rows[0][1], encoder=nacl.encoding.HexEncoder)
    publickey = verifykey.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(publickey)
    unencrypted_message = message
    message = bytes(message, encoding='utf-8')
    encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)
    message = encrypted.decode('utf-8')
    message_bytes = bytes(cherrypy.session['serverRecord'] + rows[0][1] + otherUsername + message + ctime, encoding='utf-8')
    signing_key = bytes.fromhex(cherrypy.session['signingKey'])
    signing_key = nacl.signing.SigningKey(signing_key)
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    payload = {
        'loginserver_record': cherrypy.session['serverRecord'],
        'target_pubkey': rows[0][1],
        'target_username': otherUsername,
        'encrypted_message': message,
        'sender_created_at': ctime,
        'signature': signature_hex_str,
    }
    payload = json.dumps(payload).encode()

    try:
        url = "http://" + rows[0][0] + "/api/rx_privatemessage"
        reply = response(url, payload, headers)
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute(
            "create table if not exists privatemessages(id integer primary key autoincrement not null, targetUsername text not null,loginServerRecord not null, encrypted_message text not null, timeSent text not null, signature text not null)")
        c.execute(
            "insert into privatemessages(targetUsername, loginServerRecord, encrypted_message, timeSent, signature) values (?, ?, ?, ?, ?)",
            (otherUsername, cherrypy.session['serverRecord'], unencrypted_message, ctime, signature_hex_str))
        conn.commit()
        conn.close()
    except Exception as error:
        print("Send PM didn't work,", error)
        return 0
    return 1


def ping_check(username, ip):
    headers = {
        'X-username': username,
        'X-apikey': cherrypy.session['apiKey'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        'my_time': str(time.time()),
        'connection_address': cherrypy.session['myIP'],
        'connection_location': cherrypy.session['myPort'],
    }
    payload = json.dumps(payload).encode()
    url = 'http://' + ip + '/api/ping_check'
    try:
        reply = response(url, payload, headers)
        print(reply)
        return 0
    except Exception as error:
        print("failed ping check, ", error)
        return 1


def response(url, payload, headers):
    req = urllib.Request(url, data=payload, headers=headers)
    response = urllib.urlopen(req, timeout=2)
    data = response.read()  # read the received bytes
    encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
    JSON_object = json.loads(data.decode(encoding))
    response.close()
    return JSON_object


def contentFilterDB():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    badWords = ["shit", "bitch", "fuck", "cunt", "nigger", "fag", "<script>", "fanny"]
    replaceWith = ["s***", "b****", "f***", "c***", "n****", "f**", "script", "fannypack"]
    c.execute(
        "create table if not exists filter(id integer primary key autoincrement not null, word text unique not null, replaceWith not null)")
    x = 0
    c.execute("delete from filter")
    for badWord in badWords:
        c.execute("insert into filter(word, replaceWith) values (?, ?)", (badWord, replaceWith[x]))
        x = x+1
    conn.commit()
    conn.close()



