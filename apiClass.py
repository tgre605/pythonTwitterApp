import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import sqlite3

startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"

class apiClass(object):

    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_broadcast(self):
        try:
            dataIn = cherrypy.request.json
            loginServerRecord = dataIn['loginserver_record']
            message = dataIn['message']
            timeSent = dataIn['sender_created_at']
            signature = dataIn['signature']

            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute(
                "create table if not exists messages(id integer primary key autoincrement not null,loginServerRecord not null, message text not null, timeSent text not null, signature text not null)")
            c.execute("insert into messages(loginServerRecord, message, timeSent, signature) values (?, ?, ?, ?)", (loginServerRecord, message, timeSent, signature))
            conn.commit()
            conn.close()
            payload = {
                "response": "ok"
            }
            cherrypy.response.headers['Content-Type'] = 'application/json'
            return payload
        except:
            payload = {
                "response": "error"
            }
            cherrypy.response.headers['Content-Type'] = 'application/json'
            return payload

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self):
        try:
            dataIn = cherrypy.request.json
            userTime = dataIn['my_time']
            userIP = dataIn['connection_address']
            userlocation = dataIn['connection_location']
            payload = {
                "response": "ok",
                "message": "You pinging",
                "server_time": str(time.time()),

            }
            cherrypy.response.headers['Content-Type'] = 'application/json'
            return payload
        except:
            payload = {
                "response": "error"
            }
            cherrypy.response.headers['Content-Type'] = 'application/json'
            return payload

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        try:
            dataIn = cherrypy.request.json
            loginServerRecord = dataIn['loginserver_record']
            encrypted_message = dataIn['encrypted_message']
            targetUsername = dataIn['target_username']
            timeSent = dataIn['sender_created_at']
            signature = dataIn['signature']
            conn = sqlite3.connect("users.db")
            if targetUsername == 'tgre605':
                c = conn.cursor()
                c.execute(
                    "create table if not exists privatemessages(id integer primary key autoincrement not null, targetUsername text not null,loginServerRecord not null, encrypted_message text not null, timeSent text not null, signature text not null)")
                c.execute("insert into privatemessages(targetUsername, loginServerRecord, encrypted_message, timeSent, signature) values (?, ?, ?, ?, ?)",
                          (targetUsername, loginServerRecord, encrypted_message, timeSent, signature))
                conn.commit()
                conn.close()
            payload = {
                "response": "ok"
            }
            cherrypy.response.headers['Content-Type'] = 'application/json'
            return payload
        except:
            payload = {
                "response": "error"
            }
            cherrypy.response.headers['Content-Type'] = 'application/json'
            return payload