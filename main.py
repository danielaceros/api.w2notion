from flask import Flask, redirect, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
import os.path 
import json
import logging
import os
from notion_client import Client
import requests
import imgbbpy
import whisper
import pathlib
import pandas as pd
import dropbox
import traceback
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError
import re
from urllib.parse import urlparse
import datetime
from time import sleep
import requests as r
import base64 
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter, Or
from flask_socketio import SocketIO
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
CORS(app)
model = whisper.load_model("base")
timestamps = [0]
load_dotenv()
db = firestore.Client().from_service_account_json("wh2notion-62f600ea376d.json")
os.environ.get("")

SCOPES = ["https://www.googleapis.com/auth/drive"]

def googledrive(path):
  creds = None
  if os.path.exists("token.json"):
    creds = Credentials.from_authorized_user_file("token.json", SCOPES)
  if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
      creds.refresh(Request())
  try:
    service = build("drive", "v3", credentials=creds)
    file_metadata = {"name": path}
    media = MediaFileUpload(path)
    file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields="id"
        ).execute()
    service.permissions().create(
            fileId=file['id'],
            body={'role': 'reader', 'type': 'anyone'}
        ).execute()
    return f"https://drive.google.com/file/d/{file['id']}/preview"
  except HttpError as error:
    pass
  
def find_property_by_type(data, property_type):
    for key, value in data.items():
        if isinstance(value, dict):
            result = find_property_by_type(value, property_type)
            if result is not None:
                return result
        elif key == "type" and value == property_type:
            return data
    return None

@app.route('/test')
def test():
    return "🤖 Service running..."

@app.route('/v1/connect')
def connect():
    whphone = request.args.get("whphone")
    secret = request.args.get("secret")
    dbid = request.args.get("dbid")
    with open(f"{whphone}.env", "w") as file:
        file.write(f'WHPHONE="{whphone}"\nNOTION_TOKEN="{secret}"\nNOTION_DB="{dbid}"')
        file.close()
    return "🤖 OK", 200

@app.route('/v1/oauth')
def oauth():
    uid = request.cookies.get('firebaseUUID')
    ph = request.cookies.get('phone')
    code = request.args.get("code")
    bs64s = str(os.environ.get('OAUTH_CLIENT_ID')+":"+os.environ.get('OAUTH_CLIENT_SECRET'))
    bs64 = base64.b64encode(bytes(bs64s, "utf-8")).decode("utf-8")
    res = r.post("https://api.notion.com/v1/oauth/token", headers={
        "Authorization":"Basic '"+bs64+"'",
        "Content-Type":"application/json",
    }, json={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://api.w2notion.es/v1/oauth"
    })
    js = json.loads(res.text)
    notiondb = Client(auth=js['access_token'])
    dbs = notiondb.search(**{
        "filter":{
            "value": "database",
            "property": "object"
        },
        "short":{
            "direction":"descending",
            "timestamp":"last_edited_time"
        },
        "page_size": 100
    })
    dbsdics = []
    for dbitem in dbs['results']:
        if dbitem.get("id"):
            idb = dbitem.get('id')
            if dbitem.get("title"):
                dbname = dbitem.get('title')[0].get('text').get('content')
            else:
                dbname = "Untitled"
            if dbitem.get("url"):
                url = dbitem.get("url")
            else:
                url = ""
            if dbitem.get("icon"):
                if dbitem.get("icon").get("type") == "emoji":
                    icon = dbitem.get("icon").get("emoji")
                else:
                    pass
            else:
                icon = ""
            dbdic = {
            "id": idb,
            "dbname": icon + " " + dbname,
            "url": url
            }
            dbsdics.append(dbdic)
        else:
            pass
        
    try:
        doc_ref = db.collection('notion').document(uid)
        document = doc_ref.get()
        if document.exists:
            doc_ref.update({
                "clientId": js['bot_id'],
                "clientSecret": js['access_token'],
                "workspaceId": js['workspace_id'],
                "userId": js['owner']['user']['id'],
                "phone": ph,
                "databasesIds": dbsdics,
                "defaultDatabase": {"dbname": dbsdics[0]['dbname'],
                                    "id": dbsdics[0]['id'],
                                    "url": dbsdics[0]['url']}
            })
        else:
            doc_ref.set({
                "clientId": js['bot_id'],
                "clientSecret": js['access_token'],
                "workspaceId": js['workspace_id'],
                "userId": js['owner']['user']['id'],
                "phone": ph,
                "databasesIds": dbsdics,
                "defaultDatabase": {"dbname": dbsdics[0]['dbname'],
                                    "id": dbsdics[0]['id'],
                                    "url": dbsdics[0]['url']}
            })
        return redirect("https://app.w2notion.es")
    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500
        
@app.route('/webhooks', methods=['POST','GET'])
def webhook():
    try:
        if request.args.get("hub.mode") == "subscribe" and request.args.get("hub.challenge"):
            if not request.args.get("hub.verify_token") == "2c430691981da1941c99123c1b72a205":
                return "Verification token missmatch", 403
            return request.args['hub.challenge'], 200
        d = json.loads(request.data.decode('utf-8'))
        if 'entry' in d and d['entry'] and 'changes' in d['entry'][0] and d['entry'][0]['changes']:
            if 'messages' in d['entry'][0]['changes'][0]['value']:
                if int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']) > timestamps[-1]:
                    nb = d['entry'][0]['changes'][0]['value']['messages'][0]['from']
                    hs = {
                    "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                    'Content-Type': 'application/json'
                    }
                    datas = {
                    "messaging_product": "whatsapp",
                    "to": f"+{nb}",
                    "type": "text",
                    "text": {
                        "preview_url": True,
                        "body": "⏱️ ¡Listened!, sending to queue..."
                    }
                    }
                    rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                    if db.collection('customers').where(filter=FieldFilter("phone","==","+"+nb)).limit(1):
                        pay_ref = db.collection('customers').where(filter=FieldFilter("phone","==","+"+nb)).limit(1)
                        pay_doc = pay_ref.get()
                        if not pay_doc:
                            hs = {
                            "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                            'Content-Type': 'application/json'
                            }
                            datas = {
                                "messaging_product": "whatsapp",
                                "to": f"+{nb}",
                                "type": "text",
                                "text": {
                                    "preview_url": True,
                                    "body": f"🔴 User +{nb}, not on active suscription..."
                                }
                                }
                            rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                            timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                            return jsonify({'error': 'Uncatched error'}), 400
                        else:
                            user_uid = pay_doc[0].id
                            subscriptions_ref = db.collection('customers').document(user_uid).collection('subscriptions')
                            filteractive = FieldFilter("status","==","active")
                            filtertrialing = FieldFilter("status","==","trialing")
                            subscriptions_docs = subscriptions_ref.where(filter=Or(filters=[filteractive, filtertrialing])).limit(1)
                            doc = subscriptions_docs.get()
                            if doc:
                                try:
                                    doc_ref = db.collection('notion').where(filter=FieldFilter("phone","==","+"+nb)).limit(1)
                                    dcs = doc_ref.get()
                                    for dc in dcs:
                                        clientSecret = dc.get("clientSecret")
                                        nameDatabase = dc.get("defaultDatabase")['dbname']
                                        urlDatabase = dc.get("defaultDatabase")['url']
                                        defaultDatabase = dc.get("defaultDatabase")['id']
                                    if "clientSecret" and "defaultDatabase" in locals():
                                        notion = Client(auth=clientSecret)
                                        dbxs = notion.databases.retrieve(database_id=defaultDatabase)
                                        title_property = find_property_by_type(dbxs, "title")['name']
                                    else: 
                                        raise Exception
                                    if d['entry'][0]['changes'][0]['value']['messages'][0]['type'] == "text":
                                        if d['entry'][0]['changes'][0]['value']['messages'][0]['text']['body'] == ".":
                                            if int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']) > timestamps[-1]:
                                                hs = {
                                                    "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                    'Content-Type': 'application/json'
                                                    }
                                                datas = {
                                                    "messaging_product": "whatsapp",
                                                    "to": f"+{nb}",
                                                    "type": "text",
                                                    "text": {
                                                        "preview_url": True,
                                                        "body": f"🟢 ¡Ready to listen!\n🤖➡️ {nameDatabase}\n⚓ {urlDatabase}"
                                                    }
                                                }
                                                rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                                timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                        elif d['entry'][0]['changes'][0]['value']['messages'][0]['text']['body'] != ".":
                                            if int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']) > timestamps[-1]:
                                                msg = {
                                                    "id":d['entry'][0]['id'],
                                                    "waid":d['entry'][0]['changes'][0]['value']['messages'][0]['from'],
                                                    "date":d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp'],
                                                    "type":d['entry'][0]['changes'][0]['value']['messages'][0]['type'],
                                                    "content":d['entry'][0]['changes'][0]['value']['messages'][0]['text']['body']
                                                }
                                                regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
                                                url = re.findall(regex, msg['content'])
                                                if url:
                                                    caption = msg['content'].replace(url[0][0], "").strip()
                                                    if len(caption) == 0:
                                                        caption = msg['content']
                                                    else:
                                                        pass
                                                    n = notion.pages.create(**{
                                                                "parent":{
                                                                    "database_id":defaultDatabase
                                                                },
                                                                "properties":{
                                                                    f"{title_property}":{
                                                                        "type":"title",
                                                                        "title":[
                                                                            {"type": "text", 
                                                                            "text": {
                                                                                "content": caption,
                                                                                "link":{
                                                                                    "url":url[0][0]
                                                                                }
                                                                                }
                                                                            }
                                                                            ],

                                                                    }
                                                                }
                                                            })    
                                                else:
                                                    n = notion.pages.create(**{
                                                        "parent":{
                                                            "database_id":defaultDatabase
                                                        },
                                                        "properties":{
                                                            f"{title_property}":{
                                                                "type":"title",
                                                                "title":[{"type": "text", "text": {"content": msg['content']}}]
                                                            }
                                                        }
                                                    })
                                                hs = {
                                                "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                'Content-Type': 'application/json'
                                                }
                                                datas = {
                                                    "messaging_product": "whatsapp",
                                                    "to": f"+{nb}",
                                                    "type": "text",
                                                    "text": {
                                                        "preview_url": True,
                                                        "body": "🟢 ¡Task added sucessfully!\n🤖➡️ '"+msg['content']+"'\n⚓ "+n['url']
                                                    }
                                                }
                                                rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                                timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                            else:
                                                pass
                                    elif d['entry'][0]['changes'][0]['value']['messages'][0]['type'] == "image":
                                        if int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']) > timestamps[-1]:
                                                if 'caption' in d['entry'][0]['changes'][0]['value']['messages'][0]['image']:
                                                    cap = d['entry'][0]['changes'][0]['value']['messages'][0]['image']['caption']
                                                else:
                                                    cap = None
                                                msg = {
                                                            "id":d['entry'][0]['id'],
                                                            "waid":d['entry'][0]['changes'][0]['value']['messages'][0]['from'],
                                                            "date":d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp'],
                                                            "type":d['entry'][0]['changes'][0]['value']['messages'][0]['type'],
                                                            "content":d['entry'][0]['changes'][0]['value']['messages'][0]['image']['id']
                                                        }
                                                h = {
                                                    'Authorization':'Bearer '+os.environ.get("FB_APIKEY")
                                                }
                                                r = requests.get('https://graph.facebook.com/v18.0/'+msg['content']+'/', headers=h)
                                                d2 = r.json()
                                                r2 = requests.get(d2['url'], headers=h)
                                                path = "./media/"+msg['content']+'.jpg'
                                                open(path, 'wb+').write(r2.content)
                                                lk = googledrive(path)
                                                if cap == None:
                                                    cap = lk
                                                n = notion.pages.create(**{
                                                            "parent":{
                                                                "database_id":defaultDatabase
                                                            },
                                                            "properties":{
                                                                f"{title_property}":{
                                                                    "type":"title",
                                                                    "title":[
                                                                        {"type": "text", 
                                                                        "text": {
                                                                            "content": cap,
                                                                            "link":{
                                                                                "url":lk
                                                                            }
                                                                            }
                                                                        }
                                                                        ],

                                                                }
                                                            }
                                                        })
                                                os.remove(path)
                                                hs = {
                                                "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                'Content-Type': 'application/json'
                                                }
                                                datas = {
                                                    "messaging_product": "whatsapp",
                                                    "to": f"+{nb}",
                                                    "type": "text",
                                                    "text": {
                                                        "preview_url": True,
                                                        "body": "🟢 ¡Task added sucessfully!\n🤖➡️ '"+cap+"'\n⚓ "+n['url']
                                                    }
                                                }
                                                rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                                timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                        else:
                                            pass
                                    elif d['entry'][0]['changes'][0]['value']['messages'][0]['type'] == "audio":
                                        if int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']) > timestamps[-1]:
                                                msg = {
                                                            "id":d['entry'][0]['id'],
                                                            "waid":d['entry'][0]['changes'][0]['value']['messages'][0]['from'],
                                                            "date":d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp'],
                                                            "type":d['entry'][0]['changes'][0]['value']['messages'][0]['type'],
                                                            "content":d['entry'][0]['changes'][0]['value']['messages'][0]['audio']['id']
                                                        }
                                                h = {
                                                    'Authorization':'Bearer '+os.environ.get("FB_APIKEY")
                                                }
                                                r = requests.get('https://graph.facebook.com/v18.0/'+msg['content']+'/', headers=h)
                                                d2 = r.json()
                                                r2 = requests.get(d2['url'], headers=h)
                                                path = "./media/"+msg['content']+'.mp3'
                                                open(path, 'wb+').write(r2.content)
                                                if d['entry'][0]['changes'][0]['value']['messages'][0]['audio']['mime_type'] == "audio/ogg; codecs=opus":
                                                    result = model.transcribe(path)
                                                    n = notion.pages.create(**{
                                                        "parent":{
                                                            "database_id":defaultDatabase
                                                        },
                                                        "properties":{
                                                            f"{title_property}":{
                                                                "type":"title",
                                                                "title":[{"type": "text", "text": {"content": result['text'].strip()}}]
                                                            }
                                                        }
                                                    })
                                                    os.remove(path)
                                                    hs = {
                                                    "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                    'Content-Type': 'application/json'
                                                    }
                                                    datas = {
                                                        "messaging_product": "whatsapp",
                                                        "to": f"+{nb}",
                                                        "type": "text",
                                                        "text": {
                                                            "preview_url": True,
                                                            "body": "🟢 ¡Task added sucessfully!\n🤖➡️ '"+result['text'].strip()+"'\n⚓ "+n['url']
                                                        }
                                                    }
                                                    rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                                    timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                                else:
                                                    lk = googledrive(path)
                                                    n = notion.pages.create(**{
                                                            "parent":{
                                                                "database_id":defaultDatabase
                                                            },
                                                            "properties":{
                                                                f"{title_property}":{
                                                                    "type":"title",
                                                                    "title":[
                                                                        {"type": "text", 
                                                                        "text": {
                                                                            "content": lk,
                                                                            "link":{
                                                                                "url":lk
                                                                            }
                                                                            }
                                                                        }
                                                                        ],

                                                                }
                                                            }
                                                        })
                                                    os.remove(path)
                                                    hs = {
                                                    "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                    'Content-Type': 'application/json'
                                                    }
                                                    datas = {
                                                        "messaging_product": "whatsapp",
                                                        "to": f"+{nb}",
                                                        "type": "text",
                                                        "text": {
                                                            "preview_url": True,
                                                            "body": "🟢 ¡Task added sucessfully!\n🤖➡️ '"+lk+"'\n⚓ "+n['url']
                                                        }
                                                    }
                                                    rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                                    timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                        else:
                                            pass
                                    elif d['entry'][0]['changes'][0]['value']['messages'][0]['type'] == 'document':
                                        if int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']) > timestamps[-1]:
                                                msg = {
                                                            "id":d['entry'][0]['id'],
                                                            "waid":d['entry'][0]['changes'][0]['value']['messages'][0]['from'],
                                                            "date":d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp'],
                                                            "type":d['entry'][0]['changes'][0]['value']['messages'][0]['type'],
                                                            "content":d['entry'][0]['changes'][0]['value']['messages'][0]['document']['id'],
                                                            "mime":d['entry'][0]['changes'][0]['value']['messages'][0]['document']['mime_type'],
                                                            "filename":d['entry'][0]['changes'][0]['value']['messages'][0]['document']['filename'].replace(" ","")
                                                        }
                                                h = {
                                                    'Authorization':'Bearer '+os.environ.get("FB_APIKEY")
                                                }
                                                r = requests.get('https://graph.facebook.com/v18.0/'+msg['content']+'/', headers=h)
                                                d2 = r.json()
                                                r2 = requests.get(d2['url'], headers=h)
                                                path = "./media/"+msg['content']+os.path.splitext(msg['filename'])[1]
                                                open(path, 'wb+').write(r2.content)
                                                lk = googledrive(path)
                                                n = notion.pages.create(**{
                                                            "parent":{
                                                                "database_id":defaultDatabase
                                                            },
                                                            "properties":{
                                                                f"{title_property}":{
                                                                    "type":"title",
                                                                    "title":[
                                                                        {"type": "text", 
                                                                        "text": {
                                                                            "content": msg['filename'],
                                                                            "link":{
                                                                                "url":lk
                                                                            }
                                                                            }
                                                                        }
                                                                        ],

                                                                }
                                                            }
                                                        })
                                                os.remove(path)
                                                hs = {
                                                "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                'Content-Type': 'application/json'
                                                }
                                                datas = {
                                                    "messaging_product": "whatsapp",
                                                    "to": f"+{nb}",
                                                    "type": "text",
                                                    "text": {
                                                        "preview_url": True,
                                                        "body": "🟢 ¡Task added sucessfully!\n🤖➡️ '"+msg['filename']+"'\n⚓ "+n['url']
                                                    }
                                                }
                                                rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                                timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                        else:
                                            pass
                                    elif d['entry'][0]['changes'][0]['value']['messages'][0]['type'] == 'video':
                                        if int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']) > timestamps[-1]:
                                                if 'caption' in d['entry'][0]['changes'][0]['value']['messages'][0]['video']:
                                                    cap = d['entry'][0]['changes'][0]['value']['messages'][0]['video']['caption']
                                                else:
                                                    cap = None
                                                msg = {
                                                            "id":d['entry'][0]['id'],
                                                            "waid":d['entry'][0]['changes'][0]['value']['messages'][0]['from'],
                                                            "date":d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp'],
                                                            "type":d['entry'][0]['changes'][0]['value']['messages'][0]['type'],
                                                            "content":d['entry'][0]['changes'][0]['value']['messages'][0]['video']['id'],
                                                            "mime":d['entry'][0]['changes'][0]['value']['messages'][0]['video']['mime_type']
                                                        }
                                                h = {
                                                    'Authorization':'Bearer '+os.environ.get("FB_APIKEY")
                                                }
                                                r = requests.get('https://graph.facebook.com/v18.0/'+msg['content']+'/', headers=h)
                                                d2 = r.json()
                                                r2 = requests.get(d2['url'], headers=h)
                                                path = "./media/"+msg['content']+".mp4"
                                                open(path, 'wb+').write(r2.content)
                                                lk = googledrive(path)
                                                if cap == None:
                                                    cap = lk
                                                n = notion.pages.create(**{
                                                            "parent":{
                                                                "database_id":defaultDatabase
                                                            },
                                                            "properties":{
                                                                f"{title_property}":{
                                                                    "type":"title",
                                                                    "title":[
                                                                        {"type": "text", 
                                                                        "text": {
                                                                            "content": cap,
                                                                            "link":{
                                                                                "url":lk
                                                                            }
                                                                            }
                                                                        }
                                                                        ],

                                                                }
                                                            }
                                                        })
                                                os.remove(path)
                                                hs = {
                                                "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                'Content-Type': 'application/json'
                                                }
                                                datas = {
                                                    "messaging_product": "whatsapp",
                                                    "to": f"+{nb}",
                                                    "type": "text",
                                                    "text": {
                                                        "preview_url": True,
                                                        "body": "🟢 ¡Task added sucessfully!\n🤖➡️ '"+cap+"'\n⚓ "+n['url']
                                                    }
                                                }
                                                rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                                timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                        else:
                                            pass
                                    elif d['entry'][0]['changes'][0]['value']['messages'][0]['type'] == 'contacts':
                                        if int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']) > timestamps[-1]:
                                                msg = {
                                                    "id":d['entry'][0]['id'],
                                                    "waid":d['entry'][0]['changes'][0]['value']['messages'][0]['from'],
                                                    "date":d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp'],
                                                    "type":d['entry'][0]['changes'][0]['value']['messages'][0]['type'],
                                                    "contact":d['entry'][0]['changes'][0]['value']['messages'][0]['contacts'][0]['name']['formatted_name'],
                                                    "number":d['entry'][0]['changes'][0]['value']['messages'][0]['contacts'][0]['phones'][0]['phone'].strip()
                                                }
                                                n = notion.pages.create(**{
                                                            "parent":{
                                                                "database_id":defaultDatabase
                                                            },
                                                            "properties":{
                                                                f"{title_property}":{
                                                                    "type":"title",
                                                                    "title":[
                                                                        {"type": "text", 
                                                                        "text": {
                                                                            "content": msg['contact']+" - "+msg['number'],
                                                                            "link":{
                                                                                "url":"tel:"+msg['number']
                                                                            }
                                                                            }
                                                                        }
                                                                        ],

                                                                }
                                                            }
                                                        })
                                                hs = {
                                                "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                'Content-Type': 'application/json'
                                                }
                                                datas = {
                                                    "messaging_product": "whatsapp",
                                                    "to": f"+{nb}",
                                                    "type": "text",
                                                    "text": {
                                                        "preview_url": True,
                                                        "body": "🟢 ¡Task added sucessfully!\n🤖➡️ '"+msg['contact']+" - "+msg['number']+"'\n⚓ "+n['url']
                                                    }
                                                }
                                                rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                                timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                        else:
                                            pass
                                    elif d['entry'][0]['changes'][0]['value']['messages'][0]['type'] == 'location':
                                        if 'name' in d['entry'][0]['changes'][0]['value']['messages'][0]['location']:
                                            msg = {
                                                    "id":d['entry'][0]['id'],
                                                    "waid":d['entry'][0]['changes'][0]['value']['messages'][0]['from'],
                                                    "date":d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp'],
                                                    "type":d['entry'][0]['changes'][0]['value']['messages'][0]['type'],
                                                    "address":d['entry'][0]['changes'][0]['value']['messages'][0]['location']['address'],
                                                    "name":d['entry'][0]['changes'][0]['value']['messages'][0]['location']['name'],
                                                    "la":d['entry'][0]['changes'][0]['value']['messages'][0]['location']['latitude'],
                                                    "lo":d['entry'][0]['changes'][0]['value']['messages'][0]['location']['longitude']
                                                }
                                            n = notion.pages.create(**{
                                                            "parent":{
                                                                "database_id":defaultDatabase
                                                            },
                                                            "properties":{
                                                                f"{title_property}":{
                                                                    "type":"title",
                                                                    "title":[
                                                                        {"type": "text", 
                                                                        "text": {
                                                                            "content": msg['name']+" - "+msg['address'],
                                                                            "link":{
                                                                                "url":"https://www.google.es/maps/search/"+msg['name']+" "+msg['address']
                                                                            }
                                                                            }
                                                                        }
                                                                        ],

                                                                }
                                                            }
                                                        })
                                            hs = {
                                                "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                'Content-Type': 'application/json'
                                                }
                                            datas = {
                                                    "messaging_product": "whatsapp",
                                                    "to": f"+{nb}",
                                                    "type": "text",
                                                    "text": {
                                                        "preview_url": True,
                                                        "body": "🟢 ¡Task added sucessfully!\n🤖➡️ '"+msg['name']+" - "+msg['address']+"'\n⚓ "+n['url']
                                                    }
                                                }
                                            rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                            timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                        elif 'name' not in d['entry'][0]['changes'][0]['value']['messages'][0]['location']:
                                            msg = {
                                                    "id":d['entry'][0]['id'],
                                                    "waid":d['entry'][0]['changes'][0]['value']['messages'][0]['from'],
                                                    "date":d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp'],
                                                    "type":d['entry'][0]['changes'][0]['value']['messages'][0]['type'],
                                                    "la":str(d['entry'][0]['changes'][0]['value']['messages'][0]['location']['latitude']),
                                                    "lo":str(d['entry'][0]['changes'][0]['value']['messages'][0]['location']['longitude'])
                                                }
                                            n = notion.pages.create(**{
                                                            "parent":{
                                                                "database_id":defaultDatabase
                                                            },
                                                            "properties":{
                                                                f"{title_property}":{
                                                                    "type":"title",
                                                                    "title":[
                                                                        {"type": "text", 
                                                                        "text": {
                                                                            "content": msg['la']+" - "+msg['lo'],
                                                                            "link":{
                                                                                "url":"https://www.google.es/maps/@"+msg['la']+","+msg['lo']+",18z?entry=ttu"
                                                                            }
                                                                            }
                                                                        }
                                                                        ],

                                                                }
                                                            }
                                                        })
                                            hs = {
                                                "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                                'Content-Type': 'application/json'
                                                }
                                            datas = {
                                                    "messaging_product": "whatsapp",
                                                    "to": f"+{nb}",
                                                    "type": "text",
                                                    "text": {
                                                        "preview_url": True,
                                                        "body": "🟢 ¡Task added sucessfully!\n🤖➡️ '"+msg['la']+" - "+msg['lo']+"'\n⚓ "+n['url']
                                                    }
                                                }
                                            rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                            timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                        pass
                                except KeyError:
                                    pass    
                                except Exception:
                                        hs = {
                                            "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                                            'Content-Type': 'application/json'
                                            }
                                        datas = {
                                                "messaging_product": "whatsapp",
                                                "to": f"+{nb}",
                                                "type": "text",
                                                "text": {
                                                    "preview_url": True,
                                                    "body": "🔴 ¡Error while creating task...!" 
                                                }
                                            }
                                        rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                                        timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                                        return jsonify({'error': 'Uncatched error'}), 400
                                return "🤖 ¡Webhook ran!", 200
                            else:
                                hs = {
                            "Authorization": "Bearer "+os.environ.get("FB_APIKEY"),
                            'Content-Type': 'application/json'
                                }
                            datas = {
                                "messaging_product": "whatsapp",
                                "to": f"+{nb}",
                                "type": "text",
                                "text": {
                                    "preview_url": True,
                                    "body": f"🔴 User +{nb}, not on active suscription..."
                                }
                                }
                            rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                            timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                            return jsonify({'error': 'Uncatched error'}), 400       
                else:
                    return jsonify({'error': 'Timestamp unmatch error'}), 400               
            elif 'statuses' in d['entry'][0]['changes'][0]['value']:
                return jsonify({'error': 'No messages in the webhook payload'}), 400
            else:
                return jsonify({'error': 'No messages in the webhook payload'}), 400
        else:
            return jsonify({'error': 'Invalid webhook payload'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
   app.run(debug=True,host='0.0.0.0',port=5001)