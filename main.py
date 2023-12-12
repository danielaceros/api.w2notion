from flask import Flask, request
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

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
CORS(app)
model = whisper.load_model("base")
timestamps = [0]
load_dotenv()

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
    code = request.args.get("code")
    state = request.args.get("state")
    clien = os.environ.get('OAUTH_CLIENT_ID')
    bs64s = str(os.environ.get('OAUTH_CLIENT_ID')+":"+os.environ.get('OAUTH_CLIENT_SECRET'))
    bs64 = base64.b64encode(bytes(bs64s, "utf-8")).decode("utf-8")
    res = r.post("https://api.notion.com/v1/oauth/token", headers={
        "Authorization":"Basic '"+bs64+"'",
        "Content-Type":"application/json",
    }, data={
        "grant_type": "authorization_code",
        "code": code,
          "redirect_uri": "https://api.w2notion.es/v1/callback"
    })
    print(res.json()) 

    
@app.route('/v1/callback')
def callback():
    access_token = request.args.get("access_token")
    bot_id = request.args.get("bot_id")
    return access_token

@app.route('/webhooks', methods=['POST','GET'])
def webhook():
   if request.args.get("hub.mode") == "subscribe" and request.args.get("hub.challenge"):
       if not request.args.get("hub.verify_token")== "2c430691981da1941c99123c1b72a205":
           return "Verification token missmatch", 403
       return request.args['hub.challenge'], 200
   d = json.loads(request.data.decode('utf-8'))
   try:
    nb = d['entry'][0]['changes'][0]['value']['messages'][0]['from']
    load_dotenv(f"{nb}.env")
    print(nb)
   except KeyError as e:
    pass
   notion = Client(auth=os.getenv("NOTION_TOKEN"))
   try:
    if d['entry'][0]['changes'][0]['value']['messages'][0]['type'] == "text":
        if d['entry'][0]['changes'][0]['value']['messages'][0]['text']['body'] == ".":
            hs = {
                "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                'Content-Type': 'application/json'
                }
            datas = {
                "messaging_product": "whatsapp",
                "to": f"+{nb}",
                "type": "text",
                "text": {
                    "preview_url": True,
                    "body": "🦾 ¡Ready to listen!"
                }
            }
            rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
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
                                    "database_id":os.getenv("NOTION_DB")
                                },
                                "properties":{
                                    "Name":{
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
                            "database_id":os.getenv("NOTION_DB")
                        },
                        "properties":{
                            "Name":{
                                "type":"title",
                                "title":[{"type": "text", "text": {"content": msg['content']}}]
                            }
                        }
                    })
                hs = {
                "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                'Content-Type': 'application/json'
                }
                datas = {
                    "messaging_product": "whatsapp",
                    "to": f"+{nb}",
                    "type": "text",
                    "text": {
                        "preview_url": True,
                        "body": "🤖 ¡Task added sucessfully!\n"+n['url']
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
                    'Authorization':'Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF'
                }
                r = requests.get('https://graph.facebook.com/v18.0/'+msg['content']+'/', headers=h)
                d2 = r.json()
                r2 = requests.get(d2['url'], headers=h)
                path = "./media/"+msg['content']+'.jpg'
                open(path, 'wb+').write(r2.content)
                dbx = dropbox.Dropbox("sl.Bp2AkXA6nT5yu8y6BWQJDUYe68S-aje88i105EGsZuLjpUjUj0tF-ngYwUhT5ZMmH0rRn0NlP78DNuqA21ejHrOC-cL_dRHPsDLd_DHAtv-0DVF9optV8fzsiiaL40JZdanXT3PZvGRcvpo")
                with open(path, 'rb') as f:
                    dbx.files_upload(f.read(), "/"+msg['content']+".jpg", mode=WriteMode('overwrite'))
                    try:
                        lk = dbx.sharing_create_shared_link("/"+msg['content']+".jpg")
                    except:
                        raise Exception
                if cap == None:
                    cap = lk.url
                n = notion.pages.create(**{
                            "parent":{
                                "database_id":os.getenv("NOTION_DB")
                            },
                            "properties":{
                                "Name":{
                                    "type":"title",
                                    "title":[
                                        {"type": "text", 
                                        "text": {
                                            "content": cap,
                                            "link":{
                                                "url":lk.url
                                            }
                                            }
                                        }
                                        ],

                                }
                            }
                        })
                os.remove(path)
                hs = {
                "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                'Content-Type': 'application/json'
                }
                datas = {
                    "messaging_product": "whatsapp",
                    "to": f"+{nb}",
                    "type": "text",
                    "text": {
                        "preview_url": True,
                        "body": "🤖 ¡Task added sucessfully!\n"+n['url']
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
                    'Authorization':'Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF'
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
                            "database_id":os.getenv("NOTION_DB")
                        },
                        "properties":{
                            "Name":{
                                "type":"title",
                                "title":[{"type": "text", "text": {"content": result['text'].strip()}}]
                            }
                        }
                    })
                    os.remove(path)
                    hs = {
                    "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                    'Content-Type': 'application/json'
                    }
                    datas = {
                        "messaging_product": "whatsapp",
                        "to": f"+{nb}",
                        "type": "text",
                        "text": {
                            "preview_url": True,
                            "body": "🤖 ¡Task added sucessfully!\n"+n['url']
                        }
                    }
                    rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
                    timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
                else:
                    dbx = dropbox.Dropbox("sl.Bp2AkXA6nT5yu8y6BWQJDUYe68S-aje88i105EGsZuLjpUjUj0tF-ngYwUhT5ZMmH0rRn0NlP78DNuqA21ejHrOC-cL_dRHPsDLd_DHAtv-0DVF9optV8fzsiiaL40JZdanXT3PZvGRcvpo")
                    with open(path, 'rb') as f:
                        dbx.files_upload(f.read(), "/"+msg['content']+".mp3", mode=WriteMode('overwrite'))
                        try:
                            lk = dbx.sharing_create_shared_link("/"+msg['content']+".mp3")
                        except:
                            raise Exception
                    n = notion.pages.create(**{
                            "parent":{
                                "database_id":os.getenv("NOTION_DB")
                            },
                            "properties":{
                                "Name":{
                                    "type":"title",
                                    "title":[
                                        {"type": "text", 
                                        "text": {
                                            "content": lk.url,
                                            "link":{
                                                "url":lk.url
                                            }
                                            }
                                        }
                                        ],

                                }
                            }
                        })
                    os.remove(path)
                    hs = {
                    "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                    'Content-Type': 'application/json'
                    }
                    datas = {
                        "messaging_product": "whatsapp",
                        "to": f"+{nb}",
                        "type": "text",
                        "text": {
                            "preview_url": True,
                            "body": "🤖 ¡Task added sucessfully!\n"+n['url']
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
                    'Authorization':'Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF'
                }
                r = requests.get('https://graph.facebook.com/v18.0/'+msg['content']+'/', headers=h)
                d2 = r.json()
                r2 = requests.get(d2['url'], headers=h)
                path = "./media/"+msg['content']+os.path.splitext(msg['filename'])[1]
                open(path, 'wb+').write(r2.content)
                dbx = dropbox.Dropbox("sl.Bp2AkXA6nT5yu8y6BWQJDUYe68S-aje88i105EGsZuLjpUjUj0tF-ngYwUhT5ZMmH0rRn0NlP78DNuqA21ejHrOC-cL_dRHPsDLd_DHAtv-0DVF9optV8fzsiiaL40JZdanXT3PZvGRcvpo")
                with open(path, 'rb') as f:
                    dbx.files_upload(f.read(), "/"+msg['content']+os.path.splitext(msg['filename'])[1], mode=WriteMode('overwrite'))
                    try:
                        lk = dbx.sharing_create_shared_link("/"+msg['content']+os.path.splitext(msg['filename'])[1])
                    except:
                        raise Exception
                n = notion.pages.create(**{
                            "parent":{
                                "database_id":os.getenv("NOTION_DB")
                            },
                            "properties":{
                                "Name":{
                                    "type":"title",
                                    "title":[
                                        {"type": "text", 
                                        "text": {
                                            "content": msg['filename'],
                                            "link":{
                                                "url":lk.url
                                            }
                                            }
                                        }
                                        ],

                                }
                            }
                        })
                os.remove(path)
                hs = {
                "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                'Content-Type': 'application/json'
                }
                datas = {
                    "messaging_product": "whatsapp",
                    "to": f"+{nb}",
                    "type": "text",
                    "text": {
                        "preview_url": True,
                        "body": "🤖 ¡Task added sucessfully!\n"+n['url']
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
                    'Authorization':'Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF'
                }
                r = requests.get('https://graph.facebook.com/v18.0/'+msg['content']+'/', headers=h)
                d2 = r.json()
                r2 = requests.get(d2['url'], headers=h)
                path = "./media/"+msg['content']+".mp4"
                open(path, 'wb+').write(r2.content)
                dbx = dropbox.Dropbox("sl.Bp2AkXA6nT5yu8y6BWQJDUYe68S-aje88i105EGsZuLjpUjUj0tF-ngYwUhT5ZMmH0rRn0NlP78DNuqA21ejHrOC-cL_dRHPsDLd_DHAtv-0DVF9optV8fzsiiaL40JZdanXT3PZvGRcvpo")
                with open(path, 'rb') as f:
                    dbx.files_upload(f.read(), "/"+msg['content']+".mp4", mode=WriteMode('overwrite'))
                    try:
                        lk = dbx.sharing_create_shared_link("/"+msg['content']+".mp4")
                    except:
                        raise Exception
                if cap == None:
                    cap = lk.url
                n = notion.pages.create(**{
                            "parent":{
                                "database_id":os.getenv("NOTION_DB")
                            },
                            "properties":{
                                "Name":{
                                    "type":"title",
                                    "title":[
                                        {"type": "text", 
                                        "text": {
                                            "content": cap,
                                            "link":{
                                                "url":lk.url
                                            }
                                            }
                                        }
                                        ],

                                }
                            }
                        })
                os.remove(path)
                hs = {
                "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                'Content-Type': 'application/json'
                }
                datas = {
                    "messaging_product": "whatsapp",
                    "to": f"+{nb}",
                    "type": "text",
                    "text": {
                        "preview_url": True,
                        "body": "🤖 ¡Task added sucessfully!\n"+n['url']
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
                                "database_id":os.getenv("NOTION_DB")
                            },
                            "properties":{
                                "Name":{
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
                "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                'Content-Type': 'application/json'
                }
                datas = {
                    "messaging_product": "whatsapp",
                    "to": f"+{nb}",
                    "type": "text",
                    "text": {
                        "preview_url": True,
                        "body": "🤖 ¡Task added sucessfully!\n"+n['url']
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
                                "database_id":os.getenv("NOTION_DB")
                            },
                            "properties":{
                                "Name":{
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
                "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                'Content-Type': 'application/json'
                }
            datas = {
                    "messaging_product": "whatsapp",
                    "to": f"+{nb}",
                    "type": "text",
                    "text": {
                        "preview_url": True,
                        "body": "🤖 ¡Task added sucessfully!\n"+n['url']
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
                                "database_id":os.getenv("NOTION_DB")
                            },
                            "properties":{
                                "Name":{
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
                "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
                'Content-Type': 'application/json'
                }
            datas = {
                    "messaging_product": "whatsapp",
                    "to": f"+{nb}",
                    "type": "text",
                    "text": {
                        "preview_url": True,
                        "body": "🤖 ¡Task added sucessfully!\n"+n['url']
                    }
                }
            rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
            timestamps.append(int(d['entry'][0]['changes'][0]['value']['messages'][0]['timestamp']))
        pass
   except KeyError as e:
       pass
   except Exception:
        hs = {
            "Authorization": "Bearer EAAEmZB6Ke8OgBOxhARTLHk0mHHdbHstnIDqoEEoDK99SVJIllLSWFHEFYfRefYiVYLt1ZCJhvhVvjOxLTmOz6cHm3ZBeiu9JIQmzQyV29Mb7AoLDqlgnSZCsGK5i8YHuOjGbwDjWJZCBZCIfUhFgmuWwEKBEIqq20Km2tRu13tF6oLLjITo8gA9IANF9ysMejF",
            'Content-Type': 'application/json'
            }
        datas = {
                "messaging_product": "whatsapp",
                "to": f"+{nb}",
                "type": "text",
                "text": {
                    "preview_url": True,
                    "body": "😡 ¡Error while creating task...!" 
                }
            }
        rs = requests.post(f"https://graph.facebook.com/v18.0/157728167427201/messages", headers=hs, data=json.dumps(datas))
   return "🤖 ¡Webhook ran!", 200

if __name__ == "__main__":
   app.run(debug=True,host='0.0.0.0',port=5001)