#!/usr/bin/env python

class JSONScript:
    MscHttpLog={
        'name':'msc-http-log',
        'config':{
            'http_endpoint':'http://%s:9001/msc/kong'
        }
    }

    Cors={
        'name':'cors',
        'config':{
            'origins':'*',
            'methods':['GET','HEAD','PUT','PATCH',
                       'POST','DELETE',],
            'headers':['Origin','Authorization','Accept',
                      'Accept-Version','Content-Length','Content-MD5',
                      'Content-Type','Date'],
            'exposed_headers':['X-Auth-Token','x-msc-token'],
            'credentials':'true',
            'max_age':3600,
        }
    }

    keyAuth={
        'name':'key-auth',
        'config':{
            'key_names':'x-msc-token',
        },
    }

    RequestTransformer={
        'name':'request-transformer',
        'config':{
          'remove':{
              'headers':'X-Consumer-Groups',
          },
        },
    }

    MscLog={
    "logs": {
        "properties": {
            "classInfo": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":'true'
            },
            "errorType": {
                "type": "keyword"

            },
            "warnType": {
               "type": "keyword"

            },
            "debugType": {
                "type": "keyword"

            },
            "infoType": {
               "type": "keyword"

            },
            "logDesc": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                            }
                        },
                        "analyzer":"ik_max_word",
                        "fielddata":'true'
                    },
                    "logLevel": {
                        "type": "keyword"

                    },
                    "logType": {
                        "type": "keyword"

                    },
                    "logResult": {
                        "type": "keyword"

                    },
                    "logUserName": {
                       "type": "keyword"

                    },
                    "logUserIp": {
                        "type": "keyword"

                    },
                    "machineIp": {
                       "type": "keyword"

                    },
                    "system": {
                       "type": "keyword"

                    },
                    "moduleName": {
                        "type": "keyword"

                    },
                    "operateType": {
                        "type": "keyword"

                    },
                    "logUserTrueName": {
                        "type": "keyword"

                    }
                }
            }
    }