var express = require('express');
var parser = require('body-parser');
var fs = require('fs');
var moment = require('moment');
var path = require('path');
var auth_path = path.join(__dirname, '/auth-token.json');

var LogServer = {
    server:express(),

    start() {
        LogServer.auth_path = fs.readFileSync(auth_path);
        LogServer.server.options('*', (req,res,next)=>{LogServer.setHeaders(res); res.send(200)});
        LogServer.server.use((req,res,next)=>{LogServer.setHeaders(res);next()});
        LogServer.server.use(parser.json());
        LogServer.server.use(parser.urlencoded({extended:true}));
        LogServer.requests.forEach(f=>f());
        LogServer.server.listen(4644, '0.0.0.0', ()=>{
            console.log('Listening')
        })
    },
    
    setHeaders(res) {
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept,__requestverificationtoken");
        res.header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        res.header("Access-Control-Allow-Credentials", "true");
        return res;
    },

    get_tokens() {
        return new Promise((resolve,reject)=>{
            fs.readFile(auth_path, 'utf-8', (e,d)=>{
                if (e) reject(e);
                else resolve(JSON.parse(d));
            })
        })
    },

    authorize(req_token) {
        return new Promise((resolve,reject)=>{
            LogServer.get_tokens().then((tokens)=>{
                resolve(tokens.includes(req_token));
            }, e=>reject(e));
        });
    },

    __writeToLog(req_data) {
        return new Promise((resolve,reject)=>{
            if (typeof req_data == 'string') req_data = JSON.parse(req_data);
            var {pc_name, log_str} = req_data;
            if (typeof log_str != 'string') log_str = log_str.value;
            if (!pc_name || !log_str) reject(`PC Name '${pc_name}' or log '${log_str}' contain an empty value.`);
            else {
                var now = moment().format('MM-DD-Y');
                fs.writeFile(path.join(__dirname,`/logs/${now} - ${pc_name}.log`), log_str, (e)=>{
                    if (!e) resolve(true);
                    else reject(e);
                })
            }
        })
    },

    authenticateWriteToLog(req_auth, req_data) {
        return new Promise((resolve,reject)=>{
            LogServer.authorize(req_auth).then((authenticated)=>{
                if (authenticated) LogServer.__writeToLog(req_data).then(r=>resolve(authenticated ? 200:401), e=>reject(e));
            }, e=>console.warn(e));
        })
    },

    respondToLog(req,res) {
        LogServer.setHeaders(res);
        if (!req.body.auth) {
            res.sendStatus(401);
        } else if (!req.body.data) {
            res.sendStatus(400);
        } else {
            let {auth,data} = req.body;
            LogServer.authenticateWriteToLog(auth, data).then(code=>res.sendStatus(code),e=>res.status(400).send({error: e}));
        }
    },

    requests: [
        () => {LogServer.server.get('/test', (req,res)=> {res.send('<h1>Hello world!</h1>')})},
        () => {LogServer.server.post('/log', LogServer.respondToLog)}
    ]
}

LogServer.start();