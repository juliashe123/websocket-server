// server.js
import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { createServer } from 'http'
console.log("啟動 Express API & WebSocket Server...");

const app = express();
app.use(bodyParser.json());
app.use(cors()); // ✅ 允許前端跨域請求

const SECRET = "super_secret_key";
const AGENT_ACCOUNT = "service2";
const AGENT_PASSWORD_HASH = bcrypt.hashSync("123456789", 10);

// 黑名單與失敗次數
const failCounts = new Map();  // key: username, value: 次數
const blacklist = new Set();   // 被鎖定帳號

const users = new Map(); // 存放使用者 ws
const agents = new Set(); // 存放客服 ws
let userCounter = 1;

// --------- Express 登入 API ---------
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // 先檢查是否被鎖定
    if (blacklist.has(username)) {
        console.log(`帳號 ${username} 嘗試登入，但已鎖定`);
        return res.json({ success: false, msg: "帳號已鎖定" });
    }

    // 驗證帳號密碼
    if (username === AGENT_ACCOUNT && await bcrypt.compare(password, AGENT_PASSWORD_HASH)) {
        failCounts.delete(username); // 登入成功清除失敗次數
        const token = jwt.sign({ user: username }, SECRET, { expiresIn: '1h' });
        console.log(`客服 ${username} 登入成功`);
        return res.json({ success: true, token });
    } else {
        // 記錄失敗次數
        const fails = (failCounts.get(username) || 0) + 1;
        failCounts.set(username, fails);
        console.log(`登入失敗: ${username} (第 ${fails} 次)`);

        if (fails >= 5) {
            blacklist.add(username);
            console.log(`帳號 ${username} 被鎖定`);
            return res.json({ success: false, msg: "帳號已鎖定，請聯絡管理員0905604695" });
        }

        return res.json({ success: false, msg: "帳號或密碼錯誤" });
    }
});

// --------- 建立共用 HTTP Server ---------
const PORT = process.env.PORT || 3000;
const server = createServer(app);

// --------- WebSocket Server 共用 HTTP Server ---------
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
    ws.role = null;
    ws.id = null;

    ws.on('message', (message) => {
        let data;
        try { data = JSON.parse(message); } catch { return; }

        // 客服登入驗證 token
        if (data.type === 'login') {
            try {
                const payload = jwt.verify(data.token, SECRET);
                ws.role = 'agent';
                agents.add(ws);
                ws.send(JSON.stringify({ type: 'system', msg: '登入成功，你已成為客服' }));
                console.log(`客服已登入 WS: ${payload.user}`);
                return;
            } catch {
                ws.send(JSON.stringify({ type: 'system', msg: 'Token 無效' }));
                ws.close();
                return;
            }
        }

        // 使用者註冊
        if (data.type === 'register' && data.role === 'user') {
            ws.role = 'user';
            ws.id = `user${userCounter++}`;
            users.set(ws.id, ws);
            ws.send(JSON.stringify({ type: 'system', msg: `你的 ID 是 ${ws.id}` }));
            console.log(`新使用者加入: ${ws.id}`);
            return;
        }

        // 使用者訊息 → 轉發給所有客服
        if (data.type === 'msg' && ws.role === 'user') {
            agents.forEach(agent => {
                if (agent.readyState === 1) {
                    agent.send(JSON.stringify({ type: 'msg', msg: data.msg, userID: ws.id }));
                }
            });
            console.log(`使用者 ${ws.id} 發送訊息: ${data.msg}`);
        }

        // 客服回覆 → 發給所有使用者
        if (data.type === 'reply' && ws.role === 'agent') {
            users.forEach(userWs => {
                if (userWs.readyState === 1) {
                    userWs.send(JSON.stringify({ type: 'reply', msg: data.msg, from: 'agent' }));
                }
            });
            console.log(`客服回覆: ${data.msg}`);
        }
    });

    ws.on('close', () => {
        if (ws.role === 'user') {
            users.delete(ws.id);
            console.log(`使用者 ${ws.id} 離線`);
        }
        if (ws.role === 'agent') {
            agents.delete(ws);
            console.log(`客服離線`);
        }
    });
});
// --------- 啟動服務 ---------
server.listen(PORT, () => console.log(`伺服器啟動在 port ${PORT}`));
