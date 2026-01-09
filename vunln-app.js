// vulnerable-app.js - SAST検証用サンプル（本番環境では使用しないでください）

const express = require('express');
const mysql = require('mysql');
const fs = require('fs');
const app = express();

// 1. SQLインジェクション脆弱性
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // 危険: パラメータを直接クエリに埋め込み
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (error, results) => {
        res.json(results);
    });
});

// 2. XSS (Cross-Site Scripting) 脆弱性
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    // 危険: ユーザー入力をエスケープせずに出力
    res.send(`<h1>検索結果: ${searchTerm}</h1>`);
});

// 3. パストラバーサル脆弱性
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    // 危険: ファイルパスの検証なし
    fs.readFile(`./uploads/${filename}`, (err, data) => {
        if (err) throw err;
        res.send(data);
    });
});

// 4. ハードコードされた認証情報
const dbConfig = {
    host: 'localhost',
    user: 'admin',
    password: 'password123', // 危険: ハードコードされたパスワード
    database: 'production_db'
};

// 5. 安全でない乱数生成
function generateToken() {
    // 危険: Math.random()は暗号学的に安全ではない
    return Math.random().toString(36).substring(2);
}

// 6. eval()の使用
app.post('/calculate', (req, res) => {
    const expression = req.body.expression;
    // 危険: eval()によるコードインジェクション
    const result = eval(expression);
    res.json({ result: result });
});

// 7. 不適切なエラーハンドリング
app.get('/admin', (req, res) => {
    try {
        // 何らかの処理
        throw new Error('Database connection failed: mysql://admin:password123@localhost:3306/db');
    } catch (error) {
        // 危険: 機密情報を含むエラーメッセージを返す
        res.status(500).send(error.message);
    }
});

app.listen(3000);
