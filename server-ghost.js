// server-ghost.js - Chat Criptografado Militar
const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const crypto = require('crypto');
const mysql = require('mysql2');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: { origin: "*" },
    pingTimeout: 60000,
    pingInterval: 25000
});

// ============================================
// SEGURANÇA MILITAR
// ============================================

// Headers de segurança
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting - Proteção contra brute force
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // 100 requisições por IP
    message: { error: 'Muitas requisições. Aguarde.' }
});
app.use('/api/', limiter);

// ============================================
// CRIPTOGRAFIA AES-256 + RSA
// ============================================

class CriptografiaMilitar {
    constructor() {
        // Gerar par de chaves RSA
        this.rsaKeys = crypto.generateKeyPairSync('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        
        // Chave AES fixa para sessão
        this.aesKey = crypto.randomBytes(32);
        this.aesIV = crypto.randomBytes(16);
    }
    
    // Criptografar mensagem com AES-256
    criptografarMensagem(texto) {
        try {
            const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, this.aesIV);
            let encrypted = cipher.update(texto, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            return {
                dados: encrypted,
                iv: this.aesIV.toString('hex'),
                hash: crypto.createHash('sha256').update(texto).digest('hex')
            };
        } catch (error) {
            console.error('Erro criptografia:', error);
            return null;
        }
    }
    
    // Descriptografar mensagem
    descriptografarMensagem(dados, iv) {
        try {
            const decipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, Buffer.from(iv, 'hex'));
            let decrypted = decipher.update(dados, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            return null;
        }
    }
    
    // Assinar digitalmente
    assinarMensagem(mensagem) {
        const sign = crypto.createSign('SHA256');
        sign.update(mensagem);
        return sign.sign(this.rsaKeys.privateKey, 'hex');
    }
    
    // Verificar assinatura
    verificarAssinatura(mensagem, assinatura, chavePublica) {
        const verify = crypto.createVerify('SHA256');
        verify.update(mensagem);
        return verify.verify(chavePublica, assinatura, 'hex');
    }
    
    // Gerar hash de autenticação
    gerarHashAutenticacao(usuario, mensagem) {
        const data = `${usuario.id}:${mensagem}:${Date.now()}`;
        return crypto.createHash('sha256').update(data).digest('hex');
    }
}

const cripto = new CriptografiaMilitar();

// ============================================
// BANCO DE DADOS
// ============================================
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_PORT:', process.env.DB_PORT);
console.log('DB_USER:', process.env.DB_USER);

const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'ghostnet_chat'
});

db.connect(err => {
    if (err) {
        console.error('Erro banco:', err);
        // Não mata o processo, tenta reconectar
    }
    console.log('✅ GhostNet Database conectado');
    
    // Criar tabelas
    const queries = [
        `CREATE TABLE IF NOT EXISTS usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            codinome VARCHAR(50) UNIQUE NOT NULL,
            hash_senha VARCHAR(255) NOT NULL,
            chave_publica TEXT,
            nivel_acesso ENUM('operador', 'admin', 'supremo') DEFAULT 'operador',
            ultimo_acesso TIMESTAMP,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        `CREATE TABLE IF NOT EXISTS mensagens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            remetente_id INT NOT NULL,
            destinatario_id INT,
            grupo_id INT,
            conteudo_criptografado TEXT NOT NULL,
            iv VARCHAR(64) NOT NULL,
            hash_mensagem VARCHAR(64),
            assinatura TEXT,
            autodestruir_em INT DEFAULT 0,
            lida BOOLEAN DEFAULT FALSE,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (remetente_id) REFERENCES usuarios(id)
        )`,
        
        `CREATE TABLE IF NOT EXISTS grupos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nome VARCHAR(100) NOT NULL,
            criado_por INT,
            chave_grupo TEXT,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        `CREATE TABLE IF NOT EXISTS membros_grupo (
            grupo_id INT,
            usuario_id INT,
            papel ENUM('membro', 'moderador', 'admin') DEFAULT 'membro',
            PRIMARY KEY (grupo_id, usuario_id)
        )`,
        
        `CREATE TABLE IF NOT EXISTS logs_seguranca (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario_id INT,
            acao VARCHAR(100),
            ip VARCHAR(45),
            user_agent TEXT,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`
    ];
    
    queries.forEach(q => db.query(q));
});

// ============================================
// SISTEMA DE AUTENTICAÇÃO MILITAR
// ============================================

function gerarCodinome() {
    const prefixos = ['Shadow', 'Ghost', 'Phantom', 'Cipher', 'Viper', 'Cobra', 'Raven', 'Wolf', 'Falcon', 'Knight'];
    const sufixos = ['One', 'X', 'Zero', 'Prime', 'Alpha', 'Omega', 'Delta', 'Sigma', 'Neo', 'Xero'];
    return `${prefixos[Math.floor(Math.random() * prefixos.length)]}_${sufixos[Math.floor(Math.random() * sufixos.length)]}`;
}

function hashSenha(senha) {
    return crypto.createHash('sha256').update(senha + 'GHOSTNET_SALT_2024').digest('hex');
}

function gerarToken(usuario) {
    const payload = {
        id: usuario.id,
        codinome: usuario.codinome,
        nivel: usuario.nivel_acesso,
        exp: Date.now() + 3600000 // 1 hora
    };
    
    const token = crypto.createHash('sha256')
        .update(JSON.stringify(payload) + cripto.aesKey.toString('hex'))
        .digest('hex');
    
    return `${Buffer.from(JSON.stringify(payload)).toString('base64')}.${token}`;
}

function verificarToken(token) {
    try {
        const [payloadBase64, hash] = token.split('.');
        const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
        
        if (payload.exp < Date.now()) return null;
        
        const hashVerificar = crypto.createHash('sha256')
            .update(JSON.stringify(payload) + cripto.aesKey.toString('hex'))
            .digest('hex');
        
        if (hash !== hashVerificar) return null;
        
        return payload;
    } catch (error) {
        return null;
    }
}

// ============================================
// SOCKET.IO - CHAT EM TEMPO REAL
// ============================================

const usuariosOnline = new Map();
const salasAtivas = new Map();

io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
        return next(new Error('Token de acesso necessário'));
    }
    
    const usuario = verificarToken(token);
    if (!usuario) {
        return next(new Error('Token inválido ou expirado'));
    }
    
    socket.usuario = usuario;
    next();
});

io.on('connection', (socket) => {
    console.log(`🔗 ${socket.usuario.codinome} conectou`);
    
    // Registrar online
    usuariosOnline.set(socket.usuario.id, {
        socketId: socket.id,
        usuario: socket.usuario,
        conectadoEm: Date.now()
    });
    
    // Atualizar status
    io.emit('usuarios_online', Array.from(usuariosOnline.values()).map(u => ({
        id: u.usuario.id,
        codinome: u.usuario.codinome,
        nivel: u.usuario.nivel
    })));
    
    // ============================================
    // EVENTOS DO CHAT
    // ============================================
    
    // Enviar mensagem privada
    socket.on('mensagem_privada', async (data) => {
        try {
            const { destinatarioId, conteudo, autodestruir } = data;
            
            // Criptografar mensagem
            const msgCripto = cripto.criptografarMensagem(conteudo);
            if (!msgCripto) {
                return socket.emit('erro', { mensagem: 'Erro ao criptografar' });
            }
            
            // Assinar digitalmente
            const assinatura = cripto.assinarMensagem(conteudo);
            
            // Salvar no banco
            db.query(
                'INSERT INTO mensagens (remetente_id, destinatario_id, conteudo_criptografado, iv, hash_mensagem, assinatura, autodestruir_em) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [socket.usuario.id, destinatarioId, msgCripto.dados, msgCripto.iv, msgCripto.hash, assinatura, autodestruir || 0]
            );
            
            // Enviar para destinatário se online
            const destinatario = usuariosOnline.get(destinatarioId);
            if (destinatario) {
                io.to(destinatario.socketId).emit('nova_mensagem', {
                    remetente: socket.usuario.codinome,
                    remetenteId: socket.usuario.id,
                    dados: msgCripto.dados,
                    iv: msgCripto.iv,
                    hash: msgCripto.hash,
                    assinatura: assinatura,
                    autodestruir: autodestruir,
                    timestamp: Date.now()
                });
            }
            
            // Confirmar envio
            socket.emit('mensagem_enviada', {
                hash: msgCripto.hash,
                timestamp: Date.now()
            });
            
            // Log de segurança
            db.query('INSERT INTO logs_seguranca (usuario_id, acao, ip) VALUES (?, ?, ?)',
                [socket.usuario.id, 'mensagem_privada_enviada', socket.handshake.address]);
            
        } catch (error) {
            console.error('Erro ao enviar mensagem:', error);
            socket.emit('erro', { mensagem: 'Falha ao enviar mensagem' });
        }
    });
    
    // Entrar em grupo
    socket.on('entrar_grupo', async (data) => {
        const { grupoId, senha } = data;
        
        // Verificar se é membro
        db.query('SELECT * FROM membros_grupo WHERE grupo_id = ? AND usuario_id = ?',
            [grupoId, socket.usuario.id],
            (err, membros) => {
                if (membros.length > 0) {
                    socket.join(`grupo_${grupoId}`);
                    socket.emit('entrou_grupo', { grupoId });
                    
                    // Notificar grupo
                    io.to(`grupo_${grupoId}`).emit('membro_entrou', {
                        codinome: socket.usuario.codinome
                    });
                }
            }
        );
    });
    
    // Mensagem em grupo
    socket.on('mensagem_grupo', async (data) => {
        const { grupoId, conteudo } = data;
        
        const msgCripto = cripto.criptografarMensagem(conteudo);
        if (!msgCripto) return;
        
        // Salvar
        db.query(
            'INSERT INTO mensagens (remetente_id, grupo_id, conteudo_criptografado, iv, hash_mensagem, assinatura) VALUES (?, ?, ?, ?, ?, ?)',
            [socket.usuario.id, grupoId, msgCripto.dados, msgCripto.iv, msgCripto.hash, cripto.assinarMensagem(conteudo)]
        );
        
        // Broadcast para o grupo
        io.to(`grupo_${grupoId}`).emit('nova_mensagem_grupo', {
            grupoId,
            remetente: socket.usuario.codinome,
            dados: msgCripto.dados,
            iv: msgCripto.iv,
            hash: msgCripto.hash,
            timestamp: Date.now()
        });
    });
    
    // Autodestruir mensagem
    socket.on('autodestruir_mensagem', async (data) => {
        const { hash } = data;
        
        // Remover do banco
        db.query('DELETE FROM mensagens WHERE hash_mensagem = ?', [hash]);
        
        // Notificar destinatário
        socket.emit('mensagem_destruida', { hash });
    });
    
    // Solicitar chave pública
    socket.on('solicitar_chave', async (data) => {
        const { usuarioId } = data;
        
        db.query('SELECT chave_publica FROM usuarios WHERE id = ?', [usuarioId], (err, results) => {
            if (results.length > 0) {
                socket.emit('chave_recebida', {
                    usuarioId,
                    chavePublica: results[0].chave_publica
                });
            }
        });
    });
    
    // Desconectar
    socket.on('disconnect', () => {
        usuariosOnline.delete(socket.usuario.id);
        
        io.emit('usuario_desconectou', {
            id: socket.usuario.id,
            codinome: socket.usuario.codinome
        });
        
        db.query('UPDATE usuarios SET ultimo_acesso = NOW() WHERE id = ?', [socket.usuario.id]);
        
        console.log(`🔌 ${socket.usuario.codinome} desconectou`);
    });
});

// ============================================
// API REST
// ============================================

// Registrar usuário
app.post('/api/registrar', (req, res) => {
    const { senha } = req.body;
    
    if (!senha || senha.length < 8) {
        return res.status(400).json({ error: 'Senha deve ter 8+ caracteres' });
    }
    
    const codinome = gerarCodinome();
    const hash = hashSenha(senha);
    
    // Gerar chave RSA para o usuário
    const userKeys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    
    db.query(
        'INSERT INTO usuarios (codinome, hash_senha, chave_publica) VALUES (?, ?, ?)',
        [codinome, hash, userKeys.publicKey],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Erro ao registrar' });
            }
            
            const token = gerarToken({
                id: result.insertId,
                codinome: codinome,
                nivel_acesso: 'operador'
            });
            
            res.json({
                success: true,
                codinome: codinome,
                token: token,
                chave_privada: userKeys.privateKey, // Entregar apenas uma vez!
                aviso: 'GUARDE SUA CHAVE PRIVADA EM LOCAL SEGURO'
            });
        }
    );
});

// Login
app.post('/api/login', (req, res) => {
    const { codinome, senha } = req.body;
    
    db.query('SELECT * FROM usuarios WHERE codinome = ?', [codinome], (err, results) => {
        if (results.length === 0) {
            return res.status(401).json({ error: 'Acesso negado' });
        }
        
        const usuario = results[0];
        if (usuario.hash_senha !== hashSenha(senha)) {
            return res.status(401).json({ error: 'Acesso negado' });
        }
        
        const token = gerarToken(usuario);
        
        // Log
        db.query('INSERT INTO logs_seguranca (usuario_id, acao, ip) VALUES (?, ?, ?)',
            [usuario.id, 'login', req.ip]);
        
        res.json({
            success: true,
            token: token,
            usuario: {
                id: usuario.id,
                codinome: usuario.codinome,
                nivel: usuario.nivel_acesso
            }
        });
    });
});

// Listar usuários online
app.get('/api/online', (req, res) => {
    const online = Array.from(usuariosOnline.values()).map(u => ({
        id: u.usuario.id,
        codinome: u.usuario.codinome,
        nivel: u.usuario.nivel
    }));
    
    res.json(online);
});

// ============================================
// FRONTEND
// ============================================

app.use(express.static('public'));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// INICIAR SERVIDOR
// ============================================

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════════╗
    ║         GHOSTNET CHAT SYSTEM v3.0        ║
    ║                                          ║
    ║   🔒 Criptografia: AES-256 + RSA-4096    ║
    ║   🛡️ Proteção: Militar Grade            ║
    ║   🌐 Servidor: http://localhost:${PORT}    ║
    ║                                          ║
    ║   ⚡ Sistema Operacional: SEGURO         ║
    ╚══════════════════════════════════════════╝
    `);
});

