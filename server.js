// Load committed defaults from backend/.env, then let an optional untracked
// backend/.env.local override any of them for machine-specific config.
require('dotenv').config();
require('dotenv').config({ path: require('path').join(__dirname, '.env.local'), override: true });
const express      = require('express');
const cors         = require('cors');
const http         = require('http');
const WebSocket    = require('ws');
const axios        = require('axios');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const mysql        = require('mysql2/promise');
const path         = require('path');
const { ethers }   = require('ethers');
const webpush      = require('web-push');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3001;
// Base URL for same-process self-calls (e.g. chat bot hitting our own /api/predict)
const INTERNAL_API_BASE = process.env.INTERNAL_API_BASE || `http://127.0.0.1:${PORT}`;

// ─── JWT + Encryption secrets (persisted to .secrets file so restarts don't invalidate sessions) ─────
const fs = require('fs');
const SECRETS_FILE = process.env.SECRETS_FILE_PATH || path.join(__dirname, '.secrets.json');
let _secrets = {};
try { _secrets = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf8')); } catch (_) {}
if (!_secrets.JWT_SECRET) _secrets.JWT_SECRET = crypto.randomBytes(32).toString('hex');
if (!_secrets.ENC_KEY)    _secrets.ENC_KEY    = crypto.randomBytes(32).toString('hex');
try { fs.writeFileSync(SECRETS_FILE, JSON.stringify(_secrets)); } catch (_) {}
const JWT_SECRET = process.env.JWT_SECRET || _secrets.JWT_SECRET;
const ENC_KEY    = process.env.ENC_KEY    || _secrets.ENC_KEY;

// ─── MySQL DB (Aiven-compatible: SSL on by default) ─────────────────────────────
// DB_SSL defaults to true — Aiven requires TLS. Set DB_SSL=false only for a
// plain local MySQL with no TLS listener. DB_SSL_CA points at a downloaded CA
// bundle (e.g. Aiven's ca.pem) when the server cert isn't in the system trust
// store; otherwise we just validate against the system CAs.
const DB_SSL = (process.env.DB_SSL || 'true').toLowerCase() !== 'false';
function _loadDbCa() {
  if (!process.env.DB_SSL_CA) return {};
  // Normalize CRLF and stray whitespace — a mismatched line-ending or trimmed
  // trailing newline from copy/pasting into a host's secret-file UI is enough
  // to make OpenSSL reject the whole chain as self-signed/untrusted.
  const raw = fs.readFileSync(process.env.DB_SSL_CA, 'utf8').replace(/\r\n/g, '\n').trim() + '\n';
  console.log(`[db] Loaded SSL CA from ${process.env.DB_SSL_CA} (${raw.length} bytes)`);
  return { ca: raw };
}
const pool = mysql.createPool({
  host:     process.env.DB_HOST || '127.0.0.1',
  port:     parseInt(process.env.DB_PORT) || 3306,
  user:     process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'bloombark',
  waitForConnections: true,
  connectionLimit: parseInt(process.env.DB_POOL_SIZE) || 10,
  queueLimit: 0,
  ssl: !DB_SSL ? undefined : {
    ..._loadDbCa(),
    rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false',
  },
});

// Thin helpers mirroring better-sqlite3's .get()/.all()/.run() so the rest of
// this file reads the same as before, just with `await` in front of each call.
async function dbGet(sql, params = []) { const [rows] = await pool.query(sql, params); return rows[0] || null; }
async function dbAll(sql, params = []) { const [rows] = await pool.query(sql, params); return rows; }
async function dbRun(sql, params = []) { const [result] = await pool.query(sql, params); return result; }

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id                INT PRIMARY KEY AUTO_INCREMENT,
      wallet            VARCHAR(255) UNIQUE NOT NULL,
      wallet_enc        TEXT,
      generated_address VARCHAR(255),
      generated_key_enc TEXT,
      meta              TEXT,
      created_at        INT DEFAULT (UNIX_TIMESTAMP()),
      last_login        INT
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id         INT PRIMARY KEY AUTO_INCREMENT,
      wallet     VARCHAR(255) NOT NULL,
      jwt_hash   VARCHAR(255) NOT NULL,
      expires_at INT NOT NULL,
      created_at INT DEFAULT (UNIX_TIMESTAMP())
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_config (
      \`key\`     VARCHAR(255) PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_at INT DEFAULT (UNIX_TIMESTAMP())
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_profiles (
      wallet       VARCHAR(255) PRIMARY KEY,
      display_name VARCHAR(255),
      avatar       MEDIUMTEXT,
      updated_at   INT DEFAULT (UNIX_TIMESTAMP())
    )
  `);
  // ts is epoch-milliseconds (Date.now()) — needs BIGINT, a 32-bit INT overflows.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_messages (
      id           VARCHAR(64) PRIMARY KEY,
      room         VARCHAR(64) NOT NULL,
      wallet       VARCHAR(255),
      display_name VARCHAR(255),
      avatar       MEDIUMTEXT,
      text         TEXT,
      img_data     MEDIUMTEXT,
      ts           BIGINT NOT NULL
    )
  `);
  // MySQL has no "CREATE INDEX IF NOT EXISTS" — ignore the duplicate-key-name error.
  await pool.query('CREATE INDEX idx_chat_room_ts ON chat_messages(room, ts)').catch(e => {
    if (e.code !== 'ER_DUP_KEYNAME') throw e;
  });
  // Reply/edit support — added after the fact, so ALTER existing tables in place.
  // MySQL has no "ADD COLUMN IF NOT EXISTS"; ignore the duplicate-column error.
  const _addCol = sql => pool.query(sql).catch(e => { if (e.code !== 'ER_DUP_FIELDNAME') throw e; });
  await _addCol('ALTER TABLE chat_messages ADD COLUMN reply_to VARCHAR(64)');
  await _addCol('ALTER TABLE chat_messages ADD COLUMN reply_name VARCHAR(255)');
  await _addCol('ALTER TABLE chat_messages ADD COLUMN reply_text VARCHAR(280)');
  await _addCol('ALTER TABLE chat_messages ADD COLUMN edited TINYINT NOT NULL DEFAULT 0');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS watchlist (
      id         INT PRIMARY KEY AUTO_INCREMENT,
      wallet     VARCHAR(255) NOT NULL,
      address    VARCHAR(255) NOT NULL,
      chain      VARCHAR(64),
      name       VARCHAR(255),
      symbol     VARCHAR(64),
      image_url  TEXT,
      added_at   INT DEFAULT (UNIX_TIMESTAMP()),
      UNIQUE KEY uniq_wallet_address (wallet, address)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS custom_holdings (
      id         INT PRIMARY KEY AUTO_INCREMENT,
      wallet     VARCHAR(255) NOT NULL,
      address    VARCHAR(255) NOT NULL,
      chain      VARCHAR(64) NOT NULL DEFAULT 'robinhood',
      symbol     VARCHAR(64),
      name       VARCHAR(255),
      decimals   INT,
      icon_url   TEXT,
      added_at   INT DEFAULT (UNIX_TIMESTAMP()),
      UNIQUE KEY uniq_wallet_address (wallet, address)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sniper_pools (
      id             INT PRIMARY KEY AUTO_INCREMENT,
      chain          VARCHAR(64) NOT NULL DEFAULT 'robinhood',
      pool_address   VARCHAR(255) NOT NULL,
      token_address  VARCHAR(255) NOT NULL,
      quote_address  VARCHAR(255),
      symbol         VARCHAR(64),
      name           VARCHAR(255),
      decimals       INT,
      source         VARCHAR(32),
      block_number   BIGINT,
      tx_hash        VARCHAR(80),
      detected_at    BIGINT NOT NULL,
      block_time     BIGINT,
      price_usd      DOUBLE,
      liquidity_usd  DOUBLE,
      mcap_usd       DOUBLE,
      enriched_at    BIGINT,
      UNIQUE KEY uniq_chain_pool (chain, pool_address)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS token_alerts (
      id              INT PRIMARY KEY AUTO_INCREMENT,
      wallet          VARCHAR(255) NOT NULL,
      address         VARCHAR(255) NOT NULL,
      chain           VARCHAR(64),
      name            VARCHAR(255),
      symbol          VARCHAR(64),
      metric          VARCHAR(16) NOT NULL,
      baseline_value  DOUBLE NOT NULL,
      threshold_pct   DOUBLE NOT NULL,
      direction       VARCHAR(8) NOT NULL DEFAULT 'both',
      active          TINYINT NOT NULL DEFAULT 1,
      created_at      INT DEFAULT (UNIX_TIMESTAMP()),
      last_checked_at INT,
      UNIQUE KEY uniq_wallet_address_metric (wallet, address, metric)
    )
  `);
  // High/low watermarks reached since the baseline was set — lets the checker
  // catch a threshold that was crossed and reverted between two poll cycles,
  // instead of only comparing the snapshot value at check time.
  await _addCol('ALTER TABLE token_alerts ADD COLUMN high_value DOUBLE');
  await _addCol('ALTER TABLE token_alerts ADD COLUMN low_value DOUBLE');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS alert_notifications (
      id             INT PRIMARY KEY AUTO_INCREMENT,
      alert_id       INT,
      wallet         VARCHAR(255) NOT NULL,
      address        VARCHAR(255) NOT NULL,
      chain          VARCHAR(64),
      name           VARCHAR(255),
      symbol         VARCHAR(64),
      metric         VARCHAR(16) NOT NULL,
      direction      VARCHAR(8) NOT NULL,
      baseline_value DOUBLE,
      new_value      DOUBLE,
      change_pct     DOUBLE,
      message        TEXT,
      ts             BIGINT NOT NULL,
      is_read        TINYINT NOT NULL DEFAULT 0
    )
  `);
  // Alerts categories beyond token movement (Bloombark broadcast updates,
  // channel-mute notices) don't have a token address/metric/direction — relax
  // those to nullable and add the category + title/subtitle/detail fields
  // used for the collapsed-list / click-to-expand notification UI.
  await pool.query(`ALTER TABLE alert_notifications MODIFY address VARCHAR(255) NULL`);
  await pool.query(`ALTER TABLE alert_notifications MODIFY metric VARCHAR(16) NULL`);
  await pool.query(`ALTER TABLE alert_notifications MODIFY direction VARCHAR(8) NULL`);
  await _addCol("ALTER TABLE alert_notifications ADD COLUMN category VARCHAR(32) NOT NULL DEFAULT 'token_movement'");
  await _addCol('ALTER TABLE alert_notifications ADD COLUMN title VARCHAR(255)');
  await _addCol('ALTER TABLE alert_notifications ADD COLUMN subtitle VARCHAR(255)');
  await _addCol('ALTER TABLE alert_notifications ADD COLUMN detail TEXT');
  // Browser push subscriptions (Web Push API) — one row per browser/device a
  // wallet has enabled notifications on, since the same wallet can have
  // several subscribed devices. endpoint is unique per subscription.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id         INT PRIMARY KEY AUTO_INCREMENT,
      wallet     VARCHAR(255) NOT NULL,
      endpoint   VARCHAR(600) NOT NULL,
      p256dh     VARCHAR(255) NOT NULL,
      auth       VARCHAR(255) NOT NULL,
      created_at BIGINT NOT NULL,
      UNIQUE KEY uniq_endpoint (endpoint(255)),
      KEY idx_wallet (wallet)
    )
  `);
  // AI Track Record — every directional (bullish/bearish) prediction from
  // /api/predict gets logged here, then resolved ~24h later against the
  // actual price move. Public, transparent win-rate (unlike most platforms
  // that only show predictions, never their outcomes). Neutral calls are
  // deliberately not logged — they'd muddy a win/loss stat with no clear
  // right answer.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS prediction_history (
      id           INT PRIMARY KEY AUTO_INCREMENT,
      address      VARCHAR(255) NOT NULL,
      chain        VARCHAR(64) NOT NULL,
      symbol       VARCHAR(64),
      name         VARCHAR(255),
      \`signal\`   VARCHAR(16) NOT NULL,
      confidence   INT NOT NULL,
      price_at     DOUBLE NOT NULL,
      predicted_at BIGINT NOT NULL,
      resolved_at  BIGINT,
      price_after  DOUBLE,
      change_pct   DOUBLE,
      outcome      VARCHAR(16),
      KEY idx_resolved (resolved_at),
      KEY idx_predicted_at (predicted_at)
    )
  `);
  await _addCol('ALTER TABLE prediction_history ADD COLUMN image_url VARCHAR(500)');
  // "Trending on Bloombark" — internal activity signal (scans + trades),
  // separate from the GeckoTerminal-sourced Trending tab in Market Overview.
  // Community mentions are computed on the fly from chat_messages instead of
  // logged here, since that data already exists.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS token_activity_log (
      id      INT PRIMARY KEY AUTO_INCREMENT,
      address VARCHAR(255) NOT NULL,
      chain   VARCHAR(64) NOT NULL,
      symbol  VARCHAR(64),
      name    VARCHAR(255),
      \`type\` VARCHAR(16) NOT NULL,
      ts      BIGINT NOT NULL,
      KEY idx_type_ts (\`type\`, ts),
      KEY idx_address (address)
    )
  `);
  // Community: paid-channel unlocks (one-time on-chain payment, verified then recorded here)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS channel_payments (
      id         INT PRIMARY KEY AUTO_INCREMENT,
      wallet     VARCHAR(255) NOT NULL,
      room       VARCHAR(64) NOT NULL,
      tx_hash    VARCHAR(80) NOT NULL,
      amount_eth DECIMAL(20,10) NOT NULL,
      paid_at    INT DEFAULT (UNIX_TIMESTAMP()),
      UNIQUE KEY uniq_tx_hash (tx_hash),
      KEY idx_wallet_room (wallet, room)
    )
  `);
  // Community: admin-issued mutes (wallet blocked from sending chat_msg until muted_until)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS muted_wallets (
      wallet       VARCHAR(255) PRIMARY KEY,
      muted_until  BIGINT NOT NULL,
      muted_by     VARCHAR(255),
      reason       VARCHAR(280),
      created_at   INT DEFAULT (UNIX_TIMESTAMP())
    )
  `);

  // Seed default config if not set
  const caRow = await dbGet("SELECT `key` FROM app_config WHERE `key`='contract_address'");
  if (!caRow) await dbRun("INSERT INTO app_config (`key`, value) VALUES ('contract_address', 'coming_soon')");
  // Token ticker (shown on the landing page). Editable in the DB at launch.
  const tickerRow = await dbGet("SELECT `key` FROM app_config WHERE `key`='token_ticker'");
  if (!tickerRow) await dbRun("INSERT INTO app_config (`key`, value) VALUES ('token_ticker', 'BBRK')");
}

// ─── Crypto helpers ─────────────────────────────────────────────────────────────
function encrypt(text) {
  const iv  = crypto.randomBytes(12);
  const key = Buffer.from(ENC_KEY, 'hex');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc  = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag  = cipher.getAuthTag();
  return iv.toString('hex') + ':' + enc.toString('hex') + ':' + tag.toString('hex');
}

function decrypt(data) {
  const [ivHex, encHex, tagHex] = data.split(':');
  const key     = Buffer.from(ENC_KEY, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex,'hex'));
  decipher.setAuthTag(Buffer.from(tagHex,'hex'));
  return Buffer.concat([decipher.update(Buffer.from(encHex,'hex')), decipher.final()]).toString('utf8');
}

function hashJwt(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// CORS_ORIGIN: comma-separated allowlist, or unset/"*" to reflect any origin (dev default)
const _corsEnv = (process.env.CORS_ORIGIN || '').trim();
const _corsOrigin = (!_corsEnv || _corsEnv === '*')
  ? true
  : _corsEnv.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: _corsOrigin, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ─── Network environment (testnet / mainnet) ─────────────────────────────────
// Defaults to 'testnet' whenever no deployment platform env var is present
// (i.e. running locally), 'mainnet' otherwise. Override explicitly with
// NETWORK_ENV=mainnet|testnet regardless of where it's running.
const _isLocalHost = !process.env.RENDER && !process.env.VERCEL && !process.env.FLY_APP_NAME
  && !process.env.RAILWAY_ENVIRONMENT && !process.env.PRODUCTION_URL && process.env.NODE_ENV !== 'production';
const NETWORK_ENV = (process.env.NETWORK_ENV || (_isLocalHost ? 'testnet' : 'mainnet')).toLowerCase();
const IS_TESTNET  = NETWORK_ENV === 'testnet';
console.log(`[network] Running in ${NETWORK_ENV.toUpperCase()} mode${_isLocalHost ? ' (auto-detected: localhost)' : ''}`);

// Per-chain mainnet/testnet parameters. Pick with `chainCfg(key)` below.
// Testnet counterparts: Ethereum→Sepolia, Base→Base Sepolia, Arbitrum→Arbitrum
// Sepolia, Polygon→Amoy, Optimism→OP Sepolia, Robinhood→Robinhood Testnet.
// Note: DexScreener / GeckoTerminal / KyberSwap generally do not index testnet
// data, so price/analyze/trade-quote features will have no data in testnet
// mode — only direct RPC reads (balance, decimals, tx) and MetaMask network
// switching are meaningfully affected by this config.
const CHAIN_NETWORKS = {
  ethereum: {
    mainnet: { chainId: 1,        hex: '0x1',      rpc: 'https://ethereum-rpc.publicnode.com',         explorer: 'https://etherscan.io',          blockscout: 'https://eth.blockscout.com' },
    testnet: { chainId: 11155111, hex: '0xaa36a7',  rpc: 'https://ethereum-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.etherscan.io',  blockscout: 'https://eth-sepolia.blockscout.com', name: 'Sepolia' },
  },
  base: {
    mainnet: { chainId: 8453,  hex: '0x2105', rpc: 'https://base-rpc.publicnode.com',         explorer: 'https://basescan.org',         blockscout: 'https://base.blockscout.com' },
    testnet: { chainId: 84532, hex: '0x14a34', rpc: 'https://base-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.basescan.org', blockscout: 'https://base-sepolia.blockscout.com', name: 'Base Sepolia' },
  },
  arbitrum: {
    mainnet: { chainId: 42161,  hex: '0xa4b1',  rpc: 'https://arbitrum-one-rpc.publicnode.com',     explorer: 'https://arbiscan.io',         blockscout: 'https://arbitrum.blockscout.com' },
    testnet: { chainId: 421614, hex: '0x66eee', rpc: 'https://arbitrum-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.arbiscan.io', blockscout: 'https://arbitrum.blockscout.com', name: 'Arbitrum Sepolia' },
  },
  polygon: {
    mainnet: { chainId: 137,   hex: '0x89',    rpc: 'https://polygon-bor-rpc.publicnode.com',       explorer: 'https://polygonscan.com',     blockscout: 'https://polygon.blockscout.com' },
    testnet: { chainId: 80002, hex: '0x13882', rpc: 'https://polygon-amoy-bor-rpc.publicnode.com',  explorer: 'https://amoy.polygonscan.com', blockscout: 'https://polygon.blockscout.com', name: 'Polygon Amoy' },
  },
  optimism: {
    mainnet: { chainId: 10,       hex: '0xa',       rpc: 'https://optimism-rpc.publicnode.com',         explorer: 'https://optimistic.etherscan.io',        blockscout: 'https://explorer.optimism.io' },
    testnet: { chainId: 11155420, hex: '0xaa37dc',  rpc: 'https://optimism-sepolia-rpc.publicnode.com', explorer: 'https://sepolia-optimism.etherscan.io',  blockscout: 'https://explorer.optimism.io', name: 'OP Sepolia' },
  },
  robinhood: {
    // RPC points at Robinhood's own node, not Blockscout's eth-rpc proxy: the
    // proxy is rate limited to ~3 req/min without a paid key (a single
    // pending-tx confirmation poll exceeds that), while the official endpoint
    // has no such limit. ROBINHOOD_RPC_URL overrides it — useful on networks
    // where robinhood.com is DNS-blocked, which some ISPs do.
    mainnet: { chainId: 4663,  hex: '0x1237', rpc: process.env.ROBINHOOD_RPC_URL || 'https://rpc.mainnet.chain.robinhood.com/rpc', explorer: 'https://robinhoodchain.blockscout.com',      blockscout: 'https://robinhoodchain.blockscout.com' },
    testnet: { chainId: 46630, hex: '0xb626', rpc: 'https://rpc.testnet.chain.robinhood.com/rpc',            explorer: 'https://explorer.testnet.chain.robinhood.com', blockscout: 'https://explorer.testnet.chain.robinhood.com', name: 'Robinhood Testnet' },
  },
};

// Blockscout Pro API key (optional) — applies to the REST API only. That data
// (token balances, address tx history, chain stats) is Blockscout-specific and
// has no equivalent on a plain JSON-RPC node, so those calls still go through
// Blockscout; its free instance allows only ~3 req/min, the Pro gateway ~600.
// Plain RPC no longer depends on this key at all — it goes direct to
// Robinhood's node (see CHAIN_NETWORKS above).
// Explorer links shown to users are untouched — only the API-consuming host
// changes. Testnet is left alone; it isn't Blockscout-proxied.
const BLOCKSCOUT_API_KEY = process.env.BLOCKSCOUT_API_KEY || '';
const BLOCKSCOUT_AUTH_HEADERS = BLOCKSCOUT_API_KEY ? { Authorization: `Bearer ${BLOCKSCOUT_API_KEY}` } : {};
if (BLOCKSCOUT_API_KEY) {
  const rh = CHAIN_NETWORKS.robinhood.mainnet;
  // Every consumer of .blockscout appends its own `/api/v2/...` path (see
  // getEvmData, _fetchOnchainSwaps, _fetchChainTransactions) — this must be
  // the bare host, not pre-suffixed with /api/v2, or every REST call doubles
  // the path (…/api/v2/api/v2/stats) and 404s against the Pro API gateway.
  rh.blockscout = `https://api.blockscout.com/${rh.chainId}`;
}

// ─── Web Push (browser notifications) ───────────────────────────────────────
// Generate a pair with `node -e "console.log(require('web-push').generateVAPIDKeys())"`
// and set both below — without them, push notifications are silently disabled
// (subscribe endpoint returns 503) but the rest of the app still works.
const VAPID_PUBLIC_KEY  = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const PUSH_ENABLED = !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);
if (PUSH_ENABLED) {
  webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || 'mailto:bloombarkterminal@gmail.com',
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY
  );
}

// Returns the active (testnet or mainnet, per NETWORK_ENV) config for a chain key
function chainCfg(key) {
  const c = CHAIN_NETWORKS[key];
  if (!c) return null;
  return c[NETWORK_ENV] || c.mainnet;
}

// ─── External API base URLs (env-overridable; sensible public defaults) ────────
const DEXSCREENER  = process.env.DEXSCREENER_API || 'https://api.dexscreener.com';
const DS_CHART     = process.env.DEXSCREENER_CHART_API || 'https://io.dexscreener.com';
const GECKO        = process.env.GECKO_API || 'https://api.geckoterminal.com/api/v2';
const GECKO_API_KEY = process.env.GECKO_API_KEY || '';
const GECKO_HEADS  = { 'Accept': 'application/json;version=20230302', ...(GECKO_API_KEY ? { 'x-cg-pro-api-key': GECKO_API_KEY } : {}) };
const GOPLUS       = process.env.GOPLUS_API || 'https://api.gopluslabs.io/api/v1';
const GOPLUS_API_KEY = process.env.GOPLUS_API_KEY || '';
const GOPLUS_HEADS = GOPLUS_API_KEY ? { 'Authorization': GOPLUS_API_KEY } : {};

// Without GECKO_API_KEY (unset by default — see GECKO_HEADS above), GeckoTerminal's
// free-tier rate limit is tight and shared across every feature that calls it
// (Trade page chart/recent-trades, Market Overview tabs, Narrative). A 429 during
// a burst of traffic previously failed silently with no retry. This wraps any
// GeckoTerminal GET with a couple of short backoff retries specifically for 429s,
// so a single rate-limit hit doesn't fail a request outright.
async function _geckoGetWithRetry(url, opts = {}, maxRetries = 2) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await axios.get(url, opts);
    } catch (e) {
      if (e.response?.status === 429 && attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 500 * Math.pow(2, attempt))); // 500ms, 1000ms
        continue;
      }
      throw e;
    }
  }
}

// ─── Tunable parameters (all env-overridable; defaults preserve current behavior) ──
const CONFIG = {
  // Caching / TTLs (ms unless noted)
  goplusCacheTtlMs:      (parseInt(process.env.GOPLUS_CACHE_TTL_MIN)    || 10)  * 60 * 1000,
  gateCacheTtlMs:         (parseInt(process.env.GATE_CACHE_TTL_SEC)      || 30)  * 1000,
  walletMapCacheTtlMs:    (parseInt(process.env.WALLET_MAP_CACHE_TTL_MIN)|| 5)   * 60 * 1000,
  holdingsCacheTtlMs:     (parseInt(process.env.HOLDINGS_CACHE_TTL_SEC)  || 60)  * 1000,
  narrativeWarmDelayMs:   (parseInt(process.env.NARRATIVE_WARM_DELAY_SEC)|| 5)   * 1000,
  narrativeFetchDelayMs:  (parseInt(process.env.NARRATIVE_FETCH_DELAY_MS)|| 5000),
  narrativeRetryDelayMs:  (parseInt(process.env.NARRATIVE_RETRY_DELAY_MIN)||10)  * 60 * 1000,
  narrativeWaitTimeoutMs: (parseInt(process.env.NARRATIVE_WAIT_TIMEOUT_SEC)||15) * 1000,
  dashWarmDelayMs:        (parseInt(process.env.DASH_WARM_DELAY_SEC)     || 1)   * 1000,

  // Chat
  chatHistoryLimit:      parseInt(process.env.CHAT_HISTORY_LIMIT)    || 100,
  chatDbPruneLimit:      parseInt(process.env.CHAT_DB_PRUNE_LIMIT)   || 500,
  chatMsgMaxLen:         parseInt(process.env.CHAT_MSG_MAX_LEN)      || 500,
  chatNameMaxLen:        parseInt(process.env.CHAT_NAME_MAX_LEN)     || 15,
  chatBotCooldownMs:     (parseInt(process.env.CHAT_BOT_COOLDOWN_SEC) || 120) * 1000,

  // Simulated live price ticker
  priceTickIntervalMs:   parseInt(process.env.PRICE_TICK_INTERVAL_MS)    || 2000,
  priceReseedIntervalMs: (parseInt(process.env.PRICE_RESEED_INTERVAL_SEC)|| 60) * 1000,
  priceMeanRevertFactor: parseFloat(process.env.PRICE_MEANREVERT_FACTOR) || 0.08,
  priceNoisePct:         parseFloat(process.env.PRICE_NOISE_PCT)        || 0.002,
  priceClampPct:         parseFloat(process.env.PRICE_CLAMP_PCT)        || 0.02,

  // Auth / sessions
  jwtExpiresInSec:       (parseInt(process.env.JWT_EXPIRES_IN_DAYS) || 7) * 24 * 3600,

  // Wallet holdings / tracker filters
  holdingsDustUsd:       parseFloat(process.env.HOLDINGS_DUST_USD)      || 0.01,
  holdingsMaxResults:    parseInt(process.env.HOLDINGS_MAX_RESULTS)     || 50,
  walletMaxTokens:       parseInt(process.env.WALLET_MAX_TOKENS)        || 90,
  minVolumeUsdFilter:    parseFloat(process.env.MIN_VOLUME_USD_FILTER)  || 50,
};

// ─── Community moderators ──────────────────────────────────────────────────
// Comma-separated wallet addresses (case-insensitive) with delete-any-message
// and mute powers in Community chat. Set via env — empty by default so no
// wallet has admin power until explicitly configured.
const ADMIN_WALLETS = new Set(
  (process.env.ADMIN_WALLETS || '').split(',').map(w => w.trim().toLowerCase()).filter(Boolean)
);
const isAdminWallet = wallet => !!wallet && ADMIN_WALLETS.has(String(wallet).toLowerCase());

// Returns the mute expiry (epoch ms) if `wallet` is currently muted, else null.
async function _mutedUntil(wallet) {
  if (!wallet) return null;
  const row = await dbGet('SELECT muted_until FROM muted_wallets WHERE wallet=?', [String(wallet).toLowerCase()]);
  if (!row || row.muted_until <= Date.now()) return null;
  return row.muted_until;
}

const GOPLUS_CHAIN = { ethereum:'1', base:'8453', arbitrum:'42161', robinhood:'4663' };

const _gtGet = (url) => axios.get(url, { timeout: 10000, headers: GECKO_HEADS }).catch(() => null);

// Map our chain key → GeckoTerminal network id
const GECKO_NETWORK = {
  ethereum:  'eth',
  base:      'base',
  arbitrum:  'arbitrum',
  tron:      'tron',
  robinhood: 'robinhood',
};

// Map our chain key → DexScreener chainId
const DS_CHAIN = {
  ethereum:  'ethereum',
  base:      'base',
  arbitrum:  'arbitrum',
  tron:      'tron',
  robinhood: 'robinhood',
};

// ─── GoPlus Security API ───────────────────────────────────────────────────────
const _goplusCache = new Map();
async function fetchGoPlus(contractAddress, chain = 'ethereum') {
  const cacheKey = `${chain}:${contractAddress}`;
  const cached = _goplusCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CONFIG.goplusCacheTtlMs) return cached.val;
  try {
    const url = `${GOPLUS}/token_security/${GOPLUS_CHAIN[chain] || '1'}?contract_addresses=${contractAddress}`;
    const { data } = await axios.get(url, { timeout: 8000, headers: GOPLUS_HEADS });
    const token = Object.values(data?.result || {})[0];
    if (!token) return cached?.val || null;

    const cexInfo = token.is_in_cex;
    const evmResult = {
      isHoneypot:       token.is_honeypot === '1',
      honeypotReason:   token.honeypot_with_same_creator === '1' ? 'Same creator as known honeypot' : null,
      buyTax:           parseFloat(token.buy_tax || 0) * 100,
      sellTax:          parseFloat(token.sell_tax || 0) * 100,
      transferTax:      parseFloat(token.transfer_tax || 0) * 100,
      creatorAddress:   token.creator_address || null,
      creatorPercent:   parseFloat(token.creator_percent || 0) * 100,
      creatorMalicious: token.creator_address_malicious === '1',
      isMintable:       token.is_mintable === '1',
      isFreezable:      false,
      isOpenSource:     token.is_open_source === '1',
      isProxy:          token.is_proxy === '1',
      cannotBuy:        token.cannot_buy === '1',
      metadataMutable:  false,
      isTrusted:        token.is_open_source === '1',
      holderCount:      parseInt(token.holder_count || 0),
      lpHolderCount:    parseInt(token.lp_holder_count || 0),
      isInDex:          token.is_in_dex === '1',
      isInCex:          cexInfo?.listed === '1',
      cexList:          cexInfo?.cex_list || [],
      lpHolders:        (token.lp_holders || []).slice(0, 5).map(h => ({
        address: h.address, pct: parseFloat(h.percent || 0) * 100, locked: h.is_locked === 1, tag: h.tag || '',
      })),
      holders:          (token.holders || []).slice(0, 20).map(h => ({
        address: h.address, pct: parseFloat(h.percent || 0) * 100, isContract: h.is_contract === 1, locked: h.is_locked === 1, tag: h.tag || '', balance: h.balance,
      })),
      ownerAddress:     token.owner_address || null,
      ownerPercent:     parseFloat(token.owner_percent || 0) * 100,
      chain,
    };
    _goplusCache.set(cacheKey, { val: evmResult, ts: Date.now() });
    return evmResult;
  } catch (e) {
    console.error('[goplus]', e.message);
    // Return cached data if available, even if stale
    return cached?.val || null;
  }
}

function detectChainFromAddress(addr) {
  if (!addr) return 'unsupported';
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr)) return 'tron';
  if (/^0x[0-9a-fA-F]{40}$/.test(addr))           return 'ethereum'; // generic EVM — DexScreener will find actual chain
  return 'unsupported'; // Solana-style base58 addresses are no longer supported
}

function isValidAddr(addr, chain) {
  if (!addr) return false;
  if (chain === 'tron')    return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr);
  if (chain === 'ethereum' || chain === 'base' || chain === 'arbitrum')
    return /^0x[0-9a-fA-F]{40}$/.test(addr);
  return false;
}


const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── GeckoTerminal: Token info + liquidity ─────────────────────────────────────
async function fetchGeckoToken(contractAddress, network = 'eth') {
  try {
    const { data } = await axios.get(
      `${GECKO}/networks/${network}/tokens/${contractAddress}`,
      { timeout: 8000, headers: GECKO_HEADS }
    );
    const attr = data?.data?.attributes;
    if (!attr) return null;
    return {
      name:            attr.name,
      symbol:          attr.symbol,
      price:           parseFloat(attr.price_usd || 0),
      fdv:             parseFloat(attr.fdv_usd   || 0),
      marketCap:       parseFloat(attr.market_cap_usd || attr.fdv_usd || 0),
      liquidity:       parseFloat(attr.total_reserve_in_usd || 0),  // ← accurate pool reserves
      volume24h:       parseFloat(attr.volume_usd?.h24 || 0),
      totalSupply:     parseFloat(attr.normalized_total_supply || attr.total_supply || 0),
      imageUrl:        attr.image_url || null,
      holders:         attr.holders ? parseInt(attr.holders) : null,
      launchpad:       attr.launchpad_details || null,
    };
  } catch (err) {
    console.error('GeckoTerminal token error:', err.message);
    return null;
  }
}

// ─── GeckoTerminal: Pools (per-pool liquidity, txns, price changes) ────────────
async function fetchGeckoPools(contractAddress, network = 'eth') {
  try {
    const { data } = await axios.get(
      `${GECKO}/networks/${network}/tokens/${contractAddress}/pools?page=1`,
      { timeout: 8000, headers: GECKO_HEADS }
    );
    const pools = data?.data || [];
    return pools.map(p => {
      const a = p.attributes || {};
      return {
        poolAddress:    p.id?.replace(`${network}_`, '') || '',
        dexId:          a.dex_id || '',
        liquidity:      parseFloat(a.reserve_in_usd || 0),
        volume24h:      parseFloat(a.volume_usd?.h24 || 0),
        buys24h:        parseInt(a.transactions?.h24?.buys  || 0),
        sells24h:       parseInt(a.transactions?.h24?.sells || 0),
        buys1h:         parseInt(a.transactions?.h1?.buys   || 0),
        sells1h:        parseInt(a.transactions?.h1?.sells  || 0),
        buys5m:         parseInt(a.transactions?.m5?.buys   || 0),
        sells5m:        parseInt(a.transactions?.m5?.sells  || 0),
        priceChange: {
          m5:  parseFloat(a.price_change_percentage?.m5  || 0),
          h1:  parseFloat(a.price_change_percentage?.h1  || 0),
          h6:  parseFloat(a.price_change_percentage?.h6  || 0),
          h24: parseFloat(a.price_change_percentage?.h24 || 0),
        },
        price:          parseFloat(a.base_token_price_usd || 0),
        createdAt:      a.pool_created_at ? new Date(a.pool_created_at).getTime() : null,
      };
    });
  } catch (err) {
    console.error('GeckoTerminal pools error:', err.message);
    return [];
  }
}

// ─── GeckoTerminal: Real OHLCV candles ────────────────────────────────────────
async function fetchGeckoCandles(poolAddress, timeframe = 'minute', aggregate = 5, limit = 200, network = 'eth') {
  try {
    const url = `${GECKO}/networks/${network}/pools/${poolAddress}/ohlcv/${timeframe}?aggregate=${aggregate}&limit=${limit}&currency=usd&token=base`;
    const { data } = await axios.get(url, { timeout: 8000, headers: GECKO_HEADS });
    const raw = data?.data?.attributes?.ohlcv_list || [];
    if (raw.length < 2) return null;
    return raw.map(c => ({
      time:   Math.floor(c[0] / (c[0] > 1e12 ? 1000 : 1)),
      open:   parseFloat(c[1]),
      high:   parseFloat(c[2]),
      low:    parseFloat(c[3]),
      close:  parseFloat(c[4]),
      volume: parseFloat(c[5]),
    })).filter(c => c.open > 0 && c.close > 0)
       .sort((a,b) => a.time - b.time);
  } catch (err) {
    console.error('GeckoTerminal candles error:', err.message);
    return null;
  }
}

// ─── GeckoTerminal: Holders + distribution from /info endpoint ────────────────
async function fetchGeckoHolders(contractAddress, network = 'eth') {
  try {
    const { data } = await axios.get(
      `${GECKO}/networks/${network}/tokens/${contractAddress}/info`,
      { timeout: 8000, headers: GECKO_HEADS }
    );
    const attr = data?.data?.attributes;
    if (!attr) return null;

    // holders field is an object: { count, distribution_percentage: {top_10, 11_20, 21_40, rest} }
    const h = attr.holders;
    const holderCount = h?.count ? parseInt(h.count) : (typeof h === 'number' ? h : null);
    const dist = h?.distribution_percentage || {};

    return {
      holders:      holderCount,
      holderDist: {
        top10:  parseFloat(dist.top_10  || 0),
        p11_20: parseFloat(dist['11_20'] || 0),
        p21_40: parseFloat(dist['21_40'] || 0),
        rest:   parseFloat(dist.rest    || 0),
      },
      gt_score:     attr.gt_score    ? parseFloat(attr.gt_score)  : null,
      description:  attr.description || null,
      websites:     attr.websites    || [],
      discord:      attr.discord_url || null,
      telegram:     attr.telegram_handle || null,
      twitter:      attr.twitter_handle  || null,
    };
  } catch (_) {
    return null;
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────────
const rand    = (min, max) => Math.random() * (max - min) + min;
const randInt = (min, max) => Math.floor(rand(min, max));

// Seeded deterministic random — same address always produces same values
function seededRand(seed) {
  let h = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return function(min, max) {
    h ^= h << 13; h ^= h >> 17; h ^= h << 5; h = h >>> 0;
    return min + (h / 0xffffffff) * (max - min);
  };
}
function seededRandInt(rng, min, max) { return Math.floor(rng(min, max + 1)); }

function ageLabel(ms) {
  const d = Math.floor(ms / 86400000);
  const h = Math.floor(ms / 3600000);
  const m = Math.floor(ms / 60000);
  if (d > 0) return `${d}d ago`;
  if (h > 0) return `${h}h ago`;
  return `${m}m ago`;
}

function shortAddr(addr) {
  if (!addr || addr.length < 10) return addr;
  return addr.slice(0, 4) + '...' + addr.slice(-4);
}

const EXPLORER_URL = {
  ethereum:  addr => `${chainCfg('ethereum').explorer}/address/${addr}`,
  base:      addr => `${chainCfg('base').explorer}/address/${addr}`,
  arbitrum:  addr => `${chainCfg('arbitrum').explorer}/address/${addr}`,
  tron:      addr => `https://tronscan.org/#/address/${addr}`,
  robinhood: addr => `${chainCfg('robinhood').explorer}/address/${addr}`,
};

function explorerUrl(addr, chain = 'ethereum') {
  if (!addr) return null;
  if (!isValidAddr(addr, chain)) return null;
  const fn = EXPLORER_URL[chain] || EXPLORER_URL.ethereum;
  return fn(addr);
}

// ─── 1. DexScreener: Token pairs + metadata ────────────────────────────────────
async function fetchDexScreener(contractAddress, chainId = 'ethereum') {
  const { data } = await axios.get(
    `${DEXSCREENER}/latest/dex/tokens/${contractAddress}`,
    { timeout: 10000 }
  );
  if (!data.pairs?.length) return null;

  // For EVM addresses the actual chain (eth/base/arbitrum) is resolved by DexScreener
  // so we filter loosely: if chainId is 'ethereum' also accept eth/erc20 variants
  const SUPPORTED_CHAINS = ['ethereum','base','arbitrum','robinhood','tron'];
  const isEvm = ['ethereum','base','arbitrum','robinhood'].includes(chainId);
  const pairs = data.pairs
    .filter(p => isEvm ? ['ethereum','base','arbitrum','robinhood'].includes(p.chainId) : p.chainId === chainId)
    .sort((a, b) => (b.volume?.h24 || 0) - (a.volume?.h24 || 0));

  // If no pairs matched the expected chain, fall back to highest-volume among supported chains only
  const fallbackPairs = data.pairs.filter(p => SUPPORTED_CHAINS.includes(p.chainId)).sort((a,b) => (b.volume?.h24||0)-(a.volume?.h24||0));
  const bestPairs = pairs.length ? pairs : fallbackPairs;
  if (!bestPairs.length) return null;

  // Expose the actual detected chain from DexScreener
  const detectedChain = bestPairs[0].chainId;

  const p = bestPairs[0]; // highest-liquidity pair

  // Aggregate volume & txns across best matching pairs
  const totalVol24h = bestPairs.reduce((s, x) => s + (x.volume?.h24 || 0), 0);
  const totalVol1h  = bestPairs.reduce((s, x) => s + (x.volume?.h1  || 0), 0);
  const totalVol6h  = bestPairs.reduce((s, x) => s + (x.volume?.h6  || 0), 0);
  const totalVol5m  = bestPairs.reduce((s, x) => s + (x.volume?.m5  || 0), 0);
  const buys24h     = bestPairs.reduce((s, x) => s + (x.txns?.h24?.buys  || 0), 0);
  const sells24h    = bestPairs.reduce((s, x) => s + (x.txns?.h24?.sells || 0), 0);
  const buys1h      = bestPairs.reduce((s, x) => s + (x.txns?.h1?.buys   || 0), 0);
  const sells1h     = bestPairs.reduce((s, x) => s + (x.txns?.h1?.sells  || 0), 0);
  const buys5m      = bestPairs.reduce((s, x) => s + (x.txns?.m5?.buys   || 0), 0);
  const sells5m     = bestPairs.reduce((s, x) => s + (x.txns?.m5?.sells  || 0), 0);

  return {
    name:        p.baseToken?.name,
    symbol:      p.baseToken?.symbol,
    address:     p.baseToken?.address || contractAddress,
    chain:       detectedChain,
    quoteSymbol: p.quoteToken?.symbol || 'SOL',
    pairAddress: p.pairAddress,
    dexId:       p.dexId,
    url:         p.url,
    price:       parseFloat(p.priceUsd || 0),
    priceNative: parseFloat(p.priceNative || 0),
    priceChange: {
      m5:  p.priceChange?.m5  || 0,
      h1:  p.priceChange?.h1  || 0,
      h6:  p.priceChange?.h6  || 0,
      h24: p.priceChange?.h24 || 0,
    },
    marketCap:   p.marketCap || p.fdv || 0,
    fdv:         p.fdv || 0,
    liquidity:   p.liquidity?.usd  || 0,
    liquidityBase:  p.liquidity?.base  || 0,
    liquidityQuote: p.liquidity?.quote || 0,
    volume: { h24: totalVol24h, h6: totalVol6h, h1: totalVol1h, m5: totalVol5m },
    txns:   {
      buys24h, sells24h, buys1h, sells1h, buys5m, sells5m,
      buyRatio24h: buys24h + sells24h > 0 ? (buys24h / (buys24h + sells24h) * 100).toFixed(1) : '50.0',
    },
    pairCreatedAt: p.pairCreatedAt || null,
    imageUrl:    p.info?.imageUrl  || null,
    headerUrl:   p.info?.header    || null,
    websites:    (p.info?.websites || []).map(w => ({ url: w.url || w, label: w.label || null })),
    socials:     p.info?.socials   || [],
    labels:      p.labels          || [],
    allPairs:    bestPairs.length,
    allPairsData: bestPairs
      .filter(x => x.pairAddress && (
        /^0x[0-9a-fA-F]{40}$/.test(x.pairAddress) ||
        /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(x.pairAddress)
      ))
      .slice(0, 8).map(x => ({
        dex: x.dexId, pair: x.pairAddress,
        liq: x.liquidity?.usd || 0,
        liqBase: x.liquidity?.base || 0,
        vol24h: x.volume?.h24 || 0,
        buys24h: x.txns?.h24?.buys || 0,
        sells24h: x.txns?.h24?.sells || 0,
        createdAt: x.pairCreatedAt || null,
        labels: x.labels || [],
      })),
  };
}

// ─── 2. DexScreener: Real OHLCV candles ────────────────────────────────────────
async function fetchCandles(pairAddress, res = '5', chainId = 'ethereum') {
  const to   = Math.floor(Date.now() / 1000);
  const from = to - 86400; // last 24h

  // Try DexScreener chart API (internal but stable)
  const urls = [
    `${DS_CHART}/dex/chart/amm/v3/by-pair/${chainId}/${pairAddress}?from=${from}&to=${to}&res=${res}`,
    `${DS_CHART}/dex/chart/amm/v2/by-pair/${chainId}/${pairAddress}?from=${from}&to=${to}&res=${res}`,
    `${DS_CHART}/dex/chart/amm/by-pair/${chainId}/${pairAddress}?from=${from}&to=${to}&res=${res}`,
  ];

  for (const url of urls) {
    try {
      const { data } = await axios.get(url, {
        timeout: 8000,
        headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json' },
      });
      const raw = data?.candles || data?.data?.candles || data?.ohlcv || [];
      if (raw.length > 2) {
        return raw.map(c => ({
          time:   Math.floor((c.t || c.time || c[0]) / (c.t > 1e12 ? 1000 : 1)),
          open:   parseFloat(c.o || c.open  || c[1]),
          high:   parseFloat(c.h || c.high  || c[2]),
          low:    parseFloat(c.l || c.low   || c[3]),
          close:  parseFloat(c.c || c.close || c[4]),
          volume: parseFloat(c.v || c.volume|| c[5] || 0),
        })).filter(c => c.time && c.open && c.close);
      }
    } catch (_) {}
  }
  return null;
}

// Fallback: generate realistic candles from real price
function generateCandles(basePrice, count = 180) {
  const candles = [];
  let price  = basePrice || 0.000001;
  const now  = Date.now();
  const step = 5 * 60 * 1000;
  for (let i = count; i >= 0; i--) {
    const o   = price;
    const chg = price * rand(-0.035, 0.04);
    const c   = Math.max(price + chg, 0.0000001);
    const h   = Math.max(o, c) * rand(1.001, 1.02);
    const l   = Math.min(o, c) * rand(0.98, 0.999);
    candles.push({
      time:   Math.floor((now - i * step) / 1000),
      open:   +o.toFixed(10), high: +h.toFixed(10),
      low:    +l.toFixed(10), close: +c.toFixed(10),
      volume: +(rand(50000, 2000000)).toFixed(2),
    });
    price = c;
  }
  return candles;
}

// ─── 3. Fetch real traders from GeckoTerminal pool trades ──────────────────────
// Returns top wallets by volume with real addresses, PnL, entry time, hold duration
async function fetchPoolTraders(poolAddress, network, pairCreatedAt) {
  if (!poolAddress || !network) return null;
  try {
    const baseUrl = `https://api.geckoterminal.com/api/v2/networks/${network}/pools/${poolAddress}/trades`;

    // Fetch recent trades + early trades in parallel
    // Early trades: use before_timestamp = launch + 2h to capture first buyers
    const launchSec = pairCreatedAt ? Math.floor(pairCreatedAt / 1000) : null;
    const earlyTs   = launchSec ? launchSec + 7200 : null; // 2h window after launch

    const [resRecent, resEarly] = await Promise.all([
      axios.get(baseUrl, { timeout: 12000, headers: GECKO_HEADS }).catch(() => null),
      earlyTs ? axios.get(`${baseUrl}?before_timestamp=${earlyTs}`, { timeout: 12000, headers: GECKO_HEADS }).catch(() => null) : Promise.resolve(null),
    ]);

    const recentTrades = resRecent?.data?.data || [];
    const earlyTrades  = resEarly?.data?.data  || [];

    // Identify which are genuinely early: timestamp within 2h of launch
    const launchMs      = pairCreatedAt || 0;
    const launchCutoff  = launchMs + 7200000; // 2 hours after launch
    const earlyTradeIds = new Set(
      earlyTrades.filter(t => {
        const ts = t.attributes.block_timestamp ? new Date(t.attributes.block_timestamp).getTime() : 0;
        return ts > 0 && ts <= launchCutoff;
      }).map(t => t.attributes.tx_hash)
    );

    // Merge all trades, dedupe by tx_hash
    const allTrades = [...recentTrades];
    for (const t of earlyTrades) {
      if (!recentTrades.some(r => r.attributes.tx_hash === t.attributes.tx_hash)) {
        allTrades.push(t);
      }
    }

    console.log(`  [traders] raw trades from GT: ${recentTrades.length} recent + ${earlyTrades.length} early = ${allTrades.length} total`);
    if (!allTrades.length) return null;

    const nowMs = Date.now();

    // Aggregate per wallet
    const walletMap = {};
    for (const t of allTrades) {
      const a    = t.attributes;
      const addr = a.tx_from_address;
      if (!addr) continue;
      const volUsd   = parseFloat(a.volume_in_usd || 0);
      const ts       = a.block_timestamp ? new Date(a.block_timestamp).getTime() : nowMs;
      const isBuy    = a.kind === 'buy';
      const isEarly  = earlyTradeIds.has(a.tx_hash);

      if (!walletMap[addr]) {
        walletMap[addr] = { address: addr, buyVol: 0, sellVol: 0, txCount: 0, firstTs: ts, lastTs: ts, earlyBuyVol: 0, earlyTxs: 0 };
      }
      const w = walletMap[addr];
      if (isBuy) w.buyVol  += volUsd; else w.sellVol += volUsd;
      w.txCount++;
      if (ts < w.firstTs) w.firstTs = ts;
      if (ts > w.lastTs)  w.lastTs  = ts;
      if (isEarly && isBuy) { w.earlyBuyVol += volUsd; w.earlyTxs++; }
    }

    const allWallets = Object.values(walletMap);
    const maxVol     = Math.max(...allWallets.map(w => w.buyVol + w.sellVol), 1);

    // Classify each wallet
    const classified = allWallets.map(w => {
      const totalVol  = w.buyVol + w.sellVol;
      const sellRatio = w.buyVol > 0 ? w.sellVol / w.buyVol : 1;
      const holdMs    = w.lastTs - w.firstTs;
      const holdDays  = holdMs / 86400000;
      const isEarly   = w.earlyTxs > 0;

      let type = 'Trader';
      if (isEarly && sellRatio < 0.3)        type = 'Insider';
      else if (isEarly && sellRatio < 0.7)   type = 'Early Buyer';
      else if (isEarly)                       type = 'Early Buyer';
      else if (holdDays > 7 && sellRatio < 0.5) type = 'Holder';
      else if (totalVol > maxVol * 0.3)      type = 'Whale';

      const riskScore = type === 'Insider'     ? 88
                      : type === 'Early Buyer' ? 72
                      : type === 'Whale'       ? 60
                      : type === 'Holder'      ? 45
                      : 35;

      return { ...w, type, riskScore, totalVol, sellRatio, isEarly };
    });

    // Sort: early buyers first (by earlyBuyVol), then by total volume
    const earlyWallets  = classified.filter(w => w.isEarly).sort((a, b) => b.earlyBuyVol - a.earlyBuyVol);
    const recentWallets = classified.filter(w => !w.isEarly).sort((a, b) => b.totalVol - a.totalVol);
    // Merge: up to 4 early + rest filled by recent, max 12 total
    const sorted = [...earlyWallets.slice(0, 4), ...recentWallets].slice(0, 12);

    console.log(`  [traders] early=${earlyWallets.length} recent=${recentWallets.length} showing=${sorted.length}`);

    return sorted.map(w => {
      const profitUsd = Math.round(w.sellVol - w.buyVol);

      // Time labels
      const minsAgoLast  = Math.floor((nowMs - w.lastTs) / 60000);
      const minsAgoFirst = Math.floor((nowMs - w.firstTs) / 60000);
      const lastActive = minsAgoLast < 60 ? `${minsAgoLast}m ago` : minsAgoLast < 1440 ? `${Math.floor(minsAgoLast/60)}h ago` : `${Math.floor(minsAgoLast/1440)}d ago`;
      const firstBuy   = minsAgoFirst < 60 ? `${minsAgoFirst}m ago` : minsAgoFirst < 1440 ? `${Math.floor(minsAgoFirst/60)}h ago` : `${Math.floor(minsAgoFirst/1440)}d ago`;

      // Activity bars (7 days)
      const actBars = Array.from({ length: 7 }, (_, i) => {
        const dayStart = nowMs - (7 - i) * 86400000;
        const dayEnd   = dayStart + 86400000;
        const inDay    = allTrades.filter(t => {
          const ts = t.attributes.block_timestamp ? new Date(t.attributes.block_timestamp).getTime() : 0;
          return t.attributes.tx_from_address === w.address && ts >= dayStart && ts < dayEnd;
        }).length;
        return Math.min(1, inDay / 5);
      });

      return {
        address:       w.address,
        shortAddr:     shortAddr(w.address),
        allocation:    Math.round(w.totalVol),
        supplyPct:     parseFloat(((w.totalVol / maxVol) * 10).toFixed(2)),
        type:          w.type,
        riskScore:     w.riskScore,
        isRealData:    true,
        isEarlyBuyer:  w.isEarly,
        txCount7d:     w.txCount,
        profitUsd,
        buyVol:        Math.round(w.buyVol),
        sellVol:       Math.round(w.sellVol),
        earlyBuyVol:   Math.round(w.earlyBuyVol),
        firstBuy,
        lastActive,
        activity:   actBars,
        solscanUrl: `https://solscan.io/account/${w.address}`,
      };
    });
  } catch (e) {
    console.error('[traders]', e.message);
    return null;
  }
}

// ─── Build wallet entries from DexScreener pairs data ──────────────────────────
// Returns real LP pair addresses + derived risk data — no fake wallet addresses
function buildWalletsFromDex(dex, totalSupply, chain = 'ethereum') {
  if (!dex) return [];
  const allPairs  = dex.allPairsData || [];
  const supply    = totalSupply || (dex.marketCap > 0 && dex.price > 0 ? dex.marketCap / dex.price : null);
  const totalLiq  = allPairs.reduce((s, p) => s + (p.liq || 0), 0) || dex.liquidity || 1;
  const totalVol  = allPairs.reduce((s, p) => s + (p.vol24h || 0), 0) || dex.volume?.h24 || 1;
  const nowMs     = Date.now();

  const wallets = [];

  const makeEntry = (p, type, riskScore) => {
    const liqPct  = totalLiq > 0 ? (p.liq / totalLiq * 100) : 0;
    const volPct  = totalVol > 0 ? (p.vol24h / totalVol * 100) : 0;
    const txTotal = (p.buys24h || 0) + (p.sells24h || 0);
    const buyVol  = txTotal > 0
      ? Math.round((p.vol24h || 0) * ((p.buys24h || 0) / txTotal))
      : Math.round((p.vol24h || 0) * 0.5);
    const sellVol = Math.round((p.vol24h || 0) - buyVol);
    const ageMs   = p.createdAt ? nowMs - new Date(p.createdAt).getTime() : null;
    const ageDays = ageMs != null ? Math.floor(ageMs / 86400000) : null;
    const firstBuy = ageDays != null ? (ageDays === 0 ? 'Today' : `${ageDays}d ago`) : null;
    return {
      address:    p.pair,
      shortAddr:  shortAddr(p.pair),
      type,
      allocation: p.liq || 0,
      supplyPct:  parseFloat(liqPct.toFixed(2)),
      buyVol,
      sellVol,
      profitUsd:  null,
      txCount7d:  txTotal || null,
      firstBuy,
      lastActive: p.vol24h > 0 ? 'Today' : null,
      riskScore,
      isRealData: true,
      isLiqPool:  true,
      dexId:      p.dex,
      liqUsd:     p.liq || 0,
      vol24h:     p.vol24h || 0,
      volPct:     parseFloat(volPct.toFixed(1)),
      labels:     p.labels || [],
      activity:   Array.from({ length: 7 }, (_, i) => i === 6 ? Math.min(1, volPct / 100) : 0),
      solscanUrl: explorerUrl(p.pair, chain),
    };
  };

  // ── 1. Top 3 by liquidity = "Top Holders" (pools holding the most tokens) ─
  const byLiq = [...allPairs].sort((a, b) => (b.liq || 0) - (a.liq || 0)).slice(0, 3);
  byLiq.forEach((p, i) => {
    const liqPct    = totalLiq > 0 ? (p.liq / totalLiq * 100) : 0;
    const riskScore = liqPct > 50 ? 72 : liqPct > 25 ? 55 : 35;
    wallets.push(makeEntry(p, i === 0 ? 'Top Holder' : 'Holder', riskScore));
  });

  // ── 2. Top 2 by 24h volume = "Whale" pools (most traded, likely whale activity)
  //    Pick pairs not already added, else promote existing top-holder pair as Whale too
  const byVol = [...allPairs].sort((a, b) => (b.vol24h || 0) - (a.vol24h || 0));
  let whaleAdded = 0;
  for (const p of byVol) {
    if (whaleAdded >= 2) break;
    if (wallets.some(w => w.address === p.pair)) continue;
    const volPct    = totalVol > 0 ? (p.vol24h / totalVol * 100) : 0;
    const txTotal   = (p.buys24h || 0) + (p.sells24h || 0);
    const sellRatio = txTotal > 0 ? (p.sells24h / txTotal * 100) : 50;
    const riskScore = sellRatio > 60 ? 78 : volPct > 40 ? 65 : 45;
    wallets.push(makeEntry(p, 'Whale', riskScore));
    whaleAdded++;
  }

  // ── 3. Primary pair as Liquidity wallet (if not already added) ────────────
  if (dex.pairAddress && !wallets.some(w => w.address === dex.pairAddress)) {
    const txTotal   = (dex.txns?.buys24h || 0) + (dex.txns?.sells24h || 0);
    const sellRatio = txTotal > 0 ? ((dex.txns?.sells24h || 0) / txTotal * 100) : 50;
    wallets.push(makeEntry({
      pair:     dex.pairAddress,
      dex:      dex.dexId,
      liq:      dex.liquidity || 0,
      vol24h:   dex.volume?.h24 || 0,
      buys24h:  dex.txns?.buys24h || 0,
      sells24h: dex.txns?.sells24h || 0,
      createdAt: dex.pairCreatedAt || null,
      labels:   dex.labels || [],
    }, 'Liquidity', sellRatio > 60 ? 70 : 30));
  }

  return wallets.slice(0, 12);
}

// ─── Derive holder distribution from DexScreener when RPC is unavailable ───────
function deriveHoldersFromDex(mintAddress, dex, totalSupply) {
  if (!dex) return null;

  const supply = totalSupply || (dex.marketCap > 0 && dex.price > 0 ? dex.marketCap / dex.price : 1e9);

  // LP pool tokens (from liquidity.base) → real on-chain value
  const poolTokens   = dex.liquidityBase || 0;
  const poolPct      = supply > 0 ? (poolTokens / supply * 100) : 5;

  // Estimate top wallet concentration from sell/buy pressure + liquidity ratio
  const liqRatio     = dex.marketCap > 0 ? dex.liquidity / dex.marketCap : 0.05;
  const sellPressure = dex.txns.buys24h + dex.txns.sells24h > 0
    ? dex.txns.sells24h / (dex.txns.buys24h + dex.txns.sells24h) : 0.4;

  // Heuristic: low liquidity + high sell pressure → high concentration
  let estimatedTop10 = 25 + (1 - Math.min(liqRatio / 0.15, 1)) * 30 + sellPressure * 15;
  estimatedTop10 = Math.min(Math.max(estimatedTop10, 15), 75);

  // Build synthetic wallet list from LP + estimated whales
  const holders = [];

  // LP pool as one "known" holder (real pair address from DexScreener)
  if (poolTokens > 0) {
    const lpAddr = dex.pairAddress || null;
    holders.push({
      address:    lpAddr || 'LiqPool',
      shortAddr:  'LP..' + (lpAddr || '').slice(-4),
      allocation: poolTokens,
      supplyPct:  parseFloat(poolPct.toFixed(4)),
      type:       'Liquidity',
      riskScore:  10,
      isRealData: !!lpAddr,
      txCount7d:  null,
      profitUsd:  null,
      firstBuy:   null,
      lastActive: null,
      activity:   Array.from({ length: 7 }, () => 0),
      solscanUrl: lpAddr ? `https://solscan.io/account/${lpAddr}` : null,
    });
  }

  // Estimated whale wallets — clearly marked as non-real
  const remainingPct = Math.max(0, estimatedTop10 - poolPct);
  const baseRng    = seededRand(mintAddress);
  const whaleCount = Math.min(seededRandInt(baseRng, 3, 8), 9);
  let allocated = 0;
  const ageDays = dex?.pairCreatedAt ? (Date.now() - dex.pairCreatedAt) / 86400000 : 30;
  for (let i = 0; i < whaleCount && allocated < remainingPct; i++) {
    const fakeAddr = mintAddress.slice(0,4) + (i*7+11).toString(16).padStart(4,'0') + mintAddress.slice(-4);
    const rng = seededRand(fakeAddr + mintAddress + i);
    const pct = Math.min(rng(1, remainingPct / whaleCount * 1.8), remainingPct - allocated);
    const type = pct > 5 ? 'Team' : pct > 2 ? 'Insider' : 'Cluster';
    const riskScore = pct > 5 ? seededRandInt(rng, 65, 95) : seededRandInt(rng, 35, 70);
    holders.push({
      address:    null,
      shortAddr:  null,
      allocation: parseFloat((pct / 100 * supply).toFixed(0)),
      supplyPct:  parseFloat(pct.toFixed(4)),
      type,
      riskScore,
      isRealData: false,
      txCount7d:  null,
      profitUsd:  null,
      firstBuy:   null,
      lastActive: null,
      activity:   Array.from({ length: 7 }, () => 0),
      solscanUrl: null,
    });
    allocated += pct;
  }

  const top10Pct   = holders.slice(0, 10).reduce((s, h) => s + h.supplyPct, 0);
  const teamPct    = holders.filter(h => h.type === 'Team').reduce((s, h) => s + h.supplyPct, 0);
  const insiderPct = holders.filter(h => h.type === 'Insider').reduce((s, h) => s + h.supplyPct, 0);

  console.log(`  [DEX-derived] Supply: ${supply.toFixed(0)}, EstTop10: ${top10Pct.toFixed(2)}%, Pool: ${poolPct.toFixed(2)}%`);
  return { holders, totalSupply: supply, top10Pct, teamPct, insiderPct, poolPct, source: 'dex-derived' };
}

// ─── 4. Calculate real risk score from on-chain metrics ────────────────────────
function calcRiskScore(dex, holderData, goplus = null) {
  let score = 0;
  const factors = [];

  // ── A. Security flags from GoPlus (0–40 pts, highest weight) ──────────────
  if (goplus) {
    // Honeypot = immediate max risk
    if (goplus.isHoneypot) {
      score += 40; factors.push('Honeypot detected');
    } else {
      // Not open source = big red flag
      if (goplus.isOpenSource === false) { score += 12; factors.push('Contract not open source') }

      // Mintable = owner can inflate supply
      if (goplus.isMintable)  { score += 10; factors.push('Token is mintable') }

      // Freezable (Solana) = owner can freeze wallets
      if (goplus.isFreezable) { score += 8;  factors.push('Token is freezable') }

      // Proxy contract = logic can be swapped
      if (goplus.isProxy)     { score += 6;  factors.push('Proxy contract (upgradeable)') }

      // Cannot buy = honeypot variant
      if (goplus.cannotBuy)   { score += 15; factors.push('Buy transactions blocked') }

      // Buy/sell tax
      const maxTax = Math.max(goplus.buyTax || 0, goplus.sellTax || 0);
      if (maxTax >= 10)       { score += 10; factors.push(`High tax: buy ${goplus.buyTax.toFixed(1)}% / sell ${goplus.sellTax.toFixed(1)}%`) }
      else if (maxTax >= 5)   { score += 5;  factors.push(`Moderate tax: ${maxTax.toFixed(1)}%`) }

      // Creator malicious
      if (goplus.creatorMalicious) { score += 10; factors.push('Creator flagged as malicious') }

      // LP unlocked — all top LP holders unlocked
      const lpLocked = (goplus.lpHolders || []).some(h => h.locked);
      if (!lpLocked && (goplus.lpHolders || []).length > 0) {
        score += 6; factors.push('LP not locked');
      }
    }
  }

  // ── B. Holder concentration from GT distribution (0–25 pts) ───────────────
  const top10 = holderData?.top10Pct || 0;
  if (top10 > 80)      { score += 25; factors.push(`Extreme concentration: top 10 hold ${top10.toFixed(1)}%`) }
  else if (top10 > 60) { score += 18; factors.push(`High concentration: top 10 hold ${top10.toFixed(1)}%`) }
  else if (top10 > 40) { score += 10; factors.push(`Top 10 hold ${top10.toFixed(1)}%`) }
  else if (top10 > 20) { score += 4;  factors.push(`Top 10 hold ${top10.toFixed(1)}%`) }

  // ── C. Liquidity / Market Cap ratio (0–15 pts) ────────────────────────────
  const liqRatio = dex.marketCap > 0 ? (dex.liquidity / dex.marketCap) : 0;
  if (liqRatio < 0.01)      { score += 15; factors.push('Critical: very low liquidity vs mcap') }
  else if (liqRatio < 0.03) { score += 10; factors.push('Low liquidity ratio') }
  else if (liqRatio < 0.08) { score += 5;  factors.push('Moderate liquidity ratio') }
  // else good liquidity = 0 pts added

  // ── D. Token age (0–10 pts) ───────────────────────────────────────────────
  const ageDays = dex.pairCreatedAt ? (Date.now() - dex.pairCreatedAt) / 86400000 : 999;
  if (ageDays < 1)       { score += 10; factors.push('Token < 1 day old') }
  else if (ageDays < 7)  { score += 6;  factors.push(`Token ${ageDays.toFixed(0)}d old`) }
  else if (ageDays < 30) { score += 3;  factors.push(`Token ${ageDays.toFixed(0)}d old`) }

  // ── E. Sell pressure (0–10 pts) ───────────────────────────────────────────
  const total = (dex.txns?.buys24h || 0) + (dex.txns?.sells24h || 0);
  const sellRatio = total > 0 ? dex.txns.sells24h / total : 0;
  if (sellRatio > 0.70)      { score += 10; factors.push(`Heavy sell pressure: ${(sellRatio*100).toFixed(0)}% sells`) }
  else if (sellRatio > 0.60) { score += 5;  factors.push(`Elevated sell ratio: ${(sellRatio*100).toFixed(0)}%`) }

  score = Math.min(100, Math.max(1, Math.round(score)));
  const level = score >= 75 ? 'VERY HIGH' : score >= 55 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW';
  return { score, level, factors };
}

// ─── 5. Build insider alerts from real data ─────────────────────────────────────
function buildAlerts(dex, holderData, risk) {
  const alerts = [];
  const top10   = holderData?.top10Pct || 0;
  const teamPct = holderData?.teamPct  || 0;
  const ageDays = dex.pairCreatedAt ? (Date.now() - dex.pairCreatedAt) / 86400000 : 99;
  const total   = dex.txns.buys24h + dex.txns.sells24h;
  const sellR   = total > 0 ? dex.txns.sells24h / total : 0.5;
  const liqR    = dex.marketCap > 0 ? dex.liquidity / dex.marketCap : 1;
  const volR    = dex.marketCap > 0 ? dex.volume.h24 / dex.marketCap : 0;
  const holders = holderData?.holders || [];
  const insiderWals = holders.filter(h => h.type === 'Insider' || h.type === 'Team');

  // CRITICAL alerts
  if (top10 > 60)
    alerts.push({ type:'team', severity:'critical', label:'Extreme Concentration',
      desc:`Top 10 wallets control ${top10.toFixed(1)}% of supply — rug pull risk elevated`,
      detail: `${holders.filter(h=>h.type==='Team').length} team wallet(s) identified. Combined holding: ${top10.toFixed(1)}%.`,
      action: 'Monitor large sell transactions from top holders' });

  if (ageDays < 1)
    alerts.push({ type:'stealth', severity:'critical', label:'Stealth Launch Detected',
      desc:`Token launched only ${(ageDays * 24).toFixed(0)} hour(s) ago — extreme caution`,
      detail: 'Newly launched tokens have higher probability of rug pulls and pump-and-dump schemes.',
      action: 'Wait for liquidity lock confirmation before trading' });

  if (liqR < 0.02)
    alerts.push({ type:'liquidity', severity:'critical', label:'Critical Liquidity Warning',
      desc:`Liquidity is only ${(liqR*100).toFixed(2)}% of market cap — exit may be impossible`,
      detail: `Total liquidity: $${dex.liquidity.toFixed(0)} vs MCap: $${dex.marketCap.toFixed(0)}`,
      action: 'Do not enter large positions — slippage will be extreme' });

  // HIGH alerts
  if (top10 > 30 && top10 <= 60)
    alerts.push({ type:'team', severity:'high', label:'High Wallet Concentration',
      desc:`Top 10 wallets hold ${top10.toFixed(1)}% of total supply`,
      detail: `${insiderWals.length} potential insider wallet(s) detected with combined ${(insiderWals.reduce((s,h)=>s+h.supplyPct,0)).toFixed(1)}% supply.`,
      action: 'Watch for coordinated sell patterns' });

  if (sellR > 0.65)
    alerts.push({ type:'distribution', severity:'high', label:'High Sell Pressure',
      desc:`${(sellR*100).toFixed(0)}% of 24h transactions are sells (${dex.txns.sells24h} sells)`,
      detail: `Buy/Sell ratio: ${dex.txns.buys24h}/${dex.txns.sells24h}. Volume last hour: $${dex.volume.h1.toFixed(0)}.`,
      action: 'Bearish signal — insiders may be distributing' });

  if (volR > 3)
    alerts.push({ type:'distribution', severity:'high', label:'Abnormal Volume Spike',
      desc:`24h volume is ${(volR*100).toFixed(0)}% of market cap — possible wash trading`,
      detail: `Vol24h: $${(dex.volume.h24/1e3).toFixed(1)}K vs MCap: $${(dex.marketCap/1e3).toFixed(1)}K. High vol/mcap ratio suggests artificial activity.`,
      action: 'Verify volume authenticity before trading' });

  if (insiderWals.length >= 3)
    alerts.push({ type:'insider', severity:'high', label:'Insider Cluster Detected',
      desc:`${insiderWals.length} wallets classified as Team/Insider hold concentrated supply`,
      detail: `Wallets: ${insiderWals.slice(0,3).map(h=>h.shortAddr).join(', ')}${insiderWals.length>3?'...':''}.`,
      action: 'Track these wallets for sudden movement' });

  // MEDIUM alerts
  if (ageDays >= 1 && ageDays < 7)
    alerts.push({ type:'stealth', severity:'medium', label:'New Token Alert',
      desc:`Token launched ${ageDays.toFixed(0)} day(s) ago — limited price history`,
      detail: 'Low liquidity and new tokens carry higher risk of sudden price swings.',
      action: 'Use smaller position sizes until liquidity deepens' });

  if (liqR >= 0.02 && liqR < 0.05)
    alerts.push({ type:'liquidity', severity:'medium', label:'Low Liquidity Ratio',
      desc:`Liquidity is ${(liqR*100).toFixed(1)}% of market cap — slippage risk`,
      detail: `$${(dex.liquidity/1e3).toFixed(1)}K liquidity. Large orders will move price significantly.`,
      action: 'Split orders to reduce price impact' });

  if (sellR >= 0.55 && sellR <= 0.65)
    alerts.push({ type:'distribution', severity:'medium', label:'Elevated Sell Ratio',
      desc:`${(sellR*100).toFixed(0)}% sell transactions in 24h — mild selling pressure`,
      detail: `${dex.txns.sells24h} sells vs ${dex.txns.buys24h} buys in 24h.`,
      action: 'Monitor price action for trend reversal signals' });

  const absChange24h = Math.abs(dex.priceChange?.h24 || 0);
  if (absChange24h > 50)
    alerts.push({ type:'distribution', severity:'medium', label:'Extreme Price Volatility',
      desc:`Price moved ${dex.priceChange.h24 >= 0 ? '+' : ''}${dex.priceChange.h24.toFixed(1)}% in 24h`,
      detail: `5m: ${dex.priceChange.m5.toFixed(2)}%  1h: ${dex.priceChange.h1.toFixed(2)}%  24h: ${dex.priceChange.h24.toFixed(2)}%`,
      action: 'High volatility — set tight stop losses' });

  if (dex.allPairs > 3)
    alerts.push({ type:'distribution', severity:'low', label:'Multi-DEX Activity',
      desc:`Token active on ${dex.allPairs} trading pairs — fragmented liquidity`,
      detail: `Multiple pools may indicate arbitrage bots or wash trading across venues.`,
      action: 'Use the pool with highest liquidity for best execution' });

  if (!alerts.length)
    alerts.push({ type:'distribution', severity:'low', label:'Low Risk Profile',
      desc:'No major insider patterns detected — standard caution still applies',
      detail: 'Token shows balanced buy/sell ratio and adequate liquidity.',
      action: 'Continue monitoring for changes in wallet behavior' });

  // Sort by severity
  const sevOrder = { critical:0, high:1, medium:2, low:3 };
  alerts.sort((a,b) => (sevOrder[a.severity]||3) - (sevOrder[b.severity]||3));
  return alerts.slice(0, 6);
}

// ─── 6. Build volume profile from real per-hour estimation ─────────────────────
function buildVolumeProfile(dex) {
  // Use real period volumes as anchors, distribute across 24 hours
  const vol24 = dex.volume.h24;
  const vol6  = dex.volume.h6;
  const vol1  = dex.volume.h1;
  const vol5m = dex.volume.m5;
  const now   = new Date();
  const curH  = now.getHours();

  return Array.from({ length: 24 }, (_, i) => {
    const isRecent  = i === curH;
    const isLast6h  = (curH - i + 24) % 24 < 6;
    const isLast1h  = i === curH;
    const baseVol   = isLast1h ? vol1 : isLast6h ? (vol6 / 6) : ((vol24 - vol6) / 18);
    const noise     = rand(0.6, 1.4);
    const v         = Math.max(0, baseVol * noise);
    const buyPct    = parseFloat(dex.txns.buyRatio24h) / 100;
    const txPerH    = (dex.txns.buys24h + dex.txns.sells24h) / 24;
    return {
      hour:   i,
      volume: parseFloat(v.toFixed(2)),
      buys:   Math.round(txPerH * buyPct * rand(0.6, 1.4)),
      sells:  Math.round(txPerH * (1-buyPct) * rand(0.6, 1.4)),
    };
  });
}

// ─── 7. Build recent activity from real tx counts ──────────────────────────────
function buildActivity(dex, holderData, chain = 'solana', dexWallets = [], goplus = null) {
  const sym    = dex.symbol || '';
  const nowMs  = Date.now();
  const fmtUsd = v => v >= 1e6 ? `$${(v/1e6).toFixed(2)}M` : v >= 1e3 ? `$${(v/1e3).toFixed(1)}K` : `$${Math.round(v)}`;
  const allPairs = dex.allPairsData || [];
  const activities = [];

  // ── 1. HONEYPOT CHECK ────────────────────────────────────────────────────────
  if (goplus) {
    const isHp = goplus.isHoneypot;
    activities.push({
      icon: isHp ? 'sell' : 'cluster', type: 'Security', negative: isHp,
      desc: isHp ? `Honeypot detected — selling may be blocked` : `Not a honeypot — trading appears safe`,
      sub:  `Buy tax: ${goplus.buyTax.toFixed(1)}% | Sell tax: ${goplus.sellTax.toFixed(1)}% | Source: GoPlus Security`,
      time: 'Now',
      amount: isHp ? '⚠ DANGER' : '✓ Safe',
      usd: goplus.isMintable ? '⚠ Mintable token' : goplus.isFreezable ? '⚠ Freezable' : '',
      wallet: null, severity: isHp ? 'high' : 'low',
    });
  }

  // ── 2. BUY TAX / SELL TAX ────────────────────────────────────────────────────
  if (goplus) {
    const highTax = goplus.buyTax > 5 || goplus.sellTax > 5;
    activities.push({
      icon: highTax ? 'sell' : 'cluster', type: 'Tax', negative: highTax,
      desc: `Tax — Buy: ${goplus.buyTax.toFixed(1)}% | Sell: ${goplus.sellTax.toFixed(1)}%`,
      sub:  highTax
        ? `High tax detected — potential rug or fee trap`
        : `Normal tax range — no unusual fees detected`,
      time: 'Now',
      amount: highTax ? `⚠ High Tax` : `✓ Normal`,
      usd: '',
      wallet: null, severity: highTax ? 'high' : 'low',
    });
  }

  // ── 3. CREATOR ADDRESS ────────────────────────────────────────────────────────
  if (goplus?.creatorAddress) {
    const isMalicious = goplus.creatorMalicious;
    activities.push({
      icon: isMalicious ? 'sell' : 'transfer', type: 'Creator', negative: isMalicious,
      desc: isMalicious
        ? `Creator flagged as malicious address`
        : `Creator address identified`,
      sub:  goplus.creatorAddress,
      time: 'Deployed',
      amount: isMalicious ? '⚠ Flagged' : '✓ Clean',
      usd: '',
      wallet: shortAddr(goplus.creatorAddress),
      walletFull: isValidAddr(goplus.creatorAddress, chain) ? goplus.creatorAddress : null,
      severity: isMalicious ? 'high' : 'low',
    });
  }

  // ── 4. LP HOLDER ACCOUNTS ─────────────────────────────────────────────────────
  if (goplus?.lpHolders?.length) {
    const topLP    = goplus.lpHolders[0];
    const locked   = goplus.lpHolders.filter(h => h.locked).length;
    const totalPct = goplus.lpHolders.reduce((s, h) => s + h.pct, 0);
    activities.push({
      icon: 'liquidity', type: 'LP Holder', negative: locked === 0,
      desc: locked > 0
        ? `LP locked — ${locked}/${goplus.lpHolders.length} holder(s) have locked LP`
        : `LP not locked — no locked LP holders detected`,
      sub:  `Top LP holder: ${shortAddr(topLP.address)} (${topLP.pct.toFixed(2)}%) | Total tracked: ${totalPct.toFixed(1)}%`,
      time: 'Now',
      amount: locked > 0 ? `✓ ${locked} Locked` : `⚠ Unlocked`,
      usd: '',
      wallet: shortAddr(topLP.address),
      walletFull: isValidAddr(topLP.address, chain) ? topLP.address : null,
      severity: locked === 0 ? 'high' : 'low',
    });
  } else if (dex.pairAddress) {
    // Fallback: show main pair LP address from DS
    activities.push({
      icon: 'liquidity', type: 'LP Holder', negative: false,
      desc: `Liquidity pool — deployed ${dex.pairCreatedAt ? (() => { const d = Math.floor((nowMs - dex.pairCreatedAt)/86400000); return d < 30 ? `${d}d ago` : `${Math.floor(d/30)}mo ago`; })() : 'N/A'}`,
      sub:  `${dex.allPairs} pool(s) on ${dex.dexId} | TVL: ${fmtUsd(dex.liquidity)}`,
      time: 'Now',
      amount: fmtUsd(dex.liquidity) + ' TVL',
      usd: '',
      wallet: shortAddr(dex.pairAddress),
      walletFull: isValidAddr(dex.pairAddress, chain) ? dex.pairAddress : null,
      severity: 'low',
    });
  }

  // ── 5. TOKEN DUPLICATION CHECK ────────────────────────────────────────────────
  const dupCount = dex.allPairs || 1;
  const hasDups  = dupCount > 5;
  activities.push({
    icon: hasDups ? 'sell' : 'transfer', type: 'Duplicate', negative: false,
    desc: `Token active on ${dupCount} pair(s) across DEXes`,
    sub:  hasDups
      ? `High pair count — check for duplicate/clone tokens with same name`
      : `Pair count normal — no obvious duplication signal`,
    time: 'Now',
    amount: `${dupCount} pair(s)`,
    usd: '',
    wallet: null, severity: 'low',
  });

  // ── 2. DEV / TEAM BUY SIGNAL ─────────────────────────────────────────────────
  // Detect when the main pool had heavy early buys (Top Holder pool with high buy ratio)
  const topHolderPool = dexWallets.find(w => w.type === 'Top Holder');
  if (topHolderPool) {
    const txTotal  = topHolderPool.txCount7d || 0;
    const buyVol   = topHolderPool.buyVol || 0;
    const sellVol  = topHolderPool.sellVol || 0;
    const totalVol = buyVol + sellVol;
    const buyRatio = totalVol > 0 ? buyVol / totalVol : 0.5;
    if (buyRatio > 0.55) {
      activities.push({
        icon: 'cluster', type: 'Buys', negative: false,
        desc: `Top holder accumulating — ${(buyRatio*100).toFixed(0)}% buy ratio`,
        sub:  `${shortAddr(topHolderPool.address)} (${topHolderPool.dexId}) | B:${fmtUsd(buyVol)} S:${fmtUsd(sellVol)} | ${txTotal} txns`,
        time: topHolderPool.firstBuy || 'N/A',
        amount: `+${fmtUsd(buyVol)}`,
        usd: `(${topHolderPool.volPct || 0}% of pool vol)`,
        wallet: shortAddr(topHolderPool.address),
        walletFull: isValidAddr(topHolderPool.address, chain) ? topHolderPool.address : null,
        severity: 'low',
      });
    }
  }

  // ── 3. DEV / TEAM SELL SIGNAL ─────────────────────────────────────────────────
  // Detect high sell pressure from largest pool (possible dev exit)
  const sellR24 = dex.txns.buys24h + dex.txns.sells24h > 0
    ? dex.txns.sells24h / (dex.txns.buys24h + dex.txns.sells24h) : 0.5;
  if (sellR24 > 0.55) {
    const mainPool = allPairs.sort((a,b) => (b.vol24h||0) - (a.vol24h||0))[0];
    const poolAddr = mainPool?.pair;
    activities.push({
      icon: 'sell', type: 'Sells', negative: true,
      desc: `Dev/whale sell pressure — ${(sellR24*100).toFixed(0)}% sells in 24h`,
      sub:  `${dex.txns.sells24h} sells vs ${dex.txns.buys24h} buys on ${mainPool?.dex || dex.dexId}`,
      time: '24h window',
      amount: `-${dex.txns.sells24h} sell txns`,
      usd: `(${fmtUsd(dex.volume.h24 * sellR24)} sell vol)`,
      wallet: poolAddr ? shortAddr(poolAddr) : null,
      walletFull: poolAddr && isValidAddr(poolAddr, chain) ? poolAddr : null,
      severity: sellR24 > 0.65 ? 'high' : 'medium',
    });
  }

  // ── 4 & 5. WHALE BUY / SELL MOVEMENTS (one entry per whale showing dominant side) ──
  const whaleWallets = dexWallets.filter(w => w.type === 'Whale');
  whaleWallets.forEach(w => {
    const buyVol  = w.buyVol || 0;
    const sellVol = w.sellVol || 0;
    const total   = buyVol + sellVol;
    if (total < 500) return;
    const buyRatio  = buyVol / total;
    const sellRatio = sellVol / total;
    const isBuying  = buyRatio >= sellRatio;

    activities.push({
      icon:     isBuying ? 'cluster' : 'sell',
      type:     isBuying ? 'Buys' : 'Sells',
      negative: !isBuying,
      desc: isBuying
        ? `Whale buying on ${w.dexId?.toUpperCase()} — ${(buyRatio*100).toFixed(0)}% buy ratio`
        : `Whale selling on ${w.dexId?.toUpperCase()} — ${(sellRatio*100).toFixed(0)}% sell ratio`,
      sub:  `${shortAddr(w.address)} | B:${fmtUsd(buyVol)} S:${fmtUsd(sellVol)} | ${w.txCount7d || 0} txns 24h`,
      time: w.lastActive || 'Today',
      amount: isBuying ? `+${fmtUsd(buyVol)}` : `-${fmtUsd(sellVol)}`,
      usd: `(${w.volPct || 0}% of pool vol)`,
      wallet: shortAddr(w.address),
      walletFull: isValidAddr(w.address, chain) ? w.address : null,
      severity: !isBuying && sellRatio > 0.7 ? 'high' : 'medium',
    });
  });

  // ── 6. PRICE MOVEMENT (real data from DS) ────────────────────────────────────
  const p1h  = dex.priceChange.h1;
  const p24h = dex.priceChange.h24;
  if (Math.abs(p1h) > 0.5 || Math.abs(p24h) > 5) {
    activities.push({
      icon: 'transfer', type: 'Price', negative: p1h < 0,
      desc: `Price ${p1h >= 0 ? 'up' : 'down'} ${Math.abs(p1h).toFixed(2)}% in 1h | ${p24h >= 0 ? '+' : ''}${p24h.toFixed(2)}% in 24h`,
      sub:  `Vol 1h: ${fmtUsd(dex.volume.h1)} | Vol 24h: ${fmtUsd(dex.volume.h24)} | 5m: ${p1h >= 0 ? '+' : ''}${dex.priceChange.m5?.toFixed(2) || '0'}%`,
      time: '1h window',
      amount: `${p24h >= 0 ? '+' : ''}${p24h.toFixed(2)}%`,
      usd: '',
      wallet: null, severity: Math.abs(p24h) > 30 ? 'high' : Math.abs(p24h) > 10 ? 'medium' : 'low',
    });
  }

  // ── 7. BUY DOMINANCE ────────────────────────────────────────────────────────
  if (sellR24 <= 0.55) {
    activities.push({
      icon: 'cluster', type: 'Buys', negative: false,
      desc: `Buy pressure dominant — ${(100 - sellR24*100).toFixed(0)}% buys in 24h`,
      sub:  `${dex.txns.buys24h} buys vs ${dex.txns.sells24h} sells | Vol: ${fmtUsd(dex.volume.h24)}`,
      time: '24h window',
      amount: `+${dex.txns.buys24h} buy txns`,
      usd: `(${parseFloat(dex.txns.buyRatio24h).toFixed(1)}% of vol)`,
      wallet: null, severity: 'low',
    });
  }

  return activities;
}

// Helper for activity formatting (not exposed globally)
function fmt_token(v, sym) {
  v = Math.abs(parseFloat(v)) || 0;
  if (v >= 1e9) return (v/1e9).toFixed(2) + 'B ' + (sym||'');
  if (v >= 1e6) return (v/1e6).toFixed(2) + 'M ' + (sym||'');
  if (v >= 1e3) return (v/1e3).toFixed(1) + 'K ' + (sym||'');
  return Math.round(v) + ' ' + (sym||'');
}

// ─── 8. Build holder stats ──────────────────────────────────────────────────────
function buildHolderStats(holderData, dex, dsHolderCount, totalSupply) {
  const holders = holderData?.holders || [];
  const top10   = holderData?.top10Pct || 0;

  // Priority: DS-provided count → GT count (passed from geckoInfo) → cumulative unique txn estimate
  // Cumulative unique wallets ≈ total unique buyers over token lifetime
  // DexScreener aggregates buys + sells = total txns, unique addresses ≈ txns * 0.4 (repeat traders)
  const totalTxns   = (dex.txns.buys24h + dex.txns.sells24h) || 0;
  const ageDays     = dex.pairCreatedAt ? (Date.now() - dex.pairCreatedAt) / 86400000 : 1;
  const lifetimeTxns = Math.round(totalTxns * Math.max(ageDays, 1));
  const txnEstimate = Math.round(lifetimeTxns * 0.35); // ~35% unique wallets per txn

  // Use provided count or fall back to estimate (never less than RPC-found count)
  const bestTotal = dsHolderCount
    || Math.max(holders.length, txnEstimate, 1);
  const whales = holders.filter(h => h.supplyPct > 1).length;

  return {
    total:         Math.min(bestTotal, 9999999),
    whales,
    retail:        Math.max(0, bestTotal - whales),
    avgHolding:    totalSupply > 0 && bestTotal > 0 ? totalSupply / bestTotal : null,
    concentration: parseFloat(top10.toFixed(2)),
  };
}

// Which chains are turned on right now — default launch config is Robinhood
// only. Toggle via /api/admin/config?key=enabled_chains&value=robinhood,ethereum,base
let _enabledChainsCache = { list: null, at: 0 };
async function _getEnabledChains() {
  if (_enabledChainsCache.list && Date.now() - _enabledChainsCache.at < 5 * 60 * 1000) return _enabledChainsCache.list;
  const row = await dbGet("SELECT value FROM app_config WHERE `key`='enabled_chains'");
  const list = (row?.value || 'robinhood').split(',').map(s => s.trim()).filter(Boolean);
  _enabledChainsCache = { list, at: Date.now() };
  return list;
}

// ─── Main API Endpoint ─────────────────────────────────────────────────────────
app.post('/api/analyze', async (req, res) => {
  const { contractAddress, chain: requestedChain } = req.body;
  if (!contractAddress) return res.status(400).json({ error: 'Contract address required' });

  try {
    // Resolve chain: explicit selection or auto-detect from address format
    const resolvedChain = (!requestedChain || requestedChain === 'auto')
      ? detectChainFromAddress(contractAddress)
      : requestedChain;

    if (resolvedChain === 'solana' || resolvedChain === 'bsc' || resolvedChain === 'unsupported') {
      return res.status(400).json({ error: 'Solana and BSC are no longer supported on Bloombark. Supported chains: Ethereum, Base, Arbitrum, Robinhood Chain.' });
    }

    const geckoNetwork = GECKO_NETWORK[resolvedChain] || 'eth';
    const dsChainId    = DS_CHAIN[resolvedChain]    || resolvedChain;

    console.log(`\n[ANALYZE] ${contractAddress} chain=${resolvedChain} (gecko:${geckoNetwork} ds:${dsChainId})`);

    // ── Fetch DexScreener first to resolve the actual chain for EVM addresses ──
    const dex = await fetchDexScreener(contractAddress, dsChainId).catch(e => { console.error('DS:', e.message); return null; });

    // Use DexScreener's detected chain (most accurate for EVM — e.g. resolves 0x to 'base' not 'ethereum')
    const actualChain   = dex?.chain || resolvedChain;
    const actualGecko   = GECKO_NETWORK[actualChain] || geckoNetwork;

    console.log(`  → actual chain: ${actualChain} (gecko: ${actualGecko})`);

    const enabledChains = await _getEnabledChains();
    if (!enabledChains.includes(actualChain)) {
      return res.status(400).json({ error: `${actualChain} isn't enabled yet — currently supported: ${enabledChains.join(', ')}` });
    }

    // ── Parallel fetch: GeckoTerminal only (no Solana RPC) ──────────────────────
    const [gecko, geckoPools, geckoInfo] = await Promise.all([
      fetchGeckoToken(contractAddress, actualGecko).catch(e => { console.error('GT:', e.message); return null; }),
      fetchGeckoPools(contractAddress, actualGecko).catch(() => []),
      fetchGeckoHolders(contractAddress, actualGecko).catch(() => null),
    ]);
    const holderResult = null; // wallet data derived from DexScreener, not RPC

    // At least one source must return data
    if (!dex && !gecko) {
      return res.status(404).json({ error: `Token not found on ${actualChain}. Check the contract address and selected network.` });
    }

    // ── Merge: prefer real values, DexScreener fills pair-level gaps ──────────
    const bestPool   = geckoPools[0] || null;
    const bestName   = dex?.name     || gecko?.name  || contractAddress.slice(0,8);
    const bestSymbol = dex?.symbol   || gecko?.symbol || '?';
    const bestImage  = dex?.imageUrl || gecko?.imageUrl || null;

    // ── Liquidity: DexScreener primary (always matches what DS shows) ────────────
    // Only fall back to GeckoTerminal when DS explicitly shows $0
    const bestLiquidity = dex?.liquidity > 0
      ? dex.liquidity
      : (gecko?.liquidity || geckoPools.reduce((s,p) => s + p.liquidity, 0) || 0);

    // ── Volume & txns: DexScreener aggregated across all pairs (primary) ─────────
    const bestVol24h   = dex?.volume?.h24  || gecko?.volume24h || 0;
    const bestBuys24h  = dex?.txns?.buys24h  || geckoPools.reduce((s,p)=>s+p.buys24h,  0) || 0;
    const bestSells24h = dex?.txns?.sells24h || geckoPools.reduce((s,p)=>s+p.sells24h, 0) || 0;
    const bestBuys1h   = dex?.txns?.buys1h   || geckoPools.reduce((s,p)=>s+p.buys1h,   0) || 0;
    const bestSells1h  = dex?.txns?.sells1h  || geckoPools.reduce((s,p)=>s+p.sells1h,  0) || 0;
    const bestBuys5m   = dex?.txns?.buys5m   || geckoPools.reduce((s,p)=>s+p.buys5m,   0) || 0;
    const bestSells5m  = dex?.txns?.sells5m  || geckoPools.reduce((s,p)=>s+p.sells5m,  0) || 0;
    const buyRatio24h  = bestBuys24h + bestSells24h > 0
      ? (bestBuys24h / (bestBuys24h + bestSells24h) * 100).toFixed(1) : '50.0';

    // ── Price changes: DexScreener primary ───────────────────────────────────────
    const bestChange = {
      m5:  dex?.priceChange?.m5  ?? bestPool?.priceChange?.m5  ?? 0,
      h1:  dex?.priceChange?.h1  ?? bestPool?.priceChange?.h1  ?? 0,
      h6:  dex?.priceChange?.h6  ?? bestPool?.priceChange?.h6  ?? 0,
      h24: dex?.priceChange?.h24 ?? bestPool?.priceChange?.h24 ?? 0,
    };

    // ── Market cap / FDV: DexScreener primary ────────────────────────────────────
    const bestMcap = dex?.marketCap || gecko?.marketCap || gecko?.fdv || 0;
    const bestFdv  = dex?.fdv       || gecko?.fdv       || 0;

    // ── Price: DexScreener primary ───────────────────────────────────────────────
    const bestPrice  = dex?.price  || gecko?.price  || 0;

    // ── Created at: DexScreener pairCreatedAt primary ────────────────────────────
    const poolCreatedAt = dex?.pairCreatedAt || bestPool?.createdAt || null;

    // ── Holder count: GeckoTerminal /info is the most accurate free source ───────
    // GT provides count + distribution (top10%, 11-20%, etc.) from on-chain indexing.
    // DexScreener API doesn't expose holders field for most tokens.
    const realHolderCount = geckoInfo?.holders || holderResult?.holders?.length || null;
    const gtHolderDist    = geckoInfo?.holderDist || null;

    // Websites / socials: merge both sources, deduped by URL, preserving each
    // site's own label (e.g. "Website" vs "Docs") — previously flattened to
    // bare URL strings, which made every link render as a generic "Web" with
    // no way to tell multiple links apart.
    const _websiteMap = new Map(); // url -> label
    for (const w of (dex?.websites || [])) {
      const url = typeof w === 'string' ? w : w?.url;
      if (url) _websiteMap.set(url, (typeof w === 'object' && w?.label) || _websiteMap.get(url) || null);
    }
    for (const w of (geckoInfo?.websites || [])) {
      const url = typeof w === 'string' ? w : w?.url;
      const label = typeof w === 'object' ? w?.label : null;
      if (url && !_websiteMap.has(url)) _websiteMap.set(url, label || null);
    }
    const websites = [..._websiteMap.entries()].map(([url, label]) => ({ url, label }));
    const socials  = dex?.socials || [];

    // DEX id & pair address
    const dexId      = dex?.dexId      || bestPool?.dexId || 'unknown';
    const pairAddress = dex?.pairAddress || bestPool?.poolAddress || '';
    const allPairs   = Math.max(dex?.allPairs || 1, geckoPools.length);

    // Merged txns object (used by risk calc + activity builder)
    const mergedTxns = {
      buys24h: bestBuys24h, sells24h: bestSells24h,
      buys1h:  bestBuys1h,  sells1h:  bestSells1h,
      buys5m:  bestBuys5m,  sells5m:  bestSells5m,
      buyRatio24h,
    };

    // Build a unified "dex-like" object for downstream functions
    const merged = {
      ...(dex || {}),
      name: bestName, symbol: bestSymbol, price: bestPrice,
      marketCap: bestMcap, fdv: bestFdv,
      liquidity: bestLiquidity,
      liquidityBase: dex?.liquidityBase || 0,
      volume: { h24: bestVol24h, h6: dex?.volume?.h6||0, h1: dex?.volume?.h1||0, m5: dex?.volume?.m5||0 },
      txns: mergedTxns, priceChange: bestChange,
      pairCreatedAt: poolCreatedAt,
      imageUrl: bestImage, websites, socials,
      allPairs, dexId, pairAddress,
    };

    console.log(`  Token: ${merged.name} (${merged.symbol}) @ $${merged.price}`);
    console.log(`  Liquidity: $${merged.liquidity.toFixed(2)} (GT: $${gecko?.liquidity||0}, DS: $${dex?.liquidity||0})`);
    console.log(`  GT holder count: ${geckoInfo?.holders || 'N/A'}`);

    // ── Candles + GoPlus security in parallel ─────────────────────────────────
    const gtPoolAddr = bestPool?.poolAddress;
    const [candlesGT, goplus] = await Promise.all([
      gtPoolAddr ? fetchGeckoCandles(gtPoolAddr, 'minute', 5, 200).catch(() => null) : Promise.resolve(null),
      fetchGoPlus(contractAddress, actualChain).catch(() => null),
    ]);
    if (goplus) console.log(`  [goplus] honeypot=${goplus.isHoneypot} buyTax=${goplus.buyTax}% sellTax=${goplus.sellTax}%`);

    let candles = candlesGT;
    if (candles?.length > 5) console.log(`  GT candles: ${candles.length}`);
    if (!candles || candles.length < 5) {
      candles = await fetchCandles(pairAddress, '5').catch(() => null);
      if (candles?.length > 5) console.log(`  DS candles: ${candles.length}`);
    }
    if (!candles || candles.length < 5) {
      console.log('  Generated candles (no chart API)');
      candles = generateCandles(merged.price, 180);
    }
    const dexWallets = buildWalletsFromDex(merged, gecko?.totalSupply || null, actualChain);
    console.log(`  [ds-wallets] ${dexWallets.length} wallets from DS pairs`);

    const solanaTopHolders = []; // Solana no longer supported — kept as empty array for downstream code

    // ── Holder data (for distribution stats) — still derived from DexScreener ──
    const holderData = deriveHoldersFromDex(contractAddress, merged, gecko?.totalSupply || null);

    // Build distribution — only from verified real sources
    const totalSup   = holderData?.totalSupply || gecko?.totalSupply || (bestMcap > 0 && bestPrice > 0 ? bestMcap / bestPrice : 1e9);
    // LP pool % from DexScreener liquidity.base / total supply (real on-chain data)
    const liqBasePct = dex?.liquidityBase > 0 && totalSup > 0
      ? parseFloat((dex.liquidityBase / totalSup * 100).toFixed(2))
      : null;
    // Holder tier breakdown — from GeckoTerminal on-chain indexing only
    const top10Pct   = gtHolderDist?.top10  > 0 ? parseFloat(gtHolderDist.top10.toFixed(2))  : null;
    const p11_20     = gtHolderDist?.p11_20 > 0 ? parseFloat(gtHolderDist.p11_20.toFixed(2)) : null;
    const p21_40     = gtHolderDist?.p21_40 > 0 ? parseFloat(gtHolderDist.p21_40.toFixed(2)) : null;
    const restPct    = gtHolderDist?.rest   > 0 ? parseFloat(gtHolderDist.rest.toFixed(2))   : null;

    const holderDistribution = {
      top10:     top10Pct,
      liquidity: liqBasePct,
      p11_20,
      p21_40,
      rest:      restPct,
      // Derived: public = rest tier from GT (most accurate available)
      public:    restPct,
    };

    // Risk score from real metrics
    const risk = calcRiskScore(merged, holderData, goplus);
    console.log(`  Risk: ${risk.score}/100 (${risk.level})`);

    // Alerts from real data
    const alerts = buildAlerts(merged, holderData, risk);

    // Volume profile from real period data
    const volumeProfile = buildVolumeProfile(merged);

    // Recent activity from real tx data
    const recentActivity = buildActivity(merged, holderData, actualChain, dexWallets, goplus);

    // Holder stats — use real GT count if RPC gave fewer results
    // For Solana, override whale count with real data from RPC
    const holderStats = buildHolderStats(holderData, merged, realHolderCount, totalSup);
    if (solanaTopHolders.length) {
      // whales = top 3 traders (proxy since we don't have supply % from public RPC)
      holderStats.whales = Math.min(solanaTopHolders.filter(h => h.type === 'Whale').length, solanaTopHolders.length);
    }

    // Wallet relationships — top 12 holders as nodes with edges
    const allHolders = holderData?.holders || [];
    const topHolders = allHolders.slice(0, 8);
    const walletNodes = topHolders.map((h, i) => ({
      id:          `node_${i}`,
      type:        h.type,
      address:     h.shortAddr,
      fullAddress: h.address,
      connections: Math.max(1, Math.round(h.supplyPct / 2)),
      amount:      h.allocation,
      supplyPct:   h.supplyPct,
      riskScore:   h.riskScore || 50,
      txCount7d:   h.txCount7d || 0,
      profitUsd:   h.profitUsd || 0,
      firstBuy:    h.firstBuy || '?',
      lastActive:  h.lastActive || '?',
      solscanUrl:  explorerUrl(h.address, actualChain),
    }));

    // Build edges: cluster wallets of same type, link big holders to center
    const walletEdges = [];
    walletNodes.forEach((n, i) => {
      // Every node connects to center token
      walletEdges.push({ source: 'center', target: n.id, weight: n.supplyPct });
      // Cross-connections between same-type wallets
      walletNodes.slice(i + 1).forEach((m, j) => {
        if (n.type === m.type && n.type !== 'Liquidity') {
          walletEdges.push({ source: n.id, target: m.id, weight: Math.min(n.supplyPct, m.supplyPct) * 0.5 });
        }
      });
    });

    // AI summary based on real risk factors
    const sellRatio = (100 - parseFloat(merged.txns.buyRatio24h)).toFixed(0);
    const liqMcapPct = bestMcap > 0 ? (bestLiquidity / bestMcap * 100) : 0;
    const aiSummary = {
      confidence: Math.min(98, 60 + risk.score * 0.35),
      findings:   risk.factors.slice(0, 5),
      verdict: risk.score >= 75
        ? `Strong indicators of high-risk activity detected.${top10Pct != null ? ` Top 10 wallets control ${top10Pct.toFixed(1)}% of supply.` : ''} Sell ratio: ${sellRatio}%. Liquidity is ${liqMcapPct.toFixed(1)}% of market cap.`
        : risk.score >= 55
        ? `Moderate risk profile.${top10Pct != null ? ` Top 10 wallets hold ${top10Pct.toFixed(1)}%.` : ''} Monitor sell pressure (${sellRatio}% sells in 24h).`
        : `Lower risk profile detected. Token has ${merged.allPairs} active pair(s) with reasonable liquidity ratio of ${liqMcapPct.toFixed(1)}%. Standard caution applies.`,
    };

    const created  = merged.pairCreatedAt ? ageLabel(Date.now() - merged.pairCreatedAt) : 'Unknown';
    const ageDays  = merged.pairCreatedAt ? (Date.now() - merged.pairCreatedAt) / 86400000 : 99;
    const launchType = ageDays < 1 ? 'Stealth Launch' : ageDays < 7 ? 'New Launch' : 'Established';

    // Cache imageUrl so rate-limit fallbacks don't lose it
    if (merged.imageUrl) _wmc(`img:${contractAddress}`, merged.imageUrl);
    const cachedImg = _wmc(`img:${contractAddress}`);

    const response = {
      // ── Identity ──
      address:      contractAddress,
      contract:     contractAddress,
      chain:        actualChain,
      name:         merged.name,
      symbol:       merged.symbol,
      quoteSymbol:  dex?.quoteSymbol || null,
      network:      actualChain.charAt(0).toUpperCase() + actualChain.slice(1),
      dexId:        merged.dexId,
      pairAddress:  merged.pairAddress,
      gtPoolAddress: bestPool?.poolAddress || null,
      geckoNetwork:  actualGecko,
      dexUrl:       merged.url || '',
      imageUrl:     cachedImg || merged.imageUrl,
      headerUrl:    merged.headerUrl || null,
      websites:     merged.websites,
      socials:      merged.socials,
      labels:       merged.labels || [],
      verified:     !!(merged.name && merged.imageUrl),
      allPairs:     merged.allPairs,
      allPairsData: merged.allPairsData || [],

      // ── Price ──
      price:          merged.price,
      priceNative:    merged.priceNative || merged.price,
      priceChange5m:  merged.priceChange.m5,
      priceChange1h:  merged.priceChange.h1,
      priceChange6h:  merged.priceChange.h6,
      priceChange24h: merged.priceChange.h24,

      // ── Market ──
      marketCap:       merged.marketCap,
      fdv:             merged.fdv,
      liquidity:       merged.liquidity,
      liquidityBase:   merged.liquidityBase,
      liquidityQuote:  merged.liquidityQuote || 0,
      liquidityLocked: false,
      volume:          merged.volume,
      volume24h:       merged.volume.h24,

      // ── Transactions ──
      txns:      merged.txns,
      buys24h:   merged.txns.buys24h,
      sells24h:  merged.txns.sells24h,
      buyRatio:  merged.txns.buyRatio24h,

      // ── Holders ──
      potentialWallets: (() => {
        const seen = new Set();
        const all = [];
        // 0. Solana RPC real top holders (owner wallets from ATAs)
        for (const h of solanaTopHolders) {
          if (!h.address || seen.has(h.address)) continue;
          seen.add(h.address);
          all.push(h);
        }
        // 1. GoPlus real holders (top 20 with supply %)
        if (goplus?.holders?.length) {
          for (const h of goplus.holders) {
            if (!h.address || seen.has(h.address)) continue;
            seen.add(h.address);
            const pct = h.pct || 0;
            const type = h.isContract ? 'Contract' : pct > 5 ? 'Whale' : pct > 1 ? 'Top Holder' : 'Holder';
            all.push({
              address:    h.address,
              type,
              allocation: parseFloat(pct.toFixed(4)),
              riskScore:  pct > 5 ? 75 : pct > 1 ? 50 : 30,
              isRealData: true,
              tag:        h.tag || type,
              isContract: h.isContract,
              locked:     h.locked,
              activity:   [],
            });
          }
        }
        // 2. GoPlus creator
        if (goplus?.creatorAddress && !seen.has(goplus.creatorAddress)) {
          seen.add(goplus.creatorAddress);
          all.push({ address: goplus.creatorAddress, type: 'Insider', allocation: parseFloat((goplus.creatorPercent || 0).toFixed(4)), riskScore: 80, isRealData: true, tag: 'Creator', activity: [] });
        }
        // 3. GoPlus owner
        if (goplus?.ownerAddress && !seen.has(goplus.ownerAddress)) {
          seen.add(goplus.ownerAddress);
          all.push({ address: goplus.ownerAddress, type: 'Insider', allocation: parseFloat((goplus.ownerPercent || 0).toFixed(4)), riskScore: 70, isRealData: true, tag: 'Owner', activity: [] });
        }
        // 4. GoPlus LP holders
        for (const h of (goplus?.lpHolders || [])) {
          if (!h.address || seen.has(h.address)) continue;
          seen.add(h.address);
          all.push({ address: h.address, type: 'Liquidity', allocation: parseFloat((h.pct || 0).toFixed(4)), riskScore: 20, isRealData: true, tag: h.locked ? 'Locked LP' : 'LP Holder', activity: [], isLiqPool: true });
        }
        // 5. DexScreener pair wallets fallback
        for (const w of dexWallets) {
          if (!w.address || seen.has(w.address)) continue;
          seen.add(w.address);
          all.push(w);
        }
        return all.filter(w => w.address && w.isRealData);
      })(),
      holderDataSource: dexWallets.length ? 'ds-pairs' : (holderData?.source || 'none'),
      holders:     holderStats.total,
      holderStats,
      holderDistribution,
      totalSupply: totalSup,
      top10Pct,

      // ── Time ──
      created,
      pairCreatedAt: merged.pairCreatedAt,

      // ── Risk (computed from real data) ──
      riskScore:   risk.score,
      riskLevel:   risk.level,
      riskFactors: risk.factors,
      confidence:  parseFloat(aiSummary.confidence.toFixed(0)),

      // ── Security (GoPlus) ──
      security: goplus || {
        isHoneypot: false, honeypotReason: null,
        buyTax: 0, sellTax: 0,
        creatorAddress: null, creatorMalicious: false,
        isMintable: false, isFreezable: false, metadataMutable: false,
        isProxy: false, cannotBuy: false, isOpenSource: null,
        isTrusted: false, holderCount: 0,
        lpHolders: [], holders: [],
        chain: actualChain,
        _fallback: true,
      },

      // ── Analysis ──
      alerts,
      recentActivity,
      volumeProfile,
      aiSummary,

      // ── Launch info ──
      launchType,
      lpAddedTime:    'Shortly after launch',
      fundedBy:       'Unknown',
      similarRugs:    0,
      insiderAlloc:   parseFloat(((holderData?.teamPct || 0) + (holderData?.insiderPct || 0)).toFixed(2)),
      topWalletsHold: top10Pct != null ? parseFloat(top10Pct.toFixed(2)) : null,
      teamAlloc:      holderData?.holders?.filter(h=>h.type==='Team').reduce((s,h)=>s+h.allocation,0) || 0,

      // ── Charts ──
      candles,

      // ── Wallet map ──
      walletRelationships: {
        center:    shortAddr(contractAddress),
        nodes:     walletNodes,
        edges:     walletEdges,
        top10Pct:  holderData?.top10Pct || 0,
        teamPct:   holderData?.teamPct  || 0,
        source:    holderData?.source   || 'unknown',
      },
    };

    res.json({ success: true, data: response, source: 'live' });

    // Log for "Trending on Bloombark" (internal scan-activity signal).
    dbRun(
      'INSERT INTO token_activity_log (address, chain, symbol, name, `type`, ts) VALUES (?,?,?,?,?,?)',
      [response.address.toLowerCase(), response.chain, response.symbol, response.name, 'scan', Date.now()]
    ).catch(e => console.error('[trending-log] scan insert failed:', e.message));
  } catch (err) {
    console.error('Analyze error:', err.message);
    res.status(500).json({ error: 'Analysis failed', message: err.message });
  }
});

// ─── Resample 5m candles into a wider interval ────────────────────────────────
function resampleCandles(candles5m, intervalSecs) {
  if (!candles5m || candles5m.length === 0) return [];
  const buckets = new Map();
  for (const c of candles5m) {
    const bucketTime = Math.floor(c.time / intervalSecs) * intervalSecs;
    if (!buckets.has(bucketTime)) {
      buckets.set(bucketTime, { time: bucketTime, open: c.open, high: c.high, low: c.low, close: c.close, volume: c.volume || 0 });
    } else {
      const b = buckets.get(bucketTime);
      b.high   = Math.max(b.high, c.high);
      b.low    = Math.min(b.low,  c.low);
      b.close  = c.close;
      b.volume = (b.volume || 0) + (c.volume || 0);
    }
  }
  return Array.from(buckets.values()).sort((a,b) => a.time - b.time);
}

// ─── Recent Trades endpoint ─────────────────────────────────────────────────────
// Short-lived cache, keyed by pool+network+limit — the frontend polls this
// every 12s per open Trade page, and multiple users/tabs often watch the
// same pool at once. Collapsing those onto one upstream GeckoTerminal call
// per ~8s cuts real request volume without needing a different data source
// (checked — DexScreener's equivalent trade feed is Cloudflare-protected/
// undocumented). When GeckoTerminal has no data at all for a pool (e.g. it
// doesn't index the pool's DEX/launchpad — confirmed happening for pools on
// Robinhood chain's "Flap" launchpad, which return a plain 404), we fall
// back to reading Uniswap-V2-style Swap events directly from the chain via
// Blockscout's already-decoded logs endpoint + a couple of RPC eth_calls for
// token0/token1 ordering and decimals — see _fetchOnchainSwaps below.
const RECENT_TRADES_TTL = 8000;
const _recentTradesCache = new Map(); // key -> { data, at }
// Sweep stale entries periodically so this doesn't grow unbounded over the
// app's lifetime as more distinct pools get looked up.
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of _recentTradesCache) {
    if (now - entry.at > RECENT_TRADES_TTL) _recentTradesCache.delete(key);
  }
}, 60000);

function _tsToAgoStr(tsMs, nowMs) {
  const agoMs = nowMs - tsMs;
  return agoMs < 60000 ? `${Math.floor(agoMs/1000)}s ago`
    : agoMs < 3600000 ? `${Math.floor(agoMs/60000)}m ago`
    : `${Math.floor(agoMs/3600000)}h ago`;
}

// Uniswap-V2-style pair function selectors (token0/token1/decimals) — used
// only for the on-chain fallback path.
const _V2_TOKEN0_SEL  = '0x0dfe1681';
const _V2_TOKEN1_SEL  = '0xd21220a7';
const _ERC20_DEC_SEL  = '0x313ce567';

async function _ethCallWithRetry(rpcUrl, to, data, maxRetries = 1) {
  for (let attempt = 0; ; attempt++) {
    const r = await axios.post(rpcUrl,
      { jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] },
      { timeout: 8000, headers: { 'Content-Type': 'application/json', ...BLOCKSCOUT_AUTH_HEADERS } }
    ).catch(e => ({ __err: e }));
    if (!r.__err) return r.data?.result || '0x';
    if (r.__err.response?.status === 429 && attempt < maxRetries) {
      await new Promise(res => setTimeout(res, 800 * (attempt + 1)));
      continue;
    }
    return '0x';
  }
}

// token0/token1 ordering and decimals are immutable properties of a pool —
// once known they're cached forever, so a pool only ever pays the RPC cost
// on its very first lookup instead of on every 12s poll. This matters a lot
// on chains whose "RPC" is actually their block explorer proxy (Robinhood
// chain), which rate-limits a burst of eth_calls readily.
const _poolMetaCache = new Map(); // `${chain}:${pool}` -> { baseIsToken0, baseDecimals, quoteDecimals } | null (negative-cached)

async function _getPoolMeta(chain, rpcUrl, poolAddress, baseAddr) {
  const key = `${chain}:${poolAddress.toLowerCase()}`;
  if (_poolMetaCache.has(key)) return _poolMetaCache.get(key);

  // Sequential, spaced out — a burst of concurrent calls trips the shared
  // rate limit much more readily than the same calls a beat apart.
  const token0Hex = await _ethCallWithRetry(rpcUrl, poolAddress, _V2_TOKEN0_SEL);
  await new Promise(r => setTimeout(r, 300));
  const token1Hex = await _ethCallWithRetry(rpcUrl, poolAddress, _V2_TOKEN1_SEL);
  if (!token0Hex || token0Hex === '0x' || !token1Hex || token1Hex === '0x') return null; // not cached — genuinely transient, worth retrying next poll
  const token0 = '0x' + token0Hex.slice(-40);
  const token1 = '0x' + token1Hex.slice(-40);
  const baseIsToken0 = token0.toLowerCase() === baseAddr;
  if (!baseIsToken0 && token1.toLowerCase() !== baseAddr) {
    _poolMetaCache.set(key, null); // genuinely not a V2 pair holding this token — no point retrying
    return null;
  }

  await new Promise(r => setTimeout(r, 300));
  const dec0Hex = await _ethCallWithRetry(rpcUrl, token0, _ERC20_DEC_SEL);
  await new Promise(r => setTimeout(r, 300));
  const dec1Hex = await _ethCallWithRetry(rpcUrl, token1, _ERC20_DEC_SEL);
  const dec0 = dec0Hex && dec0Hex !== '0x' ? parseInt(dec0Hex, 16) : 18;
  const dec1 = dec1Hex && dec1Hex !== '0x' ? parseInt(dec1Hex, 16) : 18;

  const meta = { baseIsToken0, baseDecimals: baseIsToken0 ? dec0 : dec1, quoteDecimals: baseIsToken0 ? dec1 : dec0 };
  _poolMetaCache.set(key, meta);
  return meta;
}

// Fallback for pools GeckoTerminal doesn't index at all (404/empty) — reads
// Swap events straight from the chain via Blockscout's decoded logs, using
// DexScreener (which does index it — confirmed for Robinhood chain's Flap
// launchpad pools) purely to learn which side is base/quote and get a
// current quote-token USD rate. That current rate is applied to every swap
// in the batch rather than each swap's own historical rate, which is a fine
// approximation for a short list of genuinely recent trades but would drift
// for anything older.
async function _fetchOnchainSwaps(chain, poolAddress, limit) {
  const rpcUrl = RPC_URLS[chain];
  const blockscoutBase = BLOCKSCOUT_URLS[chain];
  if (!rpcUrl || !blockscoutBase) return [];

  const dsRes = await axios.get(`${DEXSCREENER}/latest/dex/pairs/${chain}/${poolAddress}`, { timeout: 8000 }).catch(() => null);
  const pair = dsRes?.data?.pairs?.[0];
  if (!pair) return [];
  const baseAddr = (pair.baseToken?.address || '').toLowerCase();
  const priceNative = parseFloat(pair.priceNative || 0);
  const quoteUsdPrice = priceNative > 0 ? parseFloat(pair.priceUsd || 0) / priceNative : 0;
  if (!baseAddr || !quoteUsdPrice) return [];

  const meta = await _getPoolMeta(chain, rpcUrl, poolAddress, baseAddr);
  if (!meta) return [];
  const { baseIsToken0, baseDecimals, quoteDecimals } = meta;

  const logsRes = await axios.get(`${blockscoutBase}/api/v2/addresses/${poolAddress}/logs?items_count=${Math.min(limit, 50)}`, { timeout: 10000, headers: BLOCKSCOUT_AUTH_HEADERS }).catch(() => null);
  const logs = (logsRes?.data?.items || []).filter(l => l.decoded?.method_call?.startsWith('Swap('));
  const nowMs = Date.now();

  return logs.map(log => {
    try {
      const p = Object.fromEntries((log.decoded.parameters || []).map(x => [x.name, x.value]));
      if (p.amount0In === undefined) return null; // not a V2-shaped Swap — skip rather than guess
      const amount0In  = BigInt(p.amount0In  || 0), amount1In  = BigInt(p.amount1In  || 0);
      const amount0Out = BigInt(p.amount0Out || 0), amount1Out = BigInt(p.amount1Out || 0);
      const baseOut  = baseIsToken0 ? amount0Out : amount1Out;
      const baseIn   = baseIsToken0 ? amount0In  : amount1In;
      const quoteIn  = baseIsToken0 ? amount1In  : amount0In;
      const quoteOut = baseIsToken0 ? amount1Out : amount0Out;
      const isBuy = baseOut > 0n;
      const baseAmountRaw  = isBuy ? baseOut : baseIn;
      const quoteAmountRaw = isBuy ? quoteIn : quoteOut;
      const amount = Number(baseAmountRaw) / Math.pow(10, baseDecimals);
      const quoteAmount = Number(quoteAmountRaw) / Math.pow(10, quoteDecimals);
      const volUsd = quoteAmount * quoteUsdPrice;
      if (!(amount > 0)) return null;
      const tsMs = log.block_timestamp ? new Date(log.block_timestamp).getTime() : nowMs;
      const wallet = p.to || p.sender || '';
      return {
        type: isBuy ? 'Buy' : 'Sell',
        isBuy,
        volUsd,
        priceUsd: volUsd / amount,
        amount,
        wallet: wallet ? shortAddr(wallet) : '—',
        walletFull: wallet,
        txHash: log.transaction_hash || '',
        time: _tsToAgoStr(tsMs, nowMs),
        timestamp: tsMs,
      };
    } catch (e) { return null; }
  }).filter(Boolean).sort((a, b) => b.timestamp - a.timestamp);
}

app.post('/api/recent-trades', async (req, res) => {
  try {
    const { poolAddress, network = 'eth', chain, limit: reqLimit } = req.body;
    if (!poolAddress) return res.json({ success: false, trades: [] });

    const cacheKey = `${network}:${poolAddress.toLowerCase()}:${reqLimit || 30}`;
    const cached = _recentTradesCache.get(cacheKey);
    if (cached && Date.now() - cached.at < RECENT_TRADES_TTL) {
      return res.json(cached.data);
    }

    const limit = Math.min(Math.max(parseInt(reqLimit) || 30, 1), 300);
    let trades = [];
    let geckoFailed = false;
    try {
      const url = `https://api.geckoterminal.com/api/v2/networks/${network}/pools/${poolAddress}/trades?limit=${limit}`;
      const { data } = await _geckoGetWithRetry(url, { timeout: 10000, headers: GECKO_HEADS });
      const raw = data?.data || [];
      const nowMs = Date.now();

      trades = raw.slice(0, limit).map(t => {
        const a       = t.attributes;
        const tsMs    = a.block_timestamp ? new Date(a.block_timestamp).getTime() : nowMs;
        const vol     = parseFloat(a.volume_in_usd || 0);
        const addr    = a.tx_from_address || '';
        // Execution price of the BASE token at trade time:
        // buy → base token is the "to" side; sell → base token is the "from" side
        const priceUsd = parseFloat(
          (a.kind === 'buy' ? a.price_to_in_usd : a.price_from_in_usd) || 0
        );
        // Base token amount traded
        const amount = parseFloat(
          (a.kind === 'buy' ? a.to_token_amount : a.from_token_amount) || 0
        );
        return {
          type:      a.kind === 'buy' ? 'Buy' : 'Sell',
          isBuy:     a.kind === 'buy',
          volUsd:    vol,
          priceUsd,
          amount,
          wallet:    addr ? shortAddr(addr) : '—',
          walletFull: addr,
          txHash:    a.tx_hash || '',
          time:      _tsToAgoStr(tsMs, nowMs),
          timestamp: tsMs,
        };
      });
    } catch (e) {
      trades = []; // 404/other — fall through to on-chain fallback below
      geckoFailed = true;
    }

    if (!trades.length && chain) {
      try { trades = await _fetchOnchainSwaps(chain, poolAddress, limit); }
      catch (e) { console.error('[recent-trades] onchain fallback failed:', e.message); }
    }

    const payload = { success: true, trades };
    // Don't cache a transient failure as if it were a confirmed "this pool
    // has no trades" — that would keep serving an empty result for the full
    // TTL even after the upstream hiccup passes, making the frontend's
    // recent-trades table look like it "disappeared" for several poll
    // cycles. Only cache empty results when Gecko actually responded (a
    // real 0-trade pool), not when it errored out.
    if (trades.length || !geckoFailed) {
      _recentTradesCache.set(cacheKey, { data: payload, at: Date.now() });
    }
    res.json(payload);
  } catch (e) {
    res.json({ success: false, trades: [], error: e.message });
  }
});

// ─── Candles endpoint ──────────────────────────────────────────────────────────
// interval: 5m | 15m | 1h | 4h
app.get('/api/candles/:contract', async (req, res) => {
  try {
    const contract   = req.params.contract;
    const uiInterval = req.query.interval || '5m';
    const createdAt  = req.query.createdAt ? parseInt(req.query.createdAt) : 0;
    const cutoffSec  = createdAt ? Math.floor(createdAt / 1000) : 0;
    const reqChain   = req.query.chain || 'auto';

    const INTERVAL_SECS = { '5m': 300, '15m': 900, '1h': 3600, '4h': 14400 };
    const DS_RES        = { '5m': '5',  '15m': '15', '1h': '60', '4h': '240' };
    const targetSecs    = INTERVAL_SECS[uiInterval] || 300;
    const dsRes         = DS_RES[uiInterval] || '5';

    const resolvedChain = (!reqChain || reqChain === 'auto') ? detectChainFromAddress(contract) : reqChain;
    const dsChainId     = DS_CHAIN[resolvedChain] || resolvedChain;

    // Get pair address + current USD price from DexScreener
    const dex = await fetchDexScreener(contract, dsChainId).catch(() => null);
    const pairAddress  = dex?.pairAddress || '';
    const currentPrice = dex?.price || 0;
    const actualChainId = dex?.chain || dsChainId;

    let base5m = null;
    let source = 'generated';

    if (pairAddress) {
      // Fetch directly at the requested resolution from DexScreener
      // Extend time window to get more history (7 days for 5m, 30 days for 1h/4h)
      const now  = Math.floor(Date.now() / 1000);
      const span = uiInterval === '5m'  ? 3 * 86400   // 3 days of 5m
                 : uiInterval === '15m' ? 7 * 86400   // 7 days of 15m
                 : uiInterval === '1h'  ? 30 * 86400  // 30 days of 1h
                 :                        90 * 86400;  // 90 days of 4h
      const from = now - span;

      const urls = [
        `${DS_CHART}/dex/chart/amm/v3/by-pair/${actualChainId}/${pairAddress}?from=${from}&to=${now}&res=${dsRes}`,
        `${DS_CHART}/dex/chart/amm/v2/by-pair/${actualChainId}/${pairAddress}?from=${from}&to=${now}&res=${dsRes}`,
        `${DS_CHART}/dex/chart/amm/by-pair/${actualChainId}/${pairAddress}?from=${from}&to=${now}&res=${dsRes}`,
      ];

      for (const url of urls) {
        try {
          const { data } = await axios.get(url, {
            timeout: 10000,
            headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json' },
          });
          const raw = data?.candles || data?.data?.candles || data?.ohlcv || [];
          if (raw.length > 2) {
            const parsed = raw.map(c => ({
              time:   Math.floor((c.t || c.time || c[0]) / ((c.t || c[0]) > 1e12 ? 1000 : 1)),
              open:   parseFloat(c.o || c.open  || c[1]),
              high:   parseFloat(c.h || c.high  || c[2]),
              low:    parseFloat(c.l || c.low   || c[3]),
              close:  parseFloat(c.c || c.close || c[4]),
              volume: parseFloat(c.v || c.volume|| c[5] || 0),
            })).filter(c => c.time > 0 && c.open > 0 && c.close > 0 && c.high > 0 && c.low > 0);

            if (parsed.length > 2) {
              // If prices are in native token (SOL), scale to USD
              const sorted = [...parsed].sort((a,b) => a.close - b.close);
              const medianClose = sorted[Math.floor(sorted.length / 2)]?.close || 0;
              if (currentPrice > 0 && medianClose > 0) {
                const ratio = currentPrice / medianClose;
                base5m = (ratio > 50 || ratio < 0.02)
                  ? parsed.map(c => ({ ...c, open: c.open*ratio, high: c.high*ratio, low: c.low*ratio, close: c.close*ratio }))
                  : parsed;
              } else {
                base5m = parsed;
              }
              source = 'dexscreener';
              console.log(`  DS candles: ${base5m.length} @ ${uiInterval} (${url.includes('v3')?'v3':url.includes('v2')?'v2':'v1'})`);
              break;
            }
          }
        } catch (_) {}
      }
    }

    // Fallback: generate candles from current USD price
    if (!base5m || base5m.length < 2) {
      console.log(`  Generated candles (no DS data), price=${currentPrice}`);
      base5m = generateCandles(currentPrice || 0.000001, 200);
      source = 'generated';
    }

    // Apply createdAt filter
    if (cutoffSec > 0) {
      base5m = base5m.filter(c => c.time >= cutoffSec);
    }

    // For non-5m intervals, resample from the raw DS data (DS may already return the right res,
    // but resample anyway to ensure uniform buckets)
    let candles = uiInterval === '5m' ? base5m : resampleCandles(base5m, targetSecs);
    if (!candles || candles.length < 2) candles = base5m;

    // Always drop the last candle — it's always the in-progress (partial) candle from DexScreener
    // and its close/high/low are unreliable. The frontend WebSocket live candle rebuilds it cleanly.
    if (candles.length > 2) {
      candles = candles.slice(0, -1);
    }

    res.json({
      success: true,
      data: candles,
      source,
      interval: uiInterval,
      candleCount: candles.length,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Token search endpoint ─────────────────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  try {
    const { q } = req.query;
    const { data } = await axios.get(`${DEXSCREENER}/latest/dex/search?q=${encodeURIComponent(q)}`, { timeout: 8000 });
    const tokens = (data.pairs || [])
      .filter(p => ['ethereum','base','arbitrum','robinhood'].includes(p.chainId))
      .slice(0, 10)
      .map(p => ({
        address: p.baseToken?.address,
        name:    p.baseToken?.name,
        symbol:  p.baseToken?.symbol,
        price:   p.priceUsd,
        change:  p.priceChange?.h24,
        volume:  p.volume?.h24,
        mcap:    p.marketCap,
      }));
    res.json({ success: true, data: tokens });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Trending tokens from DexScreener ─────────────────────────────────────────
// ─── Narrative Tracker ────────────────────────────────────────────────────────
const NARRATIVE_CATEGORIES = [
  { id: 'artificial-intelligence', label: 'AI & Machine Learning', icon: '🤖' },
  { id: 'meme-token',              label: 'Memecoins',             icon: '🐸' },
  { id: 'decentralized-finance-defi', label: 'DeFi',              icon: '🏦' },
  { id: 'real-world-assets-rwa',   label: 'Real World Assets',    icon: '🏛' },
  { id: 'depin',                   label: 'DePIN',                 icon: '📡' },
  { id: 'gaming',                  label: 'GameFi',                icon: '🎮' },
  { id: 'layer-2',                 label: 'Layer 2',               icon: '⚡' },
  { id: 'non-fungible-tokens-nft', label: 'NFT',                   icon: '🖼' },
  { id: 'socialfi',                label: 'SocialFi',              icon: '💬' },
  { id: 'liquid-staking',          label: 'Liquid Staking',        icon: '💧' },
  { id: 'restaking',               label: 'Restaking',             icon: '🔄' },
  { id: 'prediction-markets',      label: 'Prediction Markets',    icon: '🔮' },
  { id: 'metaverse',               label: 'Metaverse',             icon: '🌐' },
  { id: 'ai-meme-coins',           label: 'AI Memes',              icon: '🧠' },
  { id: 'base-meme-coins',         label: 'Base Memes',            icon: '🔵' },
];

let _narrativeCache = null;
let _narrativeCacheAt = 0;
let _narrativeFetching = false;
const NARRATIVE_TTL = (parseInt(process.env.NARRATIVE_TTL_MIN) || 60) * 60 * 1000; // default 1 hour

// Persist to app_config so a cold boot (Render free-tier spin-down/restart)
// can serve last-known data immediately instead of showing "Data loading"
// to every visitor until a fresh CoinGecko fetch completes.
async function _loadNarrativeCacheFromDb() {
  try {
    const row = await dbGet("SELECT value FROM app_config WHERE `key`='narrative_cache'");
    if (!row) return;
    const parsed = JSON.parse(row.value);
    if (Array.isArray(parsed?.data)) {
      _narrativeCache = parsed.data;
      _narrativeCacheAt = parsed.at || 0;
      console.log(`[narrative] restored ${_narrativeCache.length} categories from DB (age ${Math.round((Date.now()-_narrativeCacheAt)/60000)}min)`);
    }
  } catch (e) { console.error('[narrative] failed to restore from DB:', e.message); }
}

async function _saveNarrativeCacheToDb() {
  if (!_narrativeCache) return;
  try {
    const value = JSON.stringify({ data: _narrativeCache, at: _narrativeCacheAt });
    await dbRun(
      "INSERT INTO app_config (`key`, value, updated_at) VALUES ('narrative_cache',?,UNIX_TIMESTAMP()) ON DUPLICATE KEY UPDATE value=VALUES(value), updated_at=VALUES(updated_at)",
      [value]
    );
  } catch (e) { console.error('[narrative] failed to persist to DB:', e.message); }
}

async function _fetchNarrativeCounts(byId) {
  const countById = {};
  for (let i = 0; i < NARRATIVE_CATEGORIES.length; i++) {
    const n = NARRATIVE_CATEGORIES[i];
    try {
      const r = await axios.get(
        `https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&category=${n.id}&per_page=250&page=1`,
        { timeout: 12000 }
      );
      countById[n.id] = (Array.isArray(r.data) && !r.data?.status) ? r.data.length : 0;
    } catch { countById[n.id] = 0; }
    await new Promise(r => setTimeout(r, CONFIG.narrativeFetchDelayMs)); // rate-limit spacing
  }
  return countById;
}

async function _warmNarrative() {
  if (_narrativeFetching) return;
  _narrativeFetching = true;
  try {
    const { data } = await axios.get(
      'https://api.coingecko.com/api/v3/coins/categories?order=market_cap_desc',
      { timeout: 12000 }
    );
    const byId = {};
    for (const c of data) byId[c.id] = c;

    // Serve partial data immediately, then update with counts
    const partial = NARRATIVE_CATEGORIES.map(n => {
      const c = byId[n.id] || {};
      return { id:n.id, label:n.label, icon:n.icon, marketCap:c.market_cap||0, change24h:c.market_cap_change_24h||0, volume24h:c.volume_24h||0, topCoins:(c.top_3_coins||[]).slice(0,3), coinCount:0 };
    });
    if (!_narrativeCache) { _narrativeCache = partial; _narrativeCacheAt = Date.now(); }

    const countById = await _fetchNarrativeCounts(byId);
    _narrativeCache = partial.map(n => ({ ...n, coinCount: countById[n.id] || 0 }));
    _narrativeCacheAt = Date.now();
    const missing = _narrativeCache.filter(n => n.coinCount === 0).length;
    console.log(`[narrative] cache warmed — ${_narrativeCache.length - missing} counts ok, ${missing} missing`);
    await _saveNarrativeCacheToDb();

    // Retry missing counts after 10 minutes
    if (missing > 0) {
      setTimeout(async () => {
        try {
          for (const n of _narrativeCache.filter(n => n.coinCount === 0)) {
            try {
              const r = await axios.get(
                `https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&category=${n.id}&per_page=250&page=1`,
                { timeout: 12000 }
              );
              n.coinCount = (Array.isArray(r.data) && !r.data?.status) ? r.data.length : 0;
            } catch {}
            await new Promise(r => setTimeout(r, CONFIG.narrativeFetchDelayMs));
          }
          console.log('[narrative] retry counts done');
          await _saveNarrativeCacheToDb();
        } catch {}
      }, CONFIG.narrativeRetryDelayMs);
    }
  } catch (e) { console.error('[narrative warm]', e.message); }
  finally { _narrativeFetching = false; }
}

app.get('/api/narrative', async (req, res) => {
  try {
    if (_narrativeCache && Date.now() - _narrativeCacheAt < NARRATIVE_TTL) {
      return res.json({ success: true, data: _narrativeCache });
    }
    // Cache is stale or absent — kick a background refresh either way.
    _warmNarrative();
    // Stale data (e.g. restored from DB after a restart) is still useful —
    // serve it immediately rather than making every visitor wait/error out
    // while the background refresh runs.
    if (_narrativeCache) return res.json({ success: true, data: _narrativeCache, stale: true });
    // Truly no data yet (first-ever boot) — wait briefly for the warm to land.
    const _waitSteps = Math.ceil(CONFIG.narrativeWaitTimeoutMs / 1000);
    for (let i = 0; i < _waitSteps; i++) {
      await new Promise(r => setTimeout(r, 1000));
      if (_narrativeCache) return res.json({ success: true, data: _narrativeCache });
    }
    res.json({ success: false, error: 'Data loading, try again shortly' });
  } catch (e) {
    console.error('[narrative]', e.message);
    if (_narrativeCache) return res.json({ success: true, data: _narrativeCache });
    res.json({ success: false, error: e.message });
  }
});

// Pre-warm narrative on server start (background) — the DB-restored cache
// (loaded in initDb().then(), below) already covers most cold starts, so
// this just refreshes it if stale.
setTimeout(() => _warmNarrative(), CONFIG.narrativeWarmDelayMs);

app.get('/api/trending', async (req, res) => {
  try {
    // Use DexScreener boosted/trending endpoint
    const { data } = await axios.get(`${DEXSCREENER}/token-boosts/top/v1`, { timeout: 8000 });
    const tokens = (data || [])
      .filter(t => ['ethereum','base','arbitrum','robinhood'].includes(t.chainId))
      .slice(0, 5)
      .map(t => ({
        symbol:  t.description?.split(' ')[0] || t.tokenAddress?.slice(0,6),
        name:    t.description || 'Unknown',
        address: t.tokenAddress,
        risk:    randInt(30, 90),
        change:  parseFloat((rand(-20, 150)).toFixed(1)),
        volume:  rand(100000, 20000000),
        imageUrl: t.icon,
      }));
    if (tokens.length > 0) return res.json({ success: true, data: tokens });
    throw new Error('No trending data');
  } catch (_) {
    res.json({ success: true, data: [
      { symbol:'PEPE',  name:'Pepe',        address:'0x6982508145454Ce325dDbE47a25d4ec3d2311933', risk:65, change:12.3,  volume:18400000 },
      { symbol:'SHIB',  name:'Shiba Inu',   address:'0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE', risk:40, change:4.1,   volume:22100000 },
      { symbol:'BRETT', name:'Brett',       address:'0x532f27101965dd16442E59d40670FaF5eBB142E4', risk:58, change:9.8,   volume:9700000 },
      { symbol:'AERO',  name:'Aerodrome',   address:'0x940181a94A35A4569E4529A3CDfB74e38FD98631', risk:35, change:-3.2,  volume:6300000 },
      { symbol:'VIRTUAL', name:'Virtuals',  address:'0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b', risk:52, change:15.6,  volume:11200000 },
    ]});
  }
});

// ─── Market Overview: DexScreener only (trending/volume) — no GeckoTerminal calls ──
const DASH_CACHE_TTL = (parseInt(process.env.DASHBOARD_TTL_SEC) || 120) * 1000;  // default 2 minutes
const DASH_CHAINS    = ['ethereum', 'base', 'robinhood'];

// Cache per key: 'all' | 'ethereum' | 'base' | 'robinhood'
const _dashCaches   = {};
const _dashFetching = {};

const _dashChainLabel = id => ({ ethereum:'Ethereum', base:'Base', robinhood:'Robinhood' }[id] || id);
const SUPPORTED_DASH  = new Set(DASH_CHAINS);

// DexScreener search queries for All Chains trending + volume (parallel, no rate limit)
const DS_ALL_QUERIES = ['usdt','weth','usdc','pepe','wbtc','brett','aero','virtual','uni','link'];

// DexScreener token addresses per chain for per-chain view
// Token addresses per chain for DexScreener token queries
const DS_CHAIN_TOKENS = {
  ethereum: [
    '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',   // WETH
    '0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE',   // SHIB
    '0x6982508145454Ce325dDbE47a25d4ec3d2311933',   // PEPE
    '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',   // WBTC
    '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',   // UNI
    '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',   // USDC
    '0xdAC17F958D2ee523a2206206994597C13D831ec7',   // USDT
    '0x514910771AF9Ca656af840dff83E8264EcF986CA',   // LINK
    '0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE',   // AAVE
    '0xD533a949740bb3306d119CC777fa900bA034cd52',   // CRV
  ],
  base:     [
    '0x4200000000000000000000000000000000000006',   // WETH Base
    '0x532f27101965dd16442E59d40670FaF5eBB142E4',   // BRETT
    '0x940181a94A35A4569E4529A3CDfB74e38FD98631',   // AERO
    '0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf',   // cbBTC
    '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',   // USDC Base
    '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb',   // DAI Base
    '0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22',   // cbETH
    '0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b',   // VIRTUAL
  ],
  robinhood: [
    '0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73',   // WETH on Robinhood Chain
    '0xfB4729659eeF22Bfc1c2B680F6F873f8147aaaab',   // ROBIN
  ],
};

// Map a DexScreener pair to unified format
const _mapDS = p => {
  if (!p?.pairAddress) return null;
  const chainId = p.chainId || 'unknown';
  if (!SUPPORTED_DASH.has(chainId)) return null;
  return {
    name:          `${p.baseToken?.symbol || '?'} / ${p.quoteToken?.symbol || '?'}`,
    address:       p.baseToken?.address || '',
    pairAddress:   p.pairAddress,
    network:       _dashChainLabel(chainId),
    networkId:     chainId,
    price:         parseFloat(p.priceUsd || 0),
    priceChange24h:parseFloat(p.priceChange?.h24 || 0),
    volume24h:     parseFloat(p.volume?.h24 || 0),
    liquidity:     parseFloat(p.liquidity?.usd || 0),
    fdv:           parseFloat(p.fdv || p.marketCap || 0),
    createdAt:     p.pairCreatedAt ? new Date(p.pairCreatedAt).toISOString() : null,
    buys24h:       parseInt(p.txns?.h24?.buys  || 0),
    sells24h:      parseInt(p.txns?.h24?.sells || 0),
  };
};

// Compare addresses case-insensitively — DexScreener returns checksummed
// (mixed-case) addresses while GeckoTerminal returns lowercase, so the same
// pool from both sources needs normalizing or it slips past a strict === dedupe.
const _dedupe = arr => arr.filter((p, i, a) =>
  p && a.findIndex(x => x && x.pairAddress?.toLowerCase() === p.pairAddress?.toLowerCase() && x.networkId === p.networkId) === i
);

const _buildPayload = (dsPairs, chains) => {
  const pools  = _dedupe(dsPairs.filter(Boolean));

  // Backfill token age: DexScreener sometimes omits pairCreatedAt on the exact
  // (highest-volume) pair that lands in the list, while ANOTHER pool of the same
  // token has it. Use the earliest known creation time per token as its age so
  // rows like AERO/Base or VIRTUAL/Base don't show "-".
  const earliestByToken = {};
  for (const p of pools) {
    if (!p.createdAt) continue;
    const k = `${p.address?.toLowerCase()}_${p.networkId}`;
    const t = new Date(p.createdAt).getTime();
    if (!earliestByToken[k] || t < earliestByToken[k]) earliestByToken[k] = t;
  }
  for (const p of pools) {
    if (p.createdAt) continue;
    const k = `${p.address?.toLowerCase()}_${p.networkId}`;
    if (earliestByToken[k]) p.createdAt = new Date(earliestByToken[k]).toISOString();
  }

  const seenBV = new Set();
  const bestVolume = [...pools]
    .filter(p => p.volume24h > 0)
    .sort((a, b) => b.volume24h - a.volume24h)
    .filter(p => { const k = `${p.address}_${p.networkId}`; if (seenBV.has(k)) return false; seenBV.add(k); return true; })
    .slice(0, 200);

  const seenTR = new Set();
  const trending = [...pools]
    .filter(p => (p.buys24h + p.sells24h) > 0)
    .sort((a, b) => (b.buys24h + b.sells24h) - (a.buys24h + a.sells24h))
    .filter(p => { const k = `${p.address}_${p.networkId}`; if (seenTR.has(k)) return false; seenTR.add(k); return true; })
    .slice(0, 200);

  return { success: true, data: { bestVolume, trending, chains } };
};

const _dsGet = url => axios.get(url, { timeout: 8000 }).catch(() => null);

// Real "what's happening right now" pool data from GeckoTerminal's per-network
// endpoints (pools / trending_pools / new_pools) — one call per chain per
// endpoint kind. Failures (incl. 429) are swallowed so a Gecko hiccup never
// breaks the dashboard; it only means fewer fresh entries that refresh cycle.
// "uniswap-v3-robinhood" -> "Uniswap v3". The chain suffix is dropped because
// every row already carries a chain badge, and version stays lowercase since
// that's how these protocols brand themselves.
function _dexLabel(id) {
  if (!id) return '';
  return String(id).replace(/-[a-z0-9]+$/i, '').split('-')
    .map(p => /^v\d+$/i.test(p) ? p.toLowerCase() : p.charAt(0).toUpperCase() + p.slice(1))
    .join(' ');
}

async function _geckoPoolsList(chainId, kind = 'trending_pools') {
  const network = GECKO_NETWORK[chainId];
  if (!network) return [];
  try {
    const { data } = await axios.get(
      `https://api.geckoterminal.com/api/v2/networks/${network}/${kind}?limit=20&include=base_token,quote_token,dex`,
      { timeout: 8000, headers: GECKO_HEADS }
    );
    const included = {};
    for (const inc of data?.included || []) included[inc.id] = inc.attributes;
    return (data?.data || []).map(p => {
      const a = p.attributes || {};
      const baseTokenId  = p.relationships?.base_token?.data?.id;
      const quoteTokenId = p.relationships?.quote_token?.data?.id;
      const baseToken  = included[baseTokenId];
      const quoteToken = included[quoteTokenId];
      if (!a.address) return null;
      // One token routinely has several pools (different fee tiers, different
      // Uniswap versions, different quote token). Gecko encodes the fee tier as
      // a trailing suffix on a.name ("CASHCAT / WETH 1%"), and the DEX version
      // lives in the dex relationship — together they're the ONLY things that
      // tell those otherwise-identical-looking rows apart, so surface both
      // instead of dropping them.
      const feeTier = (String(a.name || '').match(/\s([\d.]+\s*%)\s*$/) || [])[1] || null;
      return {
        // Built from token symbols rather than a.name so the fee tier renders
        // as its own badge (see feeTier below) instead of running into the pair.
        name:           `${baseToken?.symbol || '?'} / ${quoteToken?.symbol || '?'}`,
        feeTier:        feeTier ? feeTier.replace(/\s+/g, '') : null,
        dex:            _dexLabel(p.relationships?.dex?.data?.id),
        address:        baseToken?.address || '',
        pairAddress:    a.address,
        network:        _dashChainLabel(chainId),
        networkId:      chainId,
        price:          parseFloat(a.base_token_price_usd || 0),
        priceChange24h: parseFloat(a.price_change_percentage?.h24 || 0),
        volume24h:      parseFloat(a.volume_usd?.h24 || 0),
        liquidity:      parseFloat(a.reserve_in_usd || 0),
        fdv:            parseFloat(a.fdv_usd || a.market_cap_usd || 0),
        createdAt:      a.pool_created_at || null,
        buys24h:        parseInt(a.transactions?.h24?.buys  || 0),
        sells24h:       parseInt(a.transactions?.h24?.sells || 0),
      };
    }).filter(Boolean);
  } catch (e) {
    console.error(`[market] gecko ${kind} failed [${chainId}]:`, e.message);
    return [];
  }
}
const _geckoTrendingPools = chainId => _geckoPoolsList(chainId, 'trending_pools');

async function _fetchDash(key) {
  if (_dashFetching[key]) return;
  _dashFetching[key] = true;
  try {
    let dsPairs = [];

    if (key === 'all') {
      // All Chains: DexScreener generic queries + Robinhood-specific queries (tokens differ from other chains),
      // plus one GeckoTerminal trending-pools call per chain so the list isn't just the same fixed tokens forever.
      const [generalRes, robinhoodRes, trendingRes] = await Promise.all([
        Promise.all(DS_ALL_QUERIES.map(q => _dsGet(`${DEXSCREENER}/latest/dex/search?q=${q}`))),
        Promise.all(['robin','cashcat','tendies','wood','home'].map(q => _dsGet(`${DEXSCREENER}/latest/dex/search?q=${q}&chainIds=robinhood`))),
        Promise.all(DASH_CHAINS.map(c => _geckoTrendingPools(c))),
      ]);
      dsPairs = [
        ...generalRes.flatMap(r => (r?.data?.pairs || []).map(_mapDS)),
        ...robinhoodRes.flatMap(r => (r?.data?.pairs || []).filter(p => p?.chainId === 'robinhood').map(_mapDS)),
        ...trendingRes.flat(),
      ];
    } else {
      // Per-chain: DS token addresses + DS searches filtered to chain, plus
      // GeckoTerminal trending pools for real day-to-day variety.
      const addrs   = DS_CHAIN_TOKENS[key] || [];
      const chainSearches = {
        ethereum:  ['weth','pepe','shib','uni','link','aave','crv','mkr'],
        base:      ['base','brett','aero','cbbtc','virtual'],
        robinhood: ['robin','cashcat','tendies','wood','home'],
      }[key] || [];

      const [dsAddrRes, dsSearchRes, trending] = await Promise.all([
        Promise.all(addrs.map(a => _dsGet(`${DEXSCREENER}/latest/dex/tokens/${a}`))),
        Promise.all(chainSearches.map(q => _dsGet(`${DEXSCREENER}/latest/dex/search?q=${q}&chainIds=${key}`))),
        _geckoTrendingPools(key),
      ]);
      dsPairs  = [
        ...dsAddrRes.flatMap(r => (r?.data?.pairs || []).filter(p => p?.chainId === key).map(_mapDS)),
        ...dsSearchRes.flatMap(r => (r?.data?.pairs || []).filter(p => p?.chainId === key).map(_mapDS)),
        ...trending,
      ].filter(p => p && p.networkId === key);
    }

    const payload = _buildPayload(dsPairs, key === 'all' ? DASH_CHAINS : [key]);
    const hasData = payload.data.bestVolume.length > 0 || payload.data.trending.length > 0;
    if (hasData) {
      _dashCaches[key] = { payload, at: Date.now() };
      console.log(`[dash:${key}] BV=${payload.data.bestVolume.length} TR=${payload.data.trending.length}`);
    } else {
      // Cache empty result to avoid repeated 503s for chains not yet indexed
      _dashCaches[key] = { payload: { ...payload, empty: true }, at: Date.now() };
      console.log(`[dash:${key}] no data available (chain may not be indexed yet)`);
    }
  } catch (e) {
    console.error(`Dashboard fetch error [${key}]:`, e.message);
  } finally {
    _dashFetching[key] = false;
  }
}

// Derive a single-chain view by filtering the reliably-warmed 'all' dataset.
// The old approach did a separate per-chain DexScreener fetch using
// `&chainIds=<chain>`, but DexScreener now ignores that filter, so those fetches
// frequently came back empty and got cached as "chain not yet indexed" for the
// full TTL (per-chain caches were never re-warmed). The 'all' dataset already
// contains every supported chain, so filtering it is both reliable and cheaper.
function _deriveChainPayload(key) {
  const all = _dashCaches['all'];
  if (!all) return null;
  const d = all.payload.data || { bestVolume: [], trending: [] };
  return {
    success: true,
    data: {
      bestVolume: d.bestVolume.filter(p => p.networkId === key),
      trending:   d.trending.filter(p => p.networkId === key),
      chains:     [key],
    },
  };
}

app.get('/api/dashboard', async (req, res) => {
  const key = DASH_CHAINS.includes(req.query.chain) ? req.query.chain : 'all';

  // 'all' is the single source of truth for every view — make sure it's warm.
  const allCached = _dashCaches['all'];
  if (!allCached || Date.now() - allCached.at >= DASH_CACHE_TTL) _fetchDash('all');

  // Wait briefly for 'all' on a cold start.
  const deadline = Date.now() + 15000;
  while (!_dashCaches['all'] && Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 300));
  }
  if (!_dashCaches['all']) {
    return res.status(503).json({ error: 'Dashboard data not yet available, please retry' });
  }

  if (key === 'all') return res.json(_dashCaches['all'].payload);

  // Per-chain: filter the 'all' dataset. Empty here means that chain genuinely
  // has no pools in the current set (rare) — not a failed/rate-limited fetch.
  const payload = _deriveChainPayload(key);
  const hasData = payload.data.bestVolume.length > 0 || payload.data.trending.length > 0;
  return res.json(hasData ? payload : { ...payload, empty: true });
});

// ─── Generic app_config-backed cache persistence — same pattern as the
// narrative cache above, reused for Market Overview's three data sources
// (chain volume, chain transactions, market tabs) so a cold boot (Render
// free-tier spin-down/restart) serves last-known-good data immediately
// instead of an empty state, and gets replaced the moment fresh data lands.
async function _saveGenericCacheToDb(configKey, value) {
  try {
    await dbRun(
      "INSERT INTO app_config (`key`, value, updated_at) VALUES (?,?,UNIX_TIMESTAMP()) ON DUPLICATE KEY UPDATE value=VALUES(value), updated_at=VALUES(updated_at)",
      [configKey, JSON.stringify(value)]
    );
  } catch (e) { console.error(`[cache-persist] failed to save ${configKey}:`, e.message); }
}
async function _loadGenericCacheFromDb(configKey) {
  try {
    const row = await dbGet('SELECT value FROM app_config WHERE `key`=?', [configKey]);
    return row ? JSON.parse(row.value) : null;
  } catch (e) { console.error(`[cache-persist] failed to load ${configKey}:`, e.message); return null; }
}

// ─── Chain-level DEX volume (DefiLlama) ─────────────────────────────────────
// DexScreener/GeckoTerminal are pool/token-centric — neither exposes a total
// "volume across this whole chain" figure. DefiLlama's dexs overview does.
const CHAIN_VOLUME_TTL = 10 * 60 * 1000; // 10 min — this doesn't need to be second-fresh
const CHAIN_VOLUME_LLAMA_ID = { ethereum: 'ethereum', base: 'base', robinhood: 'robinhood' };
let _chainVolumeCache = { data: null, at: 0 };

async function _fetchChainVolumes() {
  const entries = await Promise.all(Object.entries(CHAIN_VOLUME_LLAMA_ID).map(async ([key, llamaId]) => {
    try {
      const { data } = await axios.get(
        `https://api.llama.fi/overview/dexs/${llamaId}?excludeTotalDataChart=true&excludeTotalDataChartBreakdown=true`,
        { timeout: 10000 }
      );
      return [key, { volume24h: data?.total24h || 0, volume7d: data?.total7d || 0, change24h: data?.change_1d ?? null }];
    } catch (e) {
      console.error(`[chain-volume] ${key} failed:`, e.message);
      return [key, null];
    }
  }));
  return Object.fromEntries(entries);
}

app.get('/api/chain-volumes', async (req, res) => {
  const enabledChains = await _getEnabledChains();
  let data;
  if (_chainVolumeCache.data && Date.now() - _chainVolumeCache.at < CHAIN_VOLUME_TTL) {
    data = _chainVolumeCache.data;
  } else {
    data = await _fetchChainVolumes();
    _chainVolumeCache = { data, at: Date.now() };
    _saveGenericCacheToDb('market_chain_volume_cache', _chainVolumeCache);
  }
  // Only surface chains that are actually turned on (default: Robinhood only).
  const filtered = Object.fromEntries(Object.entries(data).filter(([k]) => enabledChains.includes(k)));
  res.json({ success: true, data: filtered });
});

// ─── Chain-level transaction activity (Blockscout) — network-wide tx count,
// not DEX-specific. Every chain we support already has a Blockscout instance
// (chainCfg(...).blockscout), and its /api/v2/stats endpoint is standardized
// across instances since it's the same open-source explorer software. ──────
const CHAIN_TX_TTL = 10 * 60 * 1000;
let _chainTxCache = { data: null, at: 0 };

let _chainTxLastErrors = {}; // temporary debug aid — key: chain, value: last fetch error message

async function _fetchChainTransactions() {
  const chains = Object.keys(CHAIN_NETWORKS);
  const entries = await Promise.all(chains.map(async (key) => {
    try {
      const base = chainCfg(key).blockscout;
      if (!base) { _chainTxLastErrors[key] = 'no blockscout base URL configured'; return [key, null]; }
      const { data } = await axios.get(`${base}/api/v2/stats`, { timeout: 10000, headers: BLOCKSCOUT_AUTH_HEADERS });
      delete _chainTxLastErrors[key];
      return [key, {
        transactionsToday: parseInt(data?.transactions_today || 0),
        totalTransactions: parseInt(data?.total_transactions || 0),
        gasPriceGwei: data?.gas_prices ? {
          slow: parseFloat(data.gas_prices.slow) || null,
          average: parseFloat(data.gas_prices.average) || null,
          fast: parseFloat(data.gas_prices.fast) || null,
        } : null,
      }];
    } catch (e) {
      const msg = e.response ? `HTTP ${e.response.status}: ${JSON.stringify(e.response.data)}` : e.message;
      _chainTxLastErrors[key] = msg;
      console.error(`[chain-tx] ${key} failed:`, msg);
      return [key, null];
    }
  }));
  return Object.fromEntries(entries);
}

app.get('/api/chain-transactions', async (req, res) => {
  const enabledChains = await _getEnabledChains();
  let data;
  if (req.query.debug === '1') {
    // Bypass cache entirely so the errors reflect this exact request.
    data = await _fetchChainTransactions();
  } else if (_chainTxCache.data && Date.now() - _chainTxCache.at < CHAIN_TX_TTL) {
    data = _chainTxCache.data;
  } else {
    data = await _fetchChainTransactions();
    _chainTxCache = { data, at: Date.now() };
    _saveGenericCacheToDb('market_chain_tx_cache', _chainTxCache);
  }
  const filtered = Object.fromEntries(Object.entries(data).filter(([k, v]) => enabledChains.includes(k) && v));
  const payload = { success: true, data: filtered };
  if (req.query.debug === '1') payload._debug = { enabledChains, rawKeys: Object.keys(data), errors: _chainTxLastErrors };
  res.json(payload);
});

// ─── Market Overview tabs (Robinhood-chain launch view): Pools, Trending,
// Top Gainers, New Pools — all sourced from GeckoTerminal's per-network
// endpoints (GeckoTerminal has no native "gainers" endpoint, so that tab is
// derived by sorting the trending-pools set by 24h price change instead).
//
// Switching tabs just serves whatever's already cached (instant, no live
// Gecko call) — the frontend's Refresh button is what triggers an actual
// fetch (?refresh=1). A background timer also keeps the cache warm every
// 2 minutes so there's real "last updated" data even before anyone hits
// Refresh themselves.
const MARKET_TAB_KINDS = { pools: 'pools', trending: 'trending_pools', 'new-pools': 'new_pools' };
const MARKET_TABS = ['pools', 'trending', 'gainers', 'new-pools'];
const MARKET_WARM_INTERVAL = 2 * 60 * 1000;
const _marketTabCache = new Map(); // `${chain}:${tab}` -> { data, at }

async function _fetchMarketTab(chain, tab) {
  let rows = tab === 'gainers'
    ? (await _geckoPoolsList(chain, 'trending_pools')).sort((a, b) => b.priceChange24h - a.priceChange24h)
    : await _geckoPoolsList(chain, MARKET_TAB_KINDS[tab]);
  rows = rows.slice(0, 30);
  const cacheKey = `${chain}:${tab}`;
  // Only cache real results — a transient Gecko failure/rate-limit returns an
  // empty list, and caching THAT would show "no data" until the next refresh.
  // Keep serving the last known-good data in that case instead.
  if (rows.length > 0) {
    _marketTabCache.set(cacheKey, { data: rows, at: Date.now() });
    _saveGenericCacheToDb('market_tab_cache', Object.fromEntries(_marketTabCache));
  }
  return _marketTabCache.get(cacheKey) || { data: rows, at: Date.now() };
}

app.get('/api/market/:tab', async (req, res) => {
  const tab = req.params.tab;
  if (!MARKET_TABS.includes(tab)) {
    return res.status(400).json({ error: 'tab must be one of ' + MARKET_TABS.join(', ') });
  }
  const enabledChains = await _getEnabledChains();
  const chain = enabledChains.includes(req.query.chain) ? req.query.chain : (enabledChains[0] || 'robinhood');
  const cacheKey = `${chain}:${tab}`;

  if (!req.query.refresh) {
    const cached = _marketTabCache.get(cacheKey);
    if (cached) return res.json({ success: true, chain, data: cached.data, lastUpdated: cached.at });
    // Nothing cached yet (first-ever request for this tab/chain) — fetch once.
  }

  const entry = await _fetchMarketTab(chain, tab);
  res.json({ success: true, chain, data: entry.data, lastUpdated: entry.at });
});

// Keep all 4 tabs warm in the background for the primary enabled chain, so
// there's always real "last updated" data ready without anyone needing to
// hit Refresh first.
async function _warmMarketTabs() {
  const enabledChains = await _getEnabledChains();
  const chain = enabledChains[0] || 'robinhood';
  for (const tab of MARKET_TABS) {
    await _fetchMarketTab(chain, tab).catch(() => {});
  }
}
setTimeout(_warmMarketTabs, CONFIG.dashWarmDelayMs);
setInterval(_warmMarketTabs, MARKET_WARM_INTERVAL);

// Pre-warm "all" on startup and keep it fresh; per-chain views derive from it.
setTimeout(() => _fetchDash('all'), CONFIG.dashWarmDelayMs);
setInterval(() => _fetchDash('all'), DASH_CACHE_TTL);

// ─── WebSocket: realtime price ticks + community chat ─────────────────────────
const subscribers = new Map();

// Chat state
const chatRooms = {
  general:  { name: 'General',   icon: '💬', messages: [] },
  trading:  { name: 'Trading',   icon: '📈', messages: [] },
  alpha:    { name: 'Alpha',     icon: '🔥', messages: [] },
  freeshill:{ name: 'Free Shill',icon: '📣', messages: [] },
  holders:  { name: 'Holders',   icon: '💎', messages: [] },
  private:  { name: 'Private',   icon: '🔐', messages: [] },
  // Read-only BloomBuy feed — no user can post here, enforced below in chat_msg.
  moon:     { name: '$BBRK Moon',icon: '🚀', messages: [], readOnly: true },
};
const MAX_CHAT_HISTORY = CONFIG.chatHistoryLimit;
const chatUsers = new Map(); // ws -> { wallet, displayName, joinedAt }

// Only Bloombot auto-replies to contract addresses posted in this room.
const BOT_REPLY_ROOM = process.env.CHAT_BOT_ROOM || 'freeshill';

// ─── Token-gated channels (parameterized via config / env) ────────────────────
// Two gate kinds:
//  - 'balance' (default): unlocks when the wallet holds >= minAmount of a
//    token (or native coin, if `token` is unset) on `chain`, re-checked live.
//  - 'paid': unlocks permanently once a one-time payment of `amountEth` ETH
//    to `treasury` on `chain` is verified on-chain (see /api/community/pay-verify).
const CHANNEL_GATES = {
  holders: {
    kind:      'balance',
    chain:     process.env.HOLDERS_GATE_CHAIN  || 'ethereum',
    // USD-value mode: token is resolved live from app_config.contract_address
    // (the same $BBRK CA the landing page and BloomBuy use) and minAmount is
    // recomputed from minUsd / live price on every check, so the required
    // token quantity tracks price instead of being a fixed amount.
    usdMode:   true,
    minUsd:    parseFloat(process.env.HOLDERS_GATE_MIN_USD || '90'),
  },
  private: {
    kind:      'paid',
    chain:     process.env.PRIVATE_GATE_CHAIN    || 'robinhood',
    treasury:  process.env.PRIVATE_GATE_TREASURY || '0xf6a2b3016c7ac86724fa71cd4b3946facb319caa',
    amountEth: parseFloat(process.env.PRIVATE_GATE_AMOUNT_ETH || '0.05'),
    symbol:    'ETH',
  },
};
const _gateCache = new Map(); // `${room}:${wallet}` -> { val, ts }

async function _ethCall(rpcUrl, to, data) {
  // Some chains' "RPC" is actually proxied through their block explorer (e.g.
  // Robinhood chain's rpc IS robinhoodchain.blockscout.com) and shares that
  // explorer's own rate limit — a burst of calls trips a 429 easily. Treat
  // any failure the same as "no data" (both existing callers already handle
  // a falsy/'0x' result gracefully) rather than throwing and killing whatever
  // Promise.all it's part of.
  try {
    const r = await axios.post(rpcUrl,
      { jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] },
      { timeout: 8000, headers: { 'Content-Type': 'application/json', ...BLOCKSCOUT_AUTH_HEADERS } });
    return r.data?.result || '0x';
  } catch (e) {
    return '0x';
  }
}

async function _nativeBalanceOnChain(rpcUrl, wallet) {
  const r = await axios.post(rpcUrl,
    { jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [wallet, 'latest'] },
    { timeout: 8000, headers: { 'Content-Type': 'application/json' } });
  const hex = r.data?.result || '0x0';
  return Number(BigInt(hex)) / 1e18;
}

// ERC-20 balanceOf(wallet) → human-readable amount (auto-fetches decimals)
async function _erc20BalanceOf(rpcUrl, token, wallet) {
  const balData = '0x70a08231' + wallet.toLowerCase().replace('0x', '').padStart(64, '0');
  const [balHex, decHex] = await Promise.all([
    _ethCall(rpcUrl, token, balData),
    _ethCall(rpcUrl, token, '0x313ce567'), // decimals()
  ]);
  const decimals = (decHex && decHex !== '0x') ? parseInt(decHex, 16) : 18;
  const raw = (balHex && balHex !== '0x') ? BigInt(balHex) : 0n;
  return Number(raw) / Math.pow(10, decimals);
}

const _isAddr = a => typeof a === 'string' && /^0x[0-9a-fA-F]{40}$/.test(a);

// Resolves the live token+price basis for a USD-value gate: reads the same
// contract_address the landing page / BloomBuy use, then looks up its price
// on DexScreener. Cached 5 minutes — this is a balance-check hot path, not
// worth hitting DexScreener on every single gate check.
const HOLDERS_GATE_EVM_CHAINS = new Set(['ethereum', 'base', 'arbitrum', 'robinhood']);

let _holdersGateBasis   = null;
let _holdersGateBasisAt = 0;
async function _resolveHoldersGateUsdBasis() {
  if (_holdersGateBasis && Date.now() - _holdersGateBasisAt < 5 * 60 * 1000) return _holdersGateBasis;
  try {
    const [caRow, tickerRow] = await Promise.all([
      dbGet("SELECT value FROM app_config WHERE `key`='contract_address'"),
      dbGet("SELECT value FROM app_config WHERE `key`='token_ticker'"),
    ]);
    const addr = caRow?.value || '';
    if (!_isAddr(addr)) { _holdersGateBasis = null; _holdersGateBasisAt = Date.now(); return null; }
    const { data } = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${addr}`, { timeout: 8000 });
    // Don't assume a fixed chain — pick the highest-liquidity pool across
    // whichever supported EVM chain the token actually trades on (same
    // pattern BloomBuy uses), so this works regardless of where $BBRK launches.
    const pairs = (data?.pairs || [])
      .filter(p => HOLDERS_GATE_EVM_CHAINS.has(p.chainId))
      .sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
    if (!pairs.length) { _holdersGateBasis = null; _holdersGateBasisAt = Date.now(); return null; }
    const p = pairs[0];
    _holdersGateBasis = {
      token:  p.baseToken?.address || addr,
      chain:  p.chainId,
      // Use the app's own ticker (same one the landing page shows) rather
      // than the on-chain symbol, so the gate always reads "$BBRK"-style.
      symbol: '$' + (tickerRow?.value || p.baseToken?.symbol || 'TOKEN'),
      price:  parseFloat(p.priceUsd || 0),
    };
    _holdersGateBasisAt = Date.now();
    return _holdersGateBasis;
  } catch (e) {
    console.error('[holders-gate] price resolve failed:', e.message);
    return _holdersGateBasis; // serve last known-good rather than locking everyone out on a hiccup
  }
}

// Returns { gated, ok, kind, ... } — shape varies slightly by gate kind (see below).
async function checkChannelGate(room, wallet) {
  const gate = CHANNEL_GATES[room];
  if (!gate) return { gated: false, ok: true };
  // Admin wallets bypass every paywall/holder gate — no need to actually buy
  // in or hold $BBRK to access Holders/Private for moderation purposes.
  if (isAdminWallet(wallet)) return { gated: true, kind: gate.kind, ok: true, isAdminBypass: true };
  const cfg     = chainCfg(gate.chain);
  const network = cfg.name || (gate.chain.charAt(0).toUpperCase() + gate.chain.slice(1));

  // ── Paid gate: one-time on-chain payment, checked against our own DB ──────
  if (gate.kind === 'paid') {
    const base = { gated: true, kind: 'paid', amountEth: gate.amountEth, symbol: gate.symbol, treasury: gate.treasury, network, chainKey: gate.chain };
    if (!wallet || !_isAddr(wallet)) return { ...base, ok: false, reason: 'no_wallet' };
    const paid = await dbGet('SELECT id FROM channel_payments WHERE room=? AND wallet=?', [room, wallet.toLowerCase()]);
    return { ...base, ok: !!paid };
  }

  // ── USD-value balance gate: token + price resolved live, so the required
  //    quantity always represents a fixed USD amount rather than a fixed
  //    token count that drifts out of sync with price. ─────────────────────
  if (gate.kind === 'balance' && gate.usdMode) {
    const basis = await _resolveHoldersGateUsdBasis();
    if (!basis || !(basis.price > 0)) {
      return { gated: true, kind: 'balance', minAmount: null, minUsd: gate.minUsd, symbol: basis?.symbol || 'TOKEN', token: null, network, ok: false, balance: 0, reason: 'token_not_live' };
    }
    // Chain is whatever the resolved token actually trades on, not a fixed config.
    const basisCfg     = chainCfg(basis.chain);
    const basisNetwork = basisCfg.name || (basis.chain.charAt(0).toUpperCase() + basis.chain.slice(1));
    const minAmount = gate.minUsd / basis.price;
    const base = { gated: true, kind: 'balance', minAmount, minUsd: gate.minUsd, symbol: basis.symbol, token: basis.token, network: basisNetwork };
    if (!wallet || !_isAddr(wallet)) return { ...base, ok: false, balance: 0, reason: 'no_wallet' };
    const key = `${room}:${wallet.toLowerCase()}`;
    const cached = _gateCache.get(key);
    if (cached && Date.now() - cached.ts < CONFIG.gateCacheTtlMs) return cached.val;
    let balance = 0;
    try { balance = await _erc20BalanceOf(basisCfg.rpc, basis.token, wallet); } catch (_) {}
    const val = { ...base, ok: balance >= minAmount, balance };
    _gateCache.set(key, { val, ts: Date.now() });
    return val;
  }

  // ── Balance gate: live on-chain balance check (existing fixed-amount behavior) ──
  const isToken = _isAddr(gate.token);
  const symbol  = gate.symbol || (isToken ? 'TOKEN' : 'ETH'); // native coin symbol default
  const base = { gated: true, kind: 'balance', minAmount: gate.minAmount, symbol, token: isToken ? gate.token : null, network };

  if (!wallet || !_isAddr(wallet)) {
    return { ...base, ok: false, balance: 0, reason: 'no_wallet' };
  }
  const key = `${room}:${wallet.toLowerCase()}`;
  const cached = _gateCache.get(key);
  if (cached && Date.now() - cached.ts < CONFIG.gateCacheTtlMs) return cached.val;

  let balance = 0;
  try {
    balance = isToken
      ? await _erc20BalanceOf(cfg.rpc, gate.token, wallet)
      : await _nativeBalanceOnChain(cfg.rpc, wallet);
  } catch (_) {}
  const val = { ...base, ok: balance >= gate.minAmount, balance };
  _gateCache.set(key, { val, ts: Date.now() });
  return val;
}

// Verify a payment tx on-chain and, if valid, permanently unlock a paid room
// for that wallet. tx_hash is UNIQUE in the DB so a tx can't be replayed to
// credit multiple times (though it would just be a harmless no-op re-insert).
app.post('/api/community/pay-verify', async (req, res) => {
  const { wallet, room, txHash } = req.body || {};
  const gate = CHANNEL_GATES[room];
  if (!gate || gate.kind !== 'paid') return res.status(400).json({ error: 'not a paid channel' });
  if (!_isAddr(wallet)) return res.status(400).json({ error: 'invalid wallet' });
  if (typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return res.status(400).json({ error: 'invalid tx hash' });

  try {
    const cfg = chainCfg(gate.chain);
    const [txRes, receiptRes] = await Promise.all([
      axios.post(cfg.rpc, { jsonrpc:'2.0', id:1, method:'eth_getTransactionByHash', params:[txHash] }, { timeout: 10000 }),
      axios.post(cfg.rpc, { jsonrpc:'2.0', id:1, method:'eth_getTransactionReceipt', params:[txHash] }, { timeout: 10000 }),
    ]);
    const tx      = txRes.data?.result;
    const receipt = receiptRes.data?.result;
    if (!tx || !receipt) return res.status(400).json({ ok: false, error: 'Transaction not found (may still be pending — try again shortly)' });
    if (receipt.status !== '0x1') return res.status(400).json({ ok: false, error: 'Transaction failed on-chain' });
    if (String(tx.from).toLowerCase() !== wallet.toLowerCase()) return res.status(400).json({ ok: false, error: 'Transaction sender does not match wallet' });
    if (String(tx.to).toLowerCase() !== gate.treasury.toLowerCase()) return res.status(400).json({ ok: false, error: 'Transaction was not sent to the treasury address' });
    const valueEth = Number(BigInt(tx.value || '0x0')) / 1e18;
    if (valueEth < gate.amountEth - 1e-9) return res.status(400).json({ ok: false, error: `Payment too low — sent ${valueEth} ETH, need ${gate.amountEth} ETH` });

    await dbRun(
      `INSERT IGNORE INTO channel_payments (wallet, room, tx_hash, amount_eth) VALUES (?,?,?,?)`,
      [wallet.toLowerCase(), room, txHash.toLowerCase(), valueEth]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Gate status for all gated rooms — used by the frontend to lock/unlock the UI
app.get('/api/community/gate/:wallet', async (req, res) => {
  const wallet = req.params.wallet === 'none' ? null : req.params.wallet;
  const out = {};
  for (const room of Object.keys(CHANNEL_GATES)) {
    out[room] = await checkChannelGate(room, wallet);
  }
  res.json({ gates: out });
});

function broadcastChat(room, payload) {
  wss.clients.forEach(c => {
    if (c.readyState === WebSocket.OPEN && chatUsers.has(c)) {
      c.send(JSON.stringify(payload));
    }
  });
}

function onlineCount() { return chatUsers.size; }

function shortAddr(addr) {
  if (!addr) return 'Anon';
  if (addr.length < 12) return addr;
  return addr.slice(0, 4) + '...' + addr.slice(-4);
}

// ─── Bloombark Chat Bot: auto-analyzes contract addresses posted in chat ─────
const BOT_NAME = 'BloomBot';
// Same lockup used for the sidebar/favicon — served by the frontend static
// root, resolved by the browser against the page's own origin (not this
// API's), so a root-relative path works regardless of where this backend
// is hosted.
const BOT_AVATAR = '/assets/brand/logo.png';
const BOT_CHAINS = new Set(['ethereum', 'base', 'arbitrum', 'polygon', 'optimism', 'robinhood']);
const _botCooldown = new Map(); // ca -> last reply ts (avoid spamming same CA)

// ─── BloomBuy: posts a card to $BBRK Moon for every on-chain BUY (sells skipped) ──
// Uses the same Bloombark logo avatar as BloomBot — same brand identity, just a
// different bot name for the different feed.
// Inline base64 copy of the same logo, used ONLY inside _botSvgCard's SVG
// header — an <image> tag nested inside an SVG that itself gets embedded via
// <img src="data:image/svg+xml;base64,..."> does not reliably resolve a
// root-relative or even same-origin URL (browsers treat img-embedded SVGs as
// an isolated image context), so that nested reference needs the image
// bytes inlined directly rather than pointing at BOT_AVATAR's path.
const BOT_AVATAR_INLINE = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAABI5ElEQVR42u29ebxkVXUv/l1rn1NVd+55YuhmkKHbKNgIKsjtVlBUlGisNhoTNRhRw1OjL3kSDdVXk2h8v8TpicEZNYmvK6LyGIyg3RcVEV8rin0FJEA3dDc99x1rOHuv9ftj733OuR3ye3k/oO0m1OdT3VWnqk7VPXvtNX7XdwFP3Z66PXV76vbU7T/pjZ66BP+ha6SPcr3iY3lKAA65NRoNXrN+E///+eya/+M7FumjH1/5KMfXK7CegDH6zOb7uf3Dca6dOyTx/1NW92v8vk98YrsBgHPPHZIf/nCcAWDp0oru3NklANiyZdrEsy5dWpF581KN71+9ul/XN/cwtgBjYwAw5ppNaElw9CkNcPhuHP6ueDeHHCvv6iS8HhcpPWRnU/ishve5f+faZeE1AtAFQCeeCD7lufM0Ga/anTt3ZpsBYDNcOJc+KQWgoQ0eoRG5+muvWnvK2d2XTXcmHQNw6sgwYISJATCRkCqB/fczBMxQAiAWDACkAoUSBKQEIlECCVmnRiwbIlWnlkhAYCDLNLGZTUXIEIFEyLjMJQCgBDIEMENUQc6vpoqoUaeJMohIBUJGFExQIYJTgDleJ/X/EhklGKgTcqogSjIVah/Ym3X2HtD9O7d3/vWOO6b23PGzAwcx0dkJYB8At3oYUs3md267bV8rCNcRYTqSx/NkazZt4hFABpfYM+edcPA9bbsLDIIhgBhgKFIQmAikAJM/RpB8q3EulRK2rIbnfuMYEAgKzY8DDIaXJhc+Q+FdUlIJ8bP+yhtw+G7Nv5sO2ROUKwoJZ/THODz2xxkMAwZBAMx0Ehw8MC87cGDO/l3bqvfc+Qv7k2tvfOTXmzft+xmwb/uSM1A769il09ffvdPhPmS/aUF4XAVgzx5vn6dnZn7+0Pik292dcrCGiwumMAQwkb/g5IXAQAEVECFcUAUxZgmAQkCkgAKsAg1CVLyPwAQQQAQBg6CqIPWrS6XvYyiIgpiQ/w4vlOp/KVHY8kEMVMDk/wIOhoSVQFQIL5HCsMIQ88ASShctMYufeXpl8Qtf3Hf+637/mO699y6568abOt/75Kce2Hj9nTsfWnwqpuY+e2Dy7p9MHjzEtBzWm3k8T7Zy5RiNjkJP/62Vbv7TDr7dVWaqaqtkoUYAVhCLEivAosoKYiixAOE4sSr75yBWJVb17xUNn1VmgWFRhM+BHTS8DwxweC/854kYMExeVFjDcSB+H7FIOD84/EYUnw+/TUAs5H+rqrJAWQFWMEPD52BYlCmzpC0rmLKZdmRG++ZMJacsd8vWvKB27qsvOeEF848dPOk73xuf3HNfa9cFF8yVWq2te/bkyunodgJVQUSKr96z+k4s3fuMqXEShXJ4Id/VTIrgDxTHAHgvQcMujSpaoUogotxfo9JdSYNaLnY0zVLvQTuQQgml7427uNA0xXcgnAvFeRUASdBgGswB5+djVjAEROQ9TwJADBJRgmqSAHPTKqcYwp13Vbd/+avTX/zUR+6+FkM4eMJpfTMP/Hj6QHAij14B2KjDyVoatV+58/mfSU/d8+bde6YcFIlqvMh+wQ3FxeFiEcLi5P8H/wCgWZF4VM/566QgpXAuyRfPkDcB5L3KsCAKJi7CBIo+g/jzRoGMAhJ9gdx0BMEiwIDATMF3Cf9T+G4omDn3L0w4ruo0JafzqzW2dj6+c0vlF3++/sF/vPfH+/7X6uH+3Zu3T03iPnQPV6RgHu8Trlizgkev2Sov+J3TBnqWzPzORGtGRQ2rAlYBkcKtEgWcACIa9zycEkS9O+cU4a5wwVCq+P+dAk40P0+8OwFEw3Fif0w13L3ukHBeC4II4JTgCLCqsIL8e60qRAEL/9udAqpBVErnEg1/j/dUwt/n76q5ZvSBBBEpMU1nTsVM6VmnpEte/MKlz2nr0PgNG7ZvO/7kaq1XXGdqCvYoNgHQv/rYpYuXXnznfeO9j/Rn7VQBIQkRMAHguFNjsJ07aCW1C4BIoMFBhPrX880RdiOCeubg+wc/zmsS8bs2agB/bvZOHQGkxbmYANLo7BFAEswR5U6myR1YDWo+RDXBLHDQPMz+9xhQMHf+fx+OUv45RdctqiSmM3msfvoL7W+8/12//NJJZ9XunNne3rdzJzpPtIP4hCSC1DvVcvVd592A5TtfcmCvc6IuUREAjNwchEUP1z8IQuEbRJ9IVXPhKGtGb679npstAAQNZsXk/kSw9yQwMOEvD9Jaktyy8EUB49JCc8k8MRRJLgDIBSCGvIYYJgpN6fWEOfgM/veRqPZVFUN8DH3mS27jf3nTXR84+eye+ypTrd1jY0+sT2CekLOuGTaj12yVF7/q1LT3mNYrx2c6KkJshaDKQTWSV6c6W10KCpXqROGCdXYKiHiPwKtobyqiCtbcdBTmQHJz4VW2U0DUL7FTKc6bf96/7lT9/0LBnJRMVq7uKf+t/tih6v8QUxCyEkr+c1AfpgopDBN1leHkoJy/uu/EZSctO/Er/+Phu+ec1DO9v2a72P/EaYEnRABGr9mqAHDagrUPDazc/0fd2nRft8OqyuRtdFws9XY8XHwHzRdOhOGU/UKLetuvChEN9n/2oud39T6A0/hcw7n9+V1ZUABYKQmcqv9s8CPyvK1q8BXie71PoVEYwndIEDSNyV6i3LcRpVKMR4Bq/jy8lTI1nGGfe/6ZfSf0LFm8bMPVO3797DMH9u14oNt5opxC80RJlmrdXHTRV2cueuOpT6styZ41MdFxqsJW2V9gFE6bCkrOXNx5dMixYiGtFItQ3pl+gSQsbhCe8HmRQsMoBDYISf567iwGRzJEHuLVQxCE+F4taR6FkP88gjmJeUr/NwbnU/1xlFJMStFJpGAWBaIJZzTt1q6ee9IkDcm1X9xx5zMvGcp23dNpH1UCgPV1Gh0Z1QtecOa2yoKpNx+UGRZnYFXJKcEJYNV7/fGCK/ziOykvKHI17EDI4m7N1TJBJJqLsAtDNFE2E7OPeeHwu5+D1im0RjRRhXr3EYML+YjinKUIgGY/16h9DokGvJBQUUeOwkX+NzIIzoFQmdRzn7Fk5Z33pQ/89KZd2847b3l769Zxe1RVAzdo3ayjpvvI7ed+q7N81yv277bWERIVhYrmF8U7Z1Tk47VI5jCVawHi91aI3TU4jDHRzHk+QQsnUUt1hhBKMMcFKfIJ0bMvHLrSbwvOonfkGCY4lBwiBOYiijGkSLhIdRsmHxUASDg4hsxIwnkT9o6kYR8xpFCYBCCoHF9L+ad3HvPwhRf+4rK5S80vtp/W2onm4+sPmCdSALBqFY9tGMNzvn/m/bXF9tLxbIrEqfcDou0Vyh09FR/bz9pJGndpySSIV/Exjhf1eQRBzAOEnR5MjYPCotAohYaJapoOcQRn313pdYTv0ZCPFMy2//nvzP2Hct5SQqWiEH4NgqxBJwh508bENOM6buWxZs7A/CVDzc9t/8nwqoUTW8dmukcVHiBqgb/+yQX/3Dnm4d/ZsXPGklAiyt4mCqDkq22syGN24JA0LAXrqprXZpHvVAk7V8Gqh/xhAmINVUEKxX1/LtZQdGL8m6ogqc/kIYZ2QesYxqyYvwjvYp7Aaxq/871GMByygSx5WJjE9zOQkIZQMYaJhAoREoYO1UT1wLHudW/Yefldv9y94eCDGCd6/BxC80QLwErUadOmUdx4yzPurCxov3kK04lmhgRK3utXqPjdaqOtV8pDNhfss6jACYddVkQMmjtjhcM1OwQsnDDJd2ORmRMU2siHilLsfOcFLe5+Le3qaNdVit/h3yOQ2YnqPNxTzM4Kxghj1rmh3iHwpoq6DrJsMEuWLl489KVPPvL9TWMLZx5PLfCEC8Do6KiuWl837zzj2r3nveJUrh6fvfDAVNcRiJ3AO33B+VJEx0yLeFtKcbdGBzGGaoAVhUgp5SsxX0AlFa/honMpdxDi9pCPQH6cfQQhVKR9UTh4mjt4JQcw5A28V+ALTjHK0ZB3yMPDaA7yz1BwAAuTAAKUcnHgNjp63MLa8l/f3/PL27+9856vfrXebTbH9KgQAABojoxhg9bNDZef+KNl5+z7bTvUWtKdhnNKrM7b/nyHSrTr7JNGIQQse99eaCj34DUKgysigzxHIEXCJsbiIpoLgcL7HTF/YEuaQjC7boGyR6/lHe7rDsWu5rCri7BQQpr5UC2CWXCXou5FQZN4RJXK0kHDg/3zh776xUdGe1dOj/989PGJCA6LAESH8LoPfTF71rmr7uxbSm88aCeAriEJ6DCnBOeKcE2k2Km5c5jH9EEgBBBXFHrK4VnuaOZZxFLcnhd2kH+PKx+LZqfk7OXO3yz1jTxVrSH7k2ubcB7E91PIAUh4f0lTaI5xCu9XxNpzSGcTwWRYMNS35NbbdfQ739lxP80gO6oEYKw5phu0bv7rGddte87Lnz7dc6xetH96wkJrxjm/81TpENVaisXzhFCoAkqR3NFSineWBpCQ/ZNSyjZqF3ApvRztPJc0BeWefa7Co+evPqWtFE2JhkUNAWUQ6PgZlCOC4L9K9OSIgtAUOFZfjzJedxAAZnIicvy8NE3NnK03/sPu76vW3cjIYzcDh08DeFOgDR1OPvS07/3wwtc863QsbT3jwIHMEoglTwlTKe0aS6+ah26FGUARPgZvLi5GkanToO411BaQL7rGBBJiWFjY6dz6orDfea0irKDm2iaqAQ7gMBQ7OXxe4o4PEU2RCSy782Hhc6HLk8QBEqforwpxNth/zWd3fW/ZsrH911//2BFEhx0WrgpaD9DPLn1F38lvmbx1V237Gft2W8dExolAhEIUqKW/Ll4+zZM+ZeVMBBhVKAkQQspY2WMNwFAONeMAHomVR1CR7InADQ8ckVJyJ4gCIweAmBxQ4rGKhhhkAgBWY9nXJ4IYAiZFEp6bPHHk35eGzzH8e1IfAiIhgWGgZoBaorqgLyHsXuLWvWbn7971g/3XqSJ7rCEhH24BIIJifQPXfeG6yanb5rx0sL1wa+8CNpmwEyU4p7COYB3Bhf+Lx4zMApkFrGP/3BG6ltB1hMwRMmfQdYxOONYWRlcYmSVYh/x81gFdGx9z6Zii6xRWCJmE8ztCJuSPOSBzQNcRukLIHCMTRjc4odYBmYT3O4K1EkAm7I87RTecI4vvd0BXgK4CmQCZhucC/51KsGpooi0yb0nHvK5+zDyv8xr0eDRRHPbbyMiI1DfUzWfe/Y2d+NHQS5bKsp2VuWqyLqzCwKr6C2ABZwHnCM4ybOYX0FmCzQjW+ruzhG5Y0MwRMkvILNDJgrAI+fNFIRHvczjxsb4XOn/xrSAsUulu1S+YBbL4WNTfA9LJOkVmHTIrcKLIXLwHwQghbyb+vdZp/jwKXRYELXOUv9+FSCZzhJYTFe5g+XJ6NoDq0RUFPIpTWN9QN9e8+Vu7n7Xq9Jv6lvLF7b5s3tSUWmJmZyX33KPzNjuFHG085eVbzUvHBBUOHjcdEkLGBE7puJS8dSnCRdXYKcClZBMV5d5ZSaUiAomhXA5LJQ5hY5HokVJhKEYfFKDuWlLq0eiFbKMO9hjOJoYmv/y5nV9f9vKp7PrP7JSjUgDKQvDlS6/bfc6Kc78+eCKtdXNby8b3ZZadYafi4+t84WN4WKoaOuSJGJ8T4Pw90EIAtFThE6FcAPKkTEwKhe+Kq5gniXCII1hy1vJsILyjoLNaTihEC6VycfAESYsutZjAJiqSTdGX8T6M9z9qPUJmpsd+9n/s/se7t+1s7b/vsRWHfqMCMEsTvH3DweO6J/3zotN7T9M5cvr+ybaQS1QZ5JxApYQTCEBS58KOR+HZaykVnHv1WnjXGha3nAia9TzG76U0bZ7p09KOD4iecngnRKXUcbnTSEvxPeddR+WoIvf51TedKBWdT1TCM9YqSpU267VNbHjoZ+3dj7WX4DcuAFEIGo0GX/2JL8789JoHv3buK05xPXP5hZNJh+ykWHKGc2iX88kfjSnfWAkUnrWACp+N8yqfg5CEukPY1XniJ+ILNCpbKlUj451LVcpYxSuZhrjjlaA4tC+43KUQP1uEkUVnQgn2Q0VWiBHbWIBKAqranuQX/zv9n/ffO/HQY40CjggBiDUDKKixHvzx07eNPvf8VZur8/E820fzJic7aoWEhNk5gfPbzecBQtZOFVBXQL9Vgw8Q0EP5e4IWcKpASNnGDGHIwECDCnCiEBdBJlEzxL7Dkj+iNKv5OCKLdRYekAo8YHgxCoCg0AwR0qwlP50iRoFBlcShT3p47Me9X7vzZ3vvP+rCwP9DVkJHCDK8cTj54qXfvV6umXPW4pn+Ty5dOCi1BcZkNhOXkYM13hyEKpI4grPeJFjrQ7rMau5t2yzcbfDMYyhpi9DNiYeqZTZEIM6/7oR91GG9v+E9+uK5c0V46cRHB11VWI3hawg9Q3RhJYarGnoPwmsiyFRhRZA5gXXi3x/6E5z4e1cASoiOWTCUwXc40xHTHPq4aYO1o7a+oW6a65r78BW847WffdFXe5dM/uW+RdMXHmy30Nrv1DgWNcoadG6BLvIXnSJaiKIfT1ATQgpmGPElWmLf3UOioXvH7zYXGkwN++wix6pe0CaG8pPn0HIlhQHngI+IDSi6g0KmEoCEOkDCszOQCNnAvO9BAu7AACZUP5WAgf5KN08VPtkEAACa65oOCqqjzv9EzTsAvOglV53/kv7FvX82vmxmzfhM23TGLVxHLaDEzKxEedmOyKtmjto1AjCp8OoptI755hG/IEwFKYCyd/Y4LK4EJy1hzh1AIm+bxWke5pG3LoDxap6jU8oAO4WAIYxcUBIOQicBbELe0YhgGKOKpBQSqxq0rDwu2vuJMQHqO60Pvefezv+FSWhS0zUaDVYF3fT2W2+6+XduX7t098K1i7qD/zRvoG9qcGlPwr2JsSpkM+fEilVLohYqTj2IRNir4phYsgpnAXUMsQTJCJIhZO+ALNOg3jU3E07YJ6RC9tE5hg3Qde8n+AXMnP/fiuaq37rYyubDWIXOamWLKl7FaxdbhrRLXHT1+FFidDqZ7NhxUB6PbD79hmx9nsN3DgaoYxN2+9+yyfMMbNnS1JH1eUgMAKhvqJtmvRkxGnjp+9Yu75zcvmSi23r1TOKenVW01u124DoK13GAUyGCECsZw0wQ0gD8jE2mxGXIV+AgIAl5fPaN5Qh1AUN5y5kheD4ARkDv+DsFmJcxETJGoYYQAKPkawG+JuDAjFAjkLwOYcgDSFNWpESopYpaougxpAvnOVoyPTj+l6+tPvuGW+//tZaam44YE3DJJcvn9PYuSJIW64ED4zQwAExOArvvmtO9Y/+lLejbM4V4fB/BAc1/J2fso6BNGGZsAjatWSkgLwjBTGwF8AkAn1j7vuedNLVE1mYVHnapPdOJnNztl6pNlF3XwrYFKurYAwkNQSDkXfuI6vXtYV6ll2v9HMq3rP69FJsZwb5vkTUHpRgTUM0SkD4Bt6i+SR5qQhYyN98KRxEWpr6oxRRMgBc6JxJ8B9XEECHrOXjDrdMHSu7HkaEBgjTihv/9klsXLz/wW/tbLVEBgxjiBFDqcFKdMiZtdW1Hsumu9NdqD7farmWz/kfsDPZUQQ9O7x/Ysf3B9oO3NzuPNEdHpw79xSp1s37Tbhrbs0h3L9xNo2tGXVlTKJTOf88zV8wcIyulp3pOB63zFHqW9vNAu9NC52BbGRWpkBoX4mvmgP0hjSFXcBCD7TIEQx7iTaShwdN/zhgNGgMFRJw139Fea4ivDBrvWCZGgxbxuz9WBuOxlL0WqCSEnkTQnwLVxLmTlyUmuW/Zj9au2nLBBkVnHT22TODjqgE2YdgAo7anN/nR4ILp8w50d8OYGqxED8dBmBZpQPDWQIDhZ/YBIOyHgQEJMNBKMTQh2WmvTPa+uXvOvZ3x9K7OePV/b783/dm7/ui/jRGtteUOpCbq3Kw3sXvlMC1av0iJyOFv8QCABwDcAABnN84+Np2PF7d6e14/OTi9puNapj2tkjgDQNgpwGQgKggcFSBRSIgSDBRCHtbNHFO8WmD4IrA7cB8Z9VpCI3KYOLa6htjee5QxEWRyreJPYqiApeewcrLaa6rIMv4FgJmFGE6AURxBArBGgFH8YrT/s8mi6julN0naLZAVBxXfl+c1nebQLCVRsFNoK5D5OBCBTQ+nSVWXmtQs7V+RDg+4FD2n9uCmB95zb3fiOT88sGfOjQ/cMPA9oub++P0bNyLZtL7pdWsDVF9Vp6Ah5A6642EAnwfw+XM+OHxeNnf8T6fnd18x1ZqBTKlLmIwE5ioKSX+hAv4VUzsxMhAoDLNfIQrZSBWvGVhn9weqFEkmRNyCF65EQpqaQywYmLKsEjhiFwPiCMSowGDfXv4ZAKz5dzkTf4NOYOwD+Pavhr85dNqOS3YdzGymWWJnNU/OvkDe4EmO2vfZOKj6ZqyYeaXEqKn1puivpTCtAdjxyq5keujm8a39G957wQnfuQ+f7EStADRlln1UUL1Z57ITufrvVl/SHbIfmdb2KVN7p1wNhpEIUVDvCoWywhgfqnGZZ8AgX+zEaG4umAlk1PcDBIcPUCShI4lNUPkmmBgCEhZvFmKPgAESQ6iyoJoqeiuK/gSY3y96erJAN35u7tlXXPHTzY0GeGTksdUCHn8nsOnXdMfdCz5SWda6xPLDbLOkBNwM+Lco2aKBxYtCOjaPyYm8qjSqgBFC10HbXdVxagmSKeodTBbPX7r39fOO7Xv91dv33et2vfQfx77T90Wi5rZ/IwgEbaLp7WW9brChqZtp87cuuujsjXsvrv4NlvBbp/dNaaVrVE1Q7uwjZQefK4gVGQ39/zF740KsLjGjr4CLPHjqIwdhhsJrQsrLRARiX2jiWEMgPaTBVHwOgkjmDBDbXbUtV1zRvuuxev9PMEFEg4lG5Otja27uPX3bBbv3tJwSG+cirQtylZn/CPKeMuXEEPronH05Vw/AYFV2wiw0MFDhhdU+uF0DBzv7Br+07TtDH3/bn3zrwbJWOvR3hmyjA4DVHzv70oP901dNTUxWeIaEE2FiBwr4LQO/q8nEsM6HhsZ4h49NdBy9afDaAKGTKLxe0gocOMkMM4wJPYIGqLDmTmLNAJVE0JMKemtkn3t8LTnwo/kf++3zx/5EtW7oUf6mIyIR1GyOERGw++6+99m9/aqJQ6ZcQJ8ceQSMeFhVx5GHcAn7x47QdoxOeK0rhLYDOgHZ0xGgLYQ2lLrKJrMJH9yvcvfu/XZrddscPv3Bd530e1t/9q0713zkikt/d/E6ajpVUKMx++8Ni0/DG4eTze+64/Pzd9ZePpj2TXWrljOBOE1gLflEj6O85uCrkR5T4I9zqAUUvQoRs2DzHgbkaGLnIV5QNaWeRM75inxfAfzuhwJkUK05kxwckB/fTNeFXy9HdG9g3HX/sHntl/rO3PGGHY9MWydIrPOW3QNjOM+KxWK4luEwccd7eq3gOYfDdAjFW6BmI0CVM9fbS8nSwQVIdg7tbD+0YP0lz7nhM95RHE7Wrh39N00Vq69enW6+bHP2vCue9fzdx3duHJ+a7DMZKbFy1DqGJdh6ARvfFYxg14mBJPE72u/4ENaZ0nMOoWDsAwwhZGqAxPjEUkKCiiGkqaKaZuhJCL0J3MrlzEu2L79t+JSfrYmUBEduKhjAlvVNVQU/MLrsivb2oYNcA3edqoPAIuziTNEJuLuOCDoOaNvi3nEojomi5RQdG48pWpk/Rzu8p2UFLQF1JU0mplK9+5H99qH+bUvNmVuvvuG+82+66qr6qWvXjlrVuikxzQIANl+2OVt99er0tg/99Ps9D6evHOofypxRaJcUmd/1cTdbZVj1gFDnCE64QCuVGFB0VqkahdYodQ1FLIIL8HUHzzwtBBAMEqOAsViq/bTtlz1/D8ACdXo8mbWfIOAnpIk6vf/d/7Bz36/mvHuoNsjWOGc19QBOAbqi6Fi/gJ0sLrpX921XXlhFy1J47Bc/R/06f7xj4+cEM1bQckKZo2TPQdVf7trhxo954KJjX3n/j5u3v+wPiZoODG00GvxoQnDXX915y8Cu3j/o6+/jrloRR+oC6si5ACdzcYExu1Op3PaeN7EEZpPYAxkxibG/oNyFRPA8qUFDCIwsX2xYd867611/dM+3Gg0kj4ftP2y1gMbG4WRk7aj97J3D19Kp21+5fceMFaEki3Qu4ps+fPN2KJVG53AWaycF4hc6hNFT8vw8BeRMJGqIRNJMDKeZ6++DedrgErj75n3li28afOv1m6+feTQHMZqDZ3zg2X+xb2jiAzP72japICHycT6x5k4eMWASgJOI21MYQyETqMFJDPWPRJGSIgF5p9AAnISsICsqhlAxDpWKolZR9KeMgVrHrV2x1LQ2nviql77429/49xzaIxYRtGbFVmzaBPrCF8+/efHxnXXZwNS8qRkSVUdWwq4Qztu+bAR8BroYCdAv3/kbd1Wo3IXKWablLmPveHmQBXJABYi400l0R/ugGzihfeazXpRceOpxv3XzO8791oHGxuFk9JqtuU3def1OHd44nNzxxts2LRs+9pysLzvVtZwjZi6jgRFBm2GFI7toXs6P+D8tYF+spXAyCm/IKXiBUZhE0ZMCxqhbdWxq+u+f850XP++29z/ei39YEEEjI5B1zTp96s+/sm/vj+av628v7XBN0M6Meix/0UgRn3cCpr8bVHvLKVpWC/8gNxHFsZZVzFhgpgu0MsVMBrQzoJUJWk4xYxUtsdTpcvKLB8ftQ/MfPPukdbt/+Ldfe+VzRtaO2oYOl3MiOrppVKCg/geSS3upd4+rEkmXxDoPRVfHBQLZIkQKUVipIJsSgkiAhUvkJ4rwMi41uwbKWw4dS8o6f9DRsullM7t+vOhtxNAtjzoV5SjoCxhrjmlj43By5SU3P3zuBU+/d2CpWzfuJsRlhixSUnH5bo473YbUcaSEdaWautPYWFFQuNi8Bu8TK1YKSjlbaizNHEFdwvsnrev2Tw4tPk5ee97wmT99/2m33LtRh5NrRoImGIXWV9XNLe+9ZeK4s1Y87Ibk1e3ptjAnHLgoZ5FXRxRKPBR1BGvA+CnNQhwV+YSQDTTeXFRToFIx4FrHPf+Yhab184XveM2rNt28QermcrpKjuqRMTEEa3zr/LdUz9x/9bbJ3U5aFbYEiuAHKwXUOtZkZ6PePLqk/Msj00akeI1amaOKDReaQretp3n1DFJ9Q+AVurA7vfnYV7//1Tf/r+izxHMPN4aT0ZFRe9L6M5sHeiZejYnMUYUNx8qfAYgFbNSHhsHmG6MgAyQUXmcCG0WS+F5ANgJO/KJXEkUlFVQM0FcDuNLJ1p4+mM6/d/kXXvHMH1waCbifFDOD4h9z5Teef5l7xsG/3zmzB7aVOGGYzCliD0CB2ces6SCzH2MWijf+QbERNJZty0xfFAAaBooEgCOWWm+XT64d163cffIr/uQl1/7LLCFogLEeevYfPX/Fwyftvmtqpt2TEhMSISa/qF4QBJwUu9qXiMNrLDAJgROEPD/DGOcFwghqqaJSceipMhK29syn1ZIT9h43+vnTzn7xTfqI/Td1jaPNBJRv14xslYYOJx84/dafnLHmzF8NLTYvb/fMVKYmrYUYFsceFRs4AGI7t3MUHMbgJIa0sg2hVhl2ZUP/XWQCi8dyBtBgbrqW4ESo1SHZl06b/rnud85c9YxbPlz/3kP1DXUz1hxTjEKHMZzc9tFb9897/nE90u+GteUkcNPHnq4cyh2TUz6pJblZoAgkiR3KAU3E7GCYUa0CQjZ75olpemLrpDu+86GBV/zzz/9pSnWM1q594qjjf2NTw+Iue+fnX3oOn7H/Swf6dp22e8+Mo6xCIMeRQArKUFeM7ovEzhIgM541rDABGor5kdcvInwiQrgcLkYWDkOETCG1noxPdMfusLctO/fj7/6XBxtXhmpbWNPhNw4P/fqUPfdMZtMLE6tAQhTrAWRCFTDu+gRFPSBB8O4Bk/jFr6RAkvhqX6Vi1FRb9rkn9aXHTyy5fcc3F7/0iituONBoNHhkZESOPrJo/If4hKWxcTj5m1fd8tBx97/0q/PP6B6bzpEzpk2bsjZZEiYHIu/suVk727pyd28EYfrwT6QIH634zt+YY8+Pxf+DY9gJ8eN0i1x77vTQ3EW14eeOP+/L//qpVTK2fgwg7xDe+P4bWwufc0yP7XUvsG1xAftbpKhDkSoGVzkFXcgdxDyCSby/UEkZAITSNp576pzkuKnjvnnjZce/8hOf/+ZEQ8Eja0flqBsY8X8rBPUNddP8m6+07rhm2zfOeeEZ9w7MS87E3Gz+eLtF2QysWkNOQXlDqIuL7sMr54qewZgnkJKZ0JxWpnjdznrOobWbQMQ8PqWWjpk5pnZcsvRLp3z7m401PkcwtnKMMAqcvOS4e6bmdS/L1PawUM4xH/2LMA4FxOSnJBkCGfjH5CuAScLgxCjSzC08hs0zhgZ0/iPLrnz7mbf98di2Ld1GAzyy9vDMDzoyBkcG/H+Tmu51L3vZ3IF3TbxzvGfibfvN/kVTBxyytjolgoqvBEvJBdRSD57mnVWliV8x4ZIzfOT9HEVTRwCoEAMJETLp2uPmDCXz7z7uDZ97y61fzsvGG+oG65puxRXP+MJ4z+Sb3BQsp5pQitymIw0qn8l7+QlgEkGSKtIUYFWBcTIwD8lpx/dihVuwhe/r/y/v++3vbdToPtDhGyx5RE0OLdfn39CoL5Gztr31YHXqjTN92fLpmTZaB9pwGTlPChzaPZRIKTYfBJxe6LglihDRyM8T6/JFazdHhi72EypZFZwZtbWWnj5/cav/54ue9bl3/ODexpXgkbE6odmU5W991jmTCyZv63a7miTMMB7hkxiCpqFamAiSBEhSVk6cmkTEpIYH5gsvHGIs0Tk7l3SGPva5F0x8ahd+MX1o+Pmfd3Ssghqbhk28GBdddNHggj9svXSiOvWayWxqOOt3czPTwsyUg20BkoWiGgc3MFTavExITg4NFJh+4uCxKxVgFPY1/ojxYyLXu1DT42YW3HrtJWNrGnolj9CIgqDD5w8nY8/de1fLTJ9srBFly8RAUiFQot6wGgtTUa72MPcMKObMSzGQGsynwbH5tvqlwe8u+cKHP/zNfYcK/lMCUBKE4U3DZrS0K373r16+uLPswNpuz9TwtHZXd8Se3OmxczUVqBK6IhDnAsGURxMSh97c2AMYG0K0NBZGGEoKqw4KDpy9hKzbwbEn9WHOrxb/9bWv2/y++oa62b1lN42OjNoVf/6sv51Y3H633d8GpQBXCKaqSCueJ7iWEnp6GD1KnQGTbBnorYzOmey/6YHXrd04ihFbwkzIb3KW8NEwPJrqG+q8st7UkUNAEK9/z4WLHjl1/ETqc8dJZo6d7E4tNxXuh7i0a10/qdTAUPWk0MTEvpzjUbpKxBUQDIl2RTILIoYxNYWqqkrFsKG+lsybXPDwGV/62JtHbl1rG1f60Oy0d5z19M5ivKc7OeUoMUmlRmlS407C1E5U98+v9mytDsn9nQflwY1/8dN/La9xY+NwMnJIL8NTAvAfdRabdX60ZpAj+bZRh5NNDyLBTxYJtjTtY0XyPjU+HiAMD5vVp07R5qWbHUoXNNr0sqsvTv7Dfycb1vh+w6yqiiv/Hfj1xUsv7u0573jGgT1m4dyF7iSc5O5pTRCwDEvv2iEjW0eyRxv7ptrgTZs28Zo1o45+w0J8dAlAA4xVdULJYWoMDydfTHYc35LOkq6TxQKZa63rU2gaRrJ4DIlTF7pBmZkqgPPNPsZUYahCxD1OXUaEhHuSJZTqEGc6Tr3J8UPVwS0P/cOWt6ABbqxvYIRG5GWfOPeZ1VPkm0qO0iollZRcT0KuJ0mor5KgRk4S123N6UsfqnUHt1Y7dE/1QPUXO25e9ot3fuiTe8qdTevXr9QnOuOHo40fYHZ8WDdY2VS/05u4oH7B0K8re17Q0skLP9554Ixu5gZdR1rq7KQKO2e0paKTEOeY2UBghbXrp7JI6piqQkhYNVPYhBPq1QRDCmUiUmU3lJCZg0Gd37ewv5JOV64EAIzVadOmTQRA7fzKi9qLpldM7hj37J4MVA1QJUUFnt1zoGZwoJ9Xze2ZwFCSYjCr4bhT9+6/+bIX3Z6ML2ruuHnR9UR/t/ffbWb5T68BfCUOgZUdJ77l6We1Wf+gS9mrOjY7Jpvuwra7ewFuk3KbhDoimpFoW0SFlDoCAStUiRIlJCBVIiQgSghswJoqUY0NapSgD4SUiFVJk9qyntoc1/uhbR+7689jEqihDR6hETn3n8+5qTu/8yI90HWG1ZiqQaUiSBNCmiiqCZAkQDW1WklJKwaoJpbn9CgvnVPFsmQQQwf7dlfHB//nw9/tuerVl/3T3QCwYUPdrDuMISEdyZ5/jI3P+LOzXrKfO++cardf3NEMrqWgrnPqSNWqEkhVlZTIqGoGp9Pk0IVKpiAH0gTMNSIkChUoiA2nxJQqIYUHaBBSJiQKEghVwEOVoduW3Zqu2fzfThSsa0qc+nbRmy5aePDifb+eSqaGUstKiVKSApWKIkkIlYRQSeCh3QaoGCBlQWocEqNaMZBaVbC0n80pg/Mxd3zuTLZt6ac+/9YFH/zCbf998vFq+jgqBaBer5tm0//x5/zFeasPDrTWT3ZbF0+1M+iEAzJYVTWqRCIudA6yL+ypFBTS1odyfhYbEZl8FHiB3glVPBhPKu2IwIZE+1jnpn3Tc7b3rh77/O33oQHGiCevGl0z6p5z1XN+v3tSds3MwbarpmxMQPOkqc/+pQlQScmngJlQMZ7sITHw2sEoqimjmkD7EnXz+5PkjP756N2z+O7dPz/mv1x44cduCULwhOcIjiiWsOGNw0mz2XQXr17de+ZHn/ffdy1q/2g/tS+emsiE2uooIVAtTVBNCSmDqkm4c7gnoNSAUgLXDJmexHBfwqbXEFcZXGOYmoHpYZheA1Mz4RiDeg2oh1UJMjiv18xB31vHPn/7fcON4SRGGWvWrPHUgXPNm9tOoY7RFfH9AlImf1ZkVgK3cSSHJs8JnBHa1mAmI8xYpQlLya5x0e8f2Gm3Lrz/tCXP3Xbz7Zv/6M+Imk61zk/0JqUjTeU/+4PPPX9mGX1qXFpPn941DeokTuGMOoU43zUa+f8AnwFEwOZTCS/gp337Nu7SMMJQmg2I3YDBhwE0YcBZW53flywY7/3wPR+4/YoIByvT0zxn/fOf3T3L/ujA9BRSJSY4mJSRGEKSOL/LU4Td7ruKjfG7P2FBahTGMFID1BJBJWFUE0VvqqilkKW9Duf0nsa69cSPr1zx8Xep1g2h6Gh+8mmAhm+0ba5ruvOvuuA9E8fju3u6k09v7+1aw1WVFEaIoL5HGxoKLkgIlBhw4kl22BtaUMqgigFVGFphUNU/Rv443glU8QaaUgYp2eri/mRxNufr937g9ivqG+pmdGS0sMN1b//tifSnU9pl7ZCIC1NGnO8cEhuJpTyPYGQtzyzQzTRQz7PvhLKCVgbMZMB0Bkx0gamO8o7phDZO353J8nve+fN73/xxoqZTNMyTUwM0wPgAZFiRdD5//mf3z3VvPPDwhGqbPPOOKNQq1AKq4rF/oauGIseA0L9BBcUkUADk5nMIkWMCw/sDPYxasrzAJPOk//bFf6cvuP2h2ztAiaBqQ93gNU13xvvPf3bntzq3TU9Ps4EhYiE2QJL4c6bG9weyidg/FLs/dBEnxkcHSeQDMEAlIY8ITgh9qaCvAgzWsuyCwRXp/h8v/cvzn/OVv1DdYIjWuSePBgiO1QUvXD2U/cPaG/cOdd64b/uEhRjA+DkbHnDDIGYwGRAbD/kyHDRCAk0YlBpowl6NJwZqvKYAM5QJZAwoSUDGvyZMUENgYyDM1syvJENZz13z7q68/Pbtt7dC6Fmwk9W9BbHL3UenXZZIh9WJUKSlj53D1gHOMcRxeO7vfoZBMeAiC3MNYg9E26p/nAEzXcJ0WzExlaa3Tm21c86afP8t33/TK4nWuQ1aN08ORFDY+RdccMFQ97K+b+/tz4YPbO9kRjm1qv7C5py/kZuXcpJlDvy5Co+80cDERMQFGicOAI6vBf41DV055EkcbTqvlsznvgfm3oUX//RzP9iJet3gqjEpO6Y3nnCjW/Xfz710anH38u7eriMmk3O5lOhbYpSRI4OIil6BvO5MpUli5YGRsVEEcGFgVFsYndoBXT4wcMFLj7/4H1519rIpYA2Njo7q0SsACmqsaVDnc52a/YvBf9ndM/Xc8R0ty2xScaGDRgs+f4SBjBIuKCM09hLN3qZRAEo1AC8gnuBB2Zd8QQ6GU4jAJkNJMpcGftn/K33pzz9724Oo1w2apfi70eCtf3iNO/Pta5dPr3TfmJicqbDzcNKcxLk0nyj+r6XHCARRSjprOGCcFp4Pl9D8QSCE89HrZJbJnEW2f2gAy1csumrDpk2L+PGYFvabMgE0vGnYjNCI1D658Mv75rSfN76zY5kriYTWWIHx45sCojInF41TN6g0gj10gChxaUhj2FnkVX/kic1Z+rkKAWXVRb3JPBq4s3czXXjXp39wPzYcsvgAYf0YNRQ883R7zZTtDPE0eyZB4VkEEc6GFrBAHu1Ngp9omkPSXTEuJpOCPCLOJcoiUUbmzcKMEKYyYKZjzE/37nNmxeSr/+X6PzifuOk2bHj8TAEf5jjfjK4dtS/4Wv1De+Znrz6wYyZjkyRWAJEkjIGbPTcwH9uSD4soD2cMHDxRHZemdVAE/1FUtQRWVifOpkuq6Xzb/92n38IXjl0z+gjqPs1bXvzVV69OQE234aPDnxjvc8PZLmcFZDQjqAXEKiQwlDvnKWgjO7hfXN/f4GxgCQ99g1Y8Va21XLCP58OwFJ3AoNKxvr9xsks40Erwr7V9qJ06dSUUqNdXHn0aoL6hbkbXjtoXffVVr5k4tvPevQ9N2lR6Eicm0KLEwW1xBi/nQxniEAifzks83WYx5xvFfL/4OAhEeO5RICwuVQws6k0WTFQ/c8w7vnvR9deP7kWjwYfsfKy+enWy+bLN2akfWPun4332j6d3zFgQEj/mln0uwnkBiMQPTnxzaA5Vj8OuShQyNgtOorLf/WHglXWADY6hsz5h1M6Abpc8iUbXmLt3j0tr0fja0Zve8iyiEXm8tMDhEYBGg5v1DbL2g2tPmlqaXL1j97SQJJyJJXGebEGEASRQSQBNfENIaRhU7kCFxS0meRSzf8pCkQuUMpwTy0PEc+YM2bkHey6/77+OXjaqcD4SmVWG9XxBl23OTrnivLcdHOx8ZPyRGQcxRoSAOKkkHwjNQMwBRHKIGBFYhdgwLyBTOOsJpl0cPRemj3WthtkDPnfgZxEwrGW0M0LHGkxbwviMkX0DbcbxM28NKfOjxwmsb1rEY7ROlr/rzK/vSCZPa+9zoo6MJ1zyFw2OPJ+uRDoV5EOlPbc6+ZhfihlAeXI/zOIhFJz+DAKpOmGl2oJ+M4T+u+bs0lff3dh4LTbUDZ7u275meYyr6rz14hvdSe8dvvzAInxq6sCMGA2dhkqe4BHlWUCx1Ss4oZHCKMena0hABgo88Kwx8YrZPY1FNECzuJKUADIKl1hair5lz58+/9NnXfLe7uORx+HDAvWmpnvhV37nDXvn8dqJR7pWKTFeVfqYWUPfngvU7Rq0ggqBwuvikA+F8gN+AtFzIFWGFOSTJOxnSs9JzNDQgCya6fnb0z6067lb/mrjbcON4STYe52FNyAo1jXd8veeO7J3jv3kzN5pRxmTEyFxgezZFjG+uIK8IncIY05AwigaZyBiAq0MlzgEPK/A7EGWDOtMTkcfh2F2nHcKu13iHeMdmZ47tfSYV9hzoMCGDXU+sgEhDfDK+kqtX1Ff+OBi/ps9ew8qI2VnGSIGKuKdOsehs9PbVg0LrBJGqklJXgPTaPzLHUJFkD37qhOnNFgxPf01DLnk+/076b1bPvIvt90bFnp0pGlnefqNYYORpj37984e3H5Sz6cP1OzruvtajphYIUSWARO+gBHm/sSowjOccd63HHoTlSDOj7CNTSxxckkI8sBKIDWgQKCZ5wfipBETJ4qzR70TgTosB3uUTzi+cx6AjQvrK49sDVBfX6cRGpFdZ6ZX7qvJYjcJ5xyzdYJc/QfVHgs6GhdeKGfViD6ASjF+3UHCQAWGWDgRclJj7lnQZ+anvb9aOtX3B9v+5Obzt3zkO7ehMZwAoFnOXtz1I6P2pLc877n3L09/tJ+7r2vt7lh2xoh6FgHEaWKBOFhFZ5mjfCR8ZAvJfRryxBZKYahEeC0QTIkFEBxEF3kGg0bwM4WQTyvtZoExLWPa05lCq9I6y3MFP/Z8QPKEOn4YkYs+/gcnbZ9rLz3wyJRAyahFHj+rA9Qiz+uLCzz7OVc/8qF8/qEExc3wJPoiRJqYodSkvT3o7Sa/XDBNn1rx93u/fP3O785AQVjfIIyM2EfDFb4Fq9Mb39335/uMe99U26aYsNaknLg47suU7HmYUJYTXUvoKoos3xLyE8Rw4n0QzxASWEy4mGnoOQN8FpG1MG2kgDo/rIIjvUzw0oxltLtCj0y3cUKlc7KnIPJEl48FM5A8cbt/FTUJ0r5er5zokx7ZxZacS0QZKhJ2guROn0iREVPR0EYfIwADElUIiaqokBquJJz2JpxaaH+t99aetvnMC963s/kZbM5+GQs41HTAiOZOXrPO3v43seJt5w1/o4L/Z9J0z+pOdpEoCSeciPM63QghsodzoKohKZxMRKJw5+lfEcvScdFRTB+lwAIuxgtQonFYZWAT4zAkAsWAKDbeZfScUgTq+sFz4zMOXWMXffENlwy96ZpvHYz0BEeWADQa3MQ6ednfverEbT32NROPTKhRNpkCKs7H0KL5RVMngaI98C0oKamqn/CiKgp2Bmx62KS1ClILVB3/qscm1/VJ7Wtjf/qtOwHgvqLNSkqJHW/nadQCTXfKW4ZP21+VK/ai+wedrkDGneMKWA2x9QzWYBSzfcE+GonDvKg03VEjK5jzySmjFLgLSg2r6qnqVONoSYYNBJHE6t0LQ3kwETPCXpCiYPiTmYQx1XFoV7tDC89dOBfX4OD69Q3KhfxIEYC4+8ev6337RFVSN226fver3/1+wrayb68PY1/9jHUVz9igbIgNo+JheqBMJ1OT/LIvSzb2dXDDO/5q108uw+bskN0tzUMXfmTUYmTUrnrb84/bZ5J3PyLZW9q20ytTVpUT1ZSNzzSGnWqoyNf78UF+S8fFpdl9hkLFTneh2bToVuaiOTWvG/iwUIJGIQ6Bn3jKeT/4zEc3EqqaRIBNFE4NWl2H6dQmSwaohiMSFq6gJq9zL7ji5YsnB9O3T9tp5pqpWmWQZU8RmgJsFWT9jjBOoE7BHYXJFAwzaZh2GOivEpif98/Q5mP26U83Xn3D9giov8w3BSTAGgGNCPDoC7/6XS9euovkj7d32m9ruc68bLoDVnVqjAGUWKiY1KGuhDMIKWQpxfEcZ8+FkXJSMv/BJEAAUglVIPE+TTAZTASy3rfw/EVey0ggSyaNnEYEE3pMvU8hMI7grKNOV5H1M7WUUgDAegAjR5AANNY3aERHtDZ/6KRu22yevz9powvOVCibdioZiwpLJjLOTg9QJu1U6EDFme3O2m2mg73Htnj7H1914551pa6ae+JOXz9sMLZI0WwKRkbtrJEpAbqNkVE7/O7XLri/OnH5AzPTb5ux3UXdyS5gxSJhI4ZMQdcTuoIZIOY8lxBMEeDEHzMUBkEFLgEpjYqRIpeksUosHsJGLEEreHhaGBwOpmI4BhW1ioIlP8wq8toDIEcwlmAcw4KAFI8LOOTI7gvYUDfYspuwapFiS2wMeXSfAxgBRiCvf/3r+3544sG3TGTZe2Y67WO6e6dAGVkYNcqUu+aRxdOXiL0+Z1OUEjSMgGPjnTPP+EHQgOwJY77zqR/EHmMQ1TjC7AAKTp0P7hFYQgBjKIyoA5jEawgutbAbDazk8OQSVaBWgfYOKV0wMGSXfHfBqZe+/dr7H+vUkCdWAFQJWP/o39EcI2zxswKHw6HRVYsUW1Yq1o9oaaL6//fv3+A9ewJwwntf/tpJ6jRmMndqe/8MtGOtAYySUg4aiYteRHcBHoZQQfT8fkrIuQX84gfVHRZOA0kVBQBKLD5G/mANn+E4ZMJQPiso4QBJJ/WsoLH6nU8sC1D1IABpqkgrijRVHZwPunBwcN+Kj+rTfu/TPzjwWCeHHK3NoSiDN57+l7971v6s9dcTE1MXzoxPA11nmci4CBshKg8XLuYShN3OzBFuAA2LQHmOP0AKDHuun8A6BpLSTidQmAvgd7wWyCMOWiTYfDWazzrg0vyhODyc2BNI0SyGMUGaCjglWbDU8QW1Rff9+cpbTo3ux2PJA/BRufiN4QTNpqvX6z0nfPC3P7yjdfCHu/cevHBm96RDG+JZeQwRMYhNjh7KYyyvi33JWQNHkGjB1x5GzOfZyDg73qHIAjrO8QhACGfDKVypaJXXMUJGk4T8xHPxlLau/B7nBxBprDNoqC4G9jMh1Z7eGthVthIgDW3wY20cSY667mA0gJERe/p7XnH+9/vbn5icbD2zvXMKLOTYsBEpTbEsQHp5X0CRoqHC+Y+DoKUE7SKfCKIQnOf1CAp5AfZ0MjkyKcwUzJmqJGT2jPoIRwsW8SLg986fFe/wcRwyFZzM+P0ccBEZujpQq4GmamP+RJs4/4Oe9AIQPHzCCE7+4Lr3P9KZXD+xZ9LoeGYNJ0ZYjb8UpWFTWpBLMpVKsiqBHSzQyGq5OFv6LMdMXjCyUTPEyx78B5BX+RRrA/FzHDQGeyETFyKLCFuQEoo9wNhigwvB+xVKHEgxvXPQm1XQ3mt+GOcs/+doD/clXPvst790yfalPZ/b7qZe1t45oXAQTpLEieY5+pgX9WOBwxg6pmJdCTlwxKtsLe3ckH4tVjaMeQs7Ps4nEp1NQkEloGcUQqI8lIwahmNfQzxT4DOOzqNIwULOEfbmFJp4ZVPl1KTT0mndeeBHXgAeO5FkclQs/sioPfHdF593/xB/dXJqcnm2e8YykVGAI49rROJKEIIwwsG3hmk4no+fKxQFIQ6k4rh6IdsfjsMvTEjVQyQA17gAbqhQTvBH7KuFRAWLOYUxssI+vZtnGZl9ljF8iagDG879DhXys4MckFmReQOGq63KHX/z3m9vU1Uioie1AMQQz578vksu3Zfqpyf2TaWY7lrDnDiVfPHiANKYd89nrRIRcZgBmlcYpeDs11kMxMUEkCAIOSC1pK79PGAtOZThu6XQBH4YZKlII2XSShTJfs9UHOjvPaxdY5RCBGWBiE8QdeF08VA/1baarwPA+k1rDAD7ZBWAPL4/ceR3378/dR88uH2Pmo6KmiQRJ2CJu5ryXUo+OlOIdMMs2sQD90DExCDNF1WDy56He1pCl1GB6KJwUIJTmQ+JEOQSpGGqKIdZBxIo61W0CAVjatlniH3YKZqbIM9dKL4cTL4PQp3CgCFONO1JzeB0dWri+/v+GQBG1oy6J117+KGLf+zIa/5ud1U/uP/h/Y4sQ4j9CO4QelGOA4zZF4AUFsQS/XXyjCFdcsjIhcyq+JnVJKKeHTQaDA42G7kXTxpTvVzsXAmAUCXPNxjTxiHMowgWCY89eKQII2NYF6MLHwZqKIlTGCYZtIVRZGC3aGkPVWd0w9V/ffv2DRrALE9CjqBi5//V739yF3cub23dbw18CT3vBQjhl9+hjFiAVTUqKg5ESURXUJGVdFA4IvHWm8lEVy738APNPIQLNWyKsNKX/zT3/inu8nzoNeXhIeL4eA4YRipC0xgx5M4mB02gcWAgQVhgyICZNOm3fKz2SPLr7KNQULOJJyVBRL74J3zo9Z/ebbLLpx86YJmSJNpbgt9xMalD5VhKw1pSqMupilfKkMLzA6AsUBZ13IVyVir+RfBR4Q+EHT4rOZTDeoNmiHCxMmQs4BvjXSP2QTkMStd8lKzkg6VKcHYVrw2U0e2qLFg2h/vHK1/++zff/Ms6CuqcJ5cGaDQM1o3Ykz742o/vhH3rzLYDNoVJnEi4wKHeqgpS9qpZS2NnNQdfsvrhpOovO/FsKck9uIDQ1EyBNDbzaQ4tphhLgkghpD5lXJpfK6Kz4vpAQFo4f6qh5s855MuHehRMS+EzwPhckhp/HmMYKlAzILSka8a7t069T1WJ1pM+6Shihjc2EoyM2JMbr71yb9W8Y+bhg1kCeE9fJB8m7gGZfgcVMHAuhrYTHZoZIxCzClRVw7QYscHCR5kQKFzeX6RFqJjjAkSDqSlss0rMEAaQS4B8l3sX9JA0spS0gIe9l04Ym2DERwZMjIydW7FiPvfsSq782sgtO9ZhHeNxZhk1v/HFbwwno2+6xp7wgd/7wwM99NGDD++3rJwIiMiVRobluXqdneUrnisrLAQZyAPOfIkn6gcfIxB5V5x8K7HmvR1KymAmyukkwld4ufLuJpUqL1SOHosIgUrpZyoofij0KOZwstytCJEBR3PGMKkgI2cXnjiYrLC171z3iv/1jrrWTZOagicVUeSGuhld17Qn/9krL9xXpc9M7Bx3RsmIhnnreSJldheNiuQCQKrq6ZogFOcvKwmRGlXKcga54LIJJEzs81ohLKAwNFH1yeE4RAIRKxBdbi1JRzkTqKXe/xDiURwOGdlKJBigyGIWysAxf+Dbwb3AiGXpXZwmK8zQztZN+/8QqmiuL6MRnwwaoNFgXH6VrPyT+skHFvf+y4G9U73adfCV9LDoormtpxwtqRFmJ6xwADlSdSRkVdH1yRFSKNswOkQAuAJ26dng4AXGAmKh7ECckNfzLiB2eNZCl3c5SsgdlCo8AcFbpKOpBCvXItwIEQQz5wqOKZaUWWgIOPGYhbb3Xnfxd6+8aUt91ZgZu3xMnjwzgxSEPYv4OVhV2/20/pv2dtsnuqmOGJBRpzGe9w5YDtj0HjWJCod0D5QcABsqOZkK2hBkFJvFVKSsscmPDREC+8/mkyT9pB/NMb+kRGzUpwV9H1ABDyi1BVJBTlFClxRJwsgQUi5QoRCOkF/WIBAEEh0CHb98HlcfbL3uB398w03DG4eTGy++0T2phkYNo5FsvfwqR68786o9CS52u6YtMSd544dEnVniAInFnkLzZ1BY314SgjKFI1KBwEIlI+8pupAoCNPiSEjh4OmnKISXJq/7Fns7BoUlrg/kXkDBCsI5GxVR8X/uVAa4Tl5Kopg00qKpJAHUquO5ZJYfP8/1P+De9JPLb/rH4Y2NZHTtNfbJxRMYyrqnfPD3X7Orz3xtfPs+a5QT3y8QULQ29lr7ypuG3msKs+XJ7+5MverPVDUre4Qk2oaIVQ6JFyUl0opygADkad+A21EiNagRIQ3z6FlVlcijSpgoFQYrF1NLc/4fU7qMOSFJgIFzxGsFuHnQM7FPWBKAk0SFu666rDc5tr9376L9ld/7/ju//p3hjcPJ6GGYIWQOu93/40/pmfbXy3cPpjfs3z9ZSbrC6tmgQvIuH63td4rkXRj+dfXdhKEIGEyBbziDwoUm0YCt8YV6Yh+sUxwPFgJ99lGwg9cIjPBWDaEigZxXGmRAYIqlxZyGjnIKOsqLB7mblw+2zNvHw9haDf0DJHBKGQ+smMdL+vrvWLSle/EP3n/dHYdr8Q9/HmDVKiIi3TWn+vfjmR2idlfDBF5oIITIqzF0yHRoKFQlEkNrqM+EQDHM4iYwnGZBl3sYJ6mqwKmTTAVd9YkfUVUb+o6JVJVU2+S0rSptEnShmkWMuKpacpqRaAZRUQm80apFQ4lKkRlUzuFgWnZmAah4pqosgfCSXjP3mLl2SSf54DN//9rn/+DDN90bmVTwpJsXsKFusG6dO+Ejb7xsd5UuslunLJlKok7y3E0xyq0U72gpayZq1XvvMaJiKETJX9YSGlkD/7eKE+u7DwP3DLHPt/nMUGaIklASVCgy7y9IAqKKEoz/Ls3UqxDjtU6A7+QuXAExplIqOTaTEBNUSTSzQgknZk7NDM7vwaDot4d2dhs//+ub7vgVAbiywc11I4d1epg5nKr/BdkDx2ybX7l24uB0hbrK3syGsmiI91ln02XkwVs536shlxuWIeRwLRQSqNui8RfK8YDEIIoQO4bP+HjDQrkbH7IzIGKq+nxAqXpPZAwxg307WZ4xLnEBUkELInAqpBBJmKmWUqW/yr19PXZeb+3bS1qVy+/5r9/6wK7v/+t2z1A2BjyO/H9HlgZY7xXtvR95w99NTE0P6XS3K0wJrINazT3+fJlFSw2Y6nE9cfSnz9UYFcmgJAR1EOkWRHzEAojvQvUks0FsHHzHlYNAQGooZG4BdSoQDyOmBASGoAWSROP0X4bxsD6JbWOE2McXXRYBsRFSQ6CUjakamGqKigBphX9R5eS6BTP42s/XX7flIQDQhh+IcZh3/eEVgA11Axpxv/Wxt9R3LxlYR/c+glpPT9VBQTaNM99jUtZ7/FnsF9f89TwMFDE+RyBpPkNejQ2ePQf0RleELFQF7LGVIQQjQNkXjFQULORJxWOmJ4lRvEb7w5wQ+UYNcNA2Qa0Te+AGxeOejdxyynsrhG2VlMcAbJ5v9da7PnzTXQTo9qgRV40R6De38IdPALZ4Tju3p7WzL3N/mE5rRzOXgURhlRzUwTkYZjImgfMBniNRH4lZFScxLPARPIwJ/3FuxJz1f00ipHBOrQvXlpUAA5OoJw4O6V/HzrdfOlEYJsOGIB6XG4ghqKAHARyLGDZklH2NmA1M4LF1vvjcrggmEpW9i2equ370hesmoz7fGQPF2Mz6GxoQ9eTqDMKRP+MQzTr79rc1gpGRJySXf/QIQKPBwwCPHgpmX7WouCixEbR5FC/8ypV6pC72U7enbk/dnro9dXvqVrr9v2uPKdl/A5bEAAAAAElFTkSuQmCC';

const BUY_BOT_NAME   = 'BloomBuy';
const BUY_BOT_AVATAR = BOT_AVATAR;

const _svgEsc = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');

function _botFmtUsd(v) {
  v = parseFloat(v) || 0;
  if (v >= 1e9) return '$' + (v/1e9).toFixed(2) + 'B';
  if (v >= 1e6) return '$' + (v/1e6).toFixed(2) + 'M';
  if (v >= 1e3) return '$' + (v/1e3).toFixed(1) + 'K';
  return '$' + v.toFixed(2);
}
function _botFmtPrice(p) {
  p = parseFloat(p) || 0;
  if (p === 0) return '$0';
  if (p < 0.0001) {
    // Very small prices: show 4 significant digits in fixed notation instead of
    // scientific notation (e.g. $0.000004492, not $4.492e-6).
    const leadZeros = (p.toFixed(20).match(/^0\.(0*)/) || [,''])[1].length;
    return '$' + p.toFixed(Math.min(leadZeros + 4, 18));
  }
  if (p < 1) return '$' + p.toFixed(6);
  return '$' + p.toLocaleString('en-US', { maximumFractionDigits: 4 });
}

// Bloombark-styled result card rendered as an SVG data-URL image
function _botSvgCard(info) {
  const sigColor = info.signal === 'BULLISH' ? '#27c97f' : info.signal === 'BEARISH' ? '#f0484b' : '#f5a623';
  const chgColor = info.change24h >= 0 ? '#27c97f' : '#f0484b';
  const chgText  = (info.change24h >= 0 ? '+' : '') + info.change24h.toFixed(2) + '%';
  const stats = [
    ['MARKET CAP', _botFmtUsd(info.marketCap)],
    ['LIQUIDITY',  _botFmtUsd(info.liquidity)],
    ['VOL 24H',    _botFmtUsd(info.volume24h)],
    ['BUY RATIO',  info.buyRatio + '%'],
  ];
  const statCells = stats.map(([label, val], i) => `
    <g transform="translate(${28 + i * 126}, 268)">
      <text x="0" y="0" font-family="Menlo, monospace" font-size="9" fill="#6b7280" letter-spacing="1">${label}</text>
      <text x="0" y="22" font-family="Menlo, monospace" font-size="15" font-weight="bold" fill="#e2e8f0">${_svgEsc(val)}</text>
    </g>`).join('');

  const svg = `<svg width="560" height="330" viewBox="0 0 560 330" xmlns="http://www.w3.org/2000/svg">
  <rect width="560" height="330" rx="16" fill="#13161d"/>
  <rect x="0.5" y="0.5" width="559" height="329" rx="16" fill="none" stroke="#27c97f40"/>
  <rect x="0" y="0" width="560" height="52" rx="16" fill="#161a23"/>
  <rect x="0" y="36" width="560" height="16" fill="#161a23"/>
  <clipPath id="headerLogoClip"><circle cx="30" cy="26" r="9"/></clipPath>
  <image href="${BOT_AVATAR_INLINE}" x="21" y="17" width="18" height="18" clip-path="url(#headerLogoClip)" preserveAspectRatio="xMidYMid slice"/>
  <text x="48" y="30" font-family="Menlo, monospace" font-size="13" font-weight="bold" fill="#e2e8f0" letter-spacing="2">BLOOMBARK</text>
  <text x="152" y="30" font-family="Menlo, monospace" font-size="9" fill="#6b7280" letter-spacing="1">AI TOKEN SCAN</text>
  <rect x="${560 - 118}" y="14" width="96" height="24" rx="12" fill="${sigColor}22" stroke="${sigColor}"/>
  <text x="${560 - 70}" y="30" font-family="Menlo, monospace" font-size="11" font-weight="bold" fill="${sigColor}" text-anchor="middle">${info.signal}</text>

  <circle cx="46" cy="94" r="20" fill="#27c97f1f"/>
  <text x="46" y="100" font-family="Menlo, monospace" font-size="16" font-weight="bold" fill="#27c97f" text-anchor="middle">${_svgEsc((info.symbol || '?')[0])}</text>
  ${info.imageDataUri ? `<clipPath id="tokenLogoClip"><circle cx="46" cy="94" r="20"/></clipPath>
  <image href="${info.imageDataUri}" x="26" y="74" width="40" height="40" clip-path="url(#tokenLogoClip)" preserveAspectRatio="xMidYMid slice"/>` : ''}
  <text x="78" y="88" font-family="Menlo, monospace" font-size="19" font-weight="bold" fill="#e2e8f0">${_svgEsc(info.symbol)}</text>
  <text x="78" y="106" font-family="Menlo, monospace" font-size="11" fill="#6b7280">${_svgEsc((info.name || '').slice(0, 34))}</text>
  ${(() => {
    const badgeX = 78 + Math.min(String(info.symbol||'').length, 12) * 12 + 10;
    const badgeW = info.chain.length * 8 + 18;
    return `<rect x="${badgeX}" y="72" width="${badgeW}" height="19" rx="9.5" fill="#27c97f15" stroke="#27c97f50"/>
  <text x="${badgeX + badgeW / 2}" y="85" font-family="Menlo, monospace" font-size="9" font-weight="bold" fill="#27c97f" letter-spacing="1" text-anchor="middle">${_svgEsc(info.chain.toUpperCase())}</text>`;
  })()}

  <text x="28" y="168" font-family="Menlo, monospace" font-size="9" fill="#6b7280" letter-spacing="1.5">CURRENT PRICE</text>
  <text x="28" y="204" font-family="Menlo, monospace" font-size="32" font-weight="bold" fill="#27c97f">${_svgEsc(_botFmtPrice(info.price))}</text>
  <text x="28" y="228" font-family="Menlo, monospace" font-size="13" font-weight="bold" fill="${chgColor}">${chgText} (24h)</text>

  <g transform="translate(360, 150)">
    <rect x="0" y="0" width="172" height="86" rx="12" fill="#161a23" stroke="${sigColor}40"/>
    <text x="86" y="22" font-family="Menlo, monospace" font-size="9" fill="#6b7280" letter-spacing="1.5" text-anchor="middle">AI PREDICTION</text>
    <text x="86" y="50" font-family="Menlo, monospace" font-size="19" font-weight="bold" fill="${sigColor}" text-anchor="middle">${info.signal}</text>
    <text x="86" y="72" font-family="Menlo, monospace" font-size="10" fill="#8b92a8" text-anchor="middle">Confidence: ${info.confidence}%</text>
  </g>

  <line x1="28" y1="250" x2="532" y2="250" stroke="#1e2235"/>
  ${statCells}
  <text x="28" y="318" font-family="Menlo, monospace" font-size="8" fill="#4b5563">${_svgEsc(info.address)}</text>
  <text x="532" y="318" font-family="Menlo, monospace" font-size="8" fill="#4b5563" text-anchor="end">bloombark terminal · not financial advice</text>
</svg>`;
  return 'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64');
}

async function _botSend(roomKey, text, imgData = null, reply = null, identity = null) {
  const entry = {
    id:   Date.now() + Math.random().toString(36).slice(2,6),
    room: roomKey,
    wallet: null,
    displayName: identity?.name   || BOT_NAME,
    avatar:      identity?.avatar || BOT_AVATAR,
    text,
    imgData,
    ts: Date.now(),
    isBot: true,
    replyTo:   reply?.id   || null,
    replyName: reply?.name || null,
    replyText: reply?.text || null,
  };
  await dbRun(`INSERT IGNORE INTO chat_messages (id,room,wallet,display_name,avatar,text,img_data,ts,reply_to,reply_name,reply_text)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`, [entry.id, entry.room, entry.wallet, entry.displayName, entry.avatar, entry.text, entry.imgData, entry.ts, entry.replyTo, entry.replyName, entry.replyText]);
  broadcastChat(roomKey, { type: 'chat_msg', msg: entry, online: onlineCount() });
}

async function _chatBotAnalyze(ca, roomKey, reply = null) {
  // Cooldown: don't re-analyze the same CA more than once per 2 minutes
  const last = _botCooldown.get(ca.toLowerCase());
  if (last && Date.now() - last < CONFIG.chatBotCooldownMs) return;
  _botCooldown.set(ca.toLowerCase(), Date.now());

  try {
    // Token data from DexScreener (best pair on a supported chain)
    const dsRes = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${ca}`, { timeout: 8000 });
    const pairs = (dsRes.data?.pairs || [])
      .filter(p => BOT_CHAINS.has(p.chainId))
      .sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
    if (!pairs.length) {
      await _botSend(roomKey, `🔎 I spotted a contract address but couldn't find that token on a supported EVM chain (Ethereum, Base, Arbitrum, Polygon, Optimism, Robinhood).`, null, reply);
      return;
    }
    const p = pairs[0];

    // AI prediction from our own endpoint
    let signal = 'NEUTRAL', confidence = 50;
    try {
      const pr = await axios.post(`${INTERNAL_API_BASE}/api/predict`,
        { address: ca, chain: p.chainId }, { timeout: 15000 });
      if (pr.data?.success !== false && pr.data?.signal) {
        signal     = String(pr.data.signal).toUpperCase();
        confidence = Math.round(pr.data.confidence || 50);
      }
    } catch (_) {}
    if (!['BULLISH', 'BEARISH', 'NEUTRAL'].includes(signal)) signal = 'NEUTRAL';

    const buys  = p.txns?.h24?.buys  || 0;
    const sells = p.txns?.h24?.sells || 0;
    const buyRatio = buys + sells > 0 ? Math.round(buys / (buys + sells) * 100) : 50;

    const info = {
      address:   p.baseToken.address,
      symbol:    p.baseToken.symbol || '?',
      name:      p.baseToken.name || '',
      chain:     p.chainId,
      price:     parseFloat(p.priceUsd || 0),
      change24h: parseFloat(p.priceChange?.h24 || 0),
      marketCap: parseFloat(p.marketCap || p.fdv || 0),
      liquidity: parseFloat(p.liquidity?.usd || 0),
      volume24h: parseFloat(p.volume?.h24 || 0),
      buyRatio, signal, confidence,
      // Fetched (and inlined as base64) just below — an <image href="https://...">
      // left as an external reference doesn't reliably load here: this SVG
      // gets embedded via <img src="data:image/svg+xml;base64,...">, and
      // browsers treat img-embedded SVGs as a restricted "image context"
      // where nested external resource loads (especially through a redirect,
      // which this CDN URL always issues) frequently fail silently and fall
      // back to a generic broken-image glyph instead of the real logo.
      imageDataUri: null,
    };
    try {
      const logoUrl = `https://dd.dexscreener.com/ds-data/tokens/${p.chainId}/${p.baseToken.address}.png`;
      const logoRes = await axios.get(logoUrl, { responseType: 'arraybuffer', timeout: 5000 });
      const contentType = logoRes.headers['content-type'] || 'image/png';
      info.imageDataUri = `data:${contentType};base64,${Buffer.from(logoRes.data).toString('base64')}`;
    } catch (_) { /* no logo available — card falls back to the letter avatar */ }

    const sigEmoji = signal === 'BULLISH' ? '🟢' : signal === 'BEARISH' ? '🔴' : '🟡';
    const chg = (info.change24h >= 0 ? '+' : '') + info.change24h.toFixed(2) + '%';
    const text =
      `${sigEmoji} ${info.symbol} (${info.chain.toUpperCase()}) — ${_botFmtPrice(info.price)} (${chg} 24h)\n` +
      `AI Prediction: ${signal} · ${confidence}% confidence\n` +
      `MCap ${_botFmtUsd(info.marketCap)} · Liq ${_botFmtUsd(info.liquidity)} · Vol24h ${_botFmtUsd(info.volume24h)} · Buys ${buyRatio}%`;

    await _botSend(roomKey, text, _botSvgCard(info), reply);
  } catch (e) {
    console.error('[chatbot]', e.message);
  }
}

// ─── BloomBuy poller: watches recent trades for the configured token, posts a
// card to $BBRK Moon for every BUY (sells intentionally skipped). ─────────────
const MOON_BOT_ROOM    = 'moon';
// Guard against a stray/misconfigured MOON_BOT_CHAIN env value (e.g. an
// address pasted into the wrong field) — only accept a value that's
// actually a known chain key, otherwise fall back to the default.
const MOON_BOT_CHAIN   = (process.env.MOON_BOT_CHAIN && GECKO_NETWORK[process.env.MOON_BOT_CHAIN])
  ? process.env.MOON_BOT_CHAIN : 'robinhood';
// Token to monitor comes from app_config.contract_address — the SAME field the
// landing page CA uses — so this automatically points at $BBRK once it's live.
// Until then (value still 'coming_soon'), fall back to a well-known, actively
// traded token so the channel is verifiable right now: HOODER/Robinhood chain.
const MOON_BOT_TEST_TOKEN = process.env.MOON_BOT_TEST_TOKEN || '0x30c9c51e06faa8cc71e4c101a69a9ed8d01ee91a';
const MOON_BOT_POLL_MS    = (parseInt(process.env.MOON_BOT_POLL_SEC) || 45) * 1000;

let _moonBotPool   = null;  // { poolAddress, geckoNetwork, chainId, tokenAddress, tokenSymbol, quoteSymbol }
let _moonBotPoolAt = 0;
let _moonBotLastTs = 0;     // only trades newer than this get considered
let _moonBotSeenTx = new Set();
let _moonBotLastError = null;
let _moonBotBackoffUntil = 0;  // skip polls until this timestamp after a 429

async function _resolveMoonBotToken() {
  const caRow = await dbGet("SELECT value FROM app_config WHERE `key`='contract_address'");
  const isLive = /^0x[0-9a-fA-F]{40}$/.test(caRow?.value || '');
  return { address: isLive ? caRow.value : MOON_BOT_TEST_TOKEN, isLive };
}

async function _resolveMoonBotPool() {
  if (_moonBotPool && Date.now() - _moonBotPoolAt < 5 * 60 * 1000) return _moonBotPool;
  try {
    const { address } = await _resolveMoonBotToken();
    const { data } = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${address}`, { timeout: 8000 });
    const pairs = (data?.pairs || [])
      .filter(p => p.chainId === MOON_BOT_CHAIN)
      .sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
    if (!pairs.length) {
      _moonBotLastError = { message: `no ${MOON_BOT_CHAIN} pairs found for ${address} on DexScreener`, at: new Date().toISOString() };
      return null;
    }
    const p = pairs[0];
    const pool = {
      poolAddress:  p.pairAddress,
      geckoNetwork: GECKO_NETWORK[MOON_BOT_CHAIN] || 'eth',
      chainId:      MOON_BOT_CHAIN,
      tokenAddress: p.baseToken?.address || address,
      tokenSymbol:  p.baseToken?.symbol  || '?',
      quoteSymbol:  p.quoteToken?.symbol || 'ETH',
      marketCapUsd: p.marketCap || p.fdv || null,
    };
    // Pool changed (token swapped, e.g. test token → real $BBRK at launch) —
    // reset dedupe state so we don't compare timestamps across two pools.
    if (!_moonBotPool || _moonBotPool.poolAddress !== pool.poolAddress) {
      _moonBotLastTs = 0;
      _moonBotSeenTx = new Set();
    }
    _moonBotPool = pool;
    _moonBotPoolAt = Date.now();
    return pool;
  } catch (e) {
    _moonBotLastError = { message: `pool resolve: ${e.message}`, at: new Date().toISOString() };
    console.error('[moonbot] pool resolve failed:', e.message);
    return null;
  }
}

const _moonFmtAmt = n => {
  n = parseFloat(n) || 0;
  if (n >= 1000) return n.toLocaleString('en-US', { maximumFractionDigits: 2 });
  return n.toLocaleString('en-US', { maximumFractionDigits: n < 1 ? 6 : 4 });
};

let _moonBotPolling = false;
async function _pollMoonBotTrades() {
  if (_moonBotPolling) return; // avoid overlapping polls if one runs long
  if (Date.now() < _moonBotBackoffUntil) return; // rate-limited — sit out until backoff clears
  const enabledRow = await dbGet("SELECT value FROM app_config WHERE `key`='moonbot_enabled'");
  if (enabledRow && enabledRow.value === 'false') return; // toggled off via /api/admin/config
  _moonBotPolling = true;
  try {
    const pool = await _resolveMoonBotPool();
    if (!pool) return;
    const url = `https://api.geckoterminal.com/api/v2/networks/${pool.geckoNetwork}/pools/${pool.poolAddress}/trades?limit=20`;
    const { data } = await axios.get(url, { timeout: 10000, headers: GECKO_HEADS });
    const raw = (data?.data || []).slice().reverse(); // oldest → newest, post in order
    const isFirstRun = _moonBotLastTs === 0 && _moonBotSeenTx.size === 0;
    let maxTs = _moonBotLastTs;

    for (const t of raw) {
      const a = t.attributes || {};
      const tsMs   = a.block_timestamp ? new Date(a.block_timestamp).getTime() : 0;
      const txHash = a.tx_hash || '';
      if (!tsMs || tsMs <= _moonBotLastTs || (txHash && _moonBotSeenTx.has(txHash))) continue;
      if (txHash) {
        _moonBotSeenTx.add(txHash);
        if (_moonBotSeenTx.size > 500) _moonBotSeenTx = new Set([..._moonBotSeenTx].slice(-250));
      }
      if (tsMs > maxTs) maxTs = tsMs;

      // First poll after boot just establishes the baseline — don't spam-post
      // the last 20 historical trades on every restart.
      if (isFirstRun) continue;
      if (a.kind !== 'buy') continue; // sells intentionally not posted

      const ethAmount   = parseFloat(a.from_token_amount || 0); // quote (ETH) spent
      const tokenAmount = parseFloat(a.to_token_amount   || 0); // base token received
      const usdValue    = parseFloat(a.volume_in_usd || 0);
      const priceEth    = parseFloat(a.price_to_in_currency_token || 0);
      const priceUsd    = parseFloat(a.price_to_in_usd || 0);
      const wallet = a.tx_from_address ? shortAddr(a.tx_from_address) : '—';

      const text = `🟢 BUY ALERT\n\n` +
        `$${pool.tokenSymbol}\n` +
        `CA: ${pool.tokenAddress}\n` +
        `MCAP: ${pool.marketCapUsd ? _botFmtUsd(pool.marketCapUsd) : '—'}\n` +
        `Buy: ${_moonFmtAmt(ethAmount)} ${pool.quoteSymbol} (${_botFmtUsd(usdValue)})\n` +
        `Price ETH: ${_botFmtPrice(priceEth).replace('$', '')} ${pool.quoteSymbol}\n` +
        `Price USD: ${_botFmtPrice(priceUsd)}\n` +
        `Received: ${_moonFmtAmt(tokenAmount)} ${pool.tokenSymbol}\n` +
        `Wallet: ${wallet}`;
      await _botSend(MOON_BOT_ROOM, text, null, null, { name: BUY_BOT_NAME, avatar: BUY_BOT_AVATAR });
    }
    if (maxTs > _moonBotLastTs) _moonBotLastTs = maxTs;
    _moonBotLastError = null;
    _moonBotBackoffUntil = 0;
  } catch (e) {
    _moonBotLastError = { message: e.message, at: new Date().toISOString() };
    // Rate-limited by GeckoTerminal — back off well past the normal poll
    // interval so we stop hammering it and let the limit reset.
    if (e.response?.status === 429) _moonBotBackoffUntil = Date.now() + 3 * 60 * 1000;
    console.error('[moonbot] poll failed:', e.message);
  } finally {
    _moonBotPolling = false;
  }
}
setTimeout(_pollMoonBotTrades, 8000);
setInterval(_pollMoonBotTrades, MOON_BOT_POLL_MS);

// Temporary diagnostic — internal poller state isn't visible any other way
// without log access. Same admin token gate as /api/admin/query.
app.get('/api/admin/moonbot-status', async (req, res) => {
  if (!ADMIN_QUERY_TOKEN) return res.status(404).json({ error: 'not enabled' });
  const token = req.get('x-admin-token') || req.query.token || '';
  if (token !== ADMIN_QUERY_TOKEN) return res.status(403).json({ error: 'forbidden' });
  const enabledRow = await dbGet("SELECT value FROM app_config WHERE `key`='moonbot_enabled'");
  res.json({
    enabled: !(enabledRow && enabledRow.value === 'false'),
    pool: _moonBotPool,
    poolResolvedAt: _moonBotPoolAt ? new Date(_moonBotPoolAt).toISOString() : null,
    lastTradeTs: _moonBotLastTs ? new Date(_moonBotLastTs).toISOString() : null,
    seenTxCount: _moonBotSeenTx.size,
    currentlyPolling: _moonBotPolling,
    lastError: _moonBotLastError,
    backoffUntil: _moonBotBackoffUntil ? new Date(_moonBotBackoffUntil).toISOString() : null,
    serverNow: new Date().toISOString(),
  });
});

wss.on('connection', (ws) => {
  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw);

      // ── price subscription ──
      if (msg.type === 'subscribe') {
        const seed = parseFloat(msg.price) || 0.000001;
        subscribers.set(ws, { contract: msg.contract, price: seed, seedPrice: seed, lastReseed: Date.now() });
        ws.send(JSON.stringify({ type: 'subscribed', contract: msg.contract }));
        return;
      }

      // ── chat: join ──
      if (msg.type === 'chat_join') {
        const wallet = msg.wallet || null;
        // Load profile from DB for avatar + saved name
        const profile = wallet ? await dbGet('SELECT display_name, avatar FROM user_profiles WHERE wallet=?', [wallet]) : null;
        const displayName = profile?.display_name || msg.displayName || shortAddr(wallet) || 'Anon#' + Math.floor(Math.random() * 9999);
        const avatar = profile?.avatar || null;
        const isAdmin = isAdminWallet(wallet);
        chatUsers.set(ws, { wallet, displayName, avatar, joinedAt: Date.now(), isAdmin });
        // Send history from DB (last 100 per room). Gated rooms only include
        // history when the user's wallet passes the gate.
        const history = {};
        const gates = {};
        const roomRows = {};
        for (const k of Object.keys(chatRooms)) {
          if (CHANNEL_GATES[k]) {
            const g = await checkChannelGate(k, wallet);
            gates[k] = g;
            if (!g.ok) { history[k] = []; continue; }
          }
          roomRows[k] = await dbAll('SELECT * FROM chat_messages WHERE room=? ORDER BY ts DESC LIMIT ?', [k, MAX_CHAT_HISTORY]);
        }
        // Diamond badge = same check as Holders channel access (inline reuse
        // of checkChannelGate, same $90 threshold, same cache) — whoever can
        // open Holders gets the badge, and loses it the moment they can't.
        // Resolved once per unique wallet across all rooms' history, not per message.
        const _uniqueWallets = [...new Set(Object.values(roomRows).flat().map(r => r.wallet).filter(Boolean))];
        const _diamondEntries = await Promise.all(_uniqueWallets.map(async w => [w, (await checkChannelGate('holders', w)).ok]));
        const _diamondMap = Object.fromEntries(_diamondEntries);
        for (const k of Object.keys(roomRows)) {
          history[k] = roomRows[k].reverse().map(r => ({
            id: r.id, room: r.room, wallet: r.wallet, displayName: r.display_name,
            avatar: r.avatar, text: r.text, imgData: r.img_data, ts: r.ts,
            isBot: (r.display_name === BOT_NAME || r.display_name === BUY_BOT_NAME) && r.wallet == null,
            isSenderAdmin: isAdminWallet(r.wallet),
            isDiamondHolder: r.wallet ? !!_diamondMap[r.wallet] : false,
            replyTo: r.reply_to, replyName: r.reply_name, replyText: r.reply_text,
            edited: !!r.edited,
          }));
        }
        const mutedUntil = wallet ? await _mutedUntil(wallet) : null;
        ws.send(JSON.stringify({ type: 'chat_history', history, gates, online: onlineCount(), isAdmin, mutedUntil }));
        broadcastChat('*', { type: 'chat_online', online: onlineCount() });
        return;
      }

      // ── chat: send message ──
      if (msg.type === 'chat_msg') {
        const user = chatUsers.get(ws);
        if (!user) return;
        const room = chatRooms[msg.room];
        if (!room) return;
        if (room.readOnly) return; // e.g. $BBRK Moon — a bot-only feed, no user posts
        // Muted wallets can't send until their mute expires
        if (user.wallet) {
          const mutedUntil = await _mutedUntil(user.wallet);
          if (mutedUntil) {
            ws.send(JSON.stringify({ type: 'chat_muted', mutedUntil }));
            return;
          }
        }
        // Token-gated channel: verify the user's wallet passes the gate
        if (CHANNEL_GATES[msg.room]) {
          const g = await checkChannelGate(msg.room, user.wallet);
          if (!g.ok) {
            ws.send(JSON.stringify({ type: 'chat_gate_denied', room: msg.room, minAmount: g.minAmount, symbol: g.symbol, balance: g.balance }));
            return;
          }
        }
        const text = String(msg.text || '').trim().slice(0, CONFIG.chatMsgMaxLen);
        const imgData = msg.imgData && typeof msg.imgData === 'string'
          && msg.imgData.startsWith('data:image/')
          && msg.imgData.length < 400000  // ~300KB raw — server-side backstop; client already compresses harder
          ? msg.imgData : null;
        if (!text && !imgData) return;
        // Reply target: resolve from DB so the snippet can't be spoofed by the client.
        let replyTo = null, replyName = null, replyText = null;
        if (msg.replyTo) {
          const tgt = await dbGet('SELECT id, display_name, text, img_data FROM chat_messages WHERE id=? AND room=?', [String(msg.replyTo), msg.room]);
          if (tgt) {
            replyTo   = tgt.id;
            replyName = tgt.display_name || 'Anon';
            replyText = (tgt.text || (tgt.img_data ? '📷 image' : '')).slice(0, 120);
          }
        }
        const entry = {
          id:   Date.now() + Math.random().toString(36).slice(2,6),
          room: msg.room,
          wallet: user.wallet,
          displayName: user.displayName,
          avatar: user.avatar || null,
          text,
          imgData,
          ts: Date.now(),
          isSenderAdmin: user.isAdmin,
          isDiamondHolder: user.wallet ? (await checkChannelGate('holders', user.wallet)).ok : false,
          replyTo, replyName, replyText,
        };
        // Persist to DB
        await dbRun(`INSERT IGNORE INTO chat_messages (id,room,wallet,display_name,avatar,text,img_data,ts,reply_to,reply_name,reply_text)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)`, [entry.id, entry.room, entry.wallet, entry.displayName, entry.avatar, entry.text, entry.imgData, entry.ts, entry.replyTo, entry.replyName, entry.replyText]);
        // Prune old messages per room (keep last CHAT_DB_PRUNE_LIMIT). The inner
        // SELECT is wrapped in a derived table because MySQL forbids selecting
        // from the same table being deleted from directly in a subquery.
        await dbRun(`DELETE FROM chat_messages WHERE room=? AND id NOT IN
          (SELECT id FROM (SELECT id FROM chat_messages WHERE room=? ORDER BY ts DESC LIMIT ?) AS keep)`,
          [entry.room, entry.room, CONFIG.chatDbPruneLimit]);
        broadcastChat(msg.room, { type: 'chat_msg', msg: entry, online: onlineCount() });

        // Bot: detect a contract address and auto-analyze it — only in the
        // designated room (Free Shill), threaded as a reply to this message.
        if (msg.room === BOT_REPLY_ROOM) {
          const caMatch = text.match(/0x[a-fA-F0-9]{40}/);
          if (caMatch) {
            const botReply = { id: entry.id, name: entry.displayName, text: (text || '📷 image').slice(0, 120) };
            _chatBotAnalyze(caMatch[0], msg.room, botReply).catch(() => {});
          }
        }
        return;
      }

      // ── chat: set display name ──
      if (msg.type === 'chat_setname') {
        const user = chatUsers.get(ws);
        if (!user) return;
        const name = String(msg.name || '').trim().slice(0, CONFIG.chatNameMaxLen);
        if (name) {
          user.displayName = name;
          if (user.wallet) await dbRun(`INSERT INTO user_profiles (wallet,display_name,avatar,updated_at) VALUES (?,?,?,UNIX_TIMESTAMP())
            ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), updated_at=VALUES(updated_at)`, [user.wallet, name, user.avatar || null]);
        }
        ws.send(JSON.stringify({ type: 'chat_nameok', displayName: user.displayName }));
        return;
      }

      // ── chat: edit own message ──
      if (msg.type === 'chat_edit') {
        const user = chatUsers.get(ws);
        if (!user || !user.wallet) return;                 // must be a wallet-identified user
        const row = await dbGet('SELECT id, room, wallet, img_data FROM chat_messages WHERE id=?', [String(msg.id || '')]);
        if (!row || row.wallet !== user.wallet) return;    // own messages only
        const text = String(msg.text || '').trim().slice(0, CONFIG.chatMsgMaxLen);
        if (!text && !row.img_data) return;                // don't allow blanking a text-only message
        await dbRun('UPDATE chat_messages SET text=?, edited=1 WHERE id=?', [text, row.id]);
        broadcastChat(row.room, { type: 'chat_edited', id: row.id, room: row.room, text });
        return;
      }

      // ── chat: delete message (own, or any message if admin) ──
      if (msg.type === 'chat_delete') {
        const user = chatUsers.get(ws);
        if (!user || !user.wallet) return;
        const row = await dbGet('SELECT id, room, wallet FROM chat_messages WHERE id=?', [String(msg.id || '')]);
        if (!row) return;
        const isOwn = row.wallet === user.wallet;
        if (!isOwn && !user.isAdmin) return;                // own messages, or any message if admin
        await dbRun('DELETE FROM chat_messages WHERE id=?', [row.id]);
        broadcastChat(row.room, { type: 'chat_deleted', id: row.id, room: row.room, byAdmin: !isOwn });
        return;
      }

      // ── admin: mute a wallet for N minutes (blocks chat_msg until it expires) ──
      if (msg.type === 'chat_mute') {
        const user = chatUsers.get(ws);
        if (!user || !user.isAdmin) return;
        const targetWallet = String(msg.wallet || '').toLowerCase();
        const minutes = Math.max(1, Math.min(43200, parseInt(msg.minutes) || 60)); // 1 min .. 30 days
        if (!_isAddr(targetWallet)) return;
        const mutedUntil = Date.now() + minutes * 60000;
        await dbRun(
          `INSERT INTO muted_wallets (wallet, muted_until, muted_by, reason) VALUES (?,?,?,?)
           ON DUPLICATE KEY UPDATE muted_until=VALUES(muted_until), muted_by=VALUES(muted_by), reason=VALUES(reason)`,
          [targetWallet, mutedUntil, user.wallet, String(msg.reason || '').slice(0, 280) || null]
        );
        await dbRun(`
          INSERT INTO alert_notifications (wallet, category, title, subtitle, detail, ts)
          VALUES (?,'muted',?,?,?,?)
        `, [
          targetWallet, 'You have been muted',
          `Muted for ${minutes} minute${minutes === 1 ? '' : 's'} in Community chat`,
          msg.reason ? `Reason: ${msg.reason}` : 'No reason was provided.',
          Date.now(),
        ]);
        ws.send(JSON.stringify({ type: 'chat_mute_ok', wallet: targetWallet, mutedUntil }));
        // Notify the muted user's live connection(s), if online, so their UI updates immediately.
        for (const [otherWs, otherUser] of chatUsers) {
          if (otherUser.wallet && otherUser.wallet.toLowerCase() === targetWallet && otherWs.readyState === WebSocket.OPEN) {
            otherWs.send(JSON.stringify({ type: 'chat_muted', mutedUntil }));
          }
        }
        return;
      }

      // ── admin: lift a mute early ──
      if (msg.type === 'chat_unmute') {
        const user = chatUsers.get(ws);
        if (!user || !user.isAdmin) return;
        const targetWallet = String(msg.wallet || '').toLowerCase();
        if (!_isAddr(targetWallet)) return;
        await dbRun('DELETE FROM muted_wallets WHERE wallet=?', [targetWallet]);
        ws.send(JSON.stringify({ type: 'chat_mute_ok', wallet: targetWallet, mutedUntil: null }));
        for (const [otherWs, otherUser] of chatUsers) {
          if (otherUser.wallet && otherUser.wallet.toLowerCase() === targetWallet && otherWs.readyState === WebSocket.OPEN) {
            otherWs.send(JSON.stringify({ type: 'chat_muted', mutedUntil: null }));
          }
        }
        return;
      }

    } catch (_) {}
  });

  ws.on('close', () => {
    subscribers.delete(ws);
    if (chatUsers.has(ws)) {
      chatUsers.delete(ws);
      broadcastChat('*', { type: 'chat_online', online: onlineCount() });
    }
  });
});

// Re-seed price from DexScreener every 60s to prevent drift
setInterval(async () => {
  const seen = new Set();
  for (const [, sub] of subscribers) {
    if (!sub.contract || seen.has(sub.contract)) continue;
    seen.add(sub.contract);
    try {
      const fresh = await fetchDexScreener(sub.contract);
      if (fresh?.price > 0) {
        for (const [, s] of subscribers) {
          if (s.contract === sub.contract) {
            s.seedPrice = fresh.price;
            // Snap current price closer to real if it has drifted >3%
            if (Math.abs(s.price - fresh.price) / fresh.price > 0.03) {
              s.price = fresh.price;
            }
          }
        }
      }
    } catch (_) {}
  }
}, CONFIG.priceReseedIntervalMs);

// Tick every PRICE_TICK_INTERVAL_MS — micro movement anchored tightly to seedPrice
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.readyState !== WebSocket.OPEN) return;
    const sub = subscribers.get(ws);
    if (!sub || !sub.seedPrice) return;

    // Mean-revert toward seed each tick, by priceMeanRevertFactor
    const drift = (sub.seedPrice - sub.price) * CONFIG.priceMeanRevertFactor;
    // Noise band around seed price (tight, never creates runaway candles)
    const noise = sub.seedPrice * rand(-CONFIG.priceNoisePct, CONFIG.priceNoisePct);
    // Hard clamp: never go outside ±priceClampPct of seedPrice
    const raw   = sub.price + drift + noise;
    sub.price   = Math.max(sub.seedPrice * (1 - CONFIG.priceClampPct), Math.min(raw, sub.seedPrice * (1 + CONFIG.priceClampPct)));

    const changePct = parseFloat(((sub.price - sub.seedPrice) / sub.seedPrice * 100).toFixed(3));
    const decimals  = sub.price < 0.000001 ? 12 : sub.price < 0.0001 ? 10 : sub.price < 0.01 ? 8 : 6;

    ws.send(JSON.stringify({
      type:      'tick',
      contract:  sub.contract,
      price:     parseFloat(sub.price.toFixed(decimals)),
      volume:    parseFloat(rand(5000, 100000).toFixed(2)),
      timestamp: Date.now(),
      change:    changePct,
    }));
  });
}, CONFIG.priceTickIntervalMs);

// ─── Wallet Tracker ───────────────────────────────────────────────────────────
const BLOCKSCOUT = { ethereum: chainCfg('ethereum').blockscout, base: chainCfg('base').blockscout, arbitrum: chainCfg('arbitrum').blockscout, robinhood: chainCfg('robinhood').blockscout };

function detectWalletChain(address) {
  if (/^0x[0-9a-fA-F]{40}$/.test(address)) return 'evm';
  return null;
}

// Resolve a token's USD price from DexScreener pairs, matching the right chain
// and the right side of the pair (priceUsd only refers to the BASE token).
// Scam clones on new chains mint themselves fake "liquidity" (even $Bs worth)
// with a misleading symbol like USDT/TAO but ~$0 real trading — so liquidity
// alone doesn't work as a spam filter. Require actual 24h trading volume instead.
const MIN_VOLUME_USD = CONFIG.minVolumeUsdFilter;
function _dsPriceFromPairs(pairs, tokenAddr, chainKey) {
  const addr = (tokenAddr || '').toLowerCase();
  const onChain = (pairs || [])
    .filter(p => p.chainId === chainKey && (p.volume?.h24 || 0) >= MIN_VOLUME_USD)
    .sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
  for (const p of onChain) {
    if (p.baseToken?.address?.toLowerCase() === addr) {
      return parseFloat(p.priceUsd || 0);
    }
    // Token is the QUOTE side: quote price = basePriceUsd / priceNative
    if (p.quoteToken?.address?.toLowerCase() === addr) {
      const baseUsd = parseFloat(p.priceUsd || 0);
      const native  = parseFloat(p.priceNative || 0);
      if (baseUsd > 0 && native > 0) return baseUsd / native;
    }
  }
  return 0;
}

async function getEvmData(address, chainKey = 'ethereum') {
  const base = BLOCKSCOUT[chainKey] || BLOCKSCOUT.ethereum;

  // Token balances
  const [tokenRes, ethRes] = await Promise.all([
    axios.get(`${base}/api/v2/addresses/${address}/token-balances`, { timeout:10000, headers: BLOCKSCOUT_AUTH_HEADERS }).catch(() => null),
    axios.get(`${base}/api/v2/addresses/${address}`, { timeout:8000, headers: BLOCKSCOUT_AUTH_HEADERS }).catch(() => null),
  ]);

  const tokens = [];

  // Native balance (ETH/MATIC) — priced via the canonical wrapped-native token
  const nativeBal = parseFloat(ethRes?.data?.coin_balance || 0) / 1e18;
  const nativeSymbol = { ethereum:'ETH', base:'ETH', arbitrum:'ETH', robinhood:'ETH' }[chainKey] || 'ETH';
  const nativeMint   = {
    ethereum:  '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', // WETH
    base:      '0x4200000000000000000000000000000000000006', // WETH Base
    arbitrum:  '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1', // WETH Arbitrum
    robinhood: '0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73', // WETH Robinhood
  }[chainKey];

  if (nativeBal > 0) {
    // Native price: Blockscout stats first, DexScreener WETH pair as fallback
    let nativePrice = await axios.get(`${base}/api/v2/stats`, { timeout:6000, headers: BLOCKSCOUT_AUTH_HEADERS })
      .then(r => parseFloat(r.data?.coin_price || 0)).catch(() => 0);
    if (!nativePrice && nativeMint) {
      nativePrice = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${nativeMint}`, { timeout:6000 })
        .then(r => _dsPriceFromPairs(r.data.pairs, nativeMint, chainKey)).catch(() => 0);
    }
    tokens.push({ symbol: nativeSymbol, name: nativeSymbol, balance: nativeBal, decimals: 18, priceUsd: nativePrice, valueUsd: nativeBal * nativePrice, address: nativeMint });
  }

  // ERC20 tokens — note: Blockscout v2 uses `address_hash` for the token address.
  // Pricing: on established chains Blockscout's exchange_rate is reliable; on
  // Robinhood Chain spam airdrops clone real symbols and inherit bogus rates,
  // so there we only trust DexScreener (spam has no real liquidity pool there).
  const trustExchangeRate = chainKey !== 'robinhood';
  const rawTokens = tokenRes?.data || [];
  const allErc20 = (Array.isArray(rawTokens) ? rawTokens : (rawTokens.items || []))
    .map(t => ({ ...t, _addr: t.token?.address_hash || t.token?.address || null }))
    .filter(t => t._addr && parseFloat(t.value || 0) > 0 && t.token?.type === 'ERC-20');
  // Most-held tokens first (real tokens have many holders, spam clones few), cap at 90
  allErc20.sort((a, b) => parseInt(b.token?.holders_count || 0) - parseInt(a.token?.holders_count || 0));
  const erc20 = allErc20.slice(0, CONFIG.walletMaxTokens);

  // DexScreener batch lookup for anything without a trusted exchange_rate
  const unpriced = erc20.filter(t => !(trustExchangeRate && parseFloat(t.token?.exchange_rate || 0) > 0));
  const priceMap = {};
  for (let i = 0; i < Math.min(unpriced.length, 90); i += 30) {
    const batch = unpriced.slice(i, i + 30);
    const ids = batch.map(t => t._addr).join(',');
    const pairs = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${ids}`, { timeout:8000 })
      .then(r => r.data.pairs || []).catch(() => []);
    for (const t of batch) {
      priceMap[t._addr.toLowerCase()] = _dsPriceFromPairs(pairs, t._addr, chainKey);
    }
  }

  for (const t of erc20) {
    const bal = parseFloat(t.value || 0) / Math.pow(10, parseInt(t.token?.decimals || 18));
    if (bal <= 0) continue;
    const trusted = trustExchangeRate ? parseFloat(t.token?.exchange_rate || 0) : 0;
    const price = trusted || priceMap[t._addr.toLowerCase()] || 0;
    tokens.push({
      symbol: t.token?.symbol || '?', name: t.token?.name || 'Unknown',
      balance: bal, decimals: parseInt(t.token?.decimals || 18),
      priceUsd: price, valueUsd: bal * price, address: t._addr,
    });
  }

  // Transactions
  const txRes = await axios.get(`${base}/api/v2/addresses/${address}/transactions`, { timeout:10000, headers: BLOCKSCOUT_AUTH_HEADERS }).catch(() => null);
  const rawTxs = txRes?.data?.items || [];
  const txs = rawTxs.map(tx => ({
    hash:      tx.hash,
    short:     tx.hash?.slice(0,8)+'…'+tx.hash?.slice(-6),
    type:      tx.from?.hash?.toLowerCase() === address.toLowerCase() ? 'Send' : 'Receive',
    status:    tx.status === 'ok' ? 'success' : 'failed',
    timestamp: new Date(tx.timestamp).getTime(),
    value:     parseFloat(tx.value || 0) / 1e18,
    fee:       parseFloat(tx.fee?.value || 0) / 1e18,
    to:        tx.to?.hash,
    from:      tx.from?.hash,
    method:    tx.method || null,
  }));

  return { tokens: tokens.sort((a,b) => b.valueUsd - a.valueUsd), txs };
}

// ─── AI Price Prediction (rule-based, no external AI API) ────────────────────
app.post('/api/predict', async (req, res) => {
  const { address, chain } = req.body;
  if (!address) return res.json({ success: false, error: 'Address required' });

  try {
    // Fetch token data from DexScreener — pick the pair the same way every
    // other endpoint does (filter to the requested chain, highest liquidity),
    // so this scores the exact pair the caller is looking at instead of
    // possibly a different pair/chain with more 24h volume.
    const dsRes = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${address}`, { timeout: 8000 }).catch(() => null);
    const allPairs = dsRes?.data?.pairs || [];
    const pairs  = chain ? allPairs.filter(p => p.chainId === chain) : allPairs;
    const pair   = (pairs.length ? pairs : allPairs).sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0))[0];

    if (!pair) return res.json({ success: false, error: 'Token not found on DexScreener' });

    const p1h  = parseFloat(pair.priceChange?.h1  || 0);
    const p6h  = parseFloat(pair.priceChange?.h6  || 0);
    const p24h = parseFloat(pair.priceChange?.h24 || 0);
    const vol24h = pair.volume?.h24 || 0;
    const vol6h  = pair.volume?.h6  || 0;
    const buys24  = pair.txns?.h24?.buys  || 0;
    const sells24 = pair.txns?.h24?.sells || 0;
    const liqUsd  = pair.liquidity?.usd   || 0;
    const fdv     = pair.fdv || pair.marketCap || 0;

    // Token age — a brand-new pool naturally has thin liquidity and
    // concentrated holders (deployer + first buyers) that would otherwise
    // look identical to a rug in progress. Bucket the age so the
    // liquidity/holder thresholds below (and the final confidence) can be
    // read relative to how long the pool has actually had to mature,
    // instead of one fixed bar for a 10-minute-old pool and a 6-month-old one.
    const poolAgeMs    = pair.pairCreatedAt ? Date.now() - pair.pairCreatedAt : null;
    const poolAgeHours = poolAgeMs != null ? poolAgeMs / 3600000 : null;
    const isBrandNew   = poolAgeHours != null && poolAgeHours < 6;   // <6h
    const isNew        = poolAgeHours != null && poolAgeHours < 24;  // <24h
    const isYoung      = poolAgeHours != null && poolAgeHours < 168; // <7d

    // GoPlus security check
    const gpChain = GOPLUS_CHAIN[chain] || GOPLUS_CHAIN['ethereum'];
    const gpRes = await axios.get(`https://api.gopluslabs.io/api/v1/token_security/${gpChain}?contract_addresses=${address}`, { timeout: 6000 }).catch(() => null);
    const gp = gpRes?.data?.result?.[address.toLowerCase()] || {};
    const isHoneypot    = gp.is_honeypot === '1';
    const holderCount   = parseInt(gp.holder_count || 0);
    const top10Pct      = parseFloat(gp.top10_holder_rate || 0) * 100;
    const creatorPct    = parseFloat(gp.creator_percent || 0) * 100;
    const isMintable    = gp.is_mintable === '1';
    const lpLocked      = gp.lp_locked_ratio != null ? parseFloat(gp.lp_locked_ratio) * 100 : null;

    // ── Scoring engine ──────────────────────────────────────────
    const signals = [];
    let bullScore = 0;
    let bearScore = 0;

    // 1. Price momentum
    const momentum = (p1h * 0.5) + (p6h * 0.3) + (p24h * 0.2);
    if (momentum > 5) {
      bullScore += 25;
      signals.push({ label: 'Price Momentum', verdict: 'bullish', detail: `+${p1h.toFixed(1)}% (1h) · +${p6h.toFixed(1)}% (6h) · +${p24h.toFixed(1)}% (24h)` });
    } else if (momentum < -5) {
      bearScore += 25;
      signals.push({ label: 'Price Momentum', verdict: 'bearish', detail: `${p1h.toFixed(1)}% (1h) · ${p6h.toFixed(1)}% (6h) · ${p24h.toFixed(1)}% (24h)` });
    } else {
      signals.push({ label: 'Price Momentum', verdict: 'neutral', detail: `${p1h.toFixed(1)}% (1h) · ${p6h.toFixed(1)}% (6h) · ${p24h.toFixed(1)}% (24h)` });
    }

    // 2. Buy/sell pressure
    const total = buys24 + sells24;
    const buyRatio = total > 0 ? buys24 / total : 0.5;
    if (buyRatio > 0.6) {
      bullScore += 20;
      signals.push({ label: 'Buy/Sell Pressure', verdict: 'bullish', detail: `${(buyRatio*100).toFixed(0)}% buys vs ${((1-buyRatio)*100).toFixed(0)}% sells (${total} txns)` });
    } else if (buyRatio < 0.4) {
      bearScore += 20;
      signals.push({ label: 'Buy/Sell Pressure', verdict: 'bearish', detail: `${(buyRatio*100).toFixed(0)}% buys vs ${((1-buyRatio)*100).toFixed(0)}% sells (${total} txns)` });
    } else {
      signals.push({ label: 'Buy/Sell Pressure', verdict: 'neutral', detail: `${(buyRatio*100).toFixed(0)}% buys · ${total} txns 24h` });
    }

    // 3. Volume trend (6h vs 24h/4 — if 6h pace > 24h avg, volume accelerating)
    const vol6hPace = vol6h * 4;
    if (vol24h > 0) {
      const volAccel = vol6hPace / vol24h;
      if (volAccel > 1.3) {
        bullScore += 20;
        signals.push({ label: 'Volume Trend', verdict: 'bullish', detail: `Accelerating — 6h pace $${(vol6hPace/1000).toFixed(1)}K vs 24h avg $${(vol24h/1000).toFixed(1)}K` });
      } else if (volAccel < 0.7) {
        bearScore += 20;
        signals.push({ label: 'Volume Trend', verdict: 'bearish', detail: `Declining — 6h pace $${(vol6hPace/1000).toFixed(1)}K vs 24h avg $${(vol24h/1000).toFixed(1)}K` });
      } else {
        signals.push({ label: 'Volume Trend', verdict: 'neutral', detail: `Stable — $${(vol24h/1000).toFixed(1)}K 24h volume` });
      }
    }

    // 4. Liquidity health — bars are relaxed for young pools, which start
    // thin by construction and aren't necessarily riskier for it.
    const liqHealthyBar = isBrandNew ? 20000 : isNew ? 50000 : 100000;
    const liqRiskyBar   = isBrandNew ? 3000  : isNew ? 6000  : 10000;
    const liqToVol = vol24h > 0 ? liqUsd / vol24h : 0;
    if (liqUsd > liqHealthyBar && liqToVol > 0.1) {
      bullScore += 10;
      signals.push({ label: 'Liquidity', verdict: 'bullish', detail: `$${(liqUsd/1000).toFixed(1)}K — healthy depth${isNew ? ' for pool age' : ''}` });
    } else if (liqUsd < liqRiskyBar) {
      bearScore += 15;
      signals.push({ label: 'Liquidity', verdict: 'bearish', detail: `$${(liqUsd/1000).toFixed(1)}K — very low, high slippage risk` });
    } else {
      signals.push({ label: 'Liquidity', verdict: 'neutral', detail: `$${(liqUsd/1000).toFixed(1)}K` });
    }

    // 5. Holder concentration (from GoPlus) — a brand-new pool is
    // dominated by the deployer + first buyers almost by definition, so the
    // "well distributed" / "high concentration" bars widen for young pools
    // rather than flagging every fresh launch as bearish on this alone.
    const holderGoodTop10 = isBrandNew ? 55 : isNew ? 45 : 30;
    const holderGoodCreator = isBrandNew ? 15 : isNew ? 10 : 5;
    const holderBadTop10  = isBrandNew ? 85 : isNew ? 75 : 60;
    const holderBadCreator = isBrandNew ? 45 : isNew ? 35 : 20;
    if (holderCount > 0) {
      if (top10Pct < holderGoodTop10 && creatorPct < holderGoodCreator) {
        bullScore += 15;
        signals.push({ label: 'Holder Distribution', verdict: 'bullish', detail: `Top 10 hold ${top10Pct.toFixed(1)}% · Creator ${creatorPct.toFixed(1)}% — well distributed${isNew ? ' for pool age' : ''}` });
      } else if (top10Pct > holderBadTop10 || creatorPct > holderBadCreator) {
        bearScore += 20;
        signals.push({ label: 'Holder Distribution', verdict: 'bearish', detail: `Top 10 hold ${top10Pct.toFixed(1)}% · Creator ${creatorPct.toFixed(1)}% — high concentration risk` });
      } else {
        signals.push({ label: 'Holder Distribution', verdict: 'neutral', detail: `Top 10: ${top10Pct.toFixed(1)}% · ${holderCount.toLocaleString()} holders` });
      }
    }

    // 6. Token age — its own signal, separate from the threshold adjustments
    // above: very young pools are inherently higher-risk (no track record,
    // classic rug window), while pools that have survived past the first
    // week with liquidity intact are a mild positive signal in themselves.
    if (poolAgeHours == null) {
      signals.push({ label: 'Token Age', verdict: 'neutral', detail: 'Pool creation time unavailable' });
    } else if (isBrandNew) {
      bearScore += 15;
      signals.push({ label: 'Token Age', verdict: 'bearish', detail: `${poolAgeHours < 1 ? Math.round(poolAgeHours * 60) + 'm' : poolAgeHours.toFixed(1) + 'h'} old — classic rug-risk window, thresholds relaxed but stay cautious` });
    } else if (isNew) {
      signals.push({ label: 'Token Age', verdict: 'neutral', detail: `${poolAgeHours.toFixed(0)}h old — still early, limited trading history` });
    } else if (isYoung) {
      signals.push({ label: 'Token Age', verdict: 'neutral', detail: `${Math.round(poolAgeHours / 24)}d old — building track record` });
    } else {
      bullScore += 10;
      signals.push({ label: 'Token Age', verdict: 'bullish', detail: `${Math.round(poolAgeHours / 24)}d old — established, survived past the early rug window` });
    }

    // 6. Security flags
    if (isHoneypot) {
      bearScore += 30;
      signals.push({ label: 'Security', verdict: 'bearish', detail: '⚠ HONEYPOT detected — cannot sell' });
    } else if (isMintable) {
      bearScore += 10;
      signals.push({ label: 'Security', verdict: 'bearish', detail: 'Token is mintable — inflation risk' });
    } else if (lpLocked !== null && lpLocked > 80) {
      bullScore += 10;
      signals.push({ label: 'Security', verdict: 'bullish', detail: `LP ${lpLocked.toFixed(0)}% locked — lower rug risk` });
    } else {
      signals.push({ label: 'Security', verdict: 'neutral', detail: 'No critical security issues detected' });
    }

    // ── Final verdict ──
    const net = bullScore - bearScore;
    let verdict, signal;
    if (net >= 20)       { verdict = 'BULLISH';  signal = 'bullish'; }
    else if (net <= -20) { verdict = 'BEARISH';  signal = 'bearish'; }
    else                 { verdict = 'NEUTRAL';  signal = 'neutral'; }

    const total_weight = bullScore + bearScore || 1;
    // Cap confidence for very young pools — there simply isn't enough
    // trading history yet for any signal combination to be as reliable as
    // the same reading on an established pool.
    const confidenceCap = isBrandNew ? 65 : isNew ? 80 : 95;
    const confidence = Math.min(confidenceCap, Math.round(Math.abs(net) / total_weight * 100 + 30));

    const summary = signal === 'bullish'
      ? `Majority of signals point upward. Buy pressure dominates with ${(buyRatio*100).toFixed(0)}% buys, price momentum ${momentum > 0 ? 'positive' : 'mixed'} across timeframes.`
      : signal === 'bearish'
      ? `Multiple bearish signals detected. Sell pressure elevated at ${((1-buyRatio)*100).toFixed(0)}% of transactions. Exercise caution.`
      : `Mixed signals — market is consolidating. No clear directional bias. Wait for a stronger signal before entering.`;

    res.json({
      success: true,
      symbol: pair.baseToken?.symbol,
      name:   pair.baseToken?.name,
      price:  pair.priceUsd,
      verdict, signal, confidence, summary, signals,
      bullScore, bearScore,
      timeframe: 'Short-term (1–24h)',
      generatedAt: new Date().toISOString(),
    });

    // Log directional calls for the public AI Track Record — deliberately
    // skips NEUTRAL (no clear right/wrong to resolve against later).
    if (verdict === 'BULLISH' || verdict === 'BEARISH') {
      dbRun(`
        INSERT INTO prediction_history (address, chain, symbol, name, \`signal\`, confidence, price_at, predicted_at, image_url)
        VALUES (?,?,?,?,?,?,?,?,?)
      `, [address.toLowerCase(), chain || pair.chainId, pair.baseToken?.symbol, pair.baseToken?.name,
          verdict, confidence, parseFloat(pair.priceUsd || 0), Date.now(), pair.info?.imageUrl || null]).catch(e => console.error('[track-record] log failed:', e.message));
    }

  } catch (e) {
    console.error('[predict]', e.message);
    res.json({ success: false, error: e.message });
  }
});

app.post('/api/wallet-tracker', async (req, res) => {
  const { address, evmChain = 'ethereum', before = null } = req.body;
  if (!address) return res.json({ success: false, error: 'Address required' });

  const chain = detectWalletChain(address);
  if (!chain) return res.json({ success: false, error: 'Invalid address format. Only EVM wallets (0x…) are supported.' });

  try {
    const { tokens, txs } = await getEvmData(address, evmChain);
    const totalUsd = tokens.reduce((s, t) => s + t.valueUsd, 0);
    return res.json({ success: true, chain: 'evm', evmChain, address, totalUsd, tokens, txs, nextCursor: null });
  } catch (e) {
    console.error('[wallet-tracker]', e.message);
    res.json({ success: false, error: e.message });
  }
});

// ─── Auth middleware ────────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.cookies?.bb_token || req.headers['authorization']?.replace('Bearer ','');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Check session still valid in DB
    const hash = hashJwt(token);
    const session = await dbGet('SELECT * FROM sessions WHERE jwt_hash=? AND expires_at>?', [hash, Math.floor(Date.now()/1000)]);
    if (!session) return res.status(401).json({ error: 'Session expired' });
    req.user = payload;
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── POST /api/auth/login ───────────────────────────────────────────────────────
// Called after frontend verifies SIWE with Privy — saves wallet + issues JWT
/* ─── Wallet ownership proof (SIWE-style challenge/response) ──────────────────
   A wallet address is public information, so accepting one on its own proves
   nothing — the caller must sign a server-issued nonce to show they hold the
   private key. Nonces are single-use and short-lived so a captured signature
   can't be replayed.
   Kept in memory rather than a table: the window between issuing a nonce and
   verifying it is seconds, and losing them on restart just means the user
   signs again. */
const AUTH_NONCE_TTL_MS = 5 * 60 * 1000;
const _authNonces = new Map(); // nonce -> { wallet, message, at }

setInterval(() => {
  const now = Date.now();
  for (const [nonce, entry] of _authNonces) {
    if (now - entry.at > AUTH_NONCE_TTL_MS) _authNonces.delete(nonce);
  }
}, 60 * 1000).unref?.();

function _siweMessage(wallet, nonce, issuedAt) {
  return [
    'Bloombark Terminal wants you to sign in with your wallet:',
    wallet,
    '',
    'Signing is free and will not trigger a blockchain transaction.',
    '',
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join('\n');
}

app.post('/api/auth/nonce', (req, res) => {
  const wallet = String(req.body?.wallet || '');
  if (!/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
    return res.status(400).json({ error: 'valid EVM wallet address required' });
  }
  const nonce    = crypto.randomBytes(16).toString('hex');
  const issuedAt = new Date().toISOString();
  // Store the exact string that gets signed, so verification can't drift from
  // what the wallet actually saw.
  const message  = _siweMessage(wallet, nonce, issuedAt);
  _authNonces.set(nonce, { wallet: wallet.toLowerCase(), message, at: Date.now() });
  res.json({ success: true, nonce, message });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { wallet, privyUserId, meta, signature, nonce } = req.body;
    if (!wallet) return res.status(400).json({ error: 'wallet required' });
    const isEvm   = /^0x[0-9a-fA-F]{40}$/.test(wallet);
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(wallet);
    if (!isEvm && !isEmail) {
      return res.status(400).json({ error: 'Invalid wallet address or email' });
    }

    const walletLower = wallet.toLowerCase();

    // EVM logins must prove ownership. Without this any caller could mint a
    // session for any address — including an admin wallet.
    if (isEvm) {
      const entry = nonce ? _authNonces.get(nonce) : null;
      // Burn the nonce on any attempt so a guessed/leaked one can't be retried.
      if (nonce) _authNonces.delete(nonce);
      if (!entry || Date.now() - entry.at > AUTH_NONCE_TTL_MS) {
        return res.status(401).json({ error: 'Sign-in challenge expired — please try connecting again' });
      }
      if (entry.wallet !== walletLower) {
        return res.status(401).json({ error: 'Challenge was issued for a different wallet' });
      }
      let recovered;
      try {
        recovered = ethers.verifyMessage(entry.message, String(signature || ''));
      } catch (_) {
        return res.status(401).json({ error: 'Malformed signature' });
      }
      if (recovered.toLowerCase() !== walletLower) {
        return res.status(401).json({ error: 'Signature does not match wallet' });
      }
    }
    const walletEnc   = encrypt(walletLower);
    const metaStr     = meta ? JSON.stringify(meta) : null;
    const now         = Math.floor(Date.now() / 1000);

    // For email users: generate a new ETH wallet if one doesn't exist yet
    let generatedAddress = null;
    let generatedKeyEnc  = null;
    if (isEmail) {
      const existing = await dbGet('SELECT generated_address, generated_key_enc FROM users WHERE wallet=?', [walletLower]);
      if (existing?.generated_address) {
        generatedAddress = existing.generated_address;
      } else {
        const newWallet  = ethers.Wallet.createRandom();
        generatedAddress = newWallet.address;
        generatedKeyEnc  = encrypt(newWallet.privateKey);
      }
    }

    // Upsert user
    await dbRun(`
      INSERT INTO users (wallet, wallet_enc, generated_address, generated_key_enc, meta, last_login)
      VALUES (?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        last_login=VALUES(last_login),
        meta=COALESCE(VALUES(meta), meta),
        generated_address=COALESCE(generated_address, VALUES(generated_address)),
        generated_key_enc=COALESCE(generated_key_enc, VALUES(generated_key_enc))
    `, [walletLower, walletEnc, generatedAddress, generatedKeyEnc, metaStr, now]);

    const user = await dbGet('SELECT * FROM users WHERE wallet=?', [walletLower]);
    const displayAddress = isEmail ? user.generated_address : walletLower;

    // Issue JWT (7 days)
    const expiresIn = CONFIG.jwtExpiresInSec;
    const token = jwt.sign(
      { wallet: walletLower, userId: user.id, privyUserId: privyUserId || null },
      JWT_SECRET,
      { expiresIn }
    );

    // Store hashed token in sessions table
    await dbRun('INSERT INTO sessions (wallet, jwt_hash, expires_at) VALUES (?,?,?)',
      [walletLower, hashJwt(token), now + expiresIn]
    );

    // Set httpOnly cookie (7 days)
    res.cookie('bb_token', token, {
      httpOnly: true,
      sameSite: 'strict',
      maxAge: expiresIn * 1000,
      path: '/',
    });

    return res.json({ success: true, token, wallet: walletLower, displayAddress, userId: user.id });
  } catch(e) {
    console.error('[auth/login]', e.message);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// ─── GET /api/auth/me ───────────────────────────────────────────────────────────
app.get('/api/auth/me', requireAuth, async (req, res) => {
  const user = await dbGet('SELECT id, wallet, generated_address, created_at, last_login FROM users WHERE wallet=?', [req.user.wallet]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  let isDiamondHolder = false;
  try { isDiamondHolder = (await checkChannelGate('holders', req.user.wallet)).ok; } catch (_) {}
  return res.json({ success: true, user, isAdmin: isAdminWallet(req.user.wallet), isDiamondHolder });
});

// ─── POST /api/auth/logout ──────────────────────────────────────────────────────
app.post('/api/auth/logout', async (req, res) => {
  const token = req.cookies?.bb_token;
  if (token) {
    await dbRun('DELETE FROM sessions WHERE jwt_hash=?', [hashJwt(token)]);
  }
  res.clearCookie('bb_token', { path: '/' });
  return res.json({ success: true });
});

// ─── Watchlist ────────────────────────────────────────────────────────────────
// (table created in initDb())

app.get('/api/watchlist', requireAuth, async (req, res) => {
  const rows = await dbAll('SELECT * FROM watchlist WHERE wallet=? ORDER BY added_at DESC', [req.user.wallet]);
  res.json({ success: true, items: rows });
});

app.get('/api/watchlist/check/:address', requireAuth, async (req, res) => {
  const row = await dbGet('SELECT id FROM watchlist WHERE wallet=? AND address=?', [req.user.wallet, req.params.address.toLowerCase()]);
  res.json({ inWatchlist: !!row });
});

app.post('/api/watchlist', requireAuth, async (req, res) => {
  const { address, chain, name, symbol, imageUrl } = req.body;
  if (!address) return res.status(400).json({ error: 'address required' });
  await dbRun(`
    INSERT INTO watchlist (wallet, address, chain, name, symbol, image_url)
    VALUES (?,?,?,?,?,?)
    ON DUPLICATE KEY UPDATE chain=VALUES(chain), name=VALUES(name), symbol=VALUES(symbol), image_url=VALUES(image_url)
  `, [req.user.wallet, address.toLowerCase(), chain || '', name || '', symbol || '', imageUrl || null]);
  res.json({ success: true });
});

app.delete('/api/watchlist/:address', requireAuth, async (req, res) => {
  await dbRun('DELETE FROM watchlist WHERE wallet=? AND address=?', [req.user.wallet, req.params.address.toLowerCase()]);
  res.json({ success: true });
});

// ─── Web Push subscriptions (browser notifications for alerts) ─────────────
app.get('/api/push/vapid-public-key', (req, res) => {
  if (!PUSH_ENABLED) return res.status(503).json({ success: false, error: 'Push not configured' });
  res.json({ success: true, publicKey: VAPID_PUBLIC_KEY });
});

app.post('/api/push/subscribe', requireAuth, async (req, res) => {
  if (!PUSH_ENABLED) return res.status(503).json({ success: false, error: 'Push not configured' });
  const { subscription } = req.body;
  const endpoint = subscription?.endpoint;
  const p256dh   = subscription?.keys?.p256dh;
  const auth     = subscription?.keys?.auth;
  if (!endpoint || !p256dh || !auth) return res.status(400).json({ error: 'Invalid subscription' });
  await dbRun(`
    INSERT INTO push_subscriptions (wallet, endpoint, p256dh, auth, created_at)
    VALUES (?,?,?,?,?)
    ON DUPLICATE KEY UPDATE wallet=VALUES(wallet), p256dh=VALUES(p256dh), auth=VALUES(auth)
  `, [req.user.wallet, endpoint, p256dh, auth, Date.now()]);
  res.json({ success: true });
});

app.post('/api/push/unsubscribe', requireAuth, async (req, res) => {
  const { endpoint } = req.body;
  if (!endpoint) return res.status(400).json({ error: 'endpoint required' });
  await dbRun('DELETE FROM push_subscriptions WHERE wallet=? AND endpoint=?', [req.user.wallet, endpoint]);
  res.json({ success: true });
});

// Sends a push notification to every device a wallet has subscribed, pruning
// subscriptions the browser has since revoked (410 Gone / 404).
async function _sendPushToWallet(wallet, payload) {
  if (!PUSH_ENABLED) return;
  let subs;
  try {
    subs = await dbAll('SELECT * FROM push_subscriptions WHERE wallet=?', [wallet]);
  } catch (e) { console.error('[push] load subs failed:', e.message); return; }
  for (const s of subs) {
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
        JSON.stringify(payload)
      );
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) {
        await dbRun('DELETE FROM push_subscriptions WHERE id=?', [s.id]).catch(() => {});
      } else {
        console.error('[push] send failed:', e.message);
      }
    }
  }
}

// ─── Token Alerts (per-watchlist-item MCAP/Volume % move alerts) ────────────
// (tables created in initDb())

app.get('/api/alerts', requireAuth, async (req, res) => {
  const rows = await dbAll('SELECT * FROM token_alerts WHERE wallet=? ORDER BY created_at DESC', [req.user.wallet]);
  res.json({ success: true, items: rows });
});

app.post('/api/alerts', requireAuth, async (req, res) => {
  const { address, chain, name, symbol, metric, baselineValue, thresholdPct, direction } = req.body;
  if (!address || !chain) return res.status(400).json({ error: 'address and chain required' });
  if (!['mcap', 'volume', 'price'].includes(metric)) return res.status(400).json({ error: 'metric must be mcap, volume, or price' });
  const dir = ['up', 'down', 'both'].includes(direction) ? direction : 'both';
  const baseline = parseFloat(baselineValue);
  // For 'price' alerts baselineValue IS the absolute target price the user
  // set — it's compared directly against the live price, not as a % move
  // origin, so thresholdPct is meaningless and not required.
  const threshold = metric === 'price' ? 0 : parseFloat(thresholdPct);
  if (!(baseline > 0)) return res.status(400).json({ error: metric === 'price' ? 'target price must be > 0' : 'baselineValue must be > 0' });
  if (metric !== 'price' && !(threshold > 0)) return res.status(400).json({ error: 'thresholdPct must be > 0' });
  await dbRun(`
    INSERT INTO token_alerts (wallet, address, chain, name, symbol, metric, baseline_value, threshold_pct, direction, active, high_value, low_value)
    VALUES (?,?,?,?,?,?,?,?,?,1,?,?)
    ON DUPLICATE KEY UPDATE chain=VALUES(chain), name=VALUES(name), symbol=VALUES(symbol),
      baseline_value=VALUES(baseline_value), threshold_pct=VALUES(threshold_pct), direction=VALUES(direction), active=1,
      high_value=VALUES(high_value), low_value=VALUES(low_value)
  `, [req.user.wallet, address.toLowerCase(), chain, name || '', symbol || '', metric, baseline, threshold, dir, baseline, baseline]);
  res.json({ success: true });
});

app.delete('/api/alerts/:id', requireAuth, async (req, res) => {
  await dbRun('DELETE FROM token_alerts WHERE id=? AND wallet=?', [req.params.id, req.user.wallet]);
  res.json({ success: true });
});

app.delete('/api/alerts/token/:address', requireAuth, async (req, res) => {
  await dbRun('DELETE FROM token_alerts WHERE wallet=? AND address=?', [req.user.wallet, req.params.address.toLowerCase()]);
  res.json({ success: true });
});

app.get('/api/alerts/notifications', requireAuth, async (req, res) => {
  const rows = await dbAll('SELECT * FROM alert_notifications WHERE wallet=? ORDER BY ts DESC LIMIT 1000', [req.user.wallet]);
  const unread = rows.filter(r => !r.is_read).length;
  res.json({ success: true, items: rows, unread });
});

app.post('/api/alerts/notifications/mark-read', requireAuth, async (req, res) => {
  await dbRun('UPDATE alert_notifications SET is_read=1 WHERE wallet=?', [req.user.wallet]);
  res.json({ success: true });
});

app.post('/api/alerts/notifications/delete', requireAuth, async (req, res) => {
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(Number).filter(Number.isFinite) : [];
  if (!ids.length) return res.status(400).json({ error: 'ids required' });
  await dbRun(`DELETE FROM alert_notifications WHERE wallet=? AND id IN (${ids.map(() => '?').join(',')})`, [req.user.wallet, ...ids]);
  res.json({ success: true });
});

app.post('/api/alerts/notifications/delete-all', requireAuth, async (req, res) => {
  await dbRun('DELETE FROM alert_notifications WHERE wallet=?', [req.user.wallet]);
  res.json({ success: true });
});

// ── Admin: blast a Bloombark notification (Title/Subtitle/Desc) to every user ──
app.post('/api/admin/alerts/blast', requireAuth, async (req, res) => {
  if (!isAdminWallet(req.user.wallet)) return res.status(403).json({ error: 'Forbidden' });
  const title = String(req.body?.title || '').trim().slice(0, 255);
  const subtitle = String(req.body?.subtitle || '').trim().slice(0, 255);
  const detail = String(req.body?.detail || '').trim().slice(0, 4000);
  if (!title) return res.status(400).json({ error: 'title required' });
  const users = await dbAll('SELECT wallet FROM users');
  const ts = Date.now();
  for (const { wallet } of users) {
    await dbRun(`
      INSERT INTO alert_notifications (wallet, category, title, subtitle, detail, ts)
      VALUES (?,'bloombark_update',?,?,?,?)
    `, [wallet, title, subtitle, detail, ts]);
  }
  res.json({ success: true, sent: users.length });
});

// Admin: clear broadcasted Bloombark-update notifications across ALL users
// (e.g. to retract a blast sent by mistake). Pass { ts } to clear only one
// specific blast batch (every row from one blast shares the same ts), or
// omit it to clear every bloombark_update notification for every user.
app.post('/api/admin/alerts/blast/clear', requireAuth, async (req, res) => {
  if (!isAdminWallet(req.user.wallet)) return res.status(403).json({ error: 'Forbidden' });
  const ts = req.body?.ts ? Number(req.body.ts) : null;
  const result = ts
    ? await dbRun('DELETE FROM alert_notifications WHERE category=? AND ts=?', ['bloombark_update', ts])
    : await dbRun('DELETE FROM alert_notifications WHERE category=?', ['bloombark_update']);
  res.json({ success: true, deleted: result.affectedRows });
});

// Background checker: periodically compares each active alert's current
// value (via DexScreener) against its baseline + threshold. All three
// metrics (mcap/volume/price) are repeatable — evaluated off the LIVE value
// each poll (not a cumulative high/low watermark), no cooldown: they fire
// again every time the condition is met, and never auto-deactivate.
async function _checkTokenAlerts() {
  let alerts;
  try {
    alerts = await dbAll('SELECT * FROM token_alerts WHERE active=1');
  } catch (e) { console.error('[alerts] load failed:', e.message); return; }
  for (const a of alerts) {
    try {
      const { data } = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${a.address}`, { timeout: 8000 });
      const pairs = (data?.pairs || []).filter(p => p.chainId === a.chain)
        .sort((x, y) => (y.liquidity?.usd || 0) - (x.liquidity?.usd || 0));
      if (!pairs.length) continue;
      const p = pairs[0];
      const currentValue = a.metric === 'mcap' ? parseFloat(p.fdv || p.marketCap || 0)
        : a.metric === 'price' ? parseFloat(p.priceUsd || 0)
        : parseFloat(p.volume?.h24 || 0);
      if (!(currentValue > 0)) continue;

      const changePct = ((currentValue - a.baseline_value) / a.baseline_value) * 100;
      // 'price' fires on touching an absolute target (baseline_value IS the
      // target); mcap/volume fire once the live value has moved threshold_pct%
      // away from baseline in the watched direction.
      const crossedUp = a.metric === 'price' ? currentValue >= a.baseline_value : changePct >= a.threshold_pct;
      const crossedDown = a.metric === 'price' ? currentValue <= a.baseline_value : changePct <= -a.threshold_pct;
      const shouldFire = (a.direction === 'up' && crossedUp) ||
                          (a.direction === 'down' && crossedDown) ||
                          (a.direction === 'both' && (crossedUp || crossedDown));

      if (shouldFire) {
        const dir = changePct >= 0 ? 'up' : 'down';
        const label = a.metric === 'mcap' ? 'Market Cap' : a.metric === 'price' ? 'Price' : 'Volume';
        const message = a.metric === 'price'
          ? `${a.symbol || a.name || 'Token'} Price reached your target of $${a.baseline_value} (now $${currentValue})`
          : `${a.symbol || a.name || 'Token'} ${label} moved ${dir} ${Math.abs(changePct).toFixed(1)}% (threshold ${a.threshold_pct}%)`;
        await dbRun(`
          INSERT INTO alert_notifications (alert_id, wallet, address, chain, name, symbol, metric, direction, baseline_value, new_value, change_pct, message, ts)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        `, [a.id, a.wallet, a.address, a.chain, a.name, a.symbol, a.metric, dir, a.baseline_value, currentValue, changePct, message, Date.now()]);
        _sendPushToWallet(a.wallet, {
          title: `${a.symbol || a.name || 'Token'} alert triggered`,
          body: message,
          url: '/alerts',
        }).catch(e => console.error('[push] alert notify failed:', e.message));
      }
      await dbRun('UPDATE token_alerts SET last_checked_at=? WHERE id=?', [Math.floor(Date.now() / 1000), a.id]);
    } catch (e) {
      console.error('[alerts] check failed for', a.address, e.message);
    }
    await new Promise(r => setTimeout(r, 300)); // gentle pacing between DexScreener calls
  }
}
setTimeout(_checkTokenAlerts, 20000);
setInterval(_checkTokenAlerts, 5 * 60 * 1000);

// ─── AI Track Record resolver ────────────────────────────────────────────────
// Every directional prediction gets checked ~24h later against the actual
// price move: BULLISH is "correct" if price rose, BEARISH if it fell (small
// dead-band around 0% to avoid crediting/blaming pure noise).
const PREDICTION_RESOLVE_AGE_MS = 24 * 60 * 60 * 1000;
const PREDICTION_FLAT_BAND_PCT  = 1.5;

async function _resolvePredictionHistory() {
  let rows;
  try {
    rows = await dbAll(
      'SELECT * FROM prediction_history WHERE resolved_at IS NULL AND predicted_at <= ? LIMIT 20',
      [Date.now() - PREDICTION_RESOLVE_AGE_MS]
    );
  } catch (e) { console.error('[track-record] load failed:', e.message); return; }

  for (const row of rows) {
    try {
      const { data } = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${row.address}`, { timeout: 8000 });
      const pairs = (data?.pairs || []).filter(p => p.chainId === row.chain)
        .sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
      const priceAfter = parseFloat(pairs[0]?.priceUsd || 0);
      if (!(priceAfter > 0)) continue;

      const changePct = ((priceAfter - row.price_at) / row.price_at) * 100;
      let outcome;
      if (Math.abs(changePct) < PREDICTION_FLAT_BAND_PCT) outcome = 'flat';
      else if (row.signal === 'BULLISH') outcome = changePct > 0 ? 'correct' : 'incorrect';
      else outcome = changePct < 0 ? 'correct' : 'incorrect';

      await dbRun(
        'UPDATE prediction_history SET resolved_at=?, price_after=?, change_pct=?, outcome=? WHERE id=?',
        [Date.now(), priceAfter, changePct, outcome, row.id]
      );
    } catch (e) {
      console.error('[track-record] resolve failed for', row.address, e.message);
    }
    await new Promise(r => setTimeout(r, 300));
  }
}
setTimeout(_resolvePredictionHistory, 30000);
setInterval(_resolvePredictionHistory, 15 * 60 * 1000);

// Public — no auth, deliberately transparent even when the AI is wrong.
app.get('/api/predict/track-record', async (req, res) => {
  try {
    const resolved = await dbAll(
      `SELECT * FROM prediction_history WHERE resolved_at IS NOT NULL ORDER BY resolved_at DESC LIMIT 200`
    );
    const decisive = resolved.filter(r => r.outcome === 'correct' || r.outcome === 'incorrect');
    const correct = decisive.filter(r => r.outcome === 'correct').length;
    const winRatePct = decisive.length ? Math.round((correct / decisive.length) * 1000) / 10 : null;
    const pendingCountRow = await dbGet('SELECT COUNT(*) AS c FROM prediction_history WHERE resolved_at IS NULL');
    const pendingRows = await dbAll(`
      SELECT address, chain, symbol, name, image_url, \`signal\`, confidence, predicted_at
      FROM prediction_history
      WHERE resolved_at IS NULL
      ORDER BY predicted_at DESC
      LIMIT 100
    `);

    // Distinct tokens ever covered (ticker + CA + image only — a quick
    // "which tokens has the AI actually called" reference list, separate
    // from the win/loss detail rows above).
    const tokenRows = await dbAll(`
      SELECT address, chain, MAX(symbol) AS symbol, MAX(name) AS name, MAX(image_url) AS image_url,
             MAX(predicted_at) AS last_predicted_at
      FROM prediction_history
      GROUP BY address, chain
      ORDER BY last_predicted_at DESC
      LIMIT 100
    `);

    res.json({
      success: true,
      totalResolved: decisive.length,
      correct,
      winRatePct,
      pendingCount: pendingCountRow?.c || 0,
      recent: resolved.slice(0, 30).map(r => ({
        address: r.address, symbol: r.symbol, name: r.name, chain: r.chain, signal: r.signal, confidence: r.confidence,
        priceAt: r.price_at, priceAfter: r.price_after, changePct: r.change_pct, outcome: r.outcome,
        predictedAt: r.predicted_at, resolvedAt: r.resolved_at, imageUrl: r.image_url,
      })),
      pending: pendingRows.map(p => ({
        address: p.address, chain: p.chain, symbol: p.symbol, name: p.name, imageUrl: p.image_url,
        signal: p.signal, confidence: p.confidence, predictedAt: p.predicted_at,
      })),
      tokens: tokenRows.map(t => ({
        address: t.address, chain: t.chain, symbol: t.symbol, name: t.name, imageUrl: t.image_url,
      })),
    });
  } catch (e) {
    console.error('[track-record] endpoint failed:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Trending on Bloombark ───────────────────────────────────────────────────
// Internal-activity trending — deliberately separate from Market Overview's
// GeckoTerminal-sourced "Trending" tab, which is price/volume-based. This one
// tracks what's actually happening ON Bloombark itself: what people are
// scanning, discussing (excluding Holders/Private/$BBRK Moon — those rooms
// aren't general token discussion), and trading.
const TRENDING_ROOM_EXCLUDE = ['holders', 'private', 'moon'];
const CA_REGEX = /0x[a-fA-F0-9]{40}/g;

app.post('/api/trade/log-activity', (req, res) => {
  const { address, chain, symbol, name } = req.body || {};
  if (!address || !chain) return res.status(400).json({ success: false, error: 'address and chain required' });
  dbRun(
    'INSERT INTO token_activity_log (address, chain, symbol, name, `type`, ts) VALUES (?,?,?,?,?,?)',
    [String(address).toLowerCase(), chain, symbol || null, name || null, 'trade', Date.now()]
  ).catch(e => console.error('[trending-log] trade insert failed:', e.message));
  res.json({ success: true });
});

const TRENDING_TTL_MS = 5 * 60 * 1000;
let _trendingCache = { data: null, at: 0 };

app.get('/api/trending-bloombark', async (req, res) => {
  // ?refresh=1 bypasses the cache — used by the frontend's Refresh button so
  // a just-posted mention/scan/trade doesn't sit invisible for up to 5min.
  const bypassCache = req.query.refresh === '1';
  if (!bypassCache && _trendingCache.data && Date.now() - _trendingCache.at < TRENDING_TTL_MS) {
    return res.json({ success: true, ...(_trendingCache.data) });
  }
  try {
    const since = Date.now() - 24 * 60 * 60 * 1000;

    const scanRows = await dbAll(`
      SELECT address, chain, MAX(symbol) AS symbol, MAX(name) AS name, COUNT(*) AS cnt
      FROM token_activity_log WHERE \`type\`='scan' AND ts > ? GROUP BY address, chain
      ORDER BY cnt DESC LIMIT 10
    `, [since]);
    const tradeRows = await dbAll(`
      SELECT address, chain, MAX(symbol) AS symbol, MAX(name) AS name, COUNT(*) AS cnt
      FROM token_activity_log WHERE \`type\`='trade' AND ts > ? GROUP BY address, chain
      ORDER BY cnt DESC LIMIT 10
    `, [since]);

    // Community mentions: pull recent messages from non-excluded rooms, then
    // regex-extract addresses in JS (chat text has no structured CA field).
    const placeholders = TRENDING_ROOM_EXCLUDE.map(() => '?').join(',');
    const messages = await dbAll(
      `SELECT text FROM chat_messages WHERE ts > ? AND room NOT IN (${placeholders})`,
      [since, ...TRENDING_ROOM_EXCLUDE]
    );
    const mentionCounts = {};
    for (const m of messages) {
      const found = (m.text || '').match(CA_REGEX) || [];
      for (const addr of found) {
        const key = addr.toLowerCase();
        mentionCounts[key] = (mentionCounts[key] || 0) + 1;
      }
    }
    // Best-effort symbol/name lookup for mentioned addresses from activity log.
    const mentionAddrs = Object.keys(mentionCounts).sort((a, b) => mentionCounts[b] - mentionCounts[a]).slice(0, 10);
    let mentionRows = [];
    if (mentionAddrs.length) {
      const mp = mentionAddrs.map(() => '?').join(',');
      const meta = await dbAll(
        `SELECT address, MAX(chain) AS chain, MAX(symbol) AS symbol, MAX(name) AS name
         FROM token_activity_log WHERE address IN (${mp}) GROUP BY address`,
        mentionAddrs
      );
      const metaMap = Object.fromEntries(meta.map(m => [m.address, m]));
      mentionRows = mentionAddrs.map(addr => ({
        address: addr, chain: metaMap[addr]?.chain || null,
        symbol: metaMap[addr]?.symbol || null, name: metaMap[addr]?.name || null,
        cnt: mentionCounts[addr],
      }));
    }

    const data = {
      mostScanned: scanRows.map(r => ({ address: r.address, chain: r.chain, symbol: r.symbol, name: r.name, count: r.cnt })),
      mostDiscussed: mentionRows.map(r => ({ address: r.address, chain: r.chain, symbol: r.symbol, name: r.name, count: r.cnt })),
      mostTraded: tradeRows.map(r => ({ address: r.address, chain: r.chain, symbol: r.symbol, name: r.name, count: r.cnt })),
    };
    _trendingCache = { data, at: Date.now() };
    res.json({ success: true, ...data });
  } catch (e) {
    console.error('[trending-bloombark] failed:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

/* ─── News: RSS aggregator + per-token coverage ───────────────────────────────
   RSS-first by design so this works with zero API keys or signups. Each source
   is fetched independently and a failing one is skipped rather than failing the
   whole feed — these are third-party endpoints we don't control, so partial
   results beat an error page.
   CryptoPanic is layered on top ONLY when CRYPTOPANIC_TOKEN is set; it adds the
   per-currency filtering and bull/bear vote signal that plain RSS lacks. */
const NEWS_SOURCES = [
  { name: 'CoinDesk',      url: 'https://www.coindesk.com/arc/outboundfeeds/rss/' },
  { name: 'Cointelegraph', url: 'https://cointelegraph.com/rss' },
  { name: 'Decrypt',       url: 'https://decrypt.co/feed' },
  { name: 'The Block',     url: 'https://www.theblock.co/rss.xml' },
];
const CRYPTOPANIC_TOKEN = process.env.CRYPTOPANIC_TOKEN || '';
const NEWS_TTL_MS = 10 * 60 * 1000;
let _newsCache = { data: null, at: 0 };

const _cdata = s => String(s || '').replace(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/, '$1');
// &amp; must be decoded LAST, otherwise "&amp;lt;" would double-decode into "<".
const _htmlEnt = s => String(s || '')
  .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&quot;/gi, '"')
  .replace(/&#0?39;|&apos;|&#x27;/gi, "'").replace(/&nbsp;/gi, ' ')
  .replace(/&#8217;|&rsquo;/gi, '’').replace(/&#8216;|&lsquo;/gi, '‘')
  .replace(/&#8220;|&ldquo;/gi, '“').replace(/&#8221;|&rdquo;/gi, '”')
  .replace(/&#8211;|&ndash;/gi, '–').replace(/&#8212;|&mdash;/gi, '—')
  .replace(/&amp;/gi, '&');
const _stripTags = s => String(s || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
const _escapeRe  = s => String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function _parseRss(xml, sourceName) {
  const out = [];
  const blocks = String(xml).match(/<item[\s>][\s\S]*?<\/item>/gi) || [];
  for (const b of blocks) {
    // Namespaced tags (atom:link, dc:date) won't collide here — the ':' isn't
    // matched by the name pattern, so <link> never picks up <atom:link>.
    const tag = name => {
      const m = b.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i'));
      return m ? _htmlEnt(_cdata(m[1])).trim() : '';
    };
    const title = _stripTags(tag('title'));
    const link  = tag('link') || _htmlEnt(_cdata(b.match(/<guid(?:\s[^>]*)?>([\s\S]*?)<\/guid>/i)?.[1] || '')).trim();
    if (!title || !link) continue;
    const pub = tag('pubDate') || tag('dc:date');
    const ts  = pub ? new Date(pub).getTime() : NaN;
    // Self-closing media tags can't be read by tag(), so grab their url attr.
    const thumb =
      b.match(/<media:content[^>]+url=["']([^"']+)["']/i)?.[1] ||
      b.match(/<media:thumbnail[^>]+url=["']([^"']+)["']/i)?.[1] ||
      b.match(/<enclosure[^>]+url=["']([^"']+)["']/i)?.[1] ||
      b.match(/<img[^>]+src=["']([^"']+)["']/i)?.[1] || null;
    out.push({
      title,
      url: link,
      source: sourceName,
      publishedAt: Number.isFinite(ts) ? ts : null,
      summary: _stripTags(tag('description')).slice(0, 220),
      thumbnail: thumb,
      votes: null,
    });
  }
  return out;
}

// Same story republished by several outlets is one story to a reader — key on
// a normalized title so the feed doesn't show the same headline four times.
function _dedupeNews(items) {
  const seen = new Set();
  const out = [];
  for (const it of items) {
    const key = String(it.title || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 80);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(it);
  }
  return out;
}

async function _fetchRssNews() {
  const settled = await Promise.allSettled(NEWS_SOURCES.map(s =>
    axios.get(s.url, { timeout: 9000, headers: { 'User-Agent': 'BloombarkTerminal/1.0 (+https://bloombark.app)' } })
      .then(r => _parseRss(r.data, s.name))
  ));
  const items = [];
  settled.forEach((r, i) => {
    if (r.status === 'fulfilled') items.push(...r.value);
    else console.error(`[news] source failed (${NEWS_SOURCES[i].name}):`, r.reason?.message);
  });
  return _dedupeNews(items).sort((a, b) => (b.publishedAt || 0) - (a.publishedAt || 0));
}

async function _fetchCryptoPanic(currencies) {
  if (!CRYPTOPANIC_TOKEN) return [];
  try {
    const params = { auth_token: CRYPTOPANIC_TOKEN, public: 'true' };
    if (currencies) params.currencies = currencies;
    const { data } = await axios.get('https://cryptopanic.com/api/v1/posts/', { params, timeout: 9000 });
    return (data?.results || []).map(p => ({
      title: p.title || '',
      url: p.url || '',
      source: p.source?.title || 'CryptoPanic',
      publishedAt: p.published_at ? new Date(p.published_at).getTime() : null,
      summary: '',
      thumbnail: null,
      votes: p.votes ? { positive: p.votes.positive || 0, negative: p.votes.negative || 0 } : null,
    })).filter(x => x.title && x.url);
  } catch (e) {
    console.error('[news] cryptopanic failed:', e.message);
    return [];
  }
}

app.get('/api/news', async (req, res) => {
  const bypass = req.query.refresh === '1';
  if (!bypass && _newsCache.data && Date.now() - _newsCache.at < NEWS_TTL_MS) {
    return res.json({ success: true, items: _newsCache.data, cached: true });
  }
  try {
    const [rss, panic] = await Promise.all([_fetchRssNews(), _fetchCryptoPanic(null)]);
    const items = _dedupeNews([...panic, ...rss])
      .sort((a, b) => (b.publishedAt || 0) - (a.publishedAt || 0))
      .slice(0, 60);
    // Never cache an empty result — every source erroring at once would
    // otherwise pin an empty feed in place for the full TTL.
    if (items.length) _newsCache = { data: items, at: Date.now() };
    res.json({ success: true, items });
  } catch (e) {
    console.error('[news] failed:', e.message);
    res.status(500).json({ success: false, error: e.message, items: [] });
  }
});

/* Per-token coverage. Most Robinhood-chain tokens are far too small to ever
   appear in mainstream crypto media, so the Community mentions (an exact
   contract-address match against our own chat) are the primary signal here and
   the headline match is the bonus — not the other way round. */
app.get('/api/news/token', async (req, res) => {
  const symbol  = String(req.query.symbol || '').trim();
  const address = String(req.query.address || '').trim().toLowerCase();
  try {
    let mentions = [];
    if (/^0x[a-f0-9]{40}$/.test(address)) {
      const since = Date.now() - 30 * 24 * 60 * 60 * 1000;
      const ph = TRENDING_ROOM_EXCLUDE.map(() => '?').join(',');
      // MySQL's default collation is case-insensitive, so a lowercased LIKE
      // still matches however the user happened to type/paste the address.
      const rows = await dbAll(
        `SELECT room, display_name, text, ts FROM chat_messages
         WHERE ts > ? AND room NOT IN (${ph}) AND text LIKE ?
         ORDER BY ts DESC LIMIT 20`,
        [since, ...TRENDING_ROOM_EXCLUDE, `%${address}%`]
      );
      mentions = rows.map(r => ({
        room: r.room,
        author: r.display_name || 'Anon',
        text: String(r.text || '').slice(0, 240),
        ts: Number(r.ts),
      }));
    }

    // Ticker match needs >=3 chars: 1–2 letter symbols match random words in
    // English headlines and would fill this card with unrelated articles.
    let articles = [];
    if (symbol.length >= 3) {
      const [rss, panic] = await Promise.all([
        _fetchRssNews(),
        _fetchCryptoPanic(symbol.toUpperCase()),
      ]);
      const re = new RegExp(`\\b\\$?${_escapeRe(symbol)}\\b`, 'i');
      articles = _dedupeNews([...panic, ...rss.filter(it => re.test(it.title))]).slice(0, 6);
    }

    res.json({ success: true, articles, mentions, mentionCount: mentions.length });
  } catch (e) {
    console.error('[news/token] failed:', e.message);
    res.status(500).json({ success: false, error: e.message, articles: [], mentions: [] });
  }
});

// ─── Sniper Assistance: on-chain new-pool detector ──────────────────────────
// Scans for the *universal* PairCreated (Uniswap V2 and every V2 fork —
// confirmed this covers Robinhood chain's official Uniswap V2 deployment AND
// the "Flap" launchpad's factory, since both emit the identical standard
// signature) and V3 PoolCreated topics, chain-wide with no address filter —
// so any current or future launchpad using either standard is caught
// automatically without per-protocol integration. Deliberately does NOT
// depend on GeckoTerminal/DexScreener for detection (only for enrichment,
// best-effort, after the fact) since a pool seconds old usually isn't
// indexed by them yet anyway.
const ROBINHOOD_WETH = '0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73';
const PAIR_CREATED_TOPIC   = '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9';
const POOL_CREATED_V3_TOPIC = '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118';

let _sniperLastBlock = 0;
let _sniperScanning  = false;

async function _sniperRpc(method, params) {
  const r = await axios.post(RPC_URLS.robinhood,
    { jsonrpc: '2.0', id: 1, method, params },
    { timeout: 15000, headers: { 'Content-Type': 'application/json', ...BLOCKSCOUT_AUTH_HEADERS } });
  if (r.data?.error) throw new Error(r.data.error.message || 'RPC error');
  return r.data?.result;
}

// Decodes topics/data shared by both event shapes — pool/pair address always
// ends up as the last 20 bytes of a 32-byte word, just at a different offset
// in `data` depending on which event it is.
function _sniperDecodeLog(log) {
  const topic0 = (log.topics[0] || '').toLowerCase();
  if (topic0 !== PAIR_CREATED_TOPIC && topic0 !== POOL_CREATED_V3_TOPIC) return null;
  const token0 = '0x' + log.topics[1].slice(-40);
  const token1 = '0x' + log.topics[2].slice(-40);
  const dataHex = log.data.replace('0x', '');
  const poolAddress = topic0 === PAIR_CREATED_TOPIC
    ? '0x' + dataHex.slice(24, 64)          // PairCreated: data = [pair][uint256]
    : '0x' + dataHex.slice(64 + 24, 128);   // PoolCreated: data = [tickSpacing][pool]
  const source = topic0 === PAIR_CREATED_TOPIC ? 'v2_pair' : 'v3_pool';
  return { token0, token1, poolAddress, source };
}

async function _sniperProcessLog(log) {
  const decoded = _sniperDecodeLog(log);
  if (!decoded) return;
  const { token0, token1, poolAddress, source } = decoded;

  const quoteAddr = ROBINHOOD_WETH.toLowerCase();
  let tokenAddress, quoteAddress;
  if (token0.toLowerCase() === quoteAddr) { tokenAddress = token1; quoteAddress = token0; }
  else if (token1.toLowerCase() === quoteAddr) { tokenAddress = token0; quoteAddress = token1; }
  else { tokenAddress = token0; quoteAddress = token1; } // exotic pair (neither side is WETH) — still record it, just can't assume which side is "the token"

  const exists = await dbGet('SELECT id FROM sniper_pools WHERE chain=? AND pool_address=?', ['robinhood', poolAddress.toLowerCase()]);
  if (exists) return;

  const [symbolHex, nameHex, decHex] = await Promise.all([
    _ethCall(RPC_URLS.robinhood, tokenAddress, '0x95d89b41').catch(() => '0x'), // symbol()
    _ethCall(RPC_URLS.robinhood, tokenAddress, '0x06fdde03').catch(() => '0x'), // name()
    _ethCall(RPC_URLS.robinhood, tokenAddress, '0x313ce567').catch(() => '0x'), // decimals()
  ]);
  const decodeStr = hex => {
    try {
      if (!hex || hex === '0x') return null;
      const clean = hex.replace('0x', '');
      const len = parseInt(clean.slice(64, 128), 16);
      const bytes = Buffer.from(clean.slice(128, 128 + len * 2), 'hex');
      return bytes.toString('utf8').replace(/\0/g, '').trim() || null;
    } catch (e) { return null; }
  };
  const symbol = decodeStr(symbolHex);
  const name = decodeStr(nameHex);
  const decimals = decHex && decHex !== '0x' ? parseInt(decHex, 16) : 18;

  await dbRun(`
    INSERT INTO sniper_pools (chain, pool_address, token_address, quote_address, symbol, name, decimals, source, block_number, tx_hash, detected_at, block_time)
    VALUES ('robinhood',?,?,?,?,?,?,?,?,?,?,?)
    ON DUPLICATE KEY UPDATE id=id
  `, [poolAddress.toLowerCase(), tokenAddress.toLowerCase(), quoteAddress.toLowerCase(), symbol, name, decimals, source,
      parseInt(log.blockNumber, 16), log.transactionHash, Date.now(), null]);
}

async function _scanNewPools() {
  if (_sniperScanning) return;
  _sniperScanning = true;
  try {
    const latestHex = await _sniperRpc('eth_blockNumber', []);
    const latest = parseInt(latestHex, 16);
    if (!latest) return;
    if (!_sniperLastBlock) _sniperLastBlock = Math.max(0, latest - 20); // bootstrap on first run
    const fromBlock = _sniperLastBlock + 1;
    if (fromBlock > latest) return;
    const toBlock = Math.min(latest, fromBlock + 2000); // cap range per call

    const logs = await _sniperRpc('eth_getLogs', [{
      fromBlock: '0x' + fromBlock.toString(16),
      toBlock: '0x' + toBlock.toString(16),
      topics: [[PAIR_CREATED_TOPIC, POOL_CREATED_V3_TOPIC]],
    }]) || [];

    for (const log of logs) {
      try { await _sniperProcessLog(log); } catch (e) { console.error('[sniper] log failed:', e.message); }
    }
    _sniperLastBlock = toBlock;
    await _saveGenericCacheToDb('sniper_last_block', _sniperLastBlock);
  } catch (e) {
    console.error('[sniper] scan failed:', e.message);
  } finally {
    _sniperScanning = false;
  }
}
// Disabled by default — this loop hits eth_getLogs every 8s nonstop and was
// the main driver burning through the Blockscout Pro API's monthly credit
// quota, starving other Robinhood-chain features (RPC calls, chain-tx stats)
// of credits. Re-enable via env once credits/plan are sorted out.
const SNIPER_SCANNER_ENABLED = process.env.SNIPER_SCANNER_ENABLED === 'true';
if (SNIPER_SCANNER_ENABLED) {
  setTimeout(_scanNewPools, 15000);
  setInterval(_scanNewPools, 8000);
}

// Best-effort enrichment: fills in price/liquidity/mcap for recently-detected
// pools once DexScreener has actually indexed them (usually within seconds to
// a couple minutes — brand new pools often aren't there yet at detection
// time, which is the whole reason detection doesn't wait on this).
async function _enrichSniperPools() {
  try {
    const rows = await dbAll(`
      SELECT * FROM sniper_pools
      WHERE enriched_at IS NULL AND detected_at > ?
      ORDER BY detected_at DESC LIMIT 20
    `, [Date.now() - 60 * 60 * 1000]); // give up after 1 hour
    for (const row of rows) {
      try {
        const dsRes = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${row.token_address}`, { timeout: 8000 }).catch(() => null);
        const pairs = (dsRes?.data?.pairs || []).filter(p => p.chainId === 'robinhood' && p.pairAddress?.toLowerCase() === row.pool_address.toLowerCase());
        if (pairs.length) {
          const p = pairs[0];
          await dbRun('UPDATE sniper_pools SET price_usd=?, liquidity_usd=?, mcap_usd=?, enriched_at=? WHERE id=?',
            [parseFloat(p.priceUsd || 0), parseFloat(p.liquidity?.usd || 0), parseFloat(p.fdv || p.marketCap || 0), Date.now(), row.id]);
        }
      } catch (e) { /* leave unenriched, will retry next cycle until the 1h cutoff */ }
    }
  } catch (e) { console.error('[sniper] enrich failed:', e.message); }
}
if (SNIPER_SCANNER_ENABLED) {
  setInterval(_enrichSniperPools, 15000);
}

app.get('/api/sniper/pools', async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 200);
  const rows = await dbAll('SELECT * FROM sniper_pools ORDER BY detected_at DESC LIMIT ?', [limit]);
  res.json({ success: true, pools: rows });
});

// ─── Keep-alive: Render's free/starter tier spins the service down after
// ~15 min with no inbound HTTP traffic. When that happens the whole Node
// process pauses — including every setInterval-based background job above
// (alert checker, BloomBuy poller, market/narrative warmers, etc), which
// silently stops alerts from firing until the next real request wakes it
// back up. Self-pinging our own public URL keeps genuine inbound traffic
// flowing so Render never sees it as idle. ────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));
if (process.env.RENDER_EXTERNAL_URL) {
  setInterval(() => {
    axios.get(`${process.env.RENDER_EXTERNAL_URL}/api/health`, { timeout: 10000 }).catch(() => {});
  }, 10 * 60 * 1000);
}

// In-memory cache for wallet-map and solana trader data (5 min TTL)
const _walletMapCache = new Map();
function _wmc(key, val) {
  if (val !== undefined) { _walletMapCache.set(key, { val, ts: Date.now() }); return val; }
  const e = _walletMapCache.get(key);
  return e && Date.now() - e.ts < CONFIG.walletMapCacheTtlMs ? e.val : null;
}

// ─── Wallet Relationship Map — real data from GoPlus + DexScreener ────────────
app.get('/api/wallet-map/:address', async (req, res) => {
  const { address } = req.params;
  const chain = (req.query.chain || 'ethereum').toLowerCase();
  try {
    const holders = [];

    // 1. Fetch GoPlus for creator + LP holder addresses
    const [goplusRaw, dexRaw] = await Promise.allSettled([
      fetchGoPlus(address, chain),
      axios.get(`${DEXSCREENER}/latest/dex/tokens/${address}`, { timeout: 8000 }).then(r => r.data),
    ]);
    const gp  = goplusRaw.status === 'fulfilled' ? goplusRaw.value : null;
    const dex = dexRaw.status === 'fulfilled' ? dexRaw.value : null;

    // 2. Creator address
    if (gp?.creatorAddress) {
      holders.push({
        address:    gp.creatorAddress,
        shortAddr:  gp.creatorAddress.slice(0,6) + '…' + gp.creatorAddress.slice(-4),
        type:       'Creator',
        supplyPct:  gp.creatorPercent || 0,
        riskScore:  gp.creatorMalicious ? 90 : 40,
        isRealData: true,
        tag:        'Token Creator',
      });
    }


    // 3. LP holders from GoPlus (real LP pool wallet addresses)
    (gp?.lpHolders || []).forEach((h, i) => {
      if (!h.address || holders.find(x => x.address === h.address)) return;
      holders.push({
        address:    h.address,
        shortAddr:  h.address.slice(0,6) + '…' + h.address.slice(-4),
        type:       h.locked ? 'LP Locked' : (i === 0 ? 'Top LP' : 'LP Holder'),
        supplyPct:  parseFloat((h.pct || 0).toFixed(3)),
        riskScore:  h.locked ? 15 : 45,
        isRealData: true,
        tag:        h.tag || (h.locked ? 'Locked LP' : 'LP Pool'),
      });
    });

    // 3b. GoPlus token holders — Whales & Top Holders (works for EVM; Solana if GoPlus has data)
    (gp?.holders || []).forEach((h) => {
      if (!h.address || holders.find(x => x.address === h.address)) return;
      const pct = h.pct || 0;
      const type = h.isContract ? 'Contract' : pct > 5 ? 'Whale' : pct > 1 ? 'Top Holder' : pct > 0.1 ? 'Insider' : 'Holder';
      holders.push({
        address:    h.address,
        shortAddr:  h.address.slice(0,6) + '…' + h.address.slice(-4),
        type,
        supplyPct:  parseFloat(pct.toFixed(4)),
        riskScore:  pct > 5 ? 75 : pct > 1 ? 50 : 30,
        isRealData: true,
        tag:        h.tag || type,
        isContract: h.isContract,
        locked:     h.locked,
      });
    });

    // 3c. Owner address if different from creator
    if (gp?.ownerAddress && gp.ownerAddress !== gp.creatorAddress && !holders.find(x => x.address === gp.ownerAddress)) {
      holders.push({
        address:    gp.ownerAddress,
        shortAddr:  gp.ownerAddress.slice(0,6) + '…' + gp.ownerAddress.slice(-4),
        type:       'Owner',
        supplyPct:  parseFloat((gp.ownerPercent || 0).toFixed(4)),
        riskScore:  60,
        isRealData: true,
        tag:        'Contract Owner',
      });
    }

    // 4. DEX pair addresses (real pool contracts from DexScreener)
    const pairs = (dex?.pairs || []).slice(0, 8);
    for (const p of pairs) {
      const addr = p.pairAddress;
      if (!addr || holders.find(x => x.address === addr)) continue;
      const liqPct = pairs.length > 0 ? parseFloat(((p.liquidity?.usd || 0) / Math.max(...pairs.map(x => x.liquidity?.usd || 1)) * 15).toFixed(2)) : 0;
      holders.push({
        address:    addr,
        shortAddr:  addr.slice(0,6) + '…' + addr.slice(-4),
        type:       p.dexId?.includes('raydium') || p.dexId?.includes('orca') ? 'DEX Pool' : 'LP Pool',
        supplyPct:  liqPct,
        riskScore:  20,
        isRealData: true,
        tag:        (p.dexId || 'DEX').toUpperCase() + ' Pool',
        liqUsd:     p.liquidity?.usd || 0,
        vol24h:     p.volume?.h24 || 0,
        buys:       p.txns?.h24?.buys || 0,
        sells:      p.txns?.h24?.sells || 0,
      });
    }


    // 4c. Insider wallets detection
    const insiderSet = new Set(holders.map(h => h.address.toLowerCase()));

    function addInsider(addr, tag, riskScore = 70) {
      const al = addr.toLowerCase();
      if (!al || insiderSet.has(al)) return;
      insiderSet.add(al);
      holders.push({
        address: addr, shortAddr: addr.slice(0,6)+'…'+addr.slice(-4),
        type: 'Insider', supplyPct: 0, riskScore, isRealData: true, tag,
      });
    }

    // Source 1: GoPlus malicious/flagged addresses
    if (gp?.creatorMalicious && gp?.creatorAddress) addInsider(gp.creatorAddress, 'Malicious Creator', 90);
    (gp?.lpHolders || []).filter(h => !h.locked && h.pct > 0).forEach(h => {
      if (h.address) addInsider(h.address, 'Unlocked LP Holder', 65);
    });

    // Source 2: Solana RPC — repeat signers across recent pool txns = bots/insiders
    if (false && chain === 'solana') { // Solana no longer supported — branch disabled, EVM path below always runs
      const SOLANA_RPC = 'https://api.mainnet-beta.solana.com';
      const poolAddresses = pairs.slice(0, 3).map(p => p.pairAddress).filter(Boolean);

      // Fetch signatures for all pools in parallel (50 each)
      const allSigners = {}; // addr → count across all pools
      await Promise.allSettled(poolAddresses.map(async (poolAddr) => {
        try {
          const sigRes = await axios.post(SOLANA_RPC, {
            jsonrpc: '2.0', id: 1, method: 'getSignaturesForAddress',
            params: [poolAddr, { limit: 50 }],
          }, { timeout: 6000 });
          const sigs = sigRes.data?.result || [];

          // Fetch 15 tx details in parallel
          const txDetails = await Promise.allSettled(sigs.slice(0, 15).map(s =>
            axios.post(SOLANA_RPC, {
              jsonrpc: '2.0', id: 1, method: 'getTransaction',
              params: [s.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }],
            }, { timeout: 4000 }).then(r => r.data?.result)
          ));

          for (const tx of txDetails) {
            if (tx.status !== 'fulfilled' || !tx.value) continue;
            const keys = tx.value?.transaction?.message?.accountKeys || [];
            // First 2 accounts are signers in most Solana txns
            for (const k of keys.slice(0, 2)) {
              const pub = (typeof k === 'string' ? k : k.pubkey || '');
              const pubL = pub.toLowerCase();
              if (!pubL || pubL === poolAddr.toLowerCase()) continue;
              allSigners[pub] = (allSigners[pub] || 0) + 1;
            }
          }
        } catch (_) {}
      }));

      // Wallets appearing 2+ times = repeat trader = potential insider/bot
      for (const [addr, count] of Object.entries(allSigners)) {
        if (count >= 2) addInsider(addr, `${count}× repeat trader`, count >= 5 ? 80 : 65);
      }
    } else {
      // EVM: wallets that received tokens in last 200 blocks (recent buyers)
      const EVM_RPC = {
        ethereum: 'https://ethereum-rpc.publicnode.com', eth: 'https://ethereum-rpc.publicnode.com',
        base: 'https://base-rpc.publicnode.com', bsc: 'https://bsc-rpc.publicnode.com',
        polygon: 'https://polygon-bor-rpc.publicnode.com', arbitrum: 'https://arbitrum-one-rpc.publicnode.com',
        optimism: 'https://optimism-rpc.publicnode.com',
      };
      const rpc = EVM_RPC[chain];
      if (rpc) {
        try {
          const blockRes = await axios.post(rpc, { jsonrpc:'2.0', id:1, method:'eth_blockNumber', params:[] }, { timeout: 4000 });
          const latestBlock = parseInt(blockRes.data?.result, 16);
          const fromBlock = '0x' + Math.max(0, latestBlock - 200).toString(16);
          const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
          const logsRes = await axios.post(rpc, {
            jsonrpc: '2.0', id: 1, method: 'eth_getLogs',
            params: [{ fromBlock, toBlock: '0x'+latestBlock.toString(16), address, topics: [TRANSFER_TOPIC] }],
          }, { timeout: 6000 });
          const logs = logsRes.data?.result || [];
          const buyCount = {};
          for (const log of logs) {
            const to = '0x' + (log.topics?.[2] || '').slice(26);
            if (to.length !== 42 || to === '0x0000000000000000000000000000000000000000') continue;
            buyCount[to.toLowerCase()] = (buyCount[to.toLowerCase()] || 0) + 1;
          }
          Object.entries(buyCount).filter(([,c]) => c >= 2).sort((a,b)=>b[1]-a[1]).slice(0,8)
            .forEach(([addr, count]) => addInsider(addr, `${count} recent buys`, 65));
        } catch (_) {}
      }
    }

    // 5. Sort by supplyPct desc, assign ranks
    holders.sort((a, b) => b.supplyPct - a.supplyPct);
    holders.forEach((h, i) => { h.rank = i + 1; });

    // 6. Build real on-chain edges via recent transactions
    const addrToIdx = {};
    holders.forEach((h, i) => { addrToIdx[h.address.toLowerCase()] = i; });

    const edges = [];
    const edgeSet = new Set();
    let liveEdges = false;

    function addEdge(i, j, type) {
      const key = `${Math.min(i,j)}-${Math.max(i,j)}`;
      if (!edgeSet.has(key)) { edgeSet.add(key); edges.push([i, j, type]); }
    }

    const poolNodes = holders.filter(h => h.type?.includes('Pool') || h.type?.includes('LP'));
    const specialNodes = holders.filter(h => h.type === 'Creator' || h.type === 'Owner');

    if (false && chain === 'solana') { // Solana no longer supported — branch disabled, EVM path below always runs
      // Solana: use public RPC to get recent transactions for each pool account
      // Extract signers (wallet addresses) from each transaction
      const SOLANA_RPC = 'https://api.mainnet-beta.solana.com';
      const walletPools = {}; // walletAddr → Set<poolIdx>

      await Promise.allSettled(poolNodes.slice(0, 4).map(async (poolNode) => {
        const poolIdx = addrToIdx[poolNode.address.toLowerCase()];
        if (poolIdx === undefined) return;
        try {
          // Get recent signatures for this pool
          const sigRes = await axios.post(SOLANA_RPC, {
            jsonrpc: '2.0', id: 1, method: 'getSignaturesForAddress',
            params: [poolNode.address, { limit: 30 }],
          }, { timeout: 6000 });
          const sigs = sigRes.data?.result || [];
          if (!sigs.length) return;

          // Fetch transactions in parallel (max 10)
          const txResults = await Promise.allSettled(
            sigs.slice(0, 10).map(s =>
              axios.post(SOLANA_RPC, {
                jsonrpc: '2.0', id: 1, method: 'getTransaction',
                params: [s.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }],
              }, { timeout: 5000 }).then(r => r.data?.result)
            )
          );

          for (const txResult of txResults) {
            if (txResult.status !== 'fulfilled' || !txResult.value) continue;
            const keys = txResult.value?.transaction?.message?.accountKeys || [];
            const signers = keys.filter(k => {
              const pub = typeof k === 'string' ? k : k.pubkey;
              const signer = typeof k === 'string' ? false : k.signer;
              return signer || typeof k === 'string';
            }).map(k => typeof k === 'string' ? k : k.pubkey).slice(0, 3); // first accounts are signers

            for (const walletAddr of signers) {
              const walletLower = walletAddr.toLowerCase();
              if (walletLower === poolNode.address.toLowerCase()) continue;
              liveEdges = true;

              // If this wallet is already a known holder node, connect directly
              const knownIdx = addrToIdx[walletLower];
              if (knownIdx !== undefined) {
                addEdge(knownIdx, poolIdx, 'traded');
              } else {
                // Track which pools this wallet touched (for co-occurrence)
                if (!walletPools[walletLower]) walletPools[walletLower] = new Set();
                walletPools[walletLower].add(poolIdx);
                // Also count appearances for ranking
              }
            }
          }
        } catch (_) {}
      }));

      // Wallets active in 2+ pools → add as Trader nodes (cross-pool activity is suspicious)
      const multiPoolTraders = Object.entries(walletPools).filter(([, s]) => s.size >= 2).slice(0, 10);
      for (const [addr, pools] of multiPoolTraders) {
        const idx = holders.length;
        addrToIdx[addr] = idx;
        holders.push({ address: addr, shortAddr: addr.slice(0,6)+'…'+addr.slice(-4), type: 'Trader', supplyPct: 0, riskScore: 50, isRealData: true, tag: `Active in ${pools.size} pools`, rank: idx+1 });
        for (const pi of pools) addEdge(idx, pi, 'traded');
      }
      // Also add top single-pool traders as Trader nodes (up to 8 most frequent)
      const singlePoolTraders = Object.entries(walletPools)
        .filter(([, s]) => s.size === 1 && addrToIdx[Object.values(s)[0]] === undefined)
        .slice(0, 8);
      for (const [addr, pools] of singlePoolTraders) {
        const idx = holders.length;
        addrToIdx[addr] = idx;
        holders.push({ address: addr, shortAddr: addr.slice(0,6)+'…'+addr.slice(-4), type: 'Trader', supplyPct: 0, riskScore: 30, isRealData: true, tag: 'Recent trader', rank: idx+1 });
        for (const pi of pools) addEdge(idx, pi, 'traded');
      }

    } else {
      // EVM: use public JSON-RPC getLogs to get Transfer events → from/to addresses
      const EVM_RPC = {
        ethereum: 'https://ethereum-rpc.publicnode.com', eth: 'https://ethereum-rpc.publicnode.com',
        base: 'https://base-rpc.publicnode.com', bsc: 'https://bsc-rpc.publicnode.com',
        polygon: 'https://polygon-bor-rpc.publicnode.com', arbitrum: 'https://arbitrum-one-rpc.publicnode.com',
        optimism: 'https://optimism-rpc.publicnode.com',
      };
      const rpc = EVM_RPC[chain];

      if (rpc) {
        try {
          // Get latest block number
          const blockRes = await axios.post(rpc, { jsonrpc:'2.0', id:1, method:'eth_blockNumber', params:[] }, { timeout: 5000 });
          const latestBlock = parseInt(blockRes.data?.result, 16);
          const fromBlock = '0x' + Math.max(0, latestBlock - 500).toString(16);
          const toBlock = '0x' + latestBlock.toString(16);

          // ERC-20 Transfer event: topic0 = keccak256("Transfer(address,address,uint256)")
          const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
          const logsRes = await axios.post(rpc, {
            jsonrpc: '2.0', id: 1, method: 'eth_getLogs',
            params: [{ fromBlock, toBlock, address, topics: [TRANSFER_TOPIC] }],
          }, { timeout: 8000 });

          const logs = logsRes.data?.result || [];
          const walletPools = {};
          const recentTraders = new Map(); // addr → count

          for (const log of logs.slice(0, 200)) {
            // topic[1]=from, topic[2]=to (padded to 32 bytes)
            const from = '0x' + (log.topics?.[1] || '').slice(26);
            const to   = '0x' + (log.topics?.[2] || '').slice(26);
            if (from.length !== 42 || to.length !== 42) continue;
            liveEdges = true;

            for (const addr of [from, to]) {
              const al = addr.toLowerCase();
              if (al === '0x0000000000000000000000000000000000000000') continue;
              recentTraders.set(al, (recentTraders.get(al) || 0) + 1);

              // If known holder, connect to pool nodes it interacted with
              const knownIdx = addrToIdx[al];
              if (knownIdx !== undefined) {
                for (const p of poolNodes.slice(0, 3)) {
                  const pi = addrToIdx[p.address.toLowerCase()];
                  if (pi !== undefined) addEdge(knownIdx, pi, 'transferred');
                }
              }
            }
          }

          // Top traders not already in holders → add as Trader nodes
          const topTraders = [...recentTraders.entries()]
            .filter(([a]) => addrToIdx[a] === undefined)
            .sort((a,b) => b[1]-a[1]).slice(0, 10);
          for (const [addr, count] of topTraders) {
            const idx = holders.length;
            addrToIdx[addr] = idx;
            holders.push({ address: addr, shortAddr: addr.slice(0,6)+'…'+addr.slice(-4), type: 'Trader', supplyPct: 0, riskScore: 30, isRealData: true, tag: `${count} recent txns`, rank: idx+1 });
            for (const p of poolNodes.slice(0, 2)) {
              const pi = addrToIdx[p.address.toLowerCase()];
              if (pi !== undefined) addEdge(idx, pi, 'transferred');
            }
          }
        } catch (_) {}
      }
    }

    // Always: connect Creator/Owner to pools (they deployed the liquidity)
    for (const s of specialNodes) {
      const si = addrToIdx[s.address.toLowerCase()];
      if (si === undefined) continue;
      for (const p of poolNodes.slice(0, 3)) {
        const pi = addrToIdx[p.address.toLowerCase()];
        if (pi !== undefined) addEdge(si, pi, 'created');
      }
    }

    // Connect top holders (>1% supply) to their nearest pool node
    const topHolderNodes = holders.filter(h => h.supplyPct > 1 && !h.type?.includes('Pool') && !h.type?.includes('LP') && h.type !== 'Creator' && h.type !== 'Owner');
    if (poolNodes.length > 0) {
      const mainPool = addrToIdx[poolNodes[0].address.toLowerCase()];
      if (mainPool !== undefined) {
        for (const h of topHolderNodes.slice(0, 8)) {
          const hi = addrToIdx[h.address.toLowerCase()];
          if (hi !== undefined) addEdge(hi, mainPool, 'holds');
        }
      }
    }

    res.json({ success: true, holders, edges, chain, source: 'goplus+dexscreener+onchain-rpc', total: holders.length, liveEdges });
  } catch (e) {
    res.json({ success: false, error: e.message, holders: [], edges: [] });
  }
});

// ─── User profile endpoints ──────────────────────────────────────────────────
app.get('/api/profile/:wallet', async (req, res) => {
  const row = await dbGet('SELECT wallet, display_name, avatar FROM user_profiles WHERE wallet=?', [req.params.wallet]);
  if (!row) return res.json({ found: false });
  res.json({ found: true, displayName: row.display_name, avatar: row.avatar });
});

app.post('/api/profile', express.json({ limit: '8mb' }), async (req, res) => {
  const { wallet, displayName, avatar } = req.body || {};
  if (!wallet) return res.status(400).json({ error: 'wallet required' });
  if (avatar && avatar.length > 7 * 1024 * 1024) return res.status(400).json({ error: 'avatar too large' });
  await dbRun(`
    INSERT INTO user_profiles (wallet, display_name, avatar, updated_at)
    VALUES (?, ?, ?, UNIX_TIMESTAMP())
    ON DUPLICATE KEY UPDATE
      display_name = VALUES(display_name),
      avatar       = VALUES(avatar),
      updated_at   = VALUES(updated_at)
  `, [wallet, displayName || null, avatar || null]);
  res.json({ ok: true });
});

// ─── Public config endpoint ─────────────────────────────────────────────────
app.get('/api/config/public', async (req, res) => {
  const [ca, ticker, enabledChains] = await Promise.all([
    dbGet("SELECT value FROM app_config WHERE `key`='contract_address'"),
    dbGet("SELECT value FROM app_config WHERE `key`='token_ticker'"),
    _getEnabledChains(),
  ]);
  res.json({
    contractAddress: ca?.value || 'coming_soon',
    tokenTicker: ticker?.value || 'BBRK',
    networkEnv: NETWORK_ENV,
    isTestnet: IS_TESTNET,
    chains: Object.fromEntries(Object.keys(CHAIN_NETWORKS).map(k => [k, chainCfg(k)])),
    // Which chains are actually turned on right now — default launch config is
    // Robinhood-only; set via /api/admin/config?key=enabled_chains&value=robinhood,ethereum,base
    enabledChains,
  });
});

// ─── Read-only admin DB query (for inspecting the DB when a direct connection
// isn't possible, e.g. TLS blocked on a local network). Disabled unless
// ADMIN_QUERY_TOKEN is set. Only SELECT/SHOW/DESCRIBE/EXPLAIN are allowed; a
// single statement at a time; results capped. Never mutates data. ────────────
const ADMIN_QUERY_TOKEN = process.env.ADMIN_QUERY_TOKEN || '';
const ADMIN_QUERY_MAX_ROWS = parseInt(process.env.ADMIN_QUERY_MAX_ROWS) || 500;

function _isReadOnlySql(sql) {
  const s = String(sql || '').trim().replace(/;\s*$/, ''); // drop one trailing ;
  if (!s) return false;
  if (s.includes(';')) return false;                       // no stacked statements
  if (/\/\*|--/.test(s)) return false;                     // no comment-based tricks
  const first = s.split(/\s+/)[0].toLowerCase();
  return ['select', 'show', 'describe', 'desc', 'explain', 'with'].includes(first);
}

app.get('/api/admin/query', async (req, res) => {
  if (!ADMIN_QUERY_TOKEN) return res.status(404).json({ error: 'not enabled' });
  const token = req.get('x-admin-token') || req.query.token || '';
  if (token !== ADMIN_QUERY_TOKEN) return res.status(403).json({ error: 'forbidden' });

  const sql = req.query.sql;
  if (!_isReadOnlySql(sql)) {
    return res.status(400).json({ error: 'only a single read-only statement (SELECT/SHOW/DESCRIBE/EXPLAIN/WITH) is allowed' });
  }
  try {
    const rows = await dbAll(sql);
    const capped = Array.isArray(rows) ? rows.slice(0, ADMIN_QUERY_MAX_ROWS) : rows;
    res.json({
      ok: true,
      rowCount: Array.isArray(rows) ? rows.length : undefined,
      truncated: Array.isArray(rows) && rows.length > ADMIN_QUERY_MAX_ROWS,
      rows: capped,
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Token-gated setter for launch-configurable app_config values (ticker + CA).
// Whitelisted keys only — cannot touch anything else. Same token as the query
// endpoint; disabled unless ADMIN_QUERY_TOKEN is set. Accepts GET or POST so a
// plain URL works when direct DB access isn't available.
async function _adminSetConfig(req, res) {
  if (!ADMIN_QUERY_TOKEN) return res.status(404).json({ error: 'not enabled' });
  const token = req.get('x-admin-token') || req.query.token || (req.body && req.body.token) || '';
  if (token !== ADMIN_QUERY_TOKEN) return res.status(403).json({ error: 'forbidden' });
  const ALLOWED = new Set(['token_ticker', 'contract_address', 'moonbot_enabled', 'enabled_chains']);
  const key   = String(req.query.key   ?? (req.body && req.body.key)   ?? '');
  const value = String(req.query.value ?? (req.body && req.body.value) ?? '');
  if (!ALLOWED.has(key)) return res.status(400).json({ error: 'key not allowed (token_ticker or contract_address only)' });
  if (!value) return res.status(400).json({ error: 'value required' });
  try {
    await dbRun(
      "INSERT INTO app_config (`key`, value, updated_at) VALUES (?,?,UNIX_TIMESTAMP()) ON DUPLICATE KEY UPDATE value=VALUES(value), updated_at=VALUES(updated_at)",
      [key, value]
    );
    const row = await dbGet('SELECT `key`, value FROM app_config WHERE `key`=?', [key]);
    res.json({ ok: true, updated: row });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
}
app.get('/api/admin/config', _adminSetConfig);
app.post('/api/admin/config', express.json(), _adminSetConfig);

// Wipe all messages in a chat room. Requires an explicit room key ('all'
// clears every room) — no default, so a bare call can't nuke everything
// by accident. Same admin token as the other /api/admin/* endpoints.
async function _adminClearChat(req, res) {
  if (!ADMIN_QUERY_TOKEN) return res.status(404).json({ error: 'not enabled' });
  const token = req.get('x-admin-token') || req.query.token || (req.body && req.body.token) || '';
  if (token !== ADMIN_QUERY_TOKEN) return res.status(403).json({ error: 'forbidden' });
  const room = String(req.query.room ?? (req.body && req.body.room) ?? '');
  if (!room) return res.status(400).json({ error: 'room required (a room key, or "all")' });
  if (room !== 'all' && !chatRooms[room]) return res.status(400).json({ error: `unknown room "${room}"` });
  try {
    const result = room === 'all'
      ? await dbRun('DELETE FROM chat_messages')
      : await dbRun('DELETE FROM chat_messages WHERE room=?', [room]);
    if (room === 'all') Object.keys(chatRooms).forEach(r => broadcastChat(r, { type: 'chat_room_cleared', room: r }));
    else broadcastChat(room, { type: 'chat_room_cleared', room });
    res.json({ ok: true, room, deleted: result?.affectedRows ?? null });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
}
app.get('/api/admin/clear-chat', _adminClearChat);
app.post('/api/admin/clear-chat', express.json(), _adminClearChat);

// Delete or edit a single AI Track Record row (prediction_history). Not
// exposed anywhere in the frontend — dev-only maintenance via curl/Postman.
// Same admin token as the other /api/admin/* endpoints.
async function _adminDeleteTrackRecord(req, res) {
  if (!ADMIN_QUERY_TOKEN) return res.status(404).json({ error: 'not enabled' });
  const token = req.get('x-admin-token') || req.query.token || (req.body && req.body.token) || '';
  if (token !== ADMIN_QUERY_TOKEN) return res.status(403).json({ error: 'forbidden' });
  const id = parseInt(req.query.id ?? (req.body && req.body.id));
  if (!id) return res.status(400).json({ error: 'id required' });
  try {
    const result = await dbRun('DELETE FROM prediction_history WHERE id=?', [id]);
    res.json({ ok: true, id, deleted: result?.affectedRows ?? null });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
}
app.get('/api/admin/track-record/delete', _adminDeleteTrackRecord);
app.post('/api/admin/track-record/delete', express.json(), _adminDeleteTrackRecord);

const TRACK_RECORD_EDITABLE_COLS = new Set([
  'symbol', 'name', 'signal', 'confidence', 'price_at', 'predicted_at',
  'resolved_at', 'price_after', 'change_pct', 'outcome', 'image_url',
]);
async function _adminUpdateTrackRecord(req, res) {
  if (!ADMIN_QUERY_TOKEN) return res.status(404).json({ error: 'not enabled' });
  const token = req.get('x-admin-token') || req.query.token || (req.body && req.body.token) || '';
  if (token !== ADMIN_QUERY_TOKEN) return res.status(403).json({ error: 'forbidden' });
  const src = req.method === 'GET' ? req.query : (req.body || {});
  const id = parseInt(src.id);
  if (!id) return res.status(400).json({ error: 'id required' });
  const sets = [];
  const values = [];
  for (const col of TRACK_RECORD_EDITABLE_COLS) {
    if (src[col] !== undefined) {
      sets.push(`\`${col}\`=?`);
      values.push(src[col]);
    }
  }
  if (!sets.length) {
    return res.status(400).json({ error: `no editable fields provided — allowed: ${[...TRACK_RECORD_EDITABLE_COLS].join(', ')}` });
  }
  try {
    values.push(id);
    await dbRun(`UPDATE prediction_history SET ${sets.join(', ')} WHERE id=?`, values);
    const row = await dbGet('SELECT * FROM prediction_history WHERE id=?', [id]);
    res.json({ ok: true, updated: row });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
}
app.get('/api/admin/track-record/update', _adminUpdateTrackRecord);
app.post('/api/admin/track-record/update', express.json(), _adminUpdateTrackRecord);

// ─── Trading proxy (KyberSwap aggregator, EVM only) ─────────────────────────
// Note: KyberSwap does not index testnet liquidity — quotes/swaps will return
// no route in testnet mode. This mapping is left as mainnet-only slugs.
const KYBER_CHAINS = { ethereum:'ethereum', base:'base', arbitrum:'arbitrum', polygon:'polygon', optimism:'optimism', avalanche:'avalanche', robinhood:'robinhood' };
// Platform fee on every trade — deducted by KyberSwap's router itself as part
// of the swap tx and sent straight to the treasury (same wallet the Private
// channel payment goes to). 5 bps = 0.05%.
const TRADE_FEE_BPS      = 5;
const TRADE_FEE_TREASURY = process.env.PRIVATE_GATE_TREASURY || '0xf6a2b3016c7ac86724fa71cd4b3946facb319caa';
const RPC_URLS = Object.fromEntries(Object.keys(CHAIN_NETWORKS).map(k => [k, chainCfg(k).rpc]));
// Robinhood's own RPC has no rate limit when tested from a residential/office
// IP, but Cloudflare (which fronts it) throttles/blocks a chunk of requests
// coming from Render's datacenter IPs — a class of traffic Cloudflare's bot
// heuristics commonly flag regardless of request volume. Blockscout's eth-rpc
// proxy is the fallback of last resort for THIS server-to-server path only
// (still capped, but better than a hard failure).
const RPC_FALLBACK_URLS = {
  robinhood: `${chainCfg('robinhood').blockscout}/api/eth-rpc`,
};

// Get best swap route
app.get('/api/trade/kyber/route', async (req, res) => {
  try {
    const { chain, tokenIn, tokenOut, amountIn } = req.query;
    const kc = KYBER_CHAINS[chain];
    if (!kc) return res.status(400).json({ error: `Unsupported chain: ${chain}` });
    if (!tokenIn || !tokenOut || !amountIn) return res.status(400).json({ error: 'missing params' });
    const r = await axios.get(`https://aggregator-api.kyberswap.com/${kc}/api/v1/routes`, {
      params: { tokenIn, tokenOut, amountIn, gasInclude: true },
      headers: { 'x-client-id': 'bloombark' }, timeout: 10000,
    });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

// Build swap transaction calldata
app.post('/api/trade/kyber/build', express.json({ limit: '1mb' }), async (req, res) => {
  try {
    const { chain, routeSummary, sender, slippageBps } = req.body || {};
    const kc = KYBER_CHAINS[chain];
    if (!kc || !routeSummary || !sender) return res.status(400).json({ error: 'missing params' });
    const r = await axios.post(`https://aggregator-api.kyberswap.com/${kc}/api/v1/route/build`, {
      routeSummary,
      sender,
      recipient: sender,
      slippageTolerance: Math.min(Math.max(parseInt(slippageBps) || 100, 5), 2000),
      source: 'bloombark',
      feeReceiver: TRADE_FEE_TREASURY,
      chargeFeeBy: 'currency_in',
      feeAmount: String(TRADE_FEE_BPS),
      isInBps: true,
    }, { headers: { 'x-client-id': 'bloombark' }, timeout: 10000 });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

// ─── KyberSwap Limit Order proxy (gasless — sign only, no tx to create) ────
// Robinhood-chain only, hardcoded server-side — never trust a client-supplied
// chainId here. Confirmed live against KyberSwap's Limit Order API: Robinhood
// (4663) uses their newer "DSLO Protocol" contract (0xcab2FA2eeab7065B45CBc
// F6E3936dDE2506b4f6C) rather than the older LimitOrderProtocol used on most
// other chains, but the Maker API endpoints behave identically either way.
const LIMIT_ORDER_API = 'https://limit-order.kyberswap.com';
const LIMIT_ORDER_CHAIN_ID = '4663';

app.post('/api/trade/limit-order/sign-message', express.json({ limit: '10kb' }), async (req, res) => {
  try {
    const { makerAsset, takerAsset, maker, makingAmount, takingAmount, expiredAt, receiver } = req.body || {};
    if (!makerAsset || !takerAsset || !maker || !makingAmount || !takingAmount || !expiredAt) {
      return res.status(400).json({ error: 'missing params' });
    }
    const r = await axios.post(`${LIMIT_ORDER_API}/write/api/v1/orders/sign-message`, {
      chainId: LIMIT_ORDER_CHAIN_ID, makerAsset, takerAsset, maker, makingAmount, takingAmount, expiredAt,
      ...(receiver ? { receiver } : {}),
    }, { timeout: 10000 });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

app.post('/api/trade/limit-order', express.json({ limit: '10kb' }), async (req, res) => {
  try {
    const { makerAsset, takerAsset, maker, makingAmount, takingAmount, expiredAt, salt, signature, receiver } = req.body || {};
    if (!makerAsset || !takerAsset || !maker || !makingAmount || !takingAmount || !expiredAt || !salt || !signature) {
      return res.status(400).json({ error: 'missing params' });
    }
    const r = await axios.post(`${LIMIT_ORDER_API}/write/api/v1/orders`, {
      chainId: LIMIT_ORDER_CHAIN_ID, makerAsset, takerAsset, maker, makingAmount, takingAmount, expiredAt, salt, signature,
      ...(receiver ? { receiver } : {}),
    }, { timeout: 10000 });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

app.get('/api/trade/limit-orders/:maker', async (req, res) => {
  try {
    const status = ['open', 'filled', 'cancelled', 'expired'].includes(req.query.status) ? req.query.status : 'open';
    const r = await axios.get(`${LIMIT_ORDER_API}/read-ks/api/v1/orders`, {
      params: { chainId: LIMIT_ORDER_CHAIN_ID, maker: req.params.maker, status },
      timeout: 10000,
    });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

app.get('/api/trade/limit-order/active-amount', async (req, res) => {
  try {
    const { maker, makerAsset } = req.query;
    if (!maker || !makerAsset) return res.status(400).json({ error: 'missing params' });
    const r = await axios.get(`${LIMIT_ORDER_API}/read-ks/api/v1/orders/active-making-amount`, {
      params: { chainId: LIMIT_ORDER_CHAIN_ID, maker, makerAsset },
      timeout: 10000,
    });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

app.post('/api/trade/limit-order/cancel-sign', express.json({ limit: '10kb' }), async (req, res) => {
  try {
    const { maker, orderIds } = req.body || {};
    if (!maker || !Array.isArray(orderIds) || !orderIds.length) return res.status(400).json({ error: 'missing params' });
    const r = await axios.post(`${LIMIT_ORDER_API}/write/api/v1/orders/cancel-sign`, {
      chainId: LIMIT_ORDER_CHAIN_ID, maker, orderIds,
    }, { timeout: 10000 });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

app.post('/api/trade/limit-order/cancel', express.json({ limit: '10kb' }), async (req, res) => {
  try {
    const { maker, orderIds, signature } = req.body || {};
    if (!maker || !Array.isArray(orderIds) || !orderIds.length || !signature) return res.status(400).json({ error: 'missing params' });
    const r = await axios.post(`${LIMIT_ORDER_API}/write/api/v1/orders/cancel`, {
      chainId: LIMIT_ORDER_CHAIN_ID, maker, orderIds, signature,
    }, { timeout: 10000 });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

// JSON-RPC proxy to public nodes (decimals, balance, allowance reads)
app.post('/api/trade/rpc/:chain', express.json({ limit: '100kb' }), async (req, res) => {
  try {
    const chain = req.params.chain;
    const url = RPC_URLS[chain];
    if (!url) return res.status(400).json({ error: 'unsupported chain' });
    // Try the chain's own RPC first (retrying once on 429), then fall back
    // to Blockscout's eth-rpc proxy if that chain has one configured — see
    // RPC_FALLBACK_URLS for why the primary can still fail from this server.
    const candidates = [url, RPC_FALLBACK_URLS[chain]].filter(Boolean);
    let lastErr;
    for (const candidateUrl of candidates) {
      for (let attempt = 0; attempt <= 1; attempt++) {
        try {
          const r = await axios.post(candidateUrl, req.body, { timeout: 10000, headers: BLOCKSCOUT_AUTH_HEADERS });
          if (r.data?.error) { lastErr = new Error(r.data.error.message || 'RPC error'); break; }
          return res.json(r.data);
        } catch (e) {
          lastErr = e;
          if (e.response?.status === 429 && attempt < 1) {
            await new Promise(r => setTimeout(r, 800));
            continue;
          }
          break;
        }
      }
    }
    res.status(502).json({ error: lastErr.message });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ─── Wallet holdings (via Blockscout instances, no API key needed) ───────────
const BLOCKSCOUT_URLS = Object.fromEntries(Object.keys(CHAIN_NETWORKS).map(k => [k, chainCfg(k).blockscout]));
const NATIVE_SYMBOLS = { ethereum:'ETH', base:'ETH', arbitrum:'ETH', optimism:'ETH', polygon:'MATIC', robinhood:'ETH' };

const _holdingsCache = new Map(); // wallet -> { ts, data }
app.get('/api/trade/holdings/:wallet', async (req, res) => {
  const wallet = req.params.wallet;
  if (!/^0x[0-9a-fA-F]{40}$/.test(wallet)) return res.status(400).json({ error: 'invalid address' });

  const cached = _holdingsCache.get(wallet.toLowerCase());
  if (cached && Date.now() - cached.ts < CONFIG.holdingsCacheTtlMs) return res.json({ holdings: cached.data, cached: true });

  const holdings = [];
  await Promise.allSettled(Object.entries(BLOCKSCOUT_URLS).map(async ([chain, base]) => {
    // ERC-20 balances
    try {
      const r = await axios.get(`${base}/api/v2/addresses/${wallet}/token-balances`, { timeout: 8000, maxRedirects: 3, headers: BLOCKSCOUT_AUTH_HEADERS });
      for (const t of (r.data || [])) {
        const tok = t.token || {};
        if (tok.type !== 'ERC-20' || !tok.decimals) continue;
        const bal = Number(t.value) / Math.pow(10, parseInt(tok.decimals));
        const usd = tok.exchange_rate ? bal * parseFloat(tok.exchange_rate) : null;
        if (bal <= 0) continue;
        if (usd !== null && usd < CONFIG.holdingsDustUsd) continue; // dust
        holdings.push({ chain, address: tok.address_hash || tok.address, symbol: tok.symbol || '?', name: tok.name || '', balance: bal, usd, icon: tok.icon_url || null, native: false, decimals: parseInt(tok.decimals) });
      }
    } catch (_) {}
    // Native balance + price
    try {
      const [balR, statsR] = await Promise.all([
        axios.get(`${base}/api/v2/addresses/${wallet}`, { timeout: 8000, maxRedirects: 3, headers: BLOCKSCOUT_AUTH_HEADERS }),
        axios.get(`${base}/api/v2/stats`, { timeout: 8000, maxRedirects: 3, headers: BLOCKSCOUT_AUTH_HEADERS }),
      ]);
      const bal = Number(balR.data?.coin_balance || 0) / 1e18;
      const price = parseFloat(statsR.data?.coin_price || 0);
      if (bal > 0) holdings.push({ chain, address: null, symbol: NATIVE_SYMBOLS[chain], name: 'Native', balance: bal, usd: price ? bal * price : null, icon: null, native: true });
    } catch (_) {}
  }));

  // Merge in manually-saved custom tokens (always Robinhood chain — see
  // POST /api/trade/custom-tokens) that Blockscout's auto-detection above
  // didn't already pick up, e.g. a token just bought that hasn't indexed
  // yet, or one under the dust threshold. Shown even at 0 balance so saving
  // one always makes it visible, same as adding it to MetaMask does.
  try {
    const custom = await dbAll('SELECT * FROM custom_holdings WHERE wallet=?', [wallet.toLowerCase()]);
    const existingAddrs = new Set(holdings.filter(h => h.address).map(h => h.address.toLowerCase()));
    for (const c of custom) {
      if (existingAddrs.has(c.address.toLowerCase())) continue;
      let bal = 0, usd = null;
      try {
        bal = await _erc20BalanceOf(RPC_URLS[c.chain], c.address, wallet);
        const dsRes = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${c.address}`, { timeout: 8000 }).catch(() => null);
        const pairs = (dsRes?.data?.pairs || []).filter(p => p.chainId === c.chain);
        if (pairs.length) {
          const price = parseFloat(pairs[0].priceUsd || 0);
          usd = price ? bal * price : null;
        }
      } catch (_) {}
      holdings.push({ chain: c.chain, address: c.address, symbol: c.symbol, name: c.name, balance: bal, usd, icon: c.icon_url, native: false, decimals: c.decimals, isCustom: true });
    }
  } catch (_) {}

  holdings.sort((a, b) => (b.usd || 0) - (a.usd || 0));
  const top = holdings.slice(0, CONFIG.holdingsMaxResults);
  _holdingsCache.set(wallet.toLowerCase(), { ts: Date.now(), data: top });
  res.json({ holdings: top });
});

// Manually-saved tokens for the Holdings list (chain hardcoded to Robinhood
// server-side, never client-controlled) — for a token the user wants
// tracked even before/without Blockscout auto-detecting a balance for it.
// Saving also feeds the frontend's "Import to MetaMask" (wallet_watchAsset)
// call with the resolved symbol/decimals/icon.
app.post('/api/trade/custom-tokens', express.json({ limit: '10kb' }), async (req, res) => {
  const { wallet, address } = req.body || {};
  if (!wallet || !/^0x[0-9a-fA-F]{40}$/.test(wallet)) return res.status(400).json({ error: 'invalid wallet' });
  if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) return res.status(400).json({ error: 'invalid token address' });
  const chain = 'robinhood';
  const walletLower = wallet.toLowerCase();
  const addrLower = address.toLowerCase();
  try {
    const dsRes = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${addrLower}`, { timeout: 8000 });
    const pairs = (dsRes.data?.pairs || []).filter(p => p.chainId === chain)
      .sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
    if (!pairs.length) return res.status(400).json({ error: 'Token not found on Robinhood chain' });
    const p = pairs[0];
    const symbol = p.baseToken?.symbol || '?';
    const name   = p.baseToken?.name || '';
    const icon   = p.info?.imageUrl || null;

    const decHex = await _ethCall(RPC_URLS[chain], addrLower, '0x313ce567');
    const decimals = decHex && decHex !== '0x' ? parseInt(decHex, 16) : 18;

    await dbRun(`
      INSERT INTO custom_holdings (wallet, address, chain, symbol, name, decimals, icon_url)
      VALUES (?,?,?,?,?,?,?)
      ON DUPLICATE KEY UPDATE symbol=VALUES(symbol), name=VALUES(name), decimals=VALUES(decimals), icon_url=VALUES(icon_url)
    `, [walletLower, addrLower, chain, symbol, name, decimals, icon]);
    _holdingsCache.delete(walletLower); // force a fresh merge on next holdings fetch

    res.json({ success: true, token: { address: addrLower, chain, symbol, name, decimals, icon } });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.delete('/api/trade/custom-tokens/:wallet/:address', async (req, res) => {
  await dbRun('DELETE FROM custom_holdings WHERE wallet=? AND address=?', [req.params.wallet.toLowerCase(), req.params.address.toLowerCase()]);
  _holdingsCache.delete(req.params.wallet.toLowerCase());
  res.json({ success: true });
});

// ─── Legacy trading proxy (0x, EVM-only backup) ─────────────────────────────

// 0x quote (EVM)
const ZEROx_API_KEY = process.env.ZEROx_API_KEY || '';
const ZEROx_CHAIN_SUBDOMAIN = { '1':'', '8453':'base.', '42161':'arbitrum.', '137':'polygon.', '10':'optimism.' };
app.get('/api/trade/quote/evm', async (req, res) => {
  try {
    const { chainId = '1', sellToken, buyToken, sellAmount, slippagePercentage = '0.01', takerAddress } = req.query;
    if (!sellToken || !buyToken || !sellAmount) return res.status(400).json({ error: 'missing params' });
    const sub = ZEROx_CHAIN_SUBDOMAIN[chainId] ?? '';
    const params = new URLSearchParams({ sellToken, buyToken, sellAmount, slippagePercentage });
    if (takerAddress) params.set('takerAddress', takerAddress);
    const url = `https://${sub}api.0x.org/swap/v1/quote?${params}`;
    const r = await axios.get(url, {
      headers: ZEROx_API_KEY ? { '0x-api-key': ZEROx_API_KEY } : {},
      timeout: 8000
    });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.error || e.message });
  }
});

// Ensure the MySQL schema exists before accepting traffic
initDb()
  .then(async () => {
    await _loadNarrativeCacheFromDb();
    // Restore Market Overview's three data sources so a cold boot serves
    // last-known-good data immediately instead of an empty state.
    const [volCache, txCache, tabCache, sniperBlock] = await Promise.all([
      _loadGenericCacheFromDb('market_chain_volume_cache'),
      _loadGenericCacheFromDb('market_chain_tx_cache'),
      _loadGenericCacheFromDb('market_tab_cache'),
      _loadGenericCacheFromDb('sniper_last_block'),
    ]);
    if (volCache?.data) { _chainVolumeCache = volCache; console.log(`[market] restored chain-volume cache from DB (age ${Math.round((Date.now()-volCache.at)/60000)}min)`); }
    if (txCache?.data) { _chainTxCache = txCache; console.log(`[market] restored chain-tx cache from DB (age ${Math.round((Date.now()-txCache.at)/60000)}min)`); }
    if (tabCache) {
      for (const [k, v] of Object.entries(tabCache)) _marketTabCache.set(k, v);
      console.log(`[market] restored ${Object.keys(tabCache).length} market-tab cache entries from DB`);
    }
    if (typeof sniperBlock === 'number' && sniperBlock > 0) { _sniperLastBlock = sniperBlock; console.log(`[sniper] resuming scan from block ${sniperBlock}`); }
    server.listen(PORT, () => console.log(`Bloombark Terminal Backend running on port ${PORT}`));
  })
  .catch((e) => {
    console.error('[db] Failed to initialize MySQL schema:', e.message);
    process.exit(1);
  });
