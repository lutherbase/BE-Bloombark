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
    mainnet: { chainId: 4663,  hex: '0x1237', rpc: 'https://robinhoodchain.blockscout.com/api/eth-rpc',      explorer: 'https://robinhoodchain.blockscout.com',      blockscout: 'https://robinhoodchain.blockscout.com' },
    testnet: { chainId: 46630, hex: '0xb626', rpc: 'https://rpc.testnet.chain.robinhood.com/rpc',            explorer: 'https://explorer.testnet.chain.robinhood.com', blockscout: 'https://explorer.testnet.chain.robinhood.com', name: 'Robinhood Testnet' },
  },
};

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
  robinhood: 'robinhood', // GeckoTerminal may not support yet — fallback to DexScreener
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
    websites:    (p.info?.websites || []).map(w => w.url || w),
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
function buildHolderStats(holderData, dex, dsHolderCount) {
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

  return {
    total:         Math.min(bestTotal, 9999999),
    whales:        holders.filter(h => h.supplyPct > 1).length,
    concentration: parseFloat(top10.toFixed(2)),
  };
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

    // Websites / socials: merge both sources
    const websites = [...new Set([...(dex?.websites||[]), ...(geckoInfo?.websites||[])])].filter(Boolean);
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
    const holderStats = buildHolderStats(holderData, merged, realHolderCount);
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
app.post('/api/recent-trades', async (req, res) => {
  try {
    const { poolAddress, network = 'eth', limit: reqLimit } = req.body;
    if (!poolAddress) return res.json({ success: false, trades: [] });

    const limit = Math.min(Math.max(parseInt(reqLimit) || 30, 1), 300);
    const url = `https://api.geckoterminal.com/api/v2/networks/${network}/pools/${poolAddress}/trades?limit=${limit}`;
    const { data } = await axios.get(url, { timeout: 10000, headers: GECKO_HEADS });
    const raw = data?.data || [];
    const nowMs = Date.now();

    const trades = raw.slice(0, limit).map(t => {
      const a       = t.attributes;
      const tsMs    = a.block_timestamp ? new Date(a.block_timestamp).getTime() : nowMs;
      const agoMs   = nowMs - tsMs;
      const agoStr  = agoMs < 60000 ? `${Math.floor(agoMs/1000)}s ago`
        : agoMs < 3600000 ? `${Math.floor(agoMs/60000)}m ago`
        : `${Math.floor(agoMs/3600000)}h ago`;
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
        time:      agoStr,
        timestamp: tsMs,
      };
    });

    res.json({ success: true, trades });
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
    // Start background warm, return partial immediately if available
    _warmNarrative();
    // Wait up to NARRATIVE_WAIT_TIMEOUT_SEC for at least partial data
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

// Pre-warm narrative on server start (background)
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

const _dedupe = arr => arr.filter((p, i, a) =>
  p && a.findIndex(x => x && x.pairAddress === p.pairAddress && x.networkId === p.networkId) === i
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
    const k = `${p.address}_${p.networkId}`;
    const t = new Date(p.createdAt).getTime();
    if (!earliestByToken[k] || t < earliestByToken[k]) earliestByToken[k] = t;
  }
  for (const p of pools) {
    if (p.createdAt) continue;
    const k = `${p.address}_${p.networkId}`;
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

async function _fetchDash(key) {
  if (_dashFetching[key]) return;
  _dashFetching[key] = true;
  try {
    let dsPairs = [];

    if (key === 'all') {
      // All Chains: DexScreener generic queries + Robinhood-specific queries (tokens differ from other chains)
      const [generalRes, robinhoodRes] = await Promise.all([
        Promise.all(DS_ALL_QUERIES.map(q => _dsGet(`${DEXSCREENER}/latest/dex/search?q=${q}`))),
        Promise.all(['robin','cashcat','tendies','wood','home'].map(q => _dsGet(`${DEXSCREENER}/latest/dex/search?q=${q}&chainIds=robinhood`))),
      ]);
      dsPairs = [
        ...generalRes.flatMap(r => (r?.data?.pairs || []).map(_mapDS)),
        ...robinhoodRes.flatMap(r => (r?.data?.pairs || []).filter(p => p?.chainId === 'robinhood').map(_mapDS)),
      ];
    } else {
      // Per-chain: DS token addresses + DS searches filtered to chain
      // (GeckoTerminal new_pools call removed — not worth the rate-limit cost)
      const addrs   = DS_CHAIN_TOKENS[key] || [];
      const chainSearches = {
        ethereum:  ['weth','pepe','shib','uni','link','aave','crv','mkr'],
        base:      ['base','brett','aero','cbbtc','virtual'],
        robinhood: ['robin','cashcat','tendies','wood','home'],
      }[key] || [];

      const [dsAddrRes, dsSearchRes] = await Promise.all([
        Promise.all(addrs.map(a => _dsGet(`${DEXSCREENER}/latest/dex/tokens/${a}`))),
        Promise.all(chainSearches.map(q => _dsGet(`${DEXSCREENER}/latest/dex/search?q=${q}&chainIds=${key}`))),
      ]);
      dsPairs  = [
        ...dsAddrRes.flatMap(r => (r?.data?.pairs || []).filter(p => p?.chainId === key).map(_mapDS)),
        ...dsSearchRes.flatMap(r => (r?.data?.pairs || []).filter(p => p?.chainId === key).map(_mapDS)),
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
    token:     process.env.HOLDERS_GATE_TOKEN  || null,  // null → native ETH gate; set a CA → ERC-20 gate
    minAmount: parseFloat(process.env.HOLDERS_GATE_MIN || '0.01'),
    symbol:    process.env.HOLDERS_GATE_SYMBOL || '',    // blank → auto (native coin symbol)
  },
  private: {
    kind:      'paid',
    chain:     process.env.PRIVATE_GATE_CHAIN    || 'ethereum',
    treasury:  process.env.PRIVATE_GATE_TREASURY || '0xf6a2b3016c7ac86724fa71cd4b3946facb319caa',
    amountEth: parseFloat(process.env.PRIVATE_GATE_AMOUNT_ETH || '0.05'),
    symbol:    'ETH',
  },
};
const _gateCache = new Map(); // `${room}:${wallet}` -> { val, ts }

async function _ethCall(rpcUrl, to, data) {
  const r = await axios.post(rpcUrl,
    { jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] },
    { timeout: 8000, headers: { 'Content-Type': 'application/json' } });
  return r.data?.result || '0x';
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

// Returns { gated, ok, kind, ... } — shape varies slightly by gate kind (see below).
async function checkChannelGate(room, wallet) {
  const gate = CHANNEL_GATES[room];
  if (!gate) return { gated: false, ok: true };
  const cfg     = chainCfg(gate.chain);
  const network = cfg.name || (gate.chain.charAt(0).toUpperCase() + gate.chain.slice(1));

  // ── Paid gate: one-time on-chain payment, checked against our own DB ──────
  if (gate.kind === 'paid') {
    const base = { gated: true, kind: 'paid', amountEth: gate.amountEth, symbol: gate.symbol, treasury: gate.treasury, network };
    if (!wallet || !_isAddr(wallet)) return { ...base, ok: false, reason: 'no_wallet' };
    const paid = await dbGet('SELECT id FROM channel_payments WHERE room=? AND wallet=?', [room, wallet.toLowerCase()]);
    return { ...base, ok: !!paid };
  }

  // ── Balance gate: live on-chain balance check (existing behavior) ────────
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
// Bloombark logo (4-color square grid) as the bot's avatar
const BOT_AVATAR = 'data:image/svg+xml;base64,' + Buffer.from(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="64" height="64">
    <rect width="24" height="24" rx="6" fill="#13161d"/>
    <rect x="3" y="3" width="8" height="8" rx="2" fill="#E86C3A"/>
    <rect x="13" y="3" width="8" height="8" rx="2" fill="#F5A623"/>
    <rect x="3" y="13" width="8" height="8" rx="2" fill="#27C97F"/>
    <rect x="13" y="13" width="8" height="8" rx="2" fill="#4a90d9"/>
  </svg>`
).toString('base64');
const BOT_CHAINS = new Set(['ethereum', 'base', 'arbitrum', 'polygon', 'optimism', 'robinhood']);
const _botCooldown = new Map(); // ca -> last reply ts (avoid spamming same CA)

// ─── BloomBuy: posts a card to $BBRK Moon for every on-chain BUY (sells skipped) ──
// Uses the same Bloombark logo avatar as BloomBot — same brand identity, just a
// different bot name for the different feed.
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
  <circle cx="30" cy="26" r="9" fill="#27c97f22" stroke="#27c97f" stroke-width="1.5"/>
  <path d="M26 29 L30 21 L34 29" stroke="#27c97f" stroke-width="1.5" fill="none"/>
  <text x="48" y="30" font-family="Menlo, monospace" font-size="13" font-weight="bold" fill="#e2e8f0" letter-spacing="2">BLOOMBARK</text>
  <text x="152" y="30" font-family="Menlo, monospace" font-size="9" fill="#6b7280" letter-spacing="1">AI TOKEN SCAN</text>
  <rect x="${560 - 118}" y="14" width="96" height="24" rx="12" fill="${sigColor}22" stroke="${sigColor}"/>
  <text x="${560 - 70}" y="30" font-family="Menlo, monospace" font-size="11" font-weight="bold" fill="${sigColor}" text-anchor="middle">${info.signal}</text>

  <circle cx="46" cy="94" r="20" fill="#27c97f1f"/>
  <text x="46" y="100" font-family="Menlo, monospace" font-size="16" font-weight="bold" fill="#27c97f" text-anchor="middle">${_svgEsc((info.symbol || '?')[0])}</text>
  <text x="78" y="88" font-family="Menlo, monospace" font-size="19" font-weight="bold" fill="#e2e8f0">${_svgEsc(info.symbol)}</text>
  <text x="78" y="106" font-family="Menlo, monospace" font-size="11" fill="#6b7280">${_svgEsc((info.name || '').slice(0, 34))}</text>
  <rect x="${78 + Math.min(String(info.symbol||'').length, 12) * 12 + 10}" y="72" width="${info.chain.length * 8 + 18}" height="19" rx="9.5" fill="#27c97f15" stroke="#27c97f50"/>
  <text x="${78 + Math.min(String(info.symbol||'').length, 12) * 12 + 19}" y="85" font-family="Menlo, monospace" font-size="9" font-weight="bold" fill="#27c97f" letter-spacing="1">${_svgEsc(info.chain.toUpperCase())}</text>

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
    };

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
const MOON_BOT_CHAIN   = process.env.MOON_BOT_CHAIN || 'ethereum';
// Token to monitor comes from app_config.contract_address — the SAME field the
// landing page CA uses — so this automatically points at $BBRK once it's live.
// Until then (value still 'coming_soon'), fall back to a well-known, actively
// traded token so the channel is verifiable right now: PEPE/Ethereum.
const MOON_BOT_TEST_TOKEN = process.env.MOON_BOT_TEST_TOKEN || '0x6982508145454Ce325dDbE47a25d4ec3d2311933';
const MOON_BOT_POLL_MS    = (parseInt(process.env.MOON_BOT_POLL_SEC) || 25) * 1000;

let _moonBotPool   = null;  // { poolAddress, geckoNetwork, chainId, tokenAddress, tokenSymbol, quoteSymbol }
let _moonBotPoolAt = 0;
let _moonBotLastTs = 0;     // only trades newer than this get considered
let _moonBotSeenTx = new Set();

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
    if (!pairs.length) return null;
    const p = pairs[0];
    const pool = {
      poolAddress:  p.pairAddress,
      geckoNetwork: GECKO_NETWORK[MOON_BOT_CHAIN] || 'eth',
      chainId:      MOON_BOT_CHAIN,
      tokenAddress: p.baseToken?.address || address,
      tokenSymbol:  p.baseToken?.symbol  || '?',
      quoteSymbol:  p.quoteToken?.symbol || 'ETH',
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
    console.error('[moonbot] pool resolve failed:', e.message);
    return null;
  }
}

const _moonFmtAmt = n => {
  n = parseFloat(n) || 0;
  if (n >= 1000) return n.toLocaleString('en-US', { maximumFractionDigits: 2 });
  return n.toLocaleString('en-US', { maximumFractionDigits: n < 1 ? 6 : 4 });
};

// Bloombark-styled BUY card (green theme, matches _botSvgCard's visual language)
function _moonBuySvgCard(t) {
  const svg = `<svg width="520" height="200" viewBox="0 0 520 200" xmlns="http://www.w3.org/2000/svg">
  <rect width="520" height="200" rx="16" fill="#0d1a12"/>
  <rect x="0.5" y="0.5" width="519" height="199" rx="16" fill="none" stroke="#27c97f55"/>
  <rect x="0" y="0" width="520" height="48" rx="16" fill="#0f2419"/>
  <rect x="0" y="34" width="520" height="14" fill="#0f2419"/>
  <path d="M22 30 L28 18 L34 30" stroke="#27c97f" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <text x="46" y="30" font-family="Menlo, monospace" font-size="13" font-weight="bold" fill="#e2e8f0" letter-spacing="2">BLOOMBUY</text>
  <rect x="${520-108}" y="13" width="88" height="22" rx="11" fill="#27c97f22" stroke="#27c97f"/>
  <text x="${520-64}" y="28" font-family="Menlo, monospace" font-size="10" font-weight="bold" fill="#27c97f" text-anchor="middle">BUY</text>

  <text x="26" y="80" font-family="Menlo, monospace" font-size="9" fill="#6b7280" letter-spacing="1.5">TOKEN</text>
  <text x="26" y="104" font-family="Menlo, monospace" font-size="22" font-weight="bold" fill="#e2e8f0">${_svgEsc(t.symbol)}</text>

  <g transform="translate(200,66)">
    <text x="0" y="0" font-family="Menlo, monospace" font-size="9" fill="#6b7280" letter-spacing="1">SPENT</text>
    <text x="0" y="20" font-family="Menlo, monospace" font-size="15" font-weight="bold" fill="#e2e8f0">${_svgEsc(t.ethAmountStr)}</text>
  </g>
  <g transform="translate(340,66)">
    <text x="0" y="0" font-family="Menlo, monospace" font-size="9" fill="#6b7280" letter-spacing="1">USD VALUE</text>
    <text x="0" y="20" font-family="Menlo, monospace" font-size="15" font-weight="bold" fill="#27c97f">${_svgEsc(t.usdStr)}</text>
  </g>
  <g transform="translate(200,110)">
    <text x="0" y="0" font-family="Menlo, monospace" font-size="9" fill="#6b7280" letter-spacing="1">RECEIVED</text>
    <text x="0" y="20" font-family="Menlo, monospace" font-size="15" font-weight="bold" fill="#e2e8f0">${_svgEsc(t.tokenAmountStr)} ${_svgEsc(t.symbol)}</text>
  </g>

  <line x1="26" y1="142" x2="494" y2="142" stroke="#1e2235"/>
  <text x="26" y="166" font-family="Menlo, monospace" font-size="9" fill="#4b5563">Buyer: ${_svgEsc(t.wallet)}</text>
  <text x="494" y="166" font-family="Menlo, monospace" font-size="9" fill="#4b5563" text-anchor="end">bloombark terminal · not financial advice</text>
</svg>`;
  return 'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64');
}

let _moonBotPolling = false;
async function _pollMoonBotTrades() {
  if (_moonBotPolling) return; // avoid overlapping polls if one runs long
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
      const wallet = a.tx_from_address ? shortAddr(a.tx_from_address) : '—';

      const card = _moonBuySvgCard({
        symbol: pool.tokenSymbol,
        ethAmountStr:   `${_moonFmtAmt(ethAmount)} ${pool.quoteSymbol}`,
        usdStr:         _botFmtUsd(usdValue),
        tokenAmountStr: _moonFmtAmt(tokenAmount),
        wallet,
      });
      const text = `🟢 BUY — ${_moonFmtAmt(ethAmount)} ${pool.quoteSymbol} (${_botFmtUsd(usdValue)}) → ${_moonFmtAmt(tokenAmount)} ${pool.tokenSymbol}`;
      await _botSend(MOON_BOT_ROOM, text, card, null, { name: BUY_BOT_NAME, avatar: BUY_BOT_AVATAR });
    }
    if (maxTs > _moonBotLastTs) _moonBotLastTs = maxTs;
  } catch (e) {
    console.error('[moonbot] poll failed:', e.message);
  } finally {
    _moonBotPolling = false;
  }
}
setTimeout(_pollMoonBotTrades, 8000);
setInterval(_pollMoonBotTrades, MOON_BOT_POLL_MS);

// Temporary diagnostic — internal poller state isn't visible any other way
// without log access. Same admin token gate as /api/admin/query.
app.get('/api/admin/moonbot-status', (req, res) => {
  if (!ADMIN_QUERY_TOKEN) return res.status(404).json({ error: 'not enabled' });
  const token = req.get('x-admin-token') || req.query.token || '';
  if (token !== ADMIN_QUERY_TOKEN) return res.status(403).json({ error: 'forbidden' });
  res.json({
    pool: _moonBotPool,
    poolResolvedAt: _moonBotPoolAt ? new Date(_moonBotPoolAt).toISOString() : null,
    lastTradeTs: _moonBotLastTs ? new Date(_moonBotLastTs).toISOString() : null,
    seenTxCount: _moonBotSeenTx.size,
    currentlyPolling: _moonBotPolling,
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
        for (const k of Object.keys(chatRooms)) {
          if (CHANNEL_GATES[k]) {
            const g = await checkChannelGate(k, wallet);
            gates[k] = g;
            if (!g.ok) { history[k] = []; continue; }
          }
          const rows = await dbAll('SELECT * FROM chat_messages WHERE room=? ORDER BY ts DESC LIMIT ?', [k, MAX_CHAT_HISTORY]);
          history[k] = rows.reverse().map(r => ({
            id: r.id, room: r.room, wallet: r.wallet, displayName: r.display_name,
            avatar: r.avatar, text: r.text, imgData: r.img_data, ts: r.ts,
            isBot: (r.display_name === BOT_NAME || r.display_name === BUY_BOT_NAME) && r.wallet == null,
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
    axios.get(`${base}/api/v2/addresses/${address}/token-balances`, { timeout:10000 }).catch(() => null),
    axios.get(`${base}/api/v2/addresses/${address}`, { timeout:8000 }).catch(() => null),
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
    let nativePrice = await axios.get(`${base}/api/v2/stats`, { timeout:6000 })
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
  const txRes = await axios.get(`${base}/api/v2/addresses/${address}/transactions`, { timeout:10000 }).catch(() => null);
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
    // Fetch token data from DexScreener
    const dsRes = await axios.get(`${DEXSCREENER}/latest/dex/tokens/${address}`, { timeout: 8000 }).catch(() => null);
    const pairs  = dsRes?.data?.pairs || [];
    const pair   = pairs.sort((a, b) => (b.volume?.h24 || 0) - (a.volume?.h24 || 0))[0];

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

    // 4. Liquidity health
    const liqToVol = vol24h > 0 ? liqUsd / vol24h : 0;
    if (liqUsd > 100000 && liqToVol > 0.1) {
      bullScore += 10;
      signals.push({ label: 'Liquidity', verdict: 'bullish', detail: `$${(liqUsd/1000).toFixed(1)}K — healthy depth` });
    } else if (liqUsd < 10000) {
      bearScore += 15;
      signals.push({ label: 'Liquidity', verdict: 'bearish', detail: `$${(liqUsd/1000).toFixed(1)}K — very low, high slippage risk` });
    } else {
      signals.push({ label: 'Liquidity', verdict: 'neutral', detail: `$${(liqUsd/1000).toFixed(1)}K` });
    }

    // 5. Holder concentration (from GoPlus)
    if (holderCount > 0) {
      if (top10Pct < 30 && creatorPct < 5) {
        bullScore += 15;
        signals.push({ label: 'Holder Distribution', verdict: 'bullish', detail: `Top 10 hold ${top10Pct.toFixed(1)}% · Creator ${creatorPct.toFixed(1)}% — well distributed` });
      } else if (top10Pct > 60 || creatorPct > 20) {
        bearScore += 20;
        signals.push({ label: 'Holder Distribution', verdict: 'bearish', detail: `Top 10 hold ${top10Pct.toFixed(1)}% · Creator ${creatorPct.toFixed(1)}% — high concentration risk` });
      } else {
        signals.push({ label: 'Holder Distribution', verdict: 'neutral', detail: `Top 10: ${top10Pct.toFixed(1)}% · ${holderCount.toLocaleString()} holders` });
      }
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
    const confidence = Math.min(95, Math.round(Math.abs(net) / total_weight * 100 + 30));

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
app.post('/api/auth/login', async (req, res) => {
  try {
    const { wallet, privyUserId, meta } = req.body;
    if (!wallet) return res.status(400).json({ error: 'wallet required' });
    const isEvm   = /^0x[0-9a-fA-F]{40}$/.test(wallet);
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(wallet);
    if (!isEvm && !isEmail) {
      return res.status(400).json({ error: 'Invalid wallet address or email' });
    }

    const walletLower = wallet.toLowerCase();
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
  return res.json({ success: true, user });
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
  const [ca, ticker] = await Promise.all([
    dbGet("SELECT value FROM app_config WHERE `key`='contract_address'"),
    dbGet("SELECT value FROM app_config WHERE `key`='token_ticker'"),
  ]);
  res.json({
    contractAddress: ca?.value || 'coming_soon',
    tokenTicker: ticker?.value || 'BBRK',
    networkEnv: NETWORK_ENV,
    isTestnet: IS_TESTNET,
    chains: Object.fromEntries(Object.keys(CHAIN_NETWORKS).map(k => [k, chainCfg(k)])),
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
  const ALLOWED = new Set(['token_ticker', 'contract_address']);
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

// ─── Trading proxy (KyberSwap aggregator, EVM only) ─────────────────────────
// Note: KyberSwap does not index testnet liquidity — quotes/swaps will return
// no route in testnet mode. This mapping is left as mainnet-only slugs.
const KYBER_CHAINS = { ethereum:'ethereum', base:'base', arbitrum:'arbitrum', polygon:'polygon', optimism:'optimism', avalanche:'avalanche', robinhood:'robinhood' };
const RPC_URLS = Object.fromEntries(Object.keys(CHAIN_NETWORKS).map(k => [k, chainCfg(k).rpc]));

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
    }, { headers: { 'x-client-id': 'bloombark' }, timeout: 10000 });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

// JSON-RPC proxy to public nodes (decimals, balance, allowance reads)
app.post('/api/trade/rpc/:chain', express.json({ limit: '100kb' }), async (req, res) => {
  try {
    const url = RPC_URLS[req.params.chain];
    if (!url) return res.status(400).json({ error: 'unsupported chain' });
    const r = await axios.post(url, req.body, { timeout: 10000 });
    res.json(r.data);
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
      const r = await axios.get(`${base}/api/v2/addresses/${wallet}/token-balances`, { timeout: 8000, maxRedirects: 3 });
      for (const t of (r.data || [])) {
        const tok = t.token || {};
        if (tok.type !== 'ERC-20' || !tok.decimals) continue;
        const bal = Number(t.value) / Math.pow(10, parseInt(tok.decimals));
        const usd = tok.exchange_rate ? bal * parseFloat(tok.exchange_rate) : null;
        if (bal <= 0) continue;
        if (usd !== null && usd < CONFIG.holdingsDustUsd) continue; // dust
        holdings.push({ chain, address: tok.address_hash || tok.address, symbol: tok.symbol || '?', name: tok.name || '', balance: bal, usd, icon: tok.icon_url || null, native: false });
      }
    } catch (_) {}
    // Native balance + price
    try {
      const [balR, statsR] = await Promise.all([
        axios.get(`${base}/api/v2/addresses/${wallet}`, { timeout: 8000, maxRedirects: 3 }),
        axios.get(`${base}/api/v2/stats`, { timeout: 8000, maxRedirects: 3 }),
      ]);
      const bal = Number(balR.data?.coin_balance || 0) / 1e18;
      const price = parseFloat(statsR.data?.coin_price || 0);
      if (bal > 0) holdings.push({ chain, address: null, symbol: NATIVE_SYMBOLS[chain], name: 'Native', balance: bal, usd: price ? bal * price : null, icon: null, native: true });
    } catch (_) {}
  }));

  holdings.sort((a, b) => (b.usd || 0) - (a.usd || 0));
  const top = holdings.slice(0, CONFIG.holdingsMaxResults);
  _holdingsCache.set(wallet.toLowerCase(), { ts: Date.now(), data: top });
  res.json({ holdings: top });
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
  .then(() => {
    server.listen(PORT, () => console.log(`Bloombark Terminal Backend running on port ${PORT}`));
  })
  .catch((e) => {
    console.error('[db] Failed to initialize MySQL schema:', e.message);
    process.exit(1);
  });
