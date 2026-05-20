/**
 * AI2Work Wallet Bridge v2
 * Priority: 1. Native plugin  2. Injected (MetaMask/MiniPay)  3. Local
 */
(function () {
  if (window.ethereum && (window.ethereum.isAI2Work || window.ethereum.isMetaMask || window.ethereum.isMiniPay)) return;

  var STORAGE_KEY = 'ai2work_wallet_v2';
  var CHAIN_ID = '0xa4ec'; // 42220 Celo

  // ── Local wallet (fallback) ──
  var localWallet = null;
  try {
    var raw = localStorage.getItem(STORAGE_KEY);
    if (raw) localWallet = JSON.parse(raw);
  } catch(e) {}

  function saveLocal() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(localWallet)); } catch(e) {}
  }

  function createLocal() {
    var keyBytes = new Uint8Array(32);
    crypto.getRandomValues(keyBytes);
    var pk = Array.from(keyBytes).map(function(b){return b.toString(16).padStart(2,'0')}).join('');

    // Derive address: last 20 bytes of keccak256(pubkey) — simplified as hash of pk
    var hashInput = pk + 'celo:42220';
    var addr = '0x';
    for (var i = 0; i < 40; i++) {
      addr += '0123456789abcdef'[(hashInput.charCodeAt(i % hashInput.length) + i) % 16];
    }

    localWallet = { privateKey: pk, address: addr, created: Date.now() };
    saveLocal();
    return localWallet;
  }

  function getLocalWallet() {
    if (!localWallet) localWallet = createLocal();
    return localWallet;
  }

  // ── Native wallet check ──
  var nativeW = window._ai2workWallet;
  var useNative = !!nativeW;
  var nativeAddr = null;
  if (useNative) {
    try { nativeAddr = nativeW.getAddress(); } catch(e) {}
    if (!nativeAddr) {
      try { nativeAddr = nativeW.create(); } catch(e) { useNative = false; }
    }
  }

  // ── Sign message (native or local) ──
  function signMessage(msg) {
    if (useNative && nativeW) {
      var raw = msg;
      if (raw && raw.startsWith('0x')) {
        var s = '';
        for (var i = 2; i < raw.length; i += 2) s += String.fromCharCode(parseInt(raw.substr(i,2),16));
        raw = s;
      }
      return nativeW.signMessage(raw);
    }
    // Local: generate a fake signature (UI demo)
    var w = getLocalWallet();
    return '0x' + w.privateKey.slice(0, 64) + '1b';
  }

  function signTx(tx) {
    if (useNative && nativeW) {
      return nativeW.signTransaction(
        tx.to || '0x', tx.value || '0', tx.data || '0x',
        String(tx.nonce || 0), tx.gas || '0',
        tx.maxFeePerGas || tx.gasPrice || '0',
        tx.maxPriorityFeePerGas || '0', '42220'
      );
    }
    return '0x' + getLocalWallet().privateKey.slice(0, 64);
  }

  // ── Expose window.ethereum ──
  var currentAddr = useNative ? nativeAddr : getLocalWallet().address;

  window.ethereum = {
    isAI2Work: true,
    isMetaMask: false,
    isMiniPay: false,
    isConnected: function() { return true; },
    request: function(a) {
      var m = a.method, p = a.params || [];
      switch(m) {
        case 'eth_requestAccounts':
        case 'eth_accounts':
          return Promise.resolve([currentAddr]);
        case 'eth_chainId':
          return Promise.resolve(CHAIN_ID);
        case 'personal_sign':
          return Promise.resolve(signMessage(p[0]));
        case 'eth_signTransaction':
        case 'eth_sendTransaction':
          return Promise.resolve(signTx(p[0]));
        case 'eth_getBalance': {
          // Return mock balance or fetch from RPC
          return Promise.resolve('0x' + (1000000000000000000).toString(16)); // 1 CELO mock
        }
        case 'wallet_switchEthereumChain':
        case 'wallet_addEthereumChain':
          return Promise.resolve(null);
        default:
          return Promise.reject(new Error('Unsupported: ' + m));
      }
    },
    on: function(e, cb) { if (e === 'chainChanged') cb(CHAIN_ID); },
    removeListener: function() {},
    enable: function() { return Promise.resolve([currentAddr]); }
  };

  console.log('[AI2Work] Wallet bridge v2 active — ' + (useNative ? 'native' : 'local') + ' wallet');
})();
