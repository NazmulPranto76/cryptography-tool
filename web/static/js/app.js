const PLAIN_TEXT = "WELCOME TO CRYPTOGRAPHY PROJECT";

const ALGOS = {
  substitution: {
    short: "SUB", label: "Substitution", icon: "",
    color: "#f59e0b", bg: "#451a03",
    ciphertext: "VTSEGDT ZG EKNHZGUKQHIN HKGPTEZ",
    note: "Key: QWERTYUIOPASDFGHJKLZXCVBNM",
    speed: 55,
  },
  transposition: {
    short: "D-TRANS", label: "Dbl Transposition", icon: "",
    color: "#10b981", bg: "#022c22",
    ciphertext: "CEGWREREATOOJOTCHOYRCMPYTPLP",
    note: "Keys: [3,1,4,2] × [2,4,1,3]",
    speed: 55,
  },
  des: {
    short: "DES", label: "DES", icon: "",
    color: "#ef4444", bg: "#450a0a",
    ciphertext: "4755A17554A561B0 594BD80157AF0DB0 4052A3774CA77FB2 4A4CB35D53B262B9",
    note: "Key: DEADBEEF01234567 (64-bit, 8 rounds)",
    speed: 30,
  },
  aes128: {
    short: "AES-128", label: "AES-128", icon: "",
    color: "#818cf8", bg: "#1e1b4b",
    ciphertext: "ACE03674458EED1E 2DAC4D38C9CA8294 8693C1B0364D77BE 6B7589C4494DCBD5",
    note: "Key: DEADBEEF×4 (128-bit, 10 rounds)",
    speed: 28,
  },
  aes192: {
    short: "AES-192", label: "AES-192", icon: "",
    color: "#c084fc", bg: "#3b0764",
    ciphertext: "E9F065D7C13573A0 62C9B8B7FAB5D20A 3E5B8A1C9D4F2E67 B31C0E9A5F7D4821",
    note: "Key: DEADBEEF×6 (192-bit, 12 rounds)",
    speed: 28,
  },
  aes256: {
    short: "AES-256", label: "AES-256", icon: "",
    color: "#a78bfa", bg: "#2e1065",
    ciphertext: "C6A786FDE2766C30 5372622CFF99B831 FA5F7F2FBD1D76E3 D29501C23562BBED",
    note: "Key: DEADBEEF×8 (256-bit, 14 rounds)",
    speed: 28,
  },
  rsa: {
    short: "RSA", label: "RSA", icon: "",
    color: "#ec4899", bg: "#500724",
    ciphertext: "206459203  |  707885371  |  1856868028",
    note: "n=3559904303, e=65537 (demo 32-bit key)",
    speed: 40,
  },
};
function initMatrix() {
  const canvas = document.getElementById('matrixCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
  resize();
  window.addEventListener('resize', resize);

  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$^&*+-=';
  const cols = Math.floor(canvas.width / 22);
  const drops = Array.from({length: cols}, () => Math.floor(Math.random() * -50));

  setInterval(() => {
    ctx.fillStyle = 'rgba(10, 10, 20, 0.07)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = '13px monospace';
    drops.forEach((y, i) => {
      const isHead = y === drops[i];
      ctx.fillStyle = isHead ? '#ffffff22' : '#1a4a1a';
      const ch = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(ch, i * 22, y * 22);
      if (y * 22 > canvas.height && Math.random() > 0.97) drops[i] = 0;
      drops[i]++;
    });
  }, 45);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
function cryptoApp() {
  return {

    view: 'home',
    appPage: 'substitution',

    selectedAlgo: 'aes128',
    displayText: '',
    phase: 'plain',
    showBadge: false,
    animGen: 0,

    get ALGOS() { return ALGOS; },
    get currentAlgo() { return ALGOS[this.selectedAlgo]; },
    get isCipher() { return this.phase === 'typing-enc' || this.phase === 'encrypted'; },
    subTab: 'enc', transTab: 'enc', desTab: 'enc',
    aesTab: 'enc', rsaTab: 'gen',  eccTab: 'params',
    suiteTab: 'timing',
    perfText: '',
    result: {}, error: '', loading: false, perfData: null,

    sub:     { plaintext: '', ciphertext: '', key: '' },
    trans:   { text: '', key1: '3 1 4 2', key2: '2 4 1 3' },
    des:     { plaintext: '', keyHex: '', ctHex: '' },
    aesData: { plaintext: '', keySize: '128', keyHex: '', ctHex: '' },
    rsaData: {
      keyBits: 512, keys: null,
      plaintext: '', chunks: null, chunkSize: 0, decrypted: null, attack: null,
      customE: '', customP: '', customQ: '',
    },
    eccData: { p: 17, a: 2, b: 2, gx: 5, gy: 1, n: 19, points: null, exchange: null },
    suite:   { plaintext: '', ciphertext: '', timeout: 60, maxAttempts: 616, timingResults: null, bruteResults: null },

    navItems: [
      { id: 'substitution', label: 'Substitution', icon: '' },
      { id: 'transposition', label: 'Transposition', icon: '' },
      { id: 'des',           label: 'DES',           icon: '' },
      { id: 'aes',           label: 'AES',           icon: '' },
      { id: 'rsa',           label: 'RSA',           icon: '' },
      { id: 'ecc',           label: 'ECC',           icon: '' },
      { id: 'simulate',      label: 'Simulate',      icon: '' },
    ],
    simData: {
      tab:        'des',
      plaintext:  'HELLO WORLD',
      desKeyHex:  '',
      aesKeyHex:  '',
      aesKeySize: 128,
      desTrace:   null,
      aesTrace:   null,
      step:       0,
      playing:    false,
      _timer:     null,
    },

    get simTrace() {
      return (this.simData.tab === 'des' ? this.simData.desTrace : this.simData.aesTrace) || null;
    },
    get simStep() {
      if (!this.simTrace) return null;
      return this.simTrace.steps[this.simData.step] || null;
    },
    get simProgress() {
      if (!this.simTrace) return 0;
      return Math.round((this.simData.step / (this.simTrace.steps.length - 1)) * 100);
    },

    // AES phase → highlight colour class for the state grid cells
    aesPhaseColor(phase) {
      const map = {
        input:        'bg-gray-700 text-gray-200',
        add_round_key:'bg-green-900  text-green-200',
        sub_bytes:    'bg-pink-900   text-pink-200',
        shift_rows:   'bg-blue-900   text-blue-200',
        mix_columns:  'bg-purple-900 text-purple-200',
        output:       'bg-indigo-900 text-indigo-200',
      };
      return map[phase] || 'bg-gray-700 text-gray-200';
    },
    init() {
      initMatrix();
      this.startAnimation();
    },

    selectAlgo(key) {
      if (key === this.selectedAlgo) return;
      this.selectedAlgo = key;
      this.animGen++;
      this.displayText = '';
      this.showBadge = false;
      this.phase = 'plain';
      this.startAnimation();
    },
    async startAnimation() {
      const gen = this.animGen;

      this.phase = 'plain';
      this.displayText = '';
      for (const ch of PLAIN_TEXT) {
        await sleep(55);
        if (gen !== this.animGen) return;
        this.displayText += ch;
      }

      await sleep(1600);
      if (gen !== this.animGen) return;

      while (this.displayText.length > 0) {
        await sleep(20);
        if (gen !== this.animGen) return;
        this.displayText = this.displayText.slice(0, -1);
      }

      await sleep(280);
      if (gen !== this.animGen) return;
      this.showBadge = true;
      this.phase = 'typing-enc';
      await sleep(220);
      if (gen !== this.animGen) return;

      const algo = ALGOS[this.selectedAlgo];
      for (const ch of algo.ciphertext) {
        await sleep(algo.speed);
        if (gen !== this.animGen) return;
        this.displayText += ch;
      }

      this.phase = 'encrypted';
      await sleep(2600);
      if (gen !== this.animGen) return;

      this.phase = 'typing-enc';
      while (this.displayText.length > 0) {
        await sleep(16);
        if (gen !== this.animGen) return;
        this.displayText = this.displayText.slice(0, -1);
      }

      await sleep(200);
      if (gen !== this.animGen) return;
      this.showBadge = false;
      this.phase = 'plain';
      await sleep(150);
      if (gen !== this.animGen) return;

      this.startAnimation();
    },

    enterTool() {
      this.animGen++;
      this.view = 'app';
    },

    clearResult() { this.result = {}; this.error = ''; },
    async api(path, body = null) {
      this.error = '';
      const opts = body
        ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
        : { method: 'GET' };
      const res = await fetch('/api/' + path, opts);

      // Parse JSON safely — a 500 from the server may return plain text, not JSON
      let data;
      try {
        data = await res.json();
      } catch {
        throw new Error(`Server error ${res.status} — restart the server and try again.`);
      }

      if (!res.ok) throw new Error(data.detail || 'Request failed');
      return data;
    },
    async subEncrypt() {
      try { this.result = await this.api('substitution/encrypt', { plaintext: this.sub.plaintext, key: this.sub.key || null }); }
      catch(e) { this.error = e.message; }
    },
    async subDecrypt() {
      try { this.result = await this.api('substitution/decrypt', { ciphertext: this.sub.ciphertext, key: this.sub.key }); }
      catch(e) { this.error = e.message; }
    },
    async subAnalyze() {
      try { this.result = await this.api('substitution/analyze', { ciphertext: this.sub.ciphertext }); }
      catch(e) { this.error = e.message; }
    },
    async transEncrypt() {
      try { this.result = await this.api('transposition/encrypt', { text: this.trans.text, key1: this.trans.key1, key2: this.trans.key2 }); }
      catch(e) { this.error = e.message; }
    },
    async transDecrypt() {
      try { this.result = await this.api('transposition/decrypt', { ciphertext: this.trans.text, key1: this.trans.key1, key2: this.trans.key2 }); }
      catch(e) { this.error = e.message; }
    },
    async desEncrypt() {
      try {
        this.result  = await this.api('des/encrypt', { plaintext: this.des.plaintext, key_hex: this.des.keyHex || null });
        this.des.keyHex = this.result.key_hex;
        this.des.ctHex  = this.result.ciphertext_hex;
      } catch(e) { this.error = e.message; }
    },
    async desDecrypt() {
      try { this.result = await this.api('des/decrypt', { ciphertext_hex: this.des.ctHex, key_hex: this.des.keyHex }); }
      catch(e) { this.error = e.message; }
    },
    async aesEncrypt() {
      try {
        this.result      = await this.api('aes/encrypt', { plaintext: this.aesData.plaintext, key_size: parseInt(this.aesData.keySize), key_hex: this.aesData.keyHex || null });
        this.aesData.keyHex = this.result.key_hex;
        this.aesData.ctHex  = this.result.ciphertext_hex;
      } catch(e) { this.error = e.message; }
    },
    async aesDecrypt() {
      try { this.result = await this.api('aes/decrypt', { ciphertext_hex: this.aesData.ctHex, key_hex: this.aesData.keyHex }); }
      catch(e) { this.error = e.message; }
    },
    async rsaGenerate() {
      this.loading = true;
      try {
        const payload = { key_bits: this.rsaData.keyBits };
        if (this.rsaData.customE) payload.custom_e = this.rsaData.customE;
        if (this.rsaData.customP) payload.custom_p = this.rsaData.customP;
        if (this.rsaData.customQ) payload.custom_q = this.rsaData.customQ;
        this.rsaData.keys     = await this.api('rsa/generate', payload);
        this.rsaData.chunks   = null;
        this.rsaData.decrypted = null;
      } catch(e) { this.error = e.message; } finally { this.loading = false; }
    },
    async rsaEncrypt() {
      if (!this.rsaData.keys)      { this.error = 'Generate a key pair first.';          return; }
      if (!this.rsaData.plaintext) { this.error = 'Enter some plaintext to encrypt.';    return; }
      try {
        const r = await this.api('rsa/encrypt', { plaintext: this.rsaData.plaintext, e: this.rsaData.keys.e, n: this.rsaData.keys.n });
        this.rsaData.chunks    = r.chunks;
        this.rsaData.chunkSize = r.chunk_size_bytes;
        this.rsaData.decrypted = null;
      } catch(err) { this.error = err.message; }
    },
    async rsaDecrypt() {
      if (!this.rsaData.chunks) return;
      try {
        const r = await this.api('rsa/decrypt', { chunks: this.rsaData.chunks, d: this.rsaData.keys.d, n: this.rsaData.keys.n });
        this.rsaData.decrypted = r.plaintext;
      } catch(err) { this.error = err.message; }
    },
    async rsaAttack() {
      this.loading = true;
      try {
        const dk = await this.api('rsa/generate', { key_bits: 32 });
        const ar = await this.api('rsa/attack', { n: dk.n, e: dk.e });
        this.rsaData.attack = { n: dk.n, e: dk.e, result: ar };
      } catch(e) { this.error = e.message; } finally { this.loading = false; }
    },
    async runSim() {
      this.simStopPlay();
      this.simData.step = 0;
      try {
        if (this.simData.tab === 'des') {
          this.simData.desTrace = await this.api('des/trace',
            { plaintext: this.simData.plaintext, key_hex: this.simData.desKeyHex || null });
        } else {
          this.simData.aesTrace = await this.api('aes/trace',
            { plaintext: this.simData.plaintext, key_size: this.simData.aesKeySize, key_hex: this.simData.aesKeyHex || null });
        }
      } catch(e) { this.error = e.message; }
    },
    simNext() {
      if (this.simTrace && this.simData.step < this.simTrace.steps.length - 1)
        this.simData.step++;
    },
    simPrev() {
      if (this.simData.step > 0) this.simData.step--;
    },
    simPlay() {
      if (this.simData.playing) { this.simStopPlay(); return; }
      this.simData.playing = true;
      this.simData._timer = setInterval(() => {
        if (!this.simTrace || this.simData.step >= this.simTrace.steps.length - 1) {
          this.simStopPlay();
        } else {
          this.simData.step++;
        }
      }, 1000);
    },
    simStopPlay() {
      clearInterval(this.simData._timer);
      this.simData.playing = false;
    },
    simReset() {
      this.simStopPlay();
      this.simData.step = 0;
    },
    async eccPoints() {
      try { const r = await this.api('ecc/points', { p: this.eccData.p, a: this.eccData.a, b: this.eccData.b }); this.eccData.points = r.points; }
      catch(e) { this.error = e.message; }
    },
    async eccExchange() {
      try { this.eccData.exchange = await this.api('ecc/exchange', { p: this.eccData.p, a: this.eccData.a, b: this.eccData.b, gx: this.eccData.gx, gy: this.eccData.gy, n: this.eccData.n }); }
      catch(e) { this.error = e.message; }
    },
    async runTiming() {
      if (!this.suite.plaintext.trim()) { this.error = 'Please enter a plaintext.'; return; }
      this.loading = true; this.error = ''; this.suite.timingResults = null;
      try {
        const r = await this.api('analysis/timing', { plaintext: this.suite.plaintext });
        this.suite.timingResults = r.results;
      } catch(e) { this.error = e.message; } finally { this.loading = false; }
    },

    async runBruteForce() {
      if (!this.suite.ciphertext.trim()) { this.error = 'Please enter a ciphertext.'; return; }
      this.loading = true; this.error = ''; this.suite.bruteResults = null;
      try {
        const r = await this.api('analysis/brute_force', {
          ciphertext:      this.suite.ciphertext,
          timeout_seconds: this.suite.timeout     || 60,
          max_attempts:    this.suite.maxAttempts || 616,
        });
        this.suite.bruteResults = r.results;
      } catch(e) { this.error = e.message; } finally { this.loading = false; }
    },
    async loadPerformance() {
      this.loading = true; this.perfData = null; this.error = '';
      const text = this.perfText.trim();
      const url  = text ? 'performance?plaintext=' + encodeURIComponent(text) : 'performance';
      try { this.perfData = await this.api(url); setTimeout(() => this.drawChart(), 120); }
      catch(e) { this.error = e.message; } finally { this.loading = false; }
    },
    drawChart() {
      const canvas = document.getElementById('perfChart');
      if (!canvas || !this.perfData) return;
      const colors = this.perfData.results.map(r =>
        ['Strong','Very Strong','Strongest'].includes(r.security) ? '#4ade80' :
        ['Educational','Weak (demo)','Demo only','Moderate (use 2048+)'].includes(r.security) ? '#fbbf24' : '#f87171'
      );
      if (window._perfChart) window._perfChart.destroy();
      window._perfChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels: this.perfData.results.map(r => r.algorithm),
          datasets: [{ label: 'Avg Time (ms)', data: this.perfData.results.map(r => r.time_ms), backgroundColor: colors, borderRadius: 6 }]
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => c.parsed.y.toFixed(4)+' ms' } } },
          scales: {
            x: { ticks: { color: '#94a3b8' }, grid: { color: '#3b3b52' } },
            y: { type: 'logarithmic', ticks: { color: '#94a3b8', callback: v => v+' ms' }, grid: { color: '#3b3b52' } }
          }
        }
      });
    },
  };
}
