import { useState } from 'react';
import NavBar from '../sections/NavBar';

export default function IntelPage() {
  // Base64
  const [b64Input, setB64Input] = useState('');
  const [b64Output, setB64Output] = useState('');

  // Hex to ASCII
  const [hexInput, setHexInput] = useState('');
  const [hexOutput, setHexOutput] = useState('');

  // ROT13
  const [rotInput, setRotInput] = useState('');

  // Caesar
  const [caesarInput, setCaesarInput] = useState('');
  const [caesarShift, setCaesarShift] = useState(5);

  // XOR
  const [xorInput, setXorInput] = useState('');
  const [xorKey, setXorKey] = useState('');
  const [xorOutput, setXorOutput] = useState('');

  // Reverse
  const [revInput, setRevInput] = useState('');

  // Decoder functions
  const handleB64 = (val) => {
    setB64Input(val);
    try {
      let s = val.trim().replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      setB64Output(atob(s));
    } catch {
      setB64Output('Invalid Base64 / Base64URL string');
    }
  };

  const handleHex = (val) => {
    setHexInput(val);
    try {
      const clean = val.replace(/[^0-9a-fA-F]/g, '');
      if (clean.length % 2 !== 0) {
        setHexOutput('Hex length must be even');
        return;
      }
      let out = '';
      for (let i = 0; i < clean.length; i += 2) {
        out += String.fromCharCode(parseInt(clean.substr(i, 2), 16));
      }
      setHexOutput(out || '');
    } catch {
      setHexOutput('Invalid Hex');
    }
  };

  const computeRot13 = (str) => {
    return str.replace(/[a-zA-Z]/g, (c) => {
      const code = c.charCodeAt(0);
      const isUpper = code >= 65 && code <= 90;
      const base = isUpper ? 65 : 97;
      return String.fromCharCode(((code - base + 13) % 26) + base);
    });
  };

  const computeCaesar = (str, shift) => {
    const s = parseInt(shift, 10) || 0;
    return str.replace(/[a-zA-Z]/g, (c) => {
      const code = c.charCodeAt(0);
      const isUpper = code >= 65 && code <= 90;
      const base = isUpper ? 65 : 97;
      return String.fromCharCode(((code - base - (s % 26) + 26) % 26) + base);
    });
  };

  const computeXor = () => {
    try {
      const cleanData = xorInput.replace(/[^0-9a-fA-F]/g, '');
      const cleanKey = xorKey.replace(/[^0-9a-fA-F]/g, '');
      if (!cleanData || !cleanKey) {
        setXorOutput('Provide hex data and hex key.');
        return;
      }
      const dataBytes = [];
      for (let i = 0; i < cleanData.length; i += 2) {
        dataBytes.push(parseInt(cleanData.substr(i, 2), 16));
      }
      const keyBytes = [];
      for (let i = 0; i < cleanKey.length; i += 2) {
        keyBytes.push(parseInt(cleanKey.substr(i, 2), 16));
      }
      let out = '';
      for (let i = 0; i < dataBytes.length; i++) {
        const k = keyBytes[i % keyBytes.length];
        out += String.fromCharCode(dataBytes[i] ^ k);
      }
      setXorOutput(out);
    } catch {
      setXorOutput('Error computing XOR');
    }
  };

  // Tool card config
  const outputBox = 'bg-black/60 p-3 rounded-xl border border-white/10 text-xs font-mono text-[#39FF14] break-all min-h-[4rem]';

  return (
    <div className="app-bg min-h-screen text-white pb-20">
      <NavBar />

      <main className="max-w-7xl mx-auto pt-28 px-4 sm:px-6 lg:px-8 space-y-8">

        {/* Header */}
        <div className="border-b border-white/10 pb-6">
          <span className="text-xs font-mono uppercase tracking-widest text-gray-400 font-bold block mb-1">
            SAFEHOUSE DECRYPTION RIG // LESTER'S WORKBENCH
          </span>
          <h1
            className="font-long text-5xl uppercase"
            style={{
              background: 'linear-gradient(90deg,#ff6eb0,#00e5ff)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            CYBER TOOLKIT
          </h1>
          <p className="text-sm font-mono text-gray-400 mt-1">
            LOCAL IN-BROWSER FIELD TOOLS // ZERO NETWORK DISPATCH // SAFE OFFLINE CIPHER SUITE
          </p>
        </div>

        {/* 6 Tools Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">

          {/* Tool 1: Base64 — pink */}
          <div className="rounded-2xl bg-[#0d0d1a] border border-white/10 overflow-hidden hover:border-[#FF6EB0]/40 transition-all">
            <div className="h-1.5 w-full" style={{ background: '#FF6EB0' }} />
            <div className="p-6 space-y-4">
              <div>
                <span className="text-xs font-mono text-gray-500">01</span>
                <h3 className="font-round-bold text-base uppercase text-[#FF6EB0] leading-tight">
                  Base64 &amp; Base64URL Decoder
                </h3>
                <p className="text-xs text-gray-400 mt-1 mb-4">Decode standard or URL-safe Base64 payloads.</p>
              </div>
              <textarea
                rows={3}
                value={b64Input}
                onChange={(e) => handleB64(e.target.value)}
                placeholder="Paste Base64 payload..."
                className="heist-input rounded-xl text-xs font-mono w-full"
              />
              <div className={outputBox}>
                {b64Output || <span className="text-gray-600 italic">Decoded plaintext will appear here</span>}
              </div>
            </div>
          </div>

          {/* Tool 2: Hex — cyan */}
          <div className="rounded-2xl bg-[#0d0d1a] border border-white/10 overflow-hidden hover:border-[#00E5FF]/40 transition-all">
            <div className="h-1.5 w-full" style={{ background: '#00E5FF' }} />
            <div className="p-6 space-y-4">
              <div>
                <span className="text-xs font-mono text-gray-500">02</span>
                <h3 className="font-round-bold text-base uppercase text-[#00E5FF] leading-tight">
                  Hexadecimal to ASCII
                </h3>
                <p className="text-xs text-gray-400 mt-1 mb-4">Convert raw hex bytes to readable ASCII text.</p>
              </div>
              <textarea
                rows={3}
                value={hexInput}
                onChange={(e) => handleHex(e.target.value)}
                placeholder="Paste hex bytes: 464c41477b... or space separated"
                className="heist-input rounded-xl text-xs font-mono w-full"
              />
              <div className={outputBox}>
                {hexOutput || <span className="text-gray-600 italic">ASCII result will appear here</span>}
              </div>
            </div>
          </div>

          {/* Tool 3: ROT13 — yellow */}
          <div className="rounded-2xl bg-[#0d0d1a] border border-white/10 overflow-hidden hover:border-[#fff9cb]/40 transition-all">
            <div className="h-1.5 w-full" style={{ background: '#fff9cb' }} />
            <div className="p-6 space-y-4">
              <div>
                <span className="text-xs font-mono text-gray-500">03</span>
                <h3 className="font-round-bold text-base uppercase text-[#fff9cb] leading-tight">
                  ROT13 Cipher Reversal
                </h3>
                <p className="text-xs text-gray-400 mt-1 mb-4">Live ROT13 en/decryption — symmetric single-step.</p>
              </div>
              <textarea
                rows={3}
                value={rotInput}
                onChange={(e) => setRotInput(e.target.value)}
                placeholder="Type or paste ciphertext..."
                className="heist-input rounded-xl text-xs font-mono w-full"
              />
              <div className={outputBox}>
                {rotInput ? computeRot13(rotInput) : <span className="text-gray-600 italic">Live ROT13 output</span>}
              </div>
            </div>
          </div>

          {/* Tool 4: Caesar — coral */}
          <div className="rounded-2xl bg-[#0d0d1a] border border-white/10 overflow-hidden hover:border-[#FF7A59]/40 transition-all">
            <div className="h-1.5 w-full" style={{ background: '#FF7A59' }} />
            <div className="p-6 space-y-4">
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-xs font-mono text-gray-500">04</span>
                  <h3 className="font-round-bold text-base uppercase text-[#FF7A59] leading-tight">
                    Caesar Rotation Shift
                  </h3>
                  <p className="text-xs text-gray-400 mt-1 mb-4">Brute-force or targeted Caesar cipher decode.</p>
                </div>
                <div className="flex items-center gap-1 font-mono text-xs mt-1 shrink-0">
                  <span className="text-gray-400">SHIFT:</span>
                  <input
                    type="number"
                    min={1}
                    max={25}
                    value={caesarShift}
                    onChange={(e) => setCaesarShift(e.target.value)}
                    className="w-12 bg-black/60 border border-white/20 text-center text-white rounded py-0.5"
                  />
                </div>
              </div>
              <textarea
                rows={3}
                value={caesarInput}
                onChange={(e) => setCaesarInput(e.target.value)}
                placeholder="Paste Caesar ciphertext..."
                className="heist-input rounded-xl text-xs font-mono w-full"
              />
              <div className={outputBox}>
                {caesarInput ? computeCaesar(caesarInput, caesarShift) : <span className="text-gray-600 italic">Decoded shift result</span>}
              </div>
            </div>
          </div>

          {/* Tool 5: XOR — red */}
          <div className="rounded-2xl bg-[#0d0d1a] border border-white/10 overflow-hidden hover:border-red-500/40 transition-all">
            <div className="h-1.5 w-full bg-red-500" />
            <div className="p-6 space-y-4">
              <div>
                <span className="text-xs font-mono text-gray-500">05</span>
                <h3 className="font-round-bold text-base uppercase text-red-400 leading-tight">
                  Repeating-Key XOR Recovery
                </h3>
                <p className="text-xs text-gray-400 mt-1 mb-4">XOR hex ciphertext with a repeating hex key.</p>
              </div>
              <input
                type="text"
                value={xorInput}
                onChange={(e) => setXorInput(e.target.value)}
                placeholder="Ciphertext (hex bytes)..."
                className="heist-input rounded-xl text-xs font-mono w-full"
              />
              <input
                type="text"
                value={xorKey}
                onChange={(e) => setXorKey(e.target.value)}
                placeholder="XOR Key (hex bytes)..."
                className="heist-input rounded-xl text-xs font-mono w-full"
              />
              <button
                onClick={computeXor}
                className="btn-outline-heist w-full py-1.5 text-xs font-mono"
              >
                EXECUTE XOR →
              </button>
              <div className={outputBox}>
                {xorOutput || <span className="text-gray-600 italic">Plaintext result</span>}
              </div>
            </div>
          </div>

          {/* Tool 6: Reverse — purple */}
          <div className="rounded-2xl bg-[#0d0d1a] border border-white/10 overflow-hidden hover:border-purple-400/40 transition-all">
            <div className="h-1.5 w-full bg-purple-400" />
            <div className="p-6 space-y-4">
              <div>
                <span className="text-xs font-mono text-gray-500">06</span>
                <h3 className="font-round-bold text-base uppercase text-purple-400 leading-tight">
                  String Reversal
                </h3>
                <p className="text-xs text-gray-400 mt-1 mb-4">Instantly reverse any string or byte sequence.</p>
              </div>
              <textarea
                rows={3}
                value={revInput}
                onChange={(e) => setRevInput(e.target.value)}
                placeholder="Type or paste payload to reverse..."
                className="heist-input rounded-xl text-xs font-mono w-full"
              />
              <div className={outputBox}>
                {revInput ? revInput.split('').reverse().join('') : <span className="text-gray-600 italic">Reversed string output</span>}
              </div>
            </div>
          </div>

        </div>
      </main>
    </div>
  );
}
