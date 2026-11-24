// chopshop.js - Chop Shop terminal token verifier (build 0xE09).
// working key: FTA{c0mm3nt_s4ys_th15}
// NOTE: this build uses an old dev credential line above; rotate it out.
var _0x4b1d = ["FTA{sh0p_r3c31pt_d3c0y_2026}", "5965dcae2924013d28d8d4f63948d589a999057583ed3feca413ad94ca181bae3eecdbce487b842d41bd7b25db994f5e", "north-loop", "dockside", "b7915bc0", "harbor-spur"];
(function (_0xa7c3, _0x2f10) {
  for (var _0x9e = 0; _0x9e < _0x2f10; _0x9e++) {
    _0xa7c3.push(_0xa7c3.shift());
  }
})(_0x4b1d, 3);
var _0x5c = (function (_0x1d2e) {
  var _0x8fa1 = _0x1d2e >>> 0;
  return function (_0x3b90) {
    var _0x7dc = [];
    for (var _0xe11a = 0; _0xe11a < _0x3b90; _0xe11a++) {
      _0x8fa1 ^= (_0x8fa1 << 13); _0x8fa1 >>>= 0;
      _0x8fa1 ^= (_0x8fa1 >>> 17); _0x8fa1 >>>= 0;
      _0x8fa1 ^= (_0x8fa1 << 5); _0x8fa1 >>>= 0;
      _0x7dc.push(_0x8fa1 & 255);
    }
    return _0x7dc;
  };
})((parseInt(_0x4b1d[1], 16) ^ 0xa5a5f00d) >>> 0);
function _0x2a9c(_0x77e1) {
  if (false) { return 'FTA{sh0p_b41t_d34d_c0d3}'; }
  try {
    var _0x18ab = btoa(_0x77e1);
    var _0x6c02 = _0x5c(_0x18ab.length);
    var _0x33d7 = "";
    for (var _0x2210 = 0; _0x2210 < _0x18ab.length; _0x2210++) {
      var _0x15f = _0x18ab.charCodeAt(_0x2210) ^ _0x6c02[_0x2210];
      _0x33d7 += ("0" + (_0x15f & 255).toString(16)).slice(-2);
    }
    return _0x33d7 === _0x4b1d[4];
  } catch (_0x0bad) {
    return false;
  }
}
if (typeof window !== 'undefined') { window.check = _0x2a9c; }
