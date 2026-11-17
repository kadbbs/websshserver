/* Independent SSH-2 client. Uses only WebSocket, Web Crypto and typed arrays.
 * RFC 4251/4252/4253/4254/4344/5656. No server-side SSH bridge is involved.
 */
(function (root) {
  "use strict";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const bytes = (value) => typeof value === "string" ? encoder.encode(value) : new Uint8Array(value);
  const concat = (...parts) => {
    parts = parts.map(bytes);
    const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  };
  const u32 = (value) => {
    const result = new Uint8Array(4);
    new DataView(result.buffer).setUint32(0, value);
    return result;
  };
  const str = (value) => { const data = bytes(value); return concat(u32(data.length), data); };
  const message = (type, ...parts) => concat(Uint8Array.of(type), ...parts);
  const equal = (a, b) => {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  };
  const mpint = (value) => {
    let data = bytes(value);
    let start = 0;
    while (start < data.length && data[start] === 0) start++;
    data = data.slice(start);
    if (data[0] & 128) data = concat(Uint8Array.of(0), data);
    return str(data);
  };
  class Reader {
    constructor(data) { this.data = bytes(data); this.offset = 0; }
    take(n) {
      if (!Number.isInteger(n) || n < 0 || this.offset + n > this.data.length) throw new Error("SSH 消息长度无效");
      const value = this.data.slice(this.offset, this.offset + n);
      this.offset += n;
      return value;
    }
    byte() { return this.take(1)[0]; }
    uint() { const b = this.take(4); return new DataView(b.buffer, b.byteOffset, 4).getUint32(0); }
    string() { return this.take(this.uint()); }
    text() { return decoder.decode(this.string()); }
    end() { if (this.offset !== this.data.length) throw new Error("SSH 消息包含多余字段"); }
  }
  class ByteQueue {
    constructor() { this.chunks = []; this.length = 0; this.pending = null; this.error = null; }
    push(data) {
      if (this.error) return;
      if (this.length + data.length > 8 * 1024 * 1024) { this.fail(new Error("SSH 接收缓冲区超限")); return; }
      if (data.length) { this.chunks.push(data); this.length += data.length; }
      this.fulfill();
    }
    fail(error) {
      this.error = error;
      if (this.pending) { this.pending.reject(error); this.pending = null; }
    }
    read(n) {
      if (this.pending) return Promise.reject(new Error("SSH 并发读取错误"));
      if (this.error) return Promise.reject(this.error);
      return new Promise((resolve, reject) => { this.pending = { n, resolve, reject }; this.fulfill(); });
    }
    fulfill() {
      if (!this.pending || this.length < this.pending.n) return;
      const { n, resolve } = this.pending;
      this.pending = null;
      const result = new Uint8Array(n);
      let offset = 0;
      while (offset < n) {
        const chunk = this.chunks[0];
        const count = Math.min(n - offset, chunk.length);
        result.set(chunk.subarray(0, count), offset);
        offset += count;
        if (count === chunk.length) this.chunks.shift();
        else this.chunks[0] = chunk.subarray(count);
      }
      this.length -= n;
      resolve(result);
    }
  }
  class CTR {
    constructor(key, iv) { this.key = key; this.counter = iv.slice(); }
    async apply(data) {
      if (data.length % 16) throw new Error("SSH 密文未对齐");
      const result = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter: this.counter, length: 128 }, this.key, data));
      let carry = data.length / 16;
      for (let i = 15; i >= 0 && carry; i--) {
        const value = this.counter[i] + (carry % 256);
        this.counter[i] = value & 255;
        carry = Math.floor(carry / 256) + (value > 255 ? 1 : 0);
      }
      return result;
    }
  }
  const algorithms = [
    "ecdh-sha2-nistp256", "ecdsa-sha2-nistp256",
    "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""
  ];
  const LOCAL_WINDOW = 2 * 1024 * 1024;
  class SSHClient {
    constructor(options) {
      this.options = options;
      this.queue = new ByteQueue();
      this.outSequence = 0; this.inSequence = 0;
      this.sendChain = Promise.resolve();
      this.pendingInput = new Uint8Array(0);
      this.localWindow = LOCAL_WINDOW;
      this.remoteChannel = null;
      this.closed = false; this.ready = false;
      this.kexBarrier = null; this.ownKex = null;
      this.bytesSinceKex = 0;
    }
    async connect() {
      if (!root.crypto || !crypto.subtle) throw new Error("浏览器需要 Web Crypto：请使用 localhost、HTTPS，或直接打开本地 HTML 文件");
      if (!this.options.onHostKey) throw new Error("必须提供主机指纹校验回调");
      const url = new URL(this.options.url);
      if (!["ws:", "wss:"].includes(url.protocol) || url.username || url.password || url.hash) throw new Error("请填写有效的 ws:// 或 wss:// 地址");
      this.timeout = setTimeout(() => this.fail(new Error("SSH 连接超时")), 60000);
      try {
        this.ws = new WebSocket(url.href);
        this.ws.binaryType = "arraybuffer";
        this.ws.onmessage = (event) => {
          if (!(event.data instanceof ArrayBuffer)) { this.fail(new Error("服务端必须发送二进制 SSH 数据")); return; }
          this.queue.push(new Uint8Array(event.data));
        };
        const connectionFailed = () => {
          const error = new Error("无法连接服务器，请检查地址、端口及服务器访问权限");
          error.code = "CONNECTION_FAILED";
          this.fail(error);
        };
        this.transportTimeout = setTimeout(connectionFailed, this.options.transportTimeout || 10000);
        this.ws.onclose = () => { if (!this.transportOpened && !this.closed) connectionFailed(); else this.finish(); };
        this.ws.onerror = () => { if (!this.transportOpened) connectionFailed(); else this.fail(new Error("服务器连接中断，请重新连接")); };
        await new Promise((resolve, reject) => {
          this.ws.onopen = () => { this.transportOpened = true; clearTimeout(this.transportTimeout); resolve(); };
          this.openReject = reject;
        });
        this.openReject = null;
        this.clientVersion = encoder.encode("SSH-2.0-WebSSH_Browser_1.0");
        this.ws.send(concat(this.clientVersion, "\r\n"));
        let bannerBytes = 0;
        for (;;) {
          const line = [];
          while (line.length < 255) {
            const c = (await this.queue.read(1))[0];
            if (++bannerBytes > 8192) throw new Error("SSH 版本前导数据超限");
            if (c === 10) break;
            line.push(c);
          }
          if (line.length >= 255) throw new Error("SSH 版本行过长");
          if (line[line.length - 1] === 13) line.pop();
          const version = decoder.decode(new Uint8Array(line));
          if (!version.startsWith("SSH-")) continue;
          if (!version.startsWith("SSH-2.0-")) throw new Error("仅支持 SSH 2.0");
          this.serverVersion = new Uint8Array(line);
          break;
        }
        await this.keyExchange();
        await this.send(message(5, str("ssh-userauth")));
        const service = new Reader((await this.expect([6])).slice(1));
        if (service.text() !== "ssh-userauth") throw new Error("SSH 用户认证服务不匹配");
        service.end();
        await this.send(message(50, str(this.options.username), str("ssh-connection"), str("password"), Uint8Array.of(0), str(this.options.password)));
        this.options.password = "";
        const auth = await this.expect([51, 52, 60]);
        if (auth[0] !== 52) throw new Error(auth[0] === 60 ? "服务端要求修改密码，当前客户端不支持" : "SSH 认证失败：请检查用户名、密码或服务端认证方式");
        await this.send(message(90, str("session"), u32(0), u32(LOCAL_WINDOW), u32(32768)));
        const opened = await this.expect([91, 92]);
        const channel = new Reader(opened.slice(1));
        if (channel.uint() !== 0) throw new Error("SSH 通道编号错误");
        if (opened[0] === 92) { channel.uint(); throw new Error("SSH 会话被拒绝：" + channel.text()); }
        this.remoteChannel = channel.uint();
        this.remoteWindow = channel.uint();
        this.remoteMax = channel.uint();
        if (!this.remoteMax) throw new Error("SSH 通道数据包大小无效");
        channel.end();
        const cols = this.options.cols || 80, rows = this.options.rows || 24;
        await this.send(message(98, u32(this.remoteChannel), str("pty-req"), Uint8Array.of(1), str("xterm-256color"), u32(cols), u32(rows), u32(0), u32(0), str(Uint8Array.of(0))));
        if ((await this.expect([99, 100]))[0] !== 99) throw new Error("服务端拒绝分配 PTY");
        await this.send(message(98, u32(this.remoteChannel), str("shell"), Uint8Array.of(1)));
        if ((await this.expect([99, 100]))[0] !== 99) throw new Error("服务端拒绝启动 Shell");
        clearTimeout(this.timeout);
        this.ready = true;
        this.rekeyTimer = setInterval(() => this.requestRekey().catch((error) => this.fail(error)), 30 * 60 * 1000);
        this.pump().catch((error) => this.fail(error));
        this.flushInput();
      } catch (error) {
        this.options.password = "";
        this.fail(error);
        throw error;
      }
    }
    async writePacket(payload) {
      if (this.closed || this.ws.readyState !== WebSocket.OPEN) throw new Error("SSH 连接已关闭");
      const block = this.outCipher ? 16 : 8;
      let padding = block - ((payload.length + 5) % block);
      if (padding < 4) padding += block;
      const packet = concat(u32(payload.length + padding + 1), Uint8Array.of(padding), payload, crypto.getRandomValues(new Uint8Array(padding)));
      let mac = new Uint8Array(0);
      if (this.outMAC) mac = new Uint8Array(await crypto.subtle.sign("HMAC", this.outMAC, concat(u32(this.outSequence), packet)));
      const encrypted = this.outCipher ? await this.outCipher.apply(packet) : packet;
      if (this.ws.bufferedAmount > 4 * 1024 * 1024) throw new Error("WebSocket 发送缓冲区超限");
      this.ws.send(concat(encrypted, mac));
      this.outSequence = (this.outSequence + 1) >>> 0;
      this.bytesSinceKex += packet.length;
    }
    rawSend(payload) {
      const task = this.sendChain.then(() => this.writePacket(payload));
      this.sendChain = task.catch(() => {});
      return task;
    }
    async send(payload) {
      // Wait outside the serialized writer so key-exchange packets cannot deadlock.
      while (this.kexBarrier) await this.kexBarrier;
      return this.rawSend(payload);
    }
    enqueue(payload) { this.send(payload).catch((error) => this.fail(error)); }
    async readPacket() {
      const block = this.inCipher ? 16 : 8;
      let first = await this.queue.read(block);
      if (this.inCipher) first = await this.inCipher.apply(first);
      const length = new DataView(first.buffer, first.byteOffset, 4).getUint32(0);
      if (length < 12 || length > 256 * 1024 || (length + 4) % block !== 0) throw new Error("SSH 数据包长度无效");
      let tail = await this.queue.read(length + 4 - block);
      if (this.inCipher && tail.length) tail = await this.inCipher.apply(tail);
      const packet = concat(first, tail);
      if (this.inMAC) {
        const mac = await this.queue.read(32);
        if (!await crypto.subtle.verify("HMAC", this.inMAC, mac, concat(u32(this.inSequence), packet))) throw new Error("SSH 消息完整性校验失败，连接已终止");
      }
      this.inSequence = (this.inSequence + 1) >>> 0;
      const padding = packet[4];
      if (padding < 4 || padding + 1 >= length) throw new Error("SSH 填充长度无效");
      this.bytesSinceKex += packet.length;
      const payload = packet.slice(5, packet.length - padding);
      if (payload[0] === 1) {
        const r = new Reader(payload.slice(1));
        r.uint();
        throw new Error("SSH 服务端断开连接：" + r.text());
      }
      return payload;
    }
    async expect(types) {
      for (;;) {
        const packet = await this.readPacket();
        if (types.includes(packet[0])) return packet;
        if (packet[0] === 20) { await this.keyExchange(packet); continue; }
        if ([2, 4, 7].includes(packet[0])) continue;
        if (packet[0] === 53) {
          if (this.options.onBanner) this.options.onBanner(new Reader(packet.slice(1)).text());
          continue;
        }
        if (this.remoteChannel !== null && this.handleChannel(packet)) continue;
        throw new Error("未预期的 SSH 消息：" + packet[0]);
      }
    }
    startKex() {
      if (!this.kexBarrier) this.kexBarrier = new Promise((resolve) => { this.releaseKex = resolve; });
      if (!this.ownKex) {
        this.ownKex = message(20, crypto.getRandomValues(new Uint8Array(16)), ...algorithms.map(str), Uint8Array.of(0), u32(0));
        this.kexSent = this.rawSend(this.ownKex);
      }
    }
    async requestRekey() {
      if (this.closed || !this.ready || this.kexBarrier) return;
      this.startKex();
      this.kexTimeout = setTimeout(() => this.fail(new Error("SSH 密钥更新超时")), 30000);
      await this.kexSent;
    }
    async keyExchange(serverInit) {
      this.startKex();
      await this.kexSent;
      if (!serverInit) serverInit = await this.expect([20]);
      const init = new Reader(serverInit.slice(1));
      init.take(16);
      const lists = Array.from({ length: 10 }, () => init.text().split(","));
      const guessed = init.byte();
      init.uint(); init.end();
      for (let i = 0; i < 8; i++) {
        if (!lists[i].includes(algorithms[i])) throw new Error("服务端不支持客户端算法：" + algorithms[i]);
      }
      if (guessed && (lists[0][0] !== algorithms[0] || lists[1][0] !== algorithms[1])) await this.readPacket();
      const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      const clientPoint = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
      await this.rawSend(message(30, str(clientPoint)));
      const reply = new Reader((await this.expect([31])).slice(1));
      const hostBlob = reply.string(), serverPoint = reply.string(), signatureBlob = reply.string();
      reply.end();
      const serverKey = await crypto.subtle.importKey("raw", serverPoint, { name: "ECDH", namedCurve: "P-256" }, false, []);
      const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: serverKey }, pair.privateKey, 256));
      const encodedK = mpint(shared);
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(str(this.clientVersion), str(this.serverVersion), str(this.ownKex), str(serverInit), str(hostBlob), str(clientPoint), str(serverPoint), encodedK)));
      const host = new Reader(hostBlob);
      if (host.text() !== algorithms[1] || host.text() !== "nistp256") throw new Error("SSH 主机密钥类型不匹配");
      const point = host.string(); host.end();
      const signature = new Reader(signatureBlob);
      if (signature.text() !== algorithms[1]) throw new Error("SSH 主机签名类型不匹配");
      const components = new Reader(signature.string()); signature.end();
      const fixedInteger = (value) => {
        if (!value.length || (value[0] & 128)) throw new Error("ECDSA 签名整数无效");
        if (value[0] === 0) value = value.slice(1);
        if (value.length > 32) throw new Error("ECDSA 签名整数超长");
        const result = new Uint8Array(32); result.set(value, 32 - value.length); return result;
      };
      const rawSignature = concat(fixedInteger(components.string()), fixedInteger(components.string()));
      components.end();
      const verifyKey = await crypto.subtle.importKey("raw", point, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifyKey, rawSignature, hash)) throw new Error("SSH 主机签名校验失败");
      const fingerprintBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", hostBlob));
      const fingerprint = "SHA256:" + btoa(String.fromCharCode(...fingerprintBytes)).replace(/=+$/, "");
      if (this.hostBlob) {
        if (!equal(hostBlob, this.hostBlob)) throw new Error("SSH 重新交换密钥时主机身份发生变化");
      } else {
        if (!await this.options.onHostKey({ fingerprint, algorithm: algorithms[1], url: this.options.url })) throw new Error("已取消主机指纹确认");
        this.hostBlob = hostBlob.slice();
        this.fingerprint = fingerprint;
      }
      if (!this.sessionID) this.sessionID = hash;
      const derive = async (letter, length) => new Uint8Array(await crypto.subtle.digest("SHA-256", concat(encodedK, hash, letter, this.sessionID))).slice(0, length);
      const [outIV, inIV, outRaw, inRaw, outMACRaw, inMACRaw] = await Promise.all([derive("A", 16), derive("B", 16), derive("C", 16), derive("D", 16), derive("E", 32), derive("F", 32)]);
      const aes = (key) => crypto.subtle.importKey("raw", key, "AES-CTR", false, ["encrypt"]);
      const hmac = (key) => crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
      const [outKey, inKey, outMAC, inMAC] = await Promise.all([aes(outRaw), aes(inRaw), hmac(outMACRaw), hmac(inMACRaw)]);
      await this.rawSend(message(21));
      this.outCipher = new CTR(outKey, outIV); this.outMAC = outMAC;
      await this.expect([21]);
      this.inCipher = new CTR(inKey, inIV); this.inMAC = inMAC;
      this.ownKex = null; this.kexSent = null;
      this.bytesSinceKex = 0;
      clearTimeout(this.kexTimeout);
      const release = this.releaseKex;
      this.kexBarrier = null; this.releaseKex = null;
      release();
      if (this.options.onSecurity) this.options.onSecurity({ fingerprint, cipher: "AES-128-CTR", mac: "HMAC-SHA-256" });
    }
    async pump() {
      while (!this.closed) {
        const packet = await this.readPacket();
        if (packet[0] === 20) await this.keyExchange(packet);
        else if ([2, 4, 7].includes(packet[0])) continue;
        else if (packet[0] === 80) {
          const request = new Reader(packet.slice(1)); request.text();
          if (request.byte()) this.enqueue(message(82));
        } else if (packet[0] === 90) {
          const request = new Reader(packet.slice(1)); request.text();
          this.enqueue(message(92, u32(request.uint()), u32(1), str("unsupported channel"), str("")));
        } else if (!this.handleChannel(packet)) throw new Error("未预期的 SSH 会话消息：" + packet[0]);
        if (this.bytesSinceKex > 64 * 1024 * 1024) await this.requestRekey();
      }
    }
    handleChannel(packet) {
      const type = packet[0];
      if (type < 93 || type > 100) return false;
      const r = new Reader(packet.slice(1));
      if (r.uint() !== 0) throw new Error("SSH 通道编号错误");
      if (type === 93) {
        const added = r.uint();
        if (this.remoteWindow + added > 0xffffffff) throw new Error("SSH 通道窗口溢出");
        this.remoteWindow += added;
        this.flushInput();
      } else if (type === 94 || type === 95) {
        if (type === 95) r.uint();
        const data = r.string();
        if (data.length > this.localWindow || data.length > 32768) throw new Error("SSH 通道接收窗口超限");
        this.localWindow -= data.length;
        if (this.options.onData) this.options.onData(data);
        if (this.localWindow < LOCAL_WINDOW / 2) {
          this.enqueue(message(93, u32(this.remoteChannel), u32(LOCAL_WINDOW - this.localWindow)));
          this.localWindow = LOCAL_WINDOW;
        }
      } else if (type === 97) {
        this.send(message(97, u32(this.remoteChannel))).then(() => this.close(), () => this.close());
      } else if (type === 98) {
        const request = r.text(), wantsReply = r.byte();
        let accepted = false;
        if (request === "exit-status") { this.exitStatus = r.uint(); accepted = true; }
        else if (request === "exit-signal") { this.exitSignal = r.text(); accepted = true; }
        if (wantsReply) this.enqueue(message(accepted ? 99 : 100, u32(this.remoteChannel)));
        // Unknown request-specific fields are intentionally ignored.
        return true;
      }
      r.end();
      return true;
    }
    write(value) {
      if (!this.ready || this.closed) return;
      const data = bytes(value);
      if (this.pendingInput.length + data.length > 1024 * 1024) { this.fail(new Error("待发送输入超过 1 MiB，请分批粘贴")); return; }
      this.pendingInput = concat(this.pendingInput, data);
      this.flushInput();
    }
    async flushInput() {
      if (this.flushing || !this.ready || this.closed) return;
      this.flushing = true;
      try {
        while (this.pendingInput.length && this.remoteWindow > 0 && !this.closed) {
          const count = Math.min(this.pendingInput.length, this.remoteWindow, this.remoteMax, 32768);
          const data = this.pendingInput.slice(0, count);
          this.pendingInput = this.pendingInput.slice(count);
          this.remoteWindow -= count;
          await this.send(message(94, u32(this.remoteChannel), str(data)));
        }
      } catch (error) { this.fail(error); }
      finally { this.flushing = false; }
    }
    resize(cols, rows) {
      if (this.ready && !this.closed) this.enqueue(message(98, u32(this.remoteChannel), str("window-change"), Uint8Array.of(0), u32(cols), u32(rows), u32(0), u32(0)));
    }
    close() {
      if (this.ws && this.ws.readyState < WebSocket.CLOSING) this.ws.close(1000, "client disconnected");
      this.finish();
    }
    fail(error) {
      if (this.closed) return;
      this.error = error;
      this.close();
    }
    finish() {
      if (this.closed) return;
      this.closed = true; this.ready = false;
      this.options.password = "";
      clearTimeout(this.timeout); clearTimeout(this.transportTimeout); clearTimeout(this.kexTimeout); clearInterval(this.rekeyTimer);
      const error = this.error || new Error("SSH 连接已关闭");
      this.queue.fail(error);
      if (this.openReject) this.openReject(error);
      if (this.releaseKex) { this.kexBarrier = null; this.releaseKex(); this.releaseKex = null; }
      if (this.options.onClose) this.options.onClose({ error: this.error, exitStatus: this.exitStatus, signal: this.exitSignal });
    }
  }
  root.WebSSH = { SSHClient, protocol: { Reader, ByteQueue, concat, u32, str, mpint, equal, CTR } };
})(globalThis);
