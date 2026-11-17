/* Small dependency-free VT-style terminal. DOM text nodes keep output selectable. */
(function (root) {
  "use strict";
  const DEFAULT_FG = "#d3dce9", DEFAULT_BG = "#0b0e14";
  const BASE = ["#18202d", "#f07887", "#80d6a3", "#e7cc85", "#7aaaf0", "#c49be8", "#79ced5", "#d3dce9", "#667389", "#ff9caa", "#a6ecc1", "#f5dfa2", "#a3c6ff", "#dab7fa", "#a2e7eb", "#ffffff"];
  function color(n) {
    if (n < 16) return BASE[Math.max(0, n)];
    if (n >= 232) { const v = 8 + (Math.min(n, 255) - 232) * 10; return `rgb(${v},${v},${v})`; }
    n -= 16;
    const component = (v) => v === 0 ? 0 : 55 + v * 40;
    return `rgb(${component(Math.floor(n / 36))},${component(Math.floor(n / 6) % 6)},${component(n % 6)})`;
  }
  function widthOf(ch) {
    if (/\p{Mark}/u.test(ch) || ch === "\u200d" || ch === "\ufe0f") return 0;
    const n = ch.codePointAt(0);
    return n >= 0x1100 && (n <= 0x115f || n === 0x2329 || n === 0x232a || (n >= 0x2e80 && n <= 0xa4cf) || (n >= 0xac00 && n <= 0xd7a3) || (n >= 0xf900 && n <= 0xfaff) || (n >= 0xfe10 && n <= 0xfe6f) || (n >= 0xff01 && n <= 0xff60) || (n >= 0xffe0 && n <= 0xffe6) || (n >= 0x1f300 && n <= 0x1faff) || (n >= 0x20000 && n <= 0x3fffd)) ? 2 : 1;
  }
  const lineDrawing = { "j": "┘", "k": "┐", "l": "┌", "m": "└", "n": "┼", "q": "─", "t": "├", "u": "┤", "v": "┴", "w": "┬", "x": "│", "a": "▒", "f": "°", "g": "±", "~": "·" };
  class Terminal {
    constructor(viewport, screen, input, options = {}) {
      this.viewport = viewport; this.screen = screen; this.input = input; this.options = options;
      this.cols = 80; this.rows = 24; this.decoder = new TextDecoder();
      this.cursor = document.createElement("div"); this.cursor.className = "terminal-cursor";
      this.reset(); this.bindInput();
      this.observer = new ResizeObserver(() => this.fit()); this.observer.observe(viewport);
      this.fit();
    }
    defaultAttr() { return { fg: DEFAULT_FG, bg: DEFAULT_BG, bold: false, dim: false, italic: false, under: false, inverse: false }; }
    blank() { return { ch: " ", width: 1, attr: this.attr }; }
    newRow() { const row = Array.from({ length: this.cols }, () => this.blank()); row.dirty = true; return row; }
    reset() {
      this.attr = this.defaultAttr(); this.x = 0; this.y = 0; this.saved = null; this.main = null;
      this.history = []; this.grid = Array.from({ length: this.rows }, () => this.newRow());
      this.top = 0; this.bottom = this.rows - 1; this.state = "normal"; this.sequence = "";
      this.cursorVisible = true; this.appCursor = false; this.bracketedPaste = false;
      this.autoWrap = true; this.wrapPending = false; this.originMode = false; this.insertMode = false;
      this.charset = [false, false]; this.activeCharset = 0; this.lastCharacter = " ";
      this.schedule();
    }
    clear() {
      this.history = []; this.grid = Array.from({ length: this.rows }, () => this.newRow());
      this.x = 0; this.y = 0; this.wrapPending = false;
      this.schedule();
    }
    write(data) {
      const text = typeof data === "string" ? data : this.decoder.decode(data, { stream: true });
      for (const ch of text) this.consume(ch);
      this.schedule();
    }
    consume(ch) {
      const code = ch.codePointAt(0);
      if (this.state === "osc" || this.state === "string") {
        if (ch === "\x07" && this.state === "osc") this.state = "normal";
        else if (ch === "\x1b") this.state = this.state === "osc" ? "osc-end" : "string-end";
        return;
      }
      if (this.state === "osc-end" || this.state === "string-end") {
        this.state = ch === "\\" ? "normal" : this.state === "osc-end" ? "osc" : "string";
        return;
      }
      if (ch === "\x1b") { this.state = "escape"; return; }
      if (ch === "\x18" || ch === "\x1a") { this.state = "normal"; return; }
      if (this.state === "charset") {
        this.charset[this.charsetTarget] = ch === "0"; this.state = "normal"; return;
      }
      if (this.state === "escape") {
        this.state = "normal";
        if (ch === "[") { this.state = "csi"; this.sequence = ""; }
        else if (ch === "]") this.state = "osc";
        else if (["P", "^", "_"].includes(ch)) this.state = "string";
        else if (ch === "(" || ch === ")") { this.charsetTarget = ch === "(" ? 0 : 1; this.state = "charset"; }
        else if (ch === "7") this.saveCursor();
        else if (ch === "8") this.restoreCursor();
        else if (ch === "D") this.lineFeed();
        else if (ch === "M") { if (this.y === this.top) this.scroll(-1); else this.y = Math.max(0, this.y - 1); }
        else if (ch === "E") { this.x = 0; this.lineFeed(); }
        else if (ch === "c") this.reset();
        return;
      }
      if (this.state === "csi") {
        if (code >= 0x40 && code <= 0x7e) {
          this.csi(ch, this.sequence); this.state = "normal";
        } else if (this.sequence.length < 256) this.sequence += ch;
        else this.state = "normal";
        return;
      }
      if (code < 32 || code === 127) {
        if (ch === "\r") { this.x = 0; this.wrapPending = false; }
        else if (["\n", "\x0b", "\x0c"].includes(ch)) this.lineFeed();
        else if (ch === "\b") { this.x = Math.max(0, this.x - 1); this.wrapPending = false; }
        else if (ch === "\t") { this.x = Math.min(this.cols - 1, (Math.floor(this.x / 8) + 1) * 8); this.wrapPending = false; }
        else if (ch === "\x0e") this.activeCharset = 1;
        else if (ch === "\x0f") this.activeCharset = 0;
        return;
      }
      this.put(this.charset[this.activeCharset] && lineDrawing[ch] ? lineDrawing[ch] : ch);
    }
    eraseCell(row, x) {
      if (row[x] && row[x].width === 0 && x > 0) row[x - 1] = this.blank();
      if (row[x] && row[x].width === 2 && x + 1 < this.cols) row[x + 1] = this.blank();
      row[x] = this.blank(); row.dirty = true;
    }
    put(ch) {
      const width = widthOf(ch);
      if (!width) {
        let x = this.wrapPending ? this.x : this.x - 1;
        if (x >= 0) {
          const row = this.grid[this.y];
          if (row[x].width === 0) x--;
          if (x >= 0) { row[x].ch += ch; row.dirty = true; }
        }
        return;
      }
      if (this.wrapPending || (width === 2 && this.x === this.cols - 1)) {
        if (this.autoWrap) { this.x = 0; this.lineFeed(); }
        this.wrapPending = false;
      }
      const row = this.grid[this.y];
      if (this.insertMode) { row.splice(this.x, 0, ...Array.from({ length: width }, () => this.blank())); row.length = this.cols; }
      this.eraseCell(row, this.x);
      if (width === 2 && this.x + 1 < this.cols) {
        this.eraseCell(row, this.x + 1);
        row[this.x + 1] = { ch: "", width: 0, attr: this.attr };
      }
      row[this.x] = { ch, width, attr: this.attr }; row.dirty = true;
      this.x += width;
      if (this.x >= this.cols) { this.x = this.cols - 1; this.wrapPending = this.autoWrap; }
      this.lastCharacter = ch;
    }
    lineFeed() {
      this.wrapPending = false;
      if (this.y === this.bottom) this.scroll(1);
      else this.y = Math.min(this.rows - 1, this.y + 1);
    }
    scroll(count) {
      count = Math.max(-(this.bottom - this.top + 1), Math.min(count, this.bottom - this.top + 1));
      for (let i = 0; i < Math.abs(count); i++) {
        if (count > 0) {
          const row = this.grid.splice(this.top, 1)[0];
          if (this.top === 0 && this.bottom === this.rows - 1 && !this.main) {
            this.history.push(row); if (this.history.length > 2000) this.history.shift();
          }
          this.grid.splice(this.bottom, 0, this.newRow());
        } else {
          this.grid.splice(this.bottom, 1); this.grid.splice(this.top, 0, this.newRow());
        }
      }
    }
    saveCursor() { this.saved = { x: this.x, y: this.y, attr: this.attr }; }
    restoreCursor() {
      if (this.saved) { this.x = Math.min(this.cols - 1, this.saved.x); this.y = Math.min(this.rows - 1, this.saved.y); this.attr = this.saved.attr; }
      this.wrapPending = false;
    }
    alternate(enabled) {
      if (enabled && !this.main) {
        this.main = { grid: this.grid, history: this.history, x: this.x, y: this.y, attr: this.attr, saved: this.saved };
        this.history = []; this.grid = Array.from({ length: this.rows }, () => this.newRow()); this.x = 0; this.y = 0;
      } else if (!enabled && this.main) {
        const saved = this.main; this.main = null;
        this.grid = saved.grid; this.history = saved.history; this.x = saved.x; this.y = saved.y; this.attr = saved.attr; this.saved = saved.saved;
        this.normalizeGrid();
      }
      this.top = 0; this.bottom = this.rows - 1; this.wrapPending = false;
    }
    csi(final, sequence) {
      const privateMode = sequence.startsWith("?");
      const prefix = sequence[0];
      const values = sequence.replace(/^[?>!]/, "").replace(/[^0-9;]/g, "").split(";").map((v) => Number(v) || 0);
      const n = Math.max(1, Math.min(values[0] || 1, 1000));
      const top = this.originMode ? this.top : 0, bottom = this.originMode ? this.bottom : this.rows - 1;
      if (!["m", "n", "c", "t"].includes(final)) this.wrapPending = false;
      if (final === "A") this.y = Math.max(top, this.y - n);
      else if (final === "B" || final === "e") this.y = Math.min(bottom, this.y + n);
      else if (final === "C" || final === "a") this.x = Math.min(this.cols - 1, this.x + n);
      else if (final === "D") this.x = Math.max(0, this.x - n);
      else if (final === "E") { this.y = Math.min(bottom, this.y + n); this.x = 0; }
      else if (final === "F") { this.y = Math.max(top, this.y - n); this.x = 0; }
      else if (final === "G" || final === "`") this.x = Math.min(this.cols - 1, n - 1);
      else if (final === "d") this.y = Math.min(bottom, top + n - 1);
      else if (final === "H" || final === "f") { this.y = Math.min(bottom, top + n - 1); this.x = Math.min(this.cols - 1, Math.max(1, values[1] || 1) - 1); }
      else if (final === "J") {
        const mode = values[0];
        if (mode === 3) this.history = [];
        else for (let y = 0; y < this.rows; y++) {
          if (mode === 2 || (mode === 0 && y > this.y) || (mode === 1 && y < this.y)) this.grid[y] = this.newRow();
          else if (y === this.y) this.eraseLine(mode);
        }
      } else if (final === "K") this.eraseLine(values[0]);
      else if (final === "m") this.sgr(values);
      else if (final === "r" && !privateMode) {
        const start = n - 1, end = (values[1] || this.rows) - 1;
        if (start < end && end < this.rows) { this.top = start; this.bottom = end; this.x = 0; this.y = this.originMode ? start : 0; }
      } else if (final === "s") this.saveCursor();
      else if (final === "u") this.restoreCursor();
      else if (final === "S") this.scroll(n);
      else if (final === "T") this.scroll(-n);
      else if (final === "L" || final === "M") {
        if (this.y >= this.top && this.y <= this.bottom) {
          const old = this.top; this.top = this.y; this.scroll(final === "L" ? -n : n); this.top = old;
        }
      } else if (["@", "P", "X"].includes(final)) {
        const row = this.grid[this.y], count = Math.min(n, this.cols - this.x);
        if (final === "@") { row.splice(this.x, 0, ...Array.from({ length: count }, () => this.blank())); row.length = this.cols; }
        else if (final === "P") { row.splice(this.x, count); while (row.length < this.cols) row.push(this.blank()); }
        else for (let i = this.x; i < this.x + count; i++) this.eraseCell(row, i);
        row.dirty = true;
      } else if (final === "b") for (let i = 0; i < n; i++) this.put(this.lastCharacter);
      else if (final === "h" || final === "l") {
        const enabled = final === "h";
        for (const mode of values) {
          if (privateMode) {
            if (mode === 1) this.appCursor = enabled;
            else if (mode === 6) { this.originMode = enabled; this.x = 0; this.y = enabled ? this.top : 0; }
            else if (mode === 7) this.autoWrap = enabled;
            else if (mode === 25) this.cursorVisible = enabled;
            else if ([47, 1047, 1049].includes(mode)) this.alternate(enabled);
            else if (mode === 1048) { if (enabled) this.saveCursor(); else this.restoreCursor(); }
            else if (mode === 2004) this.bracketedPaste = enabled;
          } else if (mode === 4) this.insertMode = enabled;
        }
      } else if (final === "n" && !privateMode) {
        if (values[0] === 6) this.send(`\x1b[${this.y + 1};${this.x + 1}R`);
        else if (values[0] === 5) this.send("\x1b[0n");
      } else if (final === "c") this.send(prefix === ">" ? "\x1b[>0;1;0c" : "\x1b[?1;2c");
      else if (final === "t" && values[0] === 18) this.send(`\x1b[8;${this.rows};${this.cols}t`);
    }
    eraseLine(mode) {
      const row = this.grid[this.y];
      const start = mode === 0 ? this.x : 0, end = mode === 1 ? this.x : this.cols - 1;
      if (mode > 2) return;
      for (let x = start; x <= end; x++) this.eraseCell(row, x);
    }
    sgr(values) {
      let attr = { ...this.attr };
      for (let i = 0; i < values.length; i++) {
        const n = values[i];
        if (n === 0) attr = this.defaultAttr();
        else if (n === 1) attr.bold = true;
        else if (n === 2) attr.dim = true;
        else if (n === 3) attr.italic = true;
        else if (n === 4) attr.under = true;
        else if (n === 7) attr.inverse = true;
        else if (n === 22) { attr.bold = false; attr.dim = false; }
        else if (n === 23) attr.italic = false;
        else if (n === 24) attr.under = false;
        else if (n === 27) attr.inverse = false;
        else if (n === 39) attr.fg = DEFAULT_FG;
        else if (n === 49) attr.bg = DEFAULT_BG;
        else if (n >= 30 && n <= 37) attr.fg = color(n - 30);
        else if (n >= 40 && n <= 47) attr.bg = color(n - 40);
        else if (n >= 90 && n <= 97) attr.fg = color(n - 90 + 8);
        else if (n >= 100 && n <= 107) attr.bg = color(n - 100 + 8);
        else if ((n === 38 || n === 48) && values[i + 1] === 5 && values[i + 2] !== undefined) { attr[n === 38 ? "fg" : "bg"] = color(Math.min(255, values[i + 2])); i += 2; }
        else if ((n === 38 || n === 48) && values[i + 1] === 2 && values.length > i + 4) { attr[n === 38 ? "fg" : "bg"] = `rgb(${values.slice(i + 2, i + 5).map((v) => Math.min(255, v)).join(",")})`; i += 4; }
      }
      this.attr = attr;
    }
    normalizeGrid() {
      for (const row of [...this.history, ...this.grid]) {
        row.length = Math.min(this.cols, row.length);
        while (row.length < this.cols) row.push(this.blank());
        if (row[this.cols - 1].width === 2) row[this.cols - 1] = this.blank();
        row.dirty = true;
      }
      while (this.grid.length < this.rows) this.grid.push(this.newRow());
      if (this.grid.length > this.rows) {
        const remove = Math.min(this.grid.length - this.rows, Math.max(0, this.y - this.rows + 1));
        if (remove) { const lines = this.grid.splice(0, remove); if (!this.main) this.history.push(...lines); this.y -= remove; }
        this.grid.length = this.rows;
      }
      this.history = this.history.slice(-2000);
      this.x = Math.min(this.x, this.cols - 1); this.y = Math.min(this.y, this.rows - 1);
    }
    fit() {
      const style = getComputedStyle(this.screen), viewportStyle = getComputedStyle(this.viewport);
      const canvas = document.createElement("canvas"), context = canvas.getContext("2d");
      context.font = style.fontSize + " " + style.fontFamily;
      this.cellWidth = context.measureText("M").width;
      this.lineHeight = parseFloat(style.lineHeight);
      const width = this.viewport.clientWidth - parseFloat(viewportStyle.paddingLeft) - parseFloat(viewportStyle.paddingRight);
      const height = this.viewport.clientHeight - parseFloat(viewportStyle.paddingTop) - parseFloat(viewportStyle.paddingBottom);
      const cols = Math.max(20, Math.min(1000, Math.floor(width / this.cellWidth)));
      const rows = Math.max(5, Math.min(500, Math.floor(height / this.lineHeight)));
      if (cols !== this.cols || rows !== this.rows) {
        this.cols = cols; this.rows = rows; this.top = 0; this.bottom = rows - 1; this.wrapPending = false;
        this.normalizeGrid();
        if (this.options.onResize) this.options.onResize(cols, rows);
      }
      this.screen.style.width = (cols * this.cellWidth) + "px";
      this.schedule();
    }
    schedule() {
      if (this.frame) return;
      this.frame = requestAnimationFrame(() => { this.frame = null; this.render(); });
    }
    renderRow(row) {
      if (!row.element) { row.element = document.createElement("div"); row.element.className = "terminal-row"; }
      if (!row.dirty) return row.element;
      const fragment = document.createDocumentFragment();
      let span = null, previous = null;
      for (const cell of row) {
        if (!cell.width) continue;
        if (cell.attr !== previous || cell.width === 2 || (span && span.dataset.wide)) {
          span = document.createElement("span"); const attr = cell.attr;
          span.style.color = attr.inverse ? attr.bg : attr.fg;
          span.style.backgroundColor = attr.inverse ? attr.fg : attr.bg;
          if (attr.bold) span.style.fontWeight = "bold";
          if (attr.dim) span.style.opacity = ".6";
          if (attr.italic) span.style.fontStyle = "italic";
          if (attr.under) span.style.textDecoration = "underline";
          if (cell.width === 2) { span.style.display = "inline-block"; span.style.width = (this.cellWidth * 2) + "px"; span.dataset.wide = "1"; }
          fragment.appendChild(span); previous = attr;
        }
        span.appendChild(document.createTextNode(cell.ch));
      }
      row.element.replaceChildren(fragment); row.dirty = false;
      return row.element;
    }
    render() {
      const bottom = this.viewport.scrollTop + this.viewport.clientHeight >= this.viewport.scrollHeight - this.lineHeight * 2;
      const rows = [...this.history, ...this.grid];
      const nodes = rows.map((row) => this.renderRow(row)); nodes.push(this.cursor);
      for (let i = 0; i < nodes.length; i++) if (this.screen.children[i] !== nodes[i]) this.screen.insertBefore(nodes[i], this.screen.children[i] || null);
      while (this.screen.children.length > nodes.length) this.screen.lastElementChild.remove();
      this.cursor.style.left = (this.x * this.cellWidth) + "px";
      this.cursor.style.top = ((this.history.length + this.y) * this.lineHeight) + "px";
      this.cursor.style.width = this.cellWidth + "px";
      this.cursor.hidden = !this.cursorVisible;
      this.input.style.top = Math.max(16, Math.min(this.viewport.scrollTop + this.viewport.clientHeight - 30, (this.history.length + this.y) * this.lineHeight + 16)) + "px";
      if (bottom) this.viewport.scrollTop = this.viewport.scrollHeight;
    }
    send(data) { if (this.options.onInput) this.options.onInput(data); }
    focus() { this.input.focus({ preventScroll: true }); }
    bindInput() {
      this.viewport.addEventListener("pointerup", () => { if (!String(getSelection())) this.focus(); });
      this.viewport.addEventListener("focus", () => this.focus());
      this.input.addEventListener("input", (event) => {
        if (event.isComposing || this.composing) return;
        if (this.input.value) this.send(this.input.value);
        this.input.value = "";
      });
      this.input.addEventListener("compositionstart", () => { this.composing = true; });
      this.input.addEventListener("compositionend", () => { this.composing = false; if (this.input.value) this.send(this.input.value); this.input.value = ""; });
      this.input.addEventListener("paste", (event) => {
        event.preventDefault();
        const text = event.clipboardData.getData("text/plain").replace(/\r\n/g, "\n");
        this.send(this.bracketedPaste ? "\x1b[200~" + text + "\x1b[201~" : text);
      });
      this.input.addEventListener("keydown", (event) => {
        if (event.isComposing || this.composing || event.key === "Process" || event.metaKey || event.getModifierState("AltGraph")) return;
        const key = event.key;
        if (event.ctrlKey && ["v", "V"].includes(key)) return;
        if (event.ctrlKey && event.shiftKey && ["c", "C"].includes(key)) return;
        let value = null;
        if (event.ctrlKey && key.length === 1) {
          const code = key.toUpperCase().charCodeAt(0);
          if (code >= 64 && code <= 95) value = String.fromCharCode(code & 31);
          else if (key === " ") value = "\x00";
          else if (key === "?") value = "\x7f";
        }
        const modifier = 1 + (event.shiftKey ? 1 : 0) + (event.altKey ? 2 : 0) + (event.ctrlKey ? 4 : 0);
        const arrows = { ArrowUp: "A", ArrowDown: "B", ArrowRight: "C", ArrowLeft: "D", Home: "H", End: "F" };
        if (arrows[key]) value = modifier > 1 ? `\x1b[1;${modifier}${arrows[key]}` : (this.appCursor ? "\x1bO" : "\x1b[") + arrows[key];
        else if (key === "Enter") value = "\r";
        else if (key === "Backspace") value = event.altKey ? "\x1b\x7f" : "\x7f";
        else if (key === "Tab") value = event.shiftKey ? "\x1b[Z" : "\t";
        else if (key === "Escape") value = "\x1b";
        else if (["Insert", "Delete", "PageUp", "PageDown"].includes(key)) {
          const codes = { Insert: 2, Delete: 3, PageUp: 5, PageDown: 6 };
          value = `\x1b[${codes[key]}${modifier > 1 ? ";" + modifier : ""}~`;
        } else if (/^F([1-9]|1[0-2])$/.test(key)) {
          const n = Number(key.slice(1));
          if (n <= 4) value = modifier > 1 ? `\x1b[1;${modifier}${"PQRS"[n - 1]}` : "\x1bO" + "PQRS"[n - 1];
          else value = `\x1b[${[15, 17, 18, 19, 20, 21, 23, 24][n - 5]}${modifier > 1 ? ";" + modifier : ""}~`;
        } else if (event.altKey && key.length === 1 && !event.ctrlKey) value = "\x1b" + key;
        if (value !== null) { event.preventDefault(); this.send(value); }
      });
    }
  }
  root.WebSSH.Terminal = Terminal;
})(globalThis);
