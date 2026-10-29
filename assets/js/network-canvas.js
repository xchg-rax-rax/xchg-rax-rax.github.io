(function () {
  "use strict";

  var NODE_COUNT = 70;
  var ROTATION_SPEED = 1;
  var SHOW_IPS = true;

  function NetworkGraph(canvas) {
    this.canvas = canvas;
    this.mouse = { x: 0, y: 0, tx: 0, ty: 0 };
    this.onMove = this.onMove.bind(this);
    this.tick = this.tick.bind(this);
  }

  NetworkGraph.prototype.start = function () {
    var self = this;
    addEventListener("mousemove", this.onMove);
    this.ro = new ResizeObserver(function () {
      self.resize();
    });
    this.ro.observe(this.canvas);
    this.resize();
    this.build();
    this.t0 = performance.now();
    this.raf = requestAnimationFrame(this.tick);
  };

  NetworkGraph.prototype.stop = function () {
    cancelAnimationFrame(this.raf);
    removeEventListener("mousemove", this.onMove);
    if (this.ro) this.ro.disconnect();
  };

  NetworkGraph.prototype.onMove = function (e) {
    this.mouse.tx = e.clientX / innerWidth - 0.5;
    this.mouse.ty = e.clientY / innerHeight - 0.5;
  };

  NetworkGraph.prototype.resize = function () {
    var c = this.canvas;
    if (!c) return;
    var dpr = Math.min(devicePixelRatio || 1, 2);
    this.w = c.clientWidth;
    this.h = c.clientHeight;
    c.width = this.w * dpr;
    c.height = this.h * dpr;
    this.ctx = c.getContext("2d");
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };

  NetworkGraph.prototype.ip = function () {
    var r = function (n) {
      return Math.floor(Math.random() * n);
    };
    var p = [
      function () { return "10." + r(255) + "." + r(255) + "." + (r(254) + 1); },
      function () { return "192.168." + r(255) + "." + (r(254) + 1); },
      function () { return "172." + (16 + r(16)) + "." + r(255) + "." + (r(254) + 1); },
      function () { return (r(223) + 1) + "." + r(255) + "." + r(255) + "." + (r(254) + 1); }
    ];
    return p[r(p.length)]();
  };

  NetworkGraph.prototype.build = function () {
    var n = (this.count = NODE_COUNT);
    this.nodes = [];
    for (var i = 0; i < n; i++) {
      var u = Math.random() * 2 - 1;
      var th = Math.random() * Math.PI * 2;
      var s = Math.sqrt(1 - u * u);
      var r = 0.55 + 0.45 * Math.sqrt(Math.random());
      this.nodes.push({
        bx: s * Math.cos(th) * r,
        by: u * r * 0.85,
        bz: s * Math.sin(th) * r,
        ph: Math.random() * 6.28,
        sp: 0.3 + Math.random() * 0.5,
        ip: this.ip(),
        label: Math.random() < 0.45,
        size: 1.4 + Math.random() * 1.8
      });
    }
    var set = new Set();
    this.edges = [];
    var nodes = this.nodes;
    nodes.forEach(function (a, i) {
      var d = nodes
        .map(function (b, j) {
          return [j, (a.bx - b.bx) * (a.bx - b.bx) + (a.by - b.by) * (a.by - b.by) + (a.bz - b.bz) * (a.bz - b.bz)];
        })
        .filter(function (x) {
          return x[0] !== i;
        })
        .sort(function (x, y) {
          return x[1] - y[1];
        })
        .slice(0, 3);
      d.forEach(function (pair) {
        var j = pair[0];
        var k = i < j ? i + "-" + j : j + "-" + i;
        if (!set.has(k)) {
          set.add(k);
          this.edges.push([Math.min(i, j), Math.max(i, j)]);
        }
      }, this);
    }, this);
    this.pulses = [];
    this.lastPulse = 0;
    this.target = Math.floor(Math.random() * n);
    this.targetAt = performance.now();
  };

  NetworkGraph.prototype.tick = function (now) {
    this.raf = requestAnimationFrame(this.tick);
    var ctx = this.ctx;
    if (!ctx || !this.w) return;
    if (NODE_COUNT !== this.count) this.build();

    var speed = ROTATION_SPEED;
    var showIps = SHOW_IPS;
    var t = (now - this.t0) / 1000;
    var w = this.w;
    var h = this.h;
    var m = this.mouse;
    m.x += (m.tx - m.x) * 0.04;
    m.y += (m.ty - m.y) * 0.04;
    var ay = t * 0.12 * speed + m.x * 0.8;
    var ax = -0.25 + Math.sin(t * 0.07) * 0.12 + m.y * 0.5;
    var cy = Math.cos(ay), sy = Math.sin(ay), cx = Math.cos(ax), sx = Math.sin(ax);
    var wide = w > 900;
    var ox = wide ? w * 0.66 : w * 0.5;
    var oy = h * 0.52;
    var R = wide ? Math.min(w * 0.36, h * 0.62) : Math.min(w, h) * 0.55;
    var D = 2.6;

    ctx.clearRect(0, 0, w, h);

    var P = this.nodes.map(function (n) {
      var x = n.bx + Math.sin(t * n.sp + n.ph) * 0.04;
      var y = n.by + Math.cos(t * n.sp * 0.8 + n.ph) * 0.04;
      var z = n.bz + Math.sin(t * n.sp * 0.6 + n.ph * 2) * 0.04;
      var x1 = x * cy + z * sy;
      var z1 = -x * sy + z * cy;
      var y2 = y * cx - z1 * sx;
      var z2 = y * sx + z1 * cx;
      var f = D / (D + z2);
      return {
        x: ox + x1 * R * f,
        y: oy + y2 * R * f,
        z: z2,
        f: f,
        a: Math.max(0.08, Math.min(1, 0.55 - z2 * 0.5))
      };
    });

    ctx.lineWidth = 1;
    for (var e = 0; e < this.edges.length; e++) {
      var edge = this.edges[e];
      var a = P[edge[0]], b = P[edge[1]];
      var al = (a.a + b.a) * 0.5;
      ctx.strokeStyle = "rgba(255,42,61," + al * 0.38 + ")";
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }

    if (now - this.lastPulse > 120 / speed) {
      this.lastPulse = now;
      var pe = this.edges[Math.floor(Math.random() * this.edges.length)];
      var flip = Math.random() < 0.5;
      this.pulses.push({
        a: flip ? pe[1] : pe[0],
        b: flip ? pe[0] : pe[1],
        s: now,
        d: 900 + Math.random() * 900
      });
    }
    this.pulses = this.pulses.filter(function (p) {
      return now - p.s < p.d;
    });
    for (var pi = 0; pi < this.pulses.length; pi++) {
      var p = this.pulses[pi];
      var k = (now - p.s) / p.d;
      var A = P[p.a], B = P[p.b];
      var x = A.x + (B.x - A.x) * k;
      var y = A.y + (B.y - A.y) * k;
      var al2 = (A.a + B.a) * 0.5;
      ctx.fillStyle = "rgba(255,140,150," + al2 + ")";
      ctx.shadowColor = "#ff2a3d";
      ctx.shadowBlur = 10;
      ctx.beginPath();
      ctx.arc(x, y, 1.8, 0, 6.29);
      ctx.fill();
    }
    ctx.shadowBlur = 0;

    if (now - this.targetAt > 4000) {
      this.target = Math.floor(Math.random() * this.nodes.length);
      this.targetAt = now;
    }

    var order = P.map(function (p, i) {
      return i;
    }).sort(function (i, j) {
      return P[j].z - P[i].z;
    });

    ctx.font = '500 10px "JetBrains Mono", monospace';
    for (var oi = 0; oi < order.length; oi++) {
      var i = order[oi];
      var pt = P[i];
      var n = this.nodes[i];
      var r = n.size * pt.f;
      ctx.fillStyle = "rgba(10,10,12,1)";
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, r + 1.5, 0, 6.29);
      ctx.fill();
      ctx.fillStyle = "rgba(255," + (60 + pt.a * 60) + "," + (70 + pt.a * 50) + "," + pt.a + ")";
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, r, 0, 6.29);
      ctx.fill();

      if (i === this.target) {
        var k2 = ((now - this.targetAt) % 1600) / 1600;
        ctx.strokeStyle = "rgba(255,42,61," + (1 - k2) * 0.9 + ")";
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, r + 4 + k2 * 22, 0, 6.29);
        ctx.stroke();
        ctx.strokeStyle = "rgba(255,90,100,0.9)";
        var s = 9;
        ctx.beginPath();
        ctx.moveTo(pt.x - s, pt.y - s + 4);
        ctx.lineTo(pt.x - s, pt.y - s);
        ctx.lineTo(pt.x - s + 4, pt.y - s);
        ctx.moveTo(pt.x + s - 4, pt.y + s);
        ctx.lineTo(pt.x + s, pt.y + s);
        ctx.lineTo(pt.x + s, pt.y + s - 4);
        ctx.stroke();
      }

      if (showIps && (n.label || i === this.target) && pt.a > 0.3) {
        ctx.fillStyle = i === this.target ? "rgba(255,120,130,1)" : "rgba(220,205,207," + (pt.a - 0.3) * 0.9 + ")";
        ctx.fillText(n.ip, pt.x + r + 6, pt.y + 3);
      }
    }
  };

  function init() {
    var canvas = document.getElementById("network-canvas");
    if (!canvas) return;
    var graph = new NetworkGraph(canvas);
    graph.start();

    if (document.visibilityState !== undefined) {
      document.addEventListener("visibilitychange", function () {
        if (document.hidden) {
          graph.stop();
        } else {
          graph.start();
        }
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
