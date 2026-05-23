const http = require("http");
const https = require("https");
const redis = require("redis");

const enabled = process.env.VITALSERVER_AUDIT_ENABLED !== "0";
const redisListKey = process.env.VITALSERVER_AUDIT_REDIS_LIST || "vitalserver:audit_events";
const redisMaxLen = parseInt(process.env.VITALSERVER_AUDIT_REDIS_MAXLEN || "10000", 10);
const httpEndpoint = process.env.VITALSERVER_AUDIT_HTTP_URL || "";
const trustProxy = process.env.VITALSERVER_TRUST_PROXY === "1";
const client = redis.createClient(6379, "0.0.0.0");
const sensitiveKeyPattern = /(password|passwd|pw|token|secret|authorization|cookie|session|key)/i;

client.on("error", function(error) {
  console.log("audit redis error", error && error.message ? error.message : error);
});

function now() {
  const d = new Date();
  return {
    ts: d.toISOString(),
    ts_unix_ms: d.getTime()
  };
}

function normalizeIp(value) {
  if (!value || typeof value !== "string") return "";
  value = value.trim();
  if (value.indexOf(",") >= 0) value = value.split(",")[0].trim();
  if (value.indexOf("for=") >= 0) {
    const match = value.match(/for="?([^;,"]+)/i);
    if (match) value = match[1];
  }
  if (value.indexOf("::ffff:") === 0) value = value.slice(7);
  if (value[0] === "[" && value[value.length - 1] === "]") value = value.slice(1, -1);
  return value;
}

function getHeader(headers, name) {
  if (!headers) return "";
  return headers[name] || headers[name.toLowerCase()] || "";
}

function getVrClientIpInfo(handshake) {
  const headers = handshake && handshake.headers ? handshake.headers : {};
  const remoteAddress = normalizeIp(handshake && handshake.address ? handshake.address : "");
  const candidates = [
    ["x-forwarded-for", normalizeIp(getHeader(headers, "x-forwarded-for"))],
    ["x-real-ip", normalizeIp(getHeader(headers, "x-real-ip"))],
    ["forwarded", normalizeIp(getHeader(headers, "forwarded"))],
    ["x-client-ip", normalizeIp(getHeader(headers, "x-client-ip"))]
  ];

  if (trustProxy) {
    for (const candidate of candidates) {
      if (candidate[1]) {
        return {
          selected_ip: candidate[1],
          selected_source: candidate[0],
          remote_address: remoteAddress,
          trust_proxy: true
        };
      }
    }
  }

  return {
    selected_ip: remoteAddress,
    selected_source: "remote-address",
    remote_address: remoteAddress,
    trust_proxy: trustProxy
  };
}

function mask(value, depth) {
  if (depth > 8) return "[depth-limit]";
  if (value === null || value === undefined) return value;
  if (Buffer.isBuffer(value)) return "[buffer:" + value.length + "]";
  if (Array.isArray(value)) return value.map(function(item) { return mask(item, depth + 1); });
  if (typeof value === "object") {
    const out = {};
    Object.keys(value).forEach(function(key) {
      out[key] = sensitiveKeyPattern.test(key) ? "[masked]" : mask(value[key], depth + 1);
    });
    return out;
  }
  if (typeof value === "string" && value.length > 2000) {
    return value.slice(0, 2000) + "...[truncated]";
  }
  return value;
}

function socketContext(socket) {
  const handshake = socket && socket.handshake ? socket.handshake : {};
  const request = socket && socket.request ? socket.request : {};
  const session = request.session || handshake.session || {};
  const user = session.userInfo
    ? {
        id: session.userInfo.id,
        name: session.userInfo.name,
        admin_yn: session.userInfo.admin_yn
      }
    : null;

  return {
    socket_id: socket && socket.id ? socket.id : null,
    user: user,
    handshake_headers: mask(handshake.headers || {}, 0)
  };
}

function writeHttp(payload) {
  if (!httpEndpoint) return;
  try {
    const body = JSON.stringify(payload);
    const url = new URL(httpEndpoint);
    const transport = url.protocol === "https:" ? https : http;
    const req = transport.request(
      {
        method: "POST",
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body)
        },
        timeout: 1000
      },
      function(res) {
        res.resume();
      }
    );
    req.on("error", function(error) {
      console.log("audit http error", error && error.message ? error.message : error);
    });
    req.on("timeout", function() {
      req.abort();
    });
    req.write(body);
    req.end();
  } catch (error) {
    console.log("audit http error", error && error.message ? error.message : error);
  }
}

function record(eventType, fields) {
  if (!enabled) return;
  try {
    const payload = Object.assign(
      {
        schema_version: 1,
        source: "vitalserver",
        event_type: eventType
      },
      now(),
      mask(fields || {}, 0)
    );
    const line = JSON.stringify(payload);
    client.rpush(redisListKey, line, function(error) {
      if (error) {
        console.log("audit redis write error", error.message);
        return;
      }
      if (Number.isFinite(redisMaxLen) && redisMaxLen > 0) {
        client.ltrim(redisListKey, -redisMaxLen, -1);
      }
    });
    writeHttp(payload);
  } catch (error) {
    console.log("audit record error", error && error.message ? error.message : error);
  }
}

module.exports = {
  getVrClientIpInfo: getVrClientIpInfo,
  mask: function(value) { return mask(value, 0); },
  record: record,
  socketContext: socketContext
};
