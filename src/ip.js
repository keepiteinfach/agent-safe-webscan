import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

function ipv4ToInt(ip) {
  return ip.split(".").reduce((n, part) => (n << 8) + Number(part), 0) >>> 0;
}

function inCidr4(ip, base, bits) {
  const shift = 32 - bits;
  return (ipv4ToInt(ip) >>> shift) === (ipv4ToInt(base) >>> shift);
}

export function isPrivateIp(ip) {
  if (!ip) return true;
  if (isIP(ip) === 4) {
    const blocked = [
      ["0.0.0.0", 8],
      ["10.0.0.0", 8],
      ["100.64.0.0", 10],
      ["127.0.0.0", 8],
      ["169.254.0.0", 16],
      ["172.16.0.0", 12],
      ["192.0.0.0", 24],
      ["192.0.2.0", 24],
      ["192.88.99.0", 24],
      ["192.168.0.0", 16],
      ["198.18.0.0", 15],
      ["198.51.100.0", 24],
      ["203.0.113.0", 24],
      ["224.0.0.0", 4],
      ["240.0.0.0", 4]
    ];
    return blocked.some(([base, bits]) => inCidr4(ip, base, bits));
  }
  if (isIP(ip) === 6) {
    const v = ip.toLowerCase();
    if (v === "::" || v === "::1") return true;
    if (v.startsWith("fc") || v.startsWith("fd")) return true; // fc00::/7 ULA
    if (/^fe[89ab]/.test(v)) return true; // fe80::/10 link-local
    if (v.startsWith("ff")) return true; // multicast
    if (v.startsWith("2001:db8:")) return true; // documentation
    if (v.startsWith("::ffff:")) {
      const mapped = v.slice(7);
      return isIP(mapped) === 4 ? isPrivateIp(mapped) : true;
    }
    return false;
  }
  return true;
}

export async function resolvePublicHostname(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new Error(`Refusing local/private hostname: ${hostname}`);
  }
  if (isIP(host)) {
    if (isPrivateIp(host)) throw new Error(`Refusing private/reserved IP: ${host}`);
    return [{ address: host, family: isIP(host) }];
  }
  const answers = await lookup(host, { all: true, verbatim: true });
  if (!answers.length) throw new Error(`DNS returned no addresses for ${hostname}`);
  for (const answer of answers) {
    if (isPrivateIp(answer.address)) {
      throw new Error(`Refusing hostname that resolves to private/reserved IP: ${hostname}`);
    }
  }
  return answers.map((a) => ({ address: a.address, family: a.family }));
}

export async function assertPublicHostname(hostname) {
  return (await resolvePublicHostname(hostname)).map((a) => a.address);
}
