import { DurableObject } from 'cloudflare:workers';
import crypto from 'node:crypto';

const settings = {
  machineId: new Uint8Array(),
  pid: 0,
  counter: 0,
};
const encodedLen = 20;
const rawLen = 12;
const errInvalidID = 'xid: invalid ID';
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const encoding = textEncoder.encode('0123456789abcdefghijklmnopqrstuv');
const dec = new Uint8Array(256).fill(0xff);
encoding.forEach((v, i) => (dec[v] = i));

export class Xid extends DurableObject {
  machineId;
  pid;
  counter;

  constructor(ctx, env) {
    super(ctx, env);

    const start = this.getRandom3Bytes();
    this.machineId = this.getRandom3Bytes();
    this.pid = this.getPid();
    this.counter = (start[0] << 16) | (start[1] << 8) | start[2];
  }

  createXid(id) {
    const xid = new Uint8Array(rawLen);

    if (id == null) {
      const view = new DataView(xid.buffer);
      const timestamp = Math.floor(Date.now() / 1000);
      view.setUint32(0, timestamp);

      xid[4] = settings.machineId[0];
      xid[5] = settings.machineId[1];
      xid[6] = settings.machineId[2];
      xid[7] = settings.pid >> 8;
      xid[8] = settings.pid & 0x00ff;

      settings.counter += 1;
      if (settings.counter > 0xffffff) {
        settings.counter = 0;
      }

      xid[9] = settings.counter >> 16;
      xid[10] = settings.counter & (0x00ffff >> 8);
      xid[11] = settings.counter & 0x0000ff;
    } else if (!(id instanceof Uint8Array) || id.length !== rawLen) {
      throw new Error(errInvalidID);
    } else {
      xid.set(id);
    }

    return xid;
  }

  defaultXid() {
    return new Uint8Array(rawLen).fill(0);
  }

  fromValue(v) {
    if (v instanceof Uint8Array && v.length === rawLen) {
      return this.createXid(v);
    }

    if (typeof v === 'string') {
      return this.parseXid(v);
    }

    if (v instanceof ArrayBuffer && v.byteLength === rawLen) {
      return this.createXid(new Uint8Array(v));
    }

    if (
      Array.isArray(v) &&
      v.length === rawLen &&
      v.every((byte) => typeof byte === 'number' && byte >= 0 && byte <= 255)
    ) {
      return this.createXid(new Uint8Array(v));
    }

    throw new Error(errInvalidID);
  }

  parseXid(id) {
    if (id.length !== encodedLen) {
      throw new Error(errInvalidID);
    }

    const xid = new Uint8Array(rawLen);
    this.decodeXid(xid, id);
    return xid;
  }

  decodeXid(xid, str) {
    const src = textEncoder.encode(str);
    if (src.length !== encodedLen) {
      throw new Error(errInvalidID);
    }

    for (const c of src) {
      if (dec[c] == 0xff) {
        throw new Error(errInvalidID);
      }
    }

    xid[11] = (dec[src[17]] << 6) | (dec[src[18]] << 1) | (dec[src[19]] >> 4);
    if (encoding[(xid[11] << 4) & 0x1f] != src[19]) {
      throw new Error(errInvalidID);
    }

    xid[10] = (dec[src[16]] << 3) | (dec[src[17]] >> 2);
    xid[9] = (dec[src[14]] << 5) | dec[src[15]];
    xid[8] = (dec[src[12]] << 7) | (dec[src[13]] << 2) | (dec[src[14]] >> 3);
    xid[7] = (dec[src[11]] << 4) | (dec[src[12]] >> 1);
    xid[6] = (dec[src[9]] << 6) | (dec[src[10]] << 1) | (dec[src[11]] >> 4);
    xid[5] = (dec[src[8]] << 3) | (dec[src[9]] >> 2);
    xid[4] = (dec[src[6]] << 5) | dec[src[7]];
    xid[3] = (dec[src[4]] << 7) | (dec[src[5]] << 2) | (dec[src[6]] >> 3);
    xid[2] = (dec[src[3]] << 4) | (dec[src[4]] >> 1);
    xid[1] = (dec[src[1]] << 6) | (dec[src[2]] << 1) | (dec[src[3]] >> 4);
    xid[0] = (dec[src[0]] << 3) | (dec[src[1]] >> 2);
  }

  encodeXid(xid) {
    const dst = new Uint8Array(encodedLen);

    dst[19] = encoding[(xid[11] << 4) & 0x1f];
    dst[18] = encoding[(xid[11] >> 1) & 0x1f];
    dst[17] = encoding[(xid[11] >> 6) | ((xid[10] << 2) & 0x1f)];
    dst[16] = encoding[xid[10] >> 3];
    dst[15] = encoding[xid[9] & 0x1f];
    dst[14] = encoding[(xid[9] >> 5) | ((xid[8] << 3) & 0x1f)];
    dst[13] = encoding[(xid[8] >> 2) & 0x1f];
    dst[12] = encoding[(xid[8] >> 7) | ((xid[7] << 1) & 0x1f)];
    dst[11] = encoding[(xid[7] >> 4) | ((xid[6] << 4) & 0x1f)];
    dst[10] = encoding[(xid[6] >> 1) & 0x1f];
    dst[9] = encoding[(xid[6] >> 6) | ((xid[5] << 2) & 0x1f)];
    dst[8] = encoding[xid[5] >> 3];
    dst[7] = encoding[xid[4] & 0x1f];
    dst[6] = encoding[(xid[4] >> 5) | ((xid[3] << 3) & 0x1f)];
    dst[5] = encoding[(xid[3] >> 2) & 0x1f];
    dst[4] = encoding[(xid[3] >> 7) | ((xid[2] << 1) & 0x1f)];
    dst[3] = encoding[(xid[2] >> 4) | ((xid[1] << 4) & 0x1f)];
    dst[2] = encoding[(xid[1] >> 1) & 0x1f];
    dst[1] = encoding[(xid[1] >> 6) | ((xid[0] << 2) & 0x1f)];
    dst[0] = encoding[xid[0] >> 3];

    return textDecoder.decode(dst);
  }

  getXidTimestamp(xid) {
    return new DataView(xid.buffer).getUint32(0);
  }

  getXidMachine(xid) {
    return new Uint8Array(xid.buffer, 4, 3);
  }

  getXidPid(xid) {
    return (xid[7] << 8) | xid[8];
  }

  getXidCounter(xid) {
    return (xid[9] << 16) | (xid[10] << 8) | xid[11];
  }

  isXidZero(xid) {
    return xid.every((byte) => byte === 0);
  }

  // xidToString(xid) {
  //   return this.encodeXid(xid);
  // }

  // xidToBytes(xid) {
  //   return new Uint8Array(xid.buffer, 0, rawLen);
  // }

  // xidToJSON(xid) {
  //   return this.encodeXid(xid);
  // }

  equalsXid(xid1, xid2) {
    for (let i = 0; i < rawLen; i++) {
      if (xid1[i] !== xid2[i]) {
        return false;
      }
    }
    return true;
  }

  getRandom3Bytes() {
    return crypto.getRandomValues(new Uint8Array(3));
  }

  getPid() {
    const buf = crypto.getRandomValues(new Uint8Array(2));
    return (buf[0] << 8) | buf[1];
  }
}
