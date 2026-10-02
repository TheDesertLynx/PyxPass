//
// uri.mjs — dash-key: / dash-st: URI framing, byte-for-byte with the dash
// wallets' DashConnectUri.kt (iOS DashConnectUri.swift) implementation.
//
// Request (dash-key:):
//   payload = 0x01 || appEphemeralPub(33) || contractId(32) || labelLen(1, <=64) || label
//   URI     = "dash-key:" || base58(payload) || "?n=<m|t|d>&v=1"
//
// State transition (dash-st:):
//   URI     = "dash-st:" || base58(transitionBytes) || "?n=<m|t|d>&v=1"
//

import { base58Decode, base58Encode } from './base58.mjs';

export const KEY_EXCHANGE_VERSION = 1;
export const STATE_TRANSITION_VERSION = 1;

export const NETWORK_IDS = { mainnet: 'm', testnet: 't', devnet: 'd' };

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Serialize a key-exchange request into its raw bytes (SERIALIZED_REQUEST_HEX). */
export function serializeKeyExchangeRequest(request) {
  if (request.appEphemeralPubKey.length !== 33) {
    throw new Error(`Invalid ephemeral public key length: expected 33, got ${request.appEphemeralPubKey.length}`);
  }
  if (request.contractId.length !== 32) {
    throw new Error(`Invalid contract ID length: expected 32, got ${request.contractId.length}`);
  }
  const labelBytes = request.label ? encoder.encode(request.label) : new Uint8Array(0);
  if (labelBytes.length > 64) {
    throw new Error(`Label too long: max 64 bytes, got ${labelBytes.length}`);
  }
  const buffer = new Uint8Array(1 + 33 + 32 + 1 + labelBytes.length);
  let offset = 0;
  buffer[offset++] = KEY_EXCHANGE_VERSION;
  buffer.set(request.appEphemeralPubKey, offset);
  offset += 33;
  buffer.set(request.contractId, offset);
  offset += 32;
  buffer[offset++] = labelBytes.length;
  if (labelBytes.length > 0) buffer.set(labelBytes, offset);
  return buffer;
}

/** Build a dash-key: URI. */
export function buildKeyExchangeUri(request, network = 'testnet') {
  const requestBytes = serializeKeyExchangeRequest(request);
  const requestData = base58Encode(requestBytes);
  return `dash-key:${requestData}?n=${NETWORK_IDS[network]}&v=${KEY_EXCHANGE_VERSION}`;
}

/** Parse a dash-key: URI. Returns null if invalid. */
export function parseKeyExchangeUri(uri) {
  try {
    if (!uri.startsWith('dash-key:')) return null;
    const withoutScheme = uri.slice('dash-key:'.length);
    const queryStart = withoutScheme.indexOf('?');
    if (queryStart === -1) return null;
    const requestData = withoutScheme.slice(0, queryStart);
    const params = new URLSearchParams(withoutScheme.slice(queryStart + 1));
    const networkId = params.get('n');
    const versionStr = params.get('v');
    if (!networkId || !versionStr) return null;
    const version = Number.parseInt(versionStr, 10);
    if (version !== KEY_EXCHANGE_VERSION) return null;
    const network = parseNetworkId(networkId);
    if (!network) return null;
    const requestBytes = base58Decode(requestData);
    if (requestBytes.length < 67) return null;

    let offset = 0;
    const byteVersion = requestBytes[offset++];
    if (byteVersion !== KEY_EXCHANGE_VERSION) return null;
    const appEphemeralPubKey = requestBytes.slice(offset, offset + 33);
    offset += 33;
    const contractId = requestBytes.slice(offset, offset + 32);
    offset += 32;
    const labelLength = requestBytes[offset++];
    if (labelLength > 64 || offset + labelLength > requestBytes.length) return null;

    let label;
    if (labelLength > 0) label = decoder.decode(requestBytes.slice(offset, offset + labelLength));
    return { request: { appEphemeralPubKey, contractId, label }, network, version };
  } catch {
    return null;
  }
}

/** Build a dash-st: URI. */
export function buildStateTransitionUri(transitionBytes, network = 'testnet') {
  return `dash-st:${base58Encode(transitionBytes)}?n=${NETWORK_IDS[network]}&v=${STATE_TRANSITION_VERSION}`;
}

/** Parse a dash-st: URI. Returns null if invalid. */
export function parseStateTransitionUri(uri) {
  try {
    if (!uri.startsWith('dash-st:')) return null;
    const withoutScheme = uri.slice('dash-st:'.length);
    const queryStart = withoutScheme.indexOf('?');
    if (queryStart === -1) return null;
    const transitionData = withoutScheme.slice(0, queryStart);
    const params = new URLSearchParams(withoutScheme.slice(queryStart + 1));
    const networkId = params.get('n');
    const versionStr = params.get('v');
    if (!networkId || !versionStr) return null;
    const version = Number.parseInt(versionStr, 10);
    if (version !== STATE_TRANSITION_VERSION) return null;
    const network = parseNetworkId(networkId);
    if (!network) return null;
    return { transitionBytes: base58Decode(transitionData), network, version };
  } catch {
    return null;
  }
}

/** Distinguish a key URI from a state-transition URI. */
export function isKeyUri(uri) {
  return uri.startsWith('dash-key:');
}
export function isStateTransitionUri(uri) {
  return uri.startsWith('dash-st:');
}

function parseNetworkId(networkId) {
  switch (networkId) {
    case 'm': return 'mainnet';
    case 't': return 'testnet';
    case 'd': return 'devnet';
    default: return null;
  }
}
