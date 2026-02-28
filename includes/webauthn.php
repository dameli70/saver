<?php

require_once __DIR__ . '/helpers.php';

function webauthnRpId(): string {
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    // Strip port
    $host = preg_replace('/:\\d+$/', '', $host);
    return strtolower($host);
}

function webauthnOrigin(): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return $scheme . '://' . $host;
}

function webauthnNewChallenge(): string {
    return b64urlEncode(random_bytes(32));
}

// ── Minimal CBOR decoder (sufficient for WebAuthn attestation) ──
function cborDecodeOne(string $data, int &$ofs): mixed {
    if ($ofs >= strlen($data)) throw new RuntimeException('CBOR: truncated');

    $b = ord($data[$ofs++]);
    $major = $b >> 5;
    $ai = $b & 31;

    $readLen = function(int $ai) use ($data, &$ofs): int {
        if ($ai < 24) return $ai;
        if ($ai === 24) {
            if ($ofs + 1 > strlen($data)) throw new RuntimeException('CBOR: truncated');
            return ord($data[$ofs++]);
        }
        if ($ai === 25) {
            if ($ofs + 2 > strlen($data)) throw new RuntimeException('CBOR: truncated');
            $v = unpack('n', substr($data, $ofs, 2))[1];
            $ofs += 2;
            return $v;
        }
        if ($ai === 26) {
            if ($ofs + 4 > strlen($data)) throw new RuntimeException('CBOR: truncated');
            $v = unpack('N', substr($data, $ofs, 4))[1];
            $ofs += 4;
            return $v;
        }
        throw new RuntimeException('CBOR: unsupported length');
    };

    if ($major === 0) {
        return $readLen($ai);
    }
    if ($major === 1) {
        $n = $readLen($ai);
        return -1 - $n;
    }
    if ($major === 2) {
        $len = $readLen($ai);
        if ($ofs + $len > strlen($data)) throw new RuntimeException('CBOR: truncated');
        $v = substr($data, $ofs, $len);
        $ofs += $len;
        return $v;
    }
    if ($major === 3) {
        $len = $readLen($ai);
        if ($ofs + $len > strlen($data)) throw new RuntimeException('CBOR: truncated');
        $v = substr($data, $ofs, $len);
        $ofs += $len;
        return $v;
    }
    if ($major === 4) {
        $len = $readLen($ai);
        $arr = [];
        for ($i = 0; $i < $len; $i++) {
            $arr[] = cborDecodeOne($data, $ofs);
        }
        return $arr;
    }
    if ($major === 5) {
        $len = $readLen($ai);
        $map = [];
        for ($i = 0; $i < $len; $i++) {
            $k = cborDecodeOne($data, $ofs);
            $v = cborDecodeOne($data, $ofs);
            if (is_string($k) || is_int($k)) {
                $map[$k] = $v;
            } else {
                $map[json_encode($k)] = $v;
            }
        }
        return $map;
    }
    if ($major === 7) {
        if ($ai === 20) return false;
        if ($ai === 21) return true;
        if ($ai === 22) return null;
        throw new RuntimeException('CBOR: unsupported simple');
    }

    throw new RuntimeException('CBOR: unsupported type');
}

function cborDecode(string $data): mixed {
    $ofs = 0;
    $v = cborDecodeOne($data, $ofs);
    return $v;
}

function asn1Len(int $len): string {
    if ($len < 128) return chr($len);
    $bytes = '';
    while ($len > 0) {
        $bytes = chr($len & 255) . $bytes;
        $len >>= 8;
    }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function asn1Oid(string $oid): string {
    $parts = array_map('intval', explode('.', $oid));
    $first = (40 * $parts[0]) + $parts[1];
    $out = chr($first);

    for ($i = 2; $i < count($parts); $i++) {
        $n = $parts[$i];
        $enc = '';
        do {
            $byte = $n & 0x7f;
            $enc = chr($byte) . $enc;
            $n >>= 7;
        } while ($n > 0);
        $encBytes = str_split($enc);
        for ($j = 0; $j < count($encBytes) - 1; $j++) {
            $encBytes[$j] = chr(ord($encBytes[$j]) | 0x80);
        }
        $out .= implode('', $encBytes);
    }

    return "\x06" . asn1Len(strlen($out)) . $out;
}

function coseEc2ToPem(array $cose): string {
    // Only supports ES256 / P-256
    $kty = $cose[1] ?? null;
    $alg = $cose[3] ?? null;
    $crv = $cose[-1] ?? null;
    $x   = $cose[-2] ?? null;
    $y   = $cose[-3] ?? null;

    if ($kty !== 2 || $alg !== -7 || $crv !== 1 || !is_string($x) || !is_string($y)) {
        throw new RuntimeException('Unsupported passkey type (only ES256/P-256 supported)');
    }

    $point = "\x04" . $x . $y;

    $algo = "\x30" . asn1Len(strlen(asn1Oid('1.2.840.10045.2.1') . asn1Oid('1.2.840.10045.3.1.7'))) . asn1Oid('1.2.840.10045.2.1') . asn1Oid('1.2.840.10045.3.1.7');
    $bitString = "\x03" . asn1Len(strlen($point) + 1) . "\x00" . $point;
    $spki = "\x30" . asn1Len(strlen($algo . $bitString)) . $algo . $bitString;

    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    return $pem;
}

function parseAuthData(string $authData): array {
    if (strlen($authData) < 37) throw new RuntimeException('authenticatorData too short');

    $rpIdHash = substr($authData, 0, 32);
    $flags = ord($authData[32]);
    $signCount = unpack('N', substr($authData, 33, 4))[1];

    $rest = substr($authData, 37);

    return [
        'rpIdHash' => $rpIdHash,
        'flags' => $flags,
        'signCount' => $signCount,
        'rest' => $rest,
    ];
}

function parseAttestedCredentialData(string $rest): array {
    if (strlen($rest) < 18) throw new RuntimeException('attestedCredentialData too short');

    $aaguid = substr($rest, 0, 16);
    $credLen = unpack('n', substr($rest, 16, 2))[1];
    $pos = 18;
    if (strlen($rest) < $pos + $credLen) throw new RuntimeException('credentialId truncated');

    $credId = substr($rest, $pos, $credLen);
    $pos += $credLen;

    $coseBytes = substr($rest, $pos);
    $cose = cborDecode($coseBytes);

    if (!is_array($cose)) throw new RuntimeException('Invalid COSE key');

    return [
        'aaguid' => $aaguid,
        'credentialId' => $credId,
        'cose' => $cose,
    ];
}

function webauthnValidateClientData(string $clientDataJsonB64u, string $expectedChallengeB64u, string $expectedType): array {
    $raw = b64urlDecode($clientDataJsonB64u);
    if ($raw === '') throw new RuntimeException('Invalid clientDataJSON');

    $data = json_decode($raw, true);
    if (!is_array($data)) throw new RuntimeException('Invalid clientDataJSON');

    if (($data['type'] ?? '') !== $expectedType) throw new RuntimeException('Invalid WebAuthn type');
    if (($data['challenge'] ?? '') !== $expectedChallengeB64u) throw new RuntimeException('Invalid challenge');
    if (($data['origin'] ?? '') !== webauthnOrigin()) throw new RuntimeException('Invalid origin');

    return [$raw, $data];
}

function webauthnVerifyRegistration(array $payload, string $expectedChallengeB64u): array {
    [$clientDataRaw, ] = webauthnValidateClientData((string)$payload['clientDataJSON'], $expectedChallengeB64u, 'webauthn.create');

    $attRaw = b64urlDecode((string)$payload['attestationObject']);
    if ($attRaw === '') throw new RuntimeException('Invalid attestationObject');

    $att = cborDecode($attRaw);
    if (!is_array($att) || empty($att['authData']) || !is_string($att['authData'])) {
        throw new RuntimeException('Invalid attestation');
    }

    $ad = parseAuthData($att['authData']);

    $rpExpected = hash('sha256', webauthnRpId(), true);
    if (!hash_equals($rpExpected, $ad['rpIdHash'])) throw new RuntimeException('rpIdHash mismatch');

    $flags = $ad['flags'];
    if (!(($flags & 0x01) === 0x01)) throw new RuntimeException('User presence required');
    if (!(($flags & 0x04) === 0x04)) throw new RuntimeException('User verification required');
    if (!(($flags & 0x40) === 0x40)) throw new RuntimeException('Missing attested credential data');

    $acd = parseAttestedCredentialData($ad['rest']);
    $pem = coseEc2ToPem($acd['cose']);

    return [
        'credentialId' => $acd['credentialId'],
        'publicKeyPem' => $pem,
        'signCount' => (int)$ad['signCount'],
        'clientDataHash' => hash('sha256', $clientDataRaw, true),
    ];
}

function webauthnVerifyAssertion(array $payload, string $expectedChallengeB64u, string $publicKeyPem, int $storedSignCount): array {
    [$clientDataRaw, ] = webauthnValidateClientData((string)$payload['clientDataJSON'], $expectedChallengeB64u, 'webauthn.get');

    $authData = b64urlDecode((string)$payload['authenticatorData']);
    $sig = b64urlDecode((string)$payload['signature']);
    if ($authData === '' || $sig === '') throw new RuntimeException('Invalid assertion');

    $ad = parseAuthData($authData);

    $rpExpected = hash('sha256', webauthnRpId(), true);
    if (!hash_equals($rpExpected, $ad['rpIdHash'])) throw new RuntimeException('rpIdHash mismatch');

    $flags = $ad['flags'];
    if (!(($flags & 0x01) === 0x01)) throw new RuntimeException('User presence required');
    if (!(($flags & 0x04) === 0x04)) throw new RuntimeException('User verification required');

    $clientHash = hash('sha256', $clientDataRaw, true);
    $msg = $authData . $clientHash;

    $ok = openssl_verify($msg, $sig, $publicKeyPem, OPENSSL_ALGO_SHA256);
    if ($ok !== 1) throw new RuntimeException('Bad signature');

    $newSignCount = (int)$ad['signCount'];
    // If both are non-zero, enforce monotonic counter.
    if ($storedSignCount > 0 && $newSignCount > 0 && $newSignCount <= $storedSignCount) {
        throw new RuntimeException('Sign counter did not increase');
    }

    return [
        'signCount' => $newSignCount,
    ];
}
