<?php

function smtpEncodeHeader(string $v): string {
    // RFC 2047 base64 encoding for non-ascii subjects/names
    if ($v === '' || preg_match('/^[\x20-\x7E]*$/', $v)) return $v;
    return '=?UTF-8?B?' . base64_encode($v) . '?=';
}

function smtpReadResponse($fp): string {
    $out = '';
    while (!feof($fp)) {
        $line = fgets($fp, 8192);
        if ($line === false) break;
        $out .= $line;
        // Lines are like: "250-..." until final "250 ..."
        if (strlen($line) >= 4 && $line[3] === ' ') break;
    }
    return $out;
}

function smtpSendCommand($fp, string $cmd, array $okCodes, ?string &$lastResp = null): bool {
    fwrite($fp, $cmd . "\r\n");
    $lastResp = smtpReadResponse($fp);
    $code = (int)substr($lastResp, 0, 3);
    return in_array($code, $okCodes, true);
}

function smtpSendMessage(string $to, string $subject, string $body, string $from): bool {
    if (!defined('SMTP_HOST') || SMTP_HOST === '') return false;

    $host = SMTP_HOST;
    $port = defined('SMTP_PORT') ? (int)SMTP_PORT : 587;
    $user = defined('SMTP_USER') ? SMTP_USER : '';
    $pass = defined('SMTP_PASS') ? SMTP_PASS : '';
    $secure = defined('SMTP_SECURE') ? SMTP_SECURE : 'tls';
    $verifyPeer = defined('SMTP_VERIFY_PEER') ? (bool)SMTP_VERIFY_PEER : true;

    $transport = $host;
    if ($secure === 'ssl') {
        $transport = 'ssl://' . $host;
        if ($port === 0) $port = 465;
    } elseif ($port === 0) {
        $port = 587;
    }

    $ctx = stream_context_create([
        'ssl' => [
            'verify_peer' => $verifyPeer,
            'verify_peer_name' => $verifyPeer,
            'allow_self_signed' => !$verifyPeer,
        ],
    ]);

    $fp = @stream_socket_client(
        $transport . ':' . $port,
        $errno,
        $errstr,
        20,
        STREAM_CLIENT_CONNECT,
        $ctx
    );

    if (!$fp) return false;

    stream_set_timeout($fp, 20);

    $resp = smtpReadResponse($fp);
    if ((int)substr($resp, 0, 3) !== 220) {
        fclose($fp);
        return false;
    }

    $hostname = $_SERVER['SERVER_NAME'] ?? gethostname() ?: 'localhost';

    if (!smtpSendCommand($fp, 'EHLO ' . $hostname, [250], $resp)) {
        if (!smtpSendCommand($fp, 'HELO ' . $hostname, [250], $resp)) {
            smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
            fclose($fp);
            return false;
        }
    }

    if ($secure === 'tls') {
        if (!smtpSendCommand($fp, 'STARTTLS', [220], $resp)) {
            smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
            fclose($fp);
            return false;
        }

        $cryptoOk = @stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($cryptoOk !== true) {
            smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
            fclose($fp);
            return false;
        }

        if (!smtpSendCommand($fp, 'EHLO ' . $hostname, [250], $resp)) {
            smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
            fclose($fp);
            return false;
        }
    }

    if ($user !== '') {
        if (!smtpSendCommand($fp, 'AUTH LOGIN', [334], $resp)) {
            smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
            fclose($fp);
            return false;
        }
        if (!smtpSendCommand($fp, base64_encode($user), [334], $resp)) {
            smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
            fclose($fp);
            return false;
        }
        if (!smtpSendCommand($fp, base64_encode($pass), [235], $resp)) {
            smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
            fclose($fp);
            return false;
        }
    }

    $fromAddr = trim($from);
    $toAddr   = trim($to);

    if (!smtpSendCommand($fp, 'MAIL FROM:<' . $fromAddr . '>', [250], $resp)) {
        smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
        fclose($fp);
        return false;
    }

    if (!smtpSendCommand($fp, 'RCPT TO:<' . $toAddr . '>', [250, 251], $resp)) {
        smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
        fclose($fp);
        return false;
    }

    if (!smtpSendCommand($fp, 'DATA', [354], $resp)) {
        smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
        fclose($fp);
        return false;
    }

    $headers = [
        'From: ' . smtpEncodeHeader(defined('APP_NAME') ? APP_NAME : '') . ' <' . $fromAddr . '>',
        'Reply-To: ' . $fromAddr,
        'To: ' . $toAddr,
        'Subject: ' . smtpEncodeHeader($subject),
        'Date: ' . date('r'),
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
    ];

    $data = implode("\r\n", $headers) . "\r\n\r\n";

    $body = str_replace(["\r\n", "\r"], "\n", $body);
    $lines = explode("\n", $body);
    foreach ($lines as &$ln) {
        if (isset($ln[0]) && $ln[0] === '.') $ln = '.' . $ln;
    }
    unset($ln);

    $data .= implode("\r\n", $lines) . "\r\n";

    fwrite($fp, $data . ".\r\n");

    $resp = smtpReadResponse($fp);
    $ok = ((int)substr($resp, 0, 3) === 250);

    smtpSendCommand($fp, 'QUIT', [221, 250], $resp);
    fclose($fp);

    return $ok;
}
