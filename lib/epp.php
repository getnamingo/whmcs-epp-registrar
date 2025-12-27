<?php

use Pinga\Tembo\EppRegistryFactory;

function epp_client(array $params)
{
    $profile = $params['epp_profile'] ?? 'generic';

    $epp = EppRegistryFactory::create($profile);
    $epp->disableLogging();

    $tls_version = '1.2';
    if (!empty($params['tls_version'])) {
        $tls_version = '1.3';
    }
    
    $verify_peer = false;
    if ($params['verify_peer'] == 'on') {
        $verify_peer = true;
    }

    $moduleDir = dirname(__DIR__);

    $certPath = trim($params['local_cert'] ?? '');
    $keyPath  = trim($params['local_pk'] ?? '');

    if ($certPath === '' || $keyPath === '') {
        throw new \RuntimeException('Client certificate and private key are required.');
    }

    if ($certPath[0] !== '/' && !preg_match('~^[A-Za-z]:[\\\\/]~', $certPath)) {
        $certPath = $moduleDir . '/' . $certPath;
    }
    if ($keyPath[0] !== '/' && !preg_match('~^[A-Za-z]:[\\\\/]~', $keyPath)) {
        $keyPath = $moduleDir . '/' . $keyPath;
    }

    $certPath = realpath($certPath);
    $keyPath  = realpath($keyPath);

    if ($certPath === false || $keyPath === false) {
        throw new \RuntimeException(
            'EPP TLS certificate or key not found or not readable. '
            . 'cert=' . ($certPath ?: 'false') . ' key=' . ($keyPath ?: 'false')
        );
    }

    // Build connection info from WHMCS module settings
    $info = [
        'host'    => $params['host'] ?? '',
        'port'    => (int)($params['port'] ?? 700),
        'timeout' => 30,
        'tls'     => $tls_version ?? '1.2',
        'bind'    => false,
        'bindip'  => '1.2.3.4:0',
        'verify_peer'      => !empty($verify_peer),
        'verify_peer_name' => false,
        'cafile'           => $params['cafile'] ?? '',
        'local_cert' => $certPath,
        'local_pk' => $keyPath,
        'passphrase'       => $params['passphrase'] ?? '',
        'allow_self_signed'=> true,
    ];

    if (empty($info['loginExtensions'])) {
        $info['loginExtensions'] = [
            'urn:ietf:params:xml:ns:secDNS-1.1',
            'urn:ietf:params:xml:ns:rgp-1.0',
        ];
    } else {
        $epp->setLoginExtensions($info['loginExtensions']);
    }

    if (empty($info['host']) || empty($info['port'])) {
        throw new \RuntimeException('EPP host/port not configured');
    }

    $epp->connect($info);

    $login = $epp->login([
        'clID'   => $params['clid'] ?? '',
        'pw'     => $params['pw'] ?? '',
        'prefix' => $params['registrarprefix'] ?? 'epp',
    ]);

    if (isset($login['error'])) {
        throw new \RuntimeException('Login Error: ' . $login['error']);
    }

    return $epp;
}

function epp_client_logout($epp)
{
    try { $epp->logout(); } catch (\Throwable $e) {}
}