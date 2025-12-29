<?php
/**
 * Namingo EPP Registrar module for WHMCS (https://www.whmcs.com/)
 *
 * Written in 2024-2025 by Taras Kondratyuk (https://namingo.org)
 * Based on Generic EPP with DNSsec Registrar Module for WHMCS written in 2019 by Lilian Rudenco (info@xpanel.com)
 * Work of Lilian Rudenco is under http://opensource.org/licenses/afl-3.0.php Academic Free License (AFL 3.0)
 *
 * @license MIT
 */

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\Schema\Blueprint;
use WHMCS\Carbon;
use WHMCS\Domain\Registrar\Domain;
use WHMCS\Domains\DomainLookup\ResultsList;
use WHMCS\Domains\DomainLookup\SearchResult;
use Pinga\Tembo\EppRegistryFactory;

function epp_MetaData()
{
    return array(
        'DisplayName' => 'EPP Registrar',
        'APIVersion' => '1.1.0',
    );
}

function epp_getConfigArray(array $params = [])
{
    if (empty($params['gtld'])) {
        epp_create_table();
        epp_create_column();
    }

    return [
        'FriendlyName' => [
            'Type'  => 'System',
            'Value' => 'EPP Registrar',
        ],

        'Description' => [
            'Type'  => 'System',
            'Value' => 'Connect WHMCS to any domain registry using the standard EPP protocol.',
        ],

        'host' => [
            'FriendlyName' => 'EPP Hostname',
            'Type'         => 'text',
            'Size'         => '32',
            'Description'  => 'Registry EPP endpoint hostname (e.g. epp.registry.tld).',
        ],

        'port' => [
            'FriendlyName' => 'EPP Port',
            'Type'         => 'text',
            'Size'         => '5',
            'Default'      => '700',
            'Description'  => 'TCP port used by the registry (700 is the standard EPP port, but some registries use a different value).',
        ],

        'tls_version' => [
            'FriendlyName' => 'Prefer TLS 1.3',
            'Type'         => 'yesno',
            'Description'  => 'Use TLS 1.3 when available; falls back to older TLS if the registry does not support it.',
        ],

        'verify_peer' => [
            'FriendlyName' => 'Verify TLS Certificate',
            'Type'         => 'yesno',
            'Description'  => 'Validate the registry server certificate (recommended). Disable only for test environments.',
        ],

        'cafile' => [
            'FriendlyName' => 'CA Bundle Path',
            'Type'         => 'text',
            'Default'      => '',
            'Description'  => 'Path to a CA bundle file used to verify the registry certificate (required when “Verify TLS Certificate” is enabled).',
        ],

        'local_cert' => [
            'FriendlyName' => 'Client Certificate (PEM)',
            'Type'         => 'text',
            'Default'      => 'cert.pem',
            'Description'  => 'Path to your registrar client certificate in PEM format.',
        ],

        'local_pk' => [
            'FriendlyName' => 'Client Private Key',
            'Type'         => 'text',
            'Default'      => 'key.pem',
            'Description'  => 'Path to your private key file (PEM).',
        ],

        'passphrase' => [
            'FriendlyName' => 'Private Key Passphrase',
            'Type'         => 'password',
            'Size'         => '32',
            'Description'  => 'Passphrase for the private key (leave blank if the key is not encrypted).',
        ],

        'clid' => [
            'FriendlyName' => 'Client ID (clID)',
            'Type'         => 'text',
            'Size'         => '20',
            'Description'  => 'Registrar identifier provided by the registry.',
        ],

        'pw' => [
            'FriendlyName' => 'Client Password',
            'Type'         => 'password',
            'Size'         => '32',
            'Description'  => 'EPP login password provided by the registry.',
        ],

        'registrarprefix' => [
            'FriendlyName' => 'Object ID Prefix',
            'Type'         => 'text',
            'Size'         => '16',
            'Description'  => 'Prefix used when generating registry object IDs (contacts/hosts). Use the value required by the registry, if any.',
        ],

        'registry_profile' => [
            'FriendlyName' => 'Registry Profile',
            'Type'    => 'dropdown',
            'Options'      => 'generic,EU,UA,VRSN',
            'Default'     => 'generic',
            'Description' => 'Select the registry profile matching the registry implementation. <a href="https://github.com/getnamingo/whmcs-epp-registrar" target="_blank">List of profiles</a>',
        ],

        'set_authinfo_on_info' => [
            'FriendlyName' => 'Set AuthInfo on Request',
            'Type'         => 'yesno',
            'Default'      => '',
            'Description'  => 'Enable if the registry does not return the transfer code on domain info and requires setting it manually first.',
        ],

        'login_extensions' => [
            'FriendlyName' => 'EPP Login Extensions',
            'Type'        => 'textarea',
            'Rows'        => 5,
            'Description' =>
                'Comma-separated EPP login extension URIs.<br>' .
                'Leave empty to use defaults.<br>' .
                '<code>urn:ietf:params:xml:ns:secDNS-1.1, urn:ietf:params:xml:ns:rgp-1.0</code>',
        ],

        'gtld' => [
            'FriendlyName' => 'gTLD Registry',
            'Type'         => 'yesno',
            'Default'      => '',
            'Description'  => 'Enable this if the registry is a generic TLD (gTLD) operated under ICANN policies.',
        ],

        'min_data_set' => [
            'FriendlyName' => 'Use Minimum Data Set',
            'Type'         => 'yesno',
            'Default'      => '',
            'Description'  => 'Use the ICANN Minimum Data Set.',
        ],

        'eurid_billing_contact' => [
            'FriendlyName' => 'EURid Billing Contact ID',
            'Type'         => 'text',
            'Default'      => '',
            'Description'  => 'Optional billing contact handle for EURid. Used only when EPP profile is EU.',
        ],

    ];
}

function epp_RegisterDomain(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $domainCheck = $epp->domainCheck([
            'domains' => [$domain],
        ]);

        if (!empty($domainCheck['error'])) {
            throw new \Exception((string)$domainCheck['error']);
        }

        $item = ($domainCheck['domains'][1] ?? null);

        if (!$item || empty($item['name'])) {
            throw new \Exception('Domain check failed: empty response');
        }

        $avail = filter_var($item['avail'] ?? false, FILTER_VALIDATE_BOOL);

        $reason = (string)($item['reason'] ?? '');
        if ($reason === '') {
            $reason = 'Domain is not available';
        }

        if (!$avail) {
            throw new \Exception($domain . ' ' . $reason);
        }

        if (empty($params['gtld']) && empty($params['min_data_set'])) {
            $contacts = [];
            
            $contactTypeMap = [
                'EU'      => ['registrant', 'tech'],                 // EURid
                'VRSN'   => ['registrant', 'admin', 'tech', 'billing'],
                'generic'=> ['registrant', 'admin', 'tech', 'billing'],
            ];

            $profile = $params['registry_profile'] ?? 'generic';

            $contactTypes = $contactTypeMap[$profile]
                ?? $contactTypeMap['generic'];

            foreach ($contactTypes as $i => $contactType) {

                $id = strtoupper(epp_random_contact_id());
                $authInfoPw = epp_random_auth_pw();

                $contactCreate = $epp->contactCreate([
                    'id'              => $id,
                    'type'            => 'int',
                    'firstname'       => $params['firstname'] ?? '',
                    'lastname'        => $params['lastname'] ?? '',
                    'companyname'     => $params['companyname'] ?? '',
                    'address1'        => $params['address1'] ?? '',
                    'address2'        => $params['address2'] ?? '',
                    'address3'        => $params['address3'] ?? '',
                    'city'            => $params['city'] ?? '',
                    'state'           => $params['state'] ?? '',
                    'postcode'        => $params['postcode'] ?? '',
                    'country'         => $params['country'] ?? '',
                    'fullphonenumber' => $params['fullphonenumber'] ?? '',
                    'email'           => $params['email'] ?? '',
                    'authInfoPw'      => $authInfoPw,
                    // EU-only extras
                    'euType'    => ($profile === 'EU') ? $contactType : null,
                ]);

                if (!empty($contactCreate['error'])) {
                    throw new \Exception((string)$contactCreate['error']);
                }

                $createdId = $contactCreate['id'] ?? $id;
                $contacts[$i + 1] = $createdId;
            }
        }

        $profile = $params['registry_profile'] ?? 'generic';
        if ($profile !== 'EU') {
            foreach (['ns1','ns2','ns3','ns4','ns5'] as $nsKey) {
                if (empty($params[$nsKey])) {
                    continue;
                }

                $hostname = (string)$params[$nsKey];

                $hostCheck = $epp->hostCheck([
                    'hostname' => $hostname,
                ]);

                if (!empty($hostCheck['error'])) {
                    throw new \Exception((string)$hostCheck['error']);
                }

                $items = $hostCheck['hosts'] ?? [];
                $item  = $items[0] ?? null;

                if (!$item) {
                    continue;
                }

                $avail = filter_var($item['avail'] ?? false, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
                $avail = $avail ?? ((int)($item['avail'] ?? 0) === 1);

                if (!$avail) {
                    continue;
                }

                $hostCreate = $epp->hostCreate([
                    'hostname' => $hostname,
                ]);

                if (!empty($hostCreate['error'])) {
                    throw new \Exception((string)$hostCreate['error']);
                }
            }
        }

        $period     = (int)($params['regperiod'] ?? 1);

        $nss = [];
        foreach (['ns1','ns2','ns3','ns4','ns5'] as $k) {
            if (!empty($params[$k])) {
                $nss[] = (string)$params[$k];
            }
        }

        $authInfoPw = epp_random_auth_pw();

        $payload = [
            'domainname' => $domain,
            'period'     => $period,
            'nss'        => $nss,
            'authInfoPw' => $authInfoPw,
        ];

        if (empty($params['gtld']) && empty($params['min_data_set'])) {
            if ($profile === 'EU') {
                $payload['registrant'] = $contacts[1] ?? null;

                $payload['contacts'] = [
                    'tech'    => $contacts[2] ?? null,
                    'billing' => trim($params['eurid_billing_contact'] ?? '') ?: null,
                ];
            } else {
                $payload['registrant'] = $contacts[1] ?? null;

                $payload['contacts'] = [
                    'admin'   => $contacts[2] ?? null,
                    'tech'    => $contacts[3] ?? null,
                    'billing' => $contacts[4] ?? null,
                ];
            }
        }

        $domainCreate = $epp->domainCreate($payload);

        if (!empty($domainCreate['error'])) {
            throw new \Exception((string)$domainCreate['error']);
        }

        if (!empty($params['gtld'])) {
            // Check if the required module 'whmcs_registrar' is active
            if (!Capsule::table('tbladdonmodules')->where('module', 'whmcs_registrar')->exists()) {
                logModuleCall('epp', 'precheck', 'Required module is not active', ['module' => 'epp'], '');
            }

            if (empty($params['min_data_set'])) {
                $contactIds = epp_insertContacts($params, $contacts);
                epp_insertDomain($params, $contactIds);
            } else {
                epp_insertDomain($params, []);
            }
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_RenewDomain(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $domainRenew = $epp->domainRenew([
            'domainname' => $domain,
            'regperiod'  => $params['regperiod'],
        ]);

        if (isset($domainRenew['error'])) {
            throw new \Exception($domainRenew['error']);
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_TransferDomain(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $domainTransfer = $epp->domainTransfer([
            'domainname' => $domain,
            'years'      => $params['regperiod'],
            'authInfoPw' => $params['eppcode'],
            'op'         => 'request',
        ]);

        if (isset($domainTransfer['error'])) {
            throw new \Exception($domainTransfer['error']);
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_GetNameservers(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);

        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }

        $i = 1;
        foreach ($info['ns'] as $ns) {
            if ($ns === '' || $ns === null) {
                continue;
            }

            $return['ns' . $i] = (string)$ns;
            $i++;
        }

        $statusList = $info['status'] ?? [];

        if (is_string($statusList) && $statusList !== '') {
            $statusList = [$statusList];
        } elseif (!is_array($statusList)) {
            $statusList = [];
        }

        $domainId = $params['domainid'];
        if (!empty($params['gtld'])) {
            $domainId = epp_getWhmcsDomainIdFromNamingo($params['sld'] . '.' . ltrim($params['tld'], '.'));
        }

        Capsule::table('epp_domain_status')->where('domain_id', $domainId)->delete();

        foreach ($statusList as $st) {
            $st = (string)$st;
            if ($st === '') {
                continue;
            }

            if ($st === 'pendingDelete') {
                Capsule::table('tbldomains')->where('id', $domainId)->update(['status' => 'Cancelled']);
            }

            Capsule::table('epp_domain_status')->insert([
                'domain_id' => $domainId,
                'status'    => $st,
            ]);
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_GetDomainInformation(array $params = [])
{
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);
            
        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }

        // Nameservers
        $nameservers = [];
        $i = 1;

        foreach (($info['ns'] ?? []) as $ns) {
            if ($ns === null || $ns === '') {
                continue;
            }

            $nameservers['ns' . $i] = (string) $ns;
            $i++;
        }

        // Transfer lock (clientTransferProhibited => locked)
        $transferLock = false;

        $domainId = $params['domainid'];
        if (!empty($params['gtld'])) {
            $domainId = epp_getWhmcsDomainIdFromNamingo($domain);
        }

        Capsule::table('epp_domain_status')->where('domain_id', $domainId)->delete();

        $statuses = $info['status'] ?? [];
        if (!is_array($statuses)) {
            $statuses = [$statuses];
        }

        foreach ($statuses as $st) {
            $st = (string)$st;

            if (empty($st)) {
                continue;
            }

            if ($st === 'pendingDelete') {
                Capsule::table('tbldomains')
                    ->where('id', $domainId)
                    ->update(['status' => 'Cancelled']);
            }

            if (stripos($st, 'clientTransferProhibited') !== false) {
                $transferLock = true;
            }

            Capsule::table('epp_domain_status')->insert([
                'domain_id' => $domainId,
                'status'    => $st,
            ]);
        }

        $expiryDate = null;
        if (!empty($info['exDate'])) {
            $date = substr((string)$info['exDate'], 0, 10);

            if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
                $expiryDate = Carbon::createFromFormat('Y-m-d', $date);
            }
        }

        // Default
        $registrationStatus = Domain::STATUS_ACTIVE;

        foreach ($statuses as $st) {
            $st = (string)$st;

            switch ($st) {
                case 'pendingDelete':
                    $registrationStatus = Domain::STATUS_PENDING_DELETE;
                    break 2;

                case 'serverHold':
                case 'clientHold':
                    $registrationStatus = Domain::STATUS_SUSPENDED;
                    break;

                case 'expired':
                    $registrationStatus = Domain::STATUS_EXPIRED;
                    break;

                case 'inactive':
                    $registrationStatus = Domain::STATUS_INACTIVE;
                    break;

                case 'serverDeleteProhibited':
                case 'clientDeleteProhibited':
                    $registrationStatus = Domain::STATUS_ACTIVE;
                    break;
            }
        }

        $domainObj = (new Domain())
            ->setDomain($domain)
            ->setNameservers($nameservers)
            ->setRegistrationStatus($registrationStatus)
            ->setTransferLock($transferLock);

        if ($expiryDate) {
            $domainObj->setExpiryDate($expiryDate);
        }

        return $domainObj;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_SaveNameservers(array $params = [])
{
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);

        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }

        $current = [];
        foreach (($info['ns'] ?? []) as $ns) {
            $ns = (string)$ns;
            if ($ns !== '') {
                $current[] = $ns;
            }
        }

        $add = [];
        foreach ($params as $k => $v) {
            if (!$v) continue;
            if (!preg_match('/^ns\d$/i', $k)) continue;

            if (in_array((string)$v, $current, true)) {
                continue;
            }

            $add[$k] = (string)$v;
        }

        $profile = $params['registry_profile'] ?? 'generic';
        if ($profile !== 'EU') {
            if (!empty($add)) {
                foreach ($add as $k => $nsName) {
                    $nsName = trim((string)$nsName);
                    if ($nsName === '') {
                        continue;
                    }

                    $hostCheck = $epp->hostCheck([
                        'hostname' => $nsName,
                    ]);

                    if (!empty($hostCheck['error'])) {
                        throw new \Exception((string)$hostCheck['error']);
                    }

                    $items = $hostCheck['hosts'] ?? [];
                    $item  = $items[1] ?? null;

                    if (!$item) {
                        continue;
                    }

                    $avail = filter_var($item['avail'] ?? false, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
                    $avail = $avail ?? ((int)($item['avail'] ?? 0) === 1);

                    if (!$avail) {
                        continue;
                    }

                    // host:create
                    $hostCreate = $epp->hostCreate([
                        'hostname' => $nsName,
                    ]);

                    if (!empty($hostCreate['error'])) {
                        throw new \Exception((string)$hostCreate['error']);
                    }
                }
            }
        }

        $final = [];
        foreach (['ns1','ns2','ns3','ns4','ns5'] as $k) {
            if (!empty($params[$k])) {
                $final[] = (string)$params[$k];
            }
        }

        if ($profile === 'EU') {
            $payload = [
                'domainname' => $domain,
                'nss'        => [],
            ];

            foreach (array_values($final) as $host) {
                $ns = ['hostName' => $host];

                if (preg_match('/\.eu$/i', $host)) {
                    $a = @dns_get_record($host, DNS_A);
                    if (!empty($a[0]['ip'])) {
                        $ns['ipv4'] = $a[0]['ip'];
                    }

                    $aaaa = @dns_get_record($host, DNS_AAAA);
                    if (!empty($aaaa[0]['ipv6'])) {
                        $ns['ipv6'] = $aaaa[0]['ipv6'];
                    }
                }

                $payload['nss'][] = $ns;
            }

            $domainUpdateNS = $epp->domainUpdateNS($payload);
        } else {
            $payload = ['domainname' => $domain];

            foreach (array_values($final) as $idx => $host) {
                $payload['ns' . ($idx + 1)] = $host;
            }

            $domainUpdateNS = $epp->domainUpdateNS($payload);
        }

        if (!empty($domainUpdateNS['error'])) {
            throw new \Exception((string)$domainUpdateNS['error']);
        }

        return ['success' => true];
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_CheckAvailability(array $params = [])
{
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $searchTerm         = trim((string) ($params['searchTerm'] ?? ''));
        $punyCodeSearchTerm = trim((string) ($params['punyCodeSearchTerm'] ?? ''));
        $tldsToInclude      = (array)  ($params['tldsToInclude'] ?? []);
        $isIdnDomain        = (bool)   ($params['isIdnDomain'] ?? false);

        $label = $isIdnDomain && $punyCodeSearchTerm ? $punyCodeSearchTerm : $searchTerm;
        $label = ltrim(strtolower($label), '.');

        $results = new ResultsList();

        foreach ($tldsToInclude as $tld) {
            $tld = ltrim(strtolower((string) $tld), '.');
            if ($tld === '' || $label === '') {
                continue;
            }

            $fqdn = $label . '.' . $tld;

            $domainCheck = $epp->domainCheck([
                'domains' => [$fqdn],
            ]);

            if (!empty($domainCheck['error'])) {
                throw new \Exception((string)$domainCheck['error']);
            }

            $item = $domainCheck['domains'][1] ?? null;
            if (!$item) {
                throw new \Exception('Domain check failed: empty response');
            }

            $avail = (int)filter_var($item['avail'] ?? false, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
            $avail = $avail ?: ((int)($item['avail'] ?? 0) === 1);

            $reason = (string)($item['reason'] ?? '');

            $searchResult = new SearchResult($label, $tld);

            if ($avail === 1) {
                $searchResult->setStatus(SearchResult::STATUS_NOT_REGISTERED);
            } else {
                // TODO: Premium domains
                $searchResult->setStatus(SearchResult::STATUS_REGISTERED);
            }

            $results->append($searchResult);
        }

        return $results;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}
function epp_GetRegistrarLock(array $params = [])
{
    $return = 'unlocked';
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);
            
        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }

        $statusList = $info['status'] ?? [];
        if (is_string($statusList) && $statusList !== '') {
            $statusList = [$statusList];
        } elseif (!is_array($statusList)) {
            $statusList = [];
        }

        foreach ($statusList as $st) {
            $st = (string)$st;
            if ($st === '') {
                continue;
            }

            if (preg_match('/clientTransferProhibited/i', $st)) {
                $return = 'locked';
                break;
            }
        }

        return $return;
    } catch (\Throwable $e) {
        $return = 'locked';
    } finally {
        epp_client_logout($epp);
    }
}

function epp_SaveRegistrarLock(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);
            
        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }
        
        $statuses = $info['status'] ?? [];
        if (!is_array($statuses)) {
            $statuses = [$statuses];
        }

        $status = [];
        foreach ($statuses as $st) {
            $st = (string)$st;
            if ($st === '') {
                continue;
            }

            if (!preg_match('/^client.+Prohibited$/i', $st)) {
                continue;
            }

            $status[$st] = true;
        }

        $add = [];
        $rem = [];

        foreach (['clientDeleteProhibited', 'clientTransferProhibited'] as $st) {
            if (($params['lockenabled'] ?? '') === 'locked') {
                if (!isset($status[$st])) {
                    $add[] = $st;
                }
            } else {
                if (isset($status[$st])) {
                    $rem[] = $st;
                }
            }
        }

        foreach ($rem as $st) {
            $resp = $epp->domainUpdateStatus([
                'domainname' => $domain,
                'command'    => 'rem',
                'status'     => $st,
            ]);

            if (!empty($resp['error'])) {
                throw new \Exception((string)$resp['error']);
            }
        }

        foreach ($add as $st) {
            $resp = $epp->domainUpdateStatus([
                'domainname' => $domain,
                'command'    => 'add',
                'status'     => $st,
            ]);

            if (!empty($resp['error'])) {
                throw new \Exception((string)$resp['error']);
            }
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_GetContactDetails(array $params = [])
{
    if (!empty($params['min_data_set'])) {
        return [];
    }

    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);
            
        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }

        $contactMap = [];
        foreach (($info['contact'] ?? []) as $row) {
            if (!is_array($row)) continue;

            $type = $row['type'] ?? null;
            $id   = $row['id'] ?? null;

            if ($type && $id) {
                $contactMap[$type] = $id;
            }
        }

        $dcontact = array_filter([
            'registrant' => $info['registrant'] ?? null,
            'admin'      => $contactMap['admin'] ?? null,
            'tech'       => $contactMap['tech'] ?? null,
            'billing'    => $contactMap['billing'] ?? null,
        ], fn($v) => !empty($v));

        $contact = [];
        foreach (array_unique(array_values($dcontact)) as $id) {
            $contactInfo = $epp->contactInfo(['contact' => $id]);

            $contact[$id] = [
                'Name'              => $contactInfo['name']   ?? '',
                'Organization'      => $contactInfo['org']    ?? '',
                'Street 1'          => $contactInfo['street1']?? '',
                'Street 2'          => $contactInfo['street2']?? '',
                'Street 3'          => $contactInfo['street3']?? '',
                'City'              => $contactInfo['city']   ?? '',
                'State or Province' => $contactInfo['state']  ?? '',
                'Postal Code'       => $contactInfo['postal'] ?? '',
                'Country Code'      => $contactInfo['country'] ?? '',
                'Phone'             => $contactInfo['voice']  ?? '',
                'Fax'               => $contactInfo['fax']    ?? '',
                'Email'             => $contactInfo['email']  ?? '',
            ];
        }

        $typeMap = [
            'registrant' => 'Registrant',
            'admin'      => 'Administrator',
            'tech'       => 'Technical',
            'billing'    => 'Billing',
        ];

        foreach ($dcontact as $type => $id) {
            if (!isset($typeMap[$type], $contact[$id])) {
                continue;
            }

            $return[$typeMap[$type]] = $contact[$id];
        }
        
        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_SaveContactDetails(array $params = [])
{
    if (!empty($params['min_data_set'])) {
        return ['success' => true];
    }

    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);

        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }

        $dcontact = [];

        if (!empty($info['registrant'])) {
            $dcontact['registrant'] = (string)$info['registrant'];
        }

        $contacts = $info['contact'] ?? [];
        if (!is_array($contacts)) {
            $contacts = [];
        }

        foreach ($contacts as $row) {
            if (!is_array($row)) {
                continue;
            }

            $type = (string)($row['type'] ?? '');
            $cid  = (string)($row['id'] ?? '');

            if ($type === '' || $cid === '') {
                continue;
            }

            if (in_array($type, ['admin','tech','billing'], true)) {
                $dcontact[$type] = $cid;
            }
        }

        foreach($dcontact as $type => $id) {
            $a = array();
            if ($type == 'registrant') {
                $a = $params['contactdetails']['Registrant'];
            }
            elseif ($type == 'admin') {
                $a = $params['contactdetails']['Administrator'];
            }
            elseif ($type == 'tech') {
                $a = $params['contactdetails']['Technical'];
            }
            elseif ($type == 'billing') {
                $a = $params['contactdetails']['Billing'];
            }

            if (empty($a)) {
                continue;
            }

            $name = ($a['Name'] ? $a['Name'] : $a['Full Name']);
            [$firstName, $lastName] = array_pad(preg_split('/\s+/', trim($name), 2), 2, '');
            $org = ($a['Organization'] ? $a['Organization'] : $a['Organisation Name']);
            $street1 = ($a['Street 1'] ? $a['Street 1'] : $a['Address 1']);
            $street2 = ($a['Street 2'] ? $a['Street 2'] : $a['Address 2']);
            $street3 = ($a['Street 3'] ? $a['Street 3'] : $a['Address 3']);
            $sp = ($a['State or Province'] ? $a['State or Province'] : $a['State']);
            $pc = ($a['Postal Code'] ? $a['Postal Code'] : $a['Postcode']);
            $cc = ($a['Country Code'] ? $a['Country Code'] : $a['Country']);

            $contactUpdate = $epp->contactUpdate([
                'id'               => $id,
                'type'             => 'int',
                'firstname'        => $firstName,
                'lastname'         => $lastName,
                'companyname'      => htmlspecialchars($org),
                'address1'         => htmlspecialchars($street1),
                'address2'         => htmlspecialchars($street2),
                'address3'         => htmlspecialchars($street3),
                'city'             => htmlspecialchars($a['City']),
                'state'            => htmlspecialchars($sp),
                'postcode'         => htmlspecialchars($pc),
                'country'          => htmlspecialchars($cc),
                'fullphonenumber'  => htmlspecialchars($a['Phone']),
                'email'            => htmlspecialchars($a['Email']),
            ]);

            if (isset($contactUpdate['error'])) {
                echo 'ContactUpdate Error: ' . $contactUpdate['error'] . PHP_EOL;
                return;
            }
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_IDProtectToggle(array $params = [])
{
    if (!empty($params['min_data_set'])) {
        return ['success' => true];
    }

    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');
        $flag = empty($params['idprotection']) ? 1 : 0;

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);

        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }

        $dcontact = [];
        if (!empty($info['registrant'])) {
            $dcontact['registrant'] = (string)$info['registrant'];
        }

        $rows = $info['contact'] ?? [];
        if (is_array($rows)) {
            foreach ($rows as $row) {
                if (!is_array($row)) continue;

                $type = (string)($row['type'] ?? '');
                $id   = (string)($row['id'] ?? '');

                if ($type === '' || $id === '') continue;

                $dcontact[$type] = $id;
            }
        }

        $contact = [];
        foreach ($dcontact as $id) {
            if (isset($contact[$id])) {
                continue;
            }
            
            $clTRID = str_replace('.', '', round(microtime(1), 3));

            $xml = array(
                'xml' => '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
        <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
          <command>
            <update>
              <contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>'.$id.'</contact:id>
                <contact:chg>
                  <contact:disclose flag="'.$flag.'">
                    <contact:name type="int"/>
                    <contact:addr type="int"/>
                    <contact:voice/>
                    <contact:fax/>
                    <contact:email/>
                  </contact:disclose>
                </contact:chg>
              </contact:update>
            </update>
            <clTRID>'.$clTRID.'</clTRID>
          </command>
        </epp>
        ');
            $rawXml = $epp->rawXml($xml);
            
            if (isset($rawXml['error'])) {
                throw new \Exception($rawXml['error']);
            }
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_GetEPPCode(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        if (!empty($params['set_authinfo_on_info'])) {
            $eppcode = epp_random_auth_pw();

            $info = $epp->domainUpdateAuthinfo([
                'domainname' => $domain,
                'authInfo'   => $eppcode,
            ]);
            
            if (isset($info['error'])) {
                throw new \Exception($info['error']);
            }
        } else {
            $info = $epp->domainInfo([
                'domainname' => $domain,
            ]);
            
            if (isset($info['error'])) {
                throw new \Exception($info['error']);
            }

            $eppcode = $info['authInfo'];
        }

        return array('eppcode' => $eppcode);
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_RegisterNameserver(array $params = [])
{
    if (($params['registry_profile'] ?? 'generic') === 'EU') {
        return [];
    }

    $return = [];
    try {
        $epp = epp_client($params);

        $hostCheck = $epp->hostCheck([
            'hostname' => $params['nameserver'],
        ]);

        if (isset($hostCheck['error'])) {
            throw new \Exception($hostCheck['error']);
        }

        $first = reset($hostCheck['hosts']);

        if (!$first) {
            throw new \Exception('Host check returned no results');
        }

        $label = $first['name'] ?? $first['id'] ?? 'unknown';

        $avail = filter_var($first['avail'] ?? false, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
        $avail = $avail ?? ((int)($first['avail'] ?? 0) === 1);

        if (!$avail) {
            $reason = $first['reason'] ?? 'no reason given';
            throw new \Exception($label . ' ' . $reason);
        }

        $hostCreate = $epp->hostCreate([
            'hostname'  => $params['nameserver'],
            'ipaddress' => $params['ipaddress'],
        ]);

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_ModifyNameserver(array $params = [])
{
    if (($params['registry_profile'] ?? 'generic') === 'EU') {
        return [];
    }

    $return = [];
    try {
        $epp = epp_client($params);

        $hostUpdate = $epp->hostUpdate([
            'hostname'          => $params['nameserver'],
            'currentipaddress'  => $params['currentipaddress'],
            'newipaddress'      => $params['newipaddress'],
        ]);

        if (isset($hostUpdate['error'])) {
            throw new \Exception($hostUpdate['error']);
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_DeleteNameserver(array $params = [])
{
    if (($params['registry_profile'] ?? 'generic') === 'EU') {
        return [];
    }

    $return = [];
    try {
        $epp = epp_client($params);
        
        $hostDelete = $epp->hostDelete([
            'hostname' => $params['nameserver'],
        ]);

        if (isset($hostDelete['error'])) {
            throw new \Exception($hostDelete['error']);
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_RequestDelete(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $domainDelete = $epp->domainDelete([
            'domainname' => $domain,
        ]);

        if (isset($domainDelete['error'])) {
            throw new \Exception($domainDelete['error']);
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_manageDNSSECDSRecords(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        if (isset($_POST['command']) && ($_POST['command'] === 'secDNSadd')) {
            $keyTag     = (int)($_POST['keyTag'] ?? 0);
            $alg        = (int)($_POST['alg'] ?? 0);
            $digestType = (int)($_POST['digestType'] ?? 0);
            $digest     = trim((string)($_POST['digest'] ?? ''));

            if ($keyTag <= 0 || $alg <= 0 || $digestType <= 0 || $digest === '') {
                throw new \Exception('Missing or invalid DNSSEC DS data');
            }

            $domainUpdateDNSSEC = $epp->domainUpdateDNSSEC([
                'domainname'   => $domain,
                'command'      => 'add',
                'keyTag_1'     => $keyTag,
                'alg_1'        => $alg,
                'digestType_1' => $digestType,
                'digest_1'     => $digest,
            ]);

            if (!empty($domainUpdateDNSSEC['error'])) {
                throw new \Exception((string)$domainUpdateDNSSEC['error']);
            }
        }

        if (isset($_POST['command']) && ($_POST['command'] === 'secDNSrem')) {
            $keyTag     = (int)($_POST['keyTag'] ?? 0);
            $alg        = (int)($_POST['alg'] ?? 0);
            $digestType = (int)($_POST['digestType'] ?? 0);
            $digest     = trim((string)($_POST['digest'] ?? ''));

            if ($keyTag <= 0 || $alg <= 0 || $digestType <= 0 || $digest === '') {
                throw new \Exception('Missing or invalid DNSSEC DS data');
            }

            $domainUpdateDNSSEC = $epp->domainUpdateDNSSEC([
                'domainname'   => $domain,
                'command'      => 'rem',
                'keyTag_1'     => $keyTag,
                'alg_1'        => $alg,
                'digestType_1' => $digestType,
                'digest_1'     => $digest,
            ]);

            if (!empty($domainUpdateDNSSEC['error'])) {
                throw new \Exception((string)$domainUpdateDNSSEC['error']);
            }
        }
        
        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);
            
        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }

        $secDNSdsData = [];
        if (!empty($info['dsData']) && is_array($info['dsData'])) {
            $DSRecords = 'YES';
            $i = 0;

            foreach ($info['dsData'] as $dsData) {
                if (!is_array($dsData)) {
                    continue;
                }

                if (!isset($dsData['keyTag'], $dsData['alg'], $dsData['digestType'], $dsData['digest'])) {
                    continue;
                }

                $i++;
                $secDNSdsData[$i]["domainid"]   = (int) $params['domainid'];
                $secDNSdsData[$i]["keyTag"]     = (string) $dsData['keyTag'];
                $secDNSdsData[$i]["alg"]        = (int) $dsData['alg'];
                $secDNSdsData[$i]["digestType"] = (int) $dsData['digestType'];
                $secDNSdsData[$i]["digest"]     = (string) $dsData['digest'];
            }

            if ($i === 0) {
                $DSRecords = "You don't have any DS records";
            }
        } else {
            $DSRecords = "You don't have any DS records";
        }

        return [
            'templatefile' => 'manageDNSSECDSRecords',
            'requirelogin' => true,
            'vars' => [
                'DSRecords' => $DSRecords,
                'DSRecordslist' => $secDNSdsData
           ],
        ];
    } catch (\Throwable $e) {
        return [
            'templatefile' => 'manageDNSSECDSRecords',
            'requirelogin' => true,
            'vars' => [
                'error' => $e->getMessage(),
            ],
        ];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_ClientAreaCustomButtonArray()
{
    $buttonarray = array(
        Lang::Trans('DNSSEC') => 'manageDNSSECDSRecords'
    );
    
    return $buttonarray;
}

function epp_AdminCustomButtonArray(array $params = [])
{
    if (!empty($params['gtld'])) {
        $domainid = epp_getNamingoDomainId($params['domainid']);
    } else {
        $domainid = $params['domainid'];
    }
    $buttons = [];

    // Check for hold status
    $holdStatus = Capsule::table('epp_domain_status')
        ->where('domain_id', '=', $domainid)
        ->where('status', '=', 'clientHold')
        ->first();

    if (isset($holdStatus->status)) {
        $buttons['Unhold Domain'] = 'UnHoldDomain';
    } else {
        $buttons['Put Domain On Hold'] = 'OnHoldDomain';
    }

    // Check for transfer pending status
    $transferPending = Capsule::table('epp_domain_status')
        ->where('domain_id', '=', $domainid)
        ->where('status', '=', 'pendingTransfer')
        ->exists();

    if ($transferPending) {
        $buttons['Approve Transfer'] = 'ApproveTransfer';
        $buttons['Cancel Transfer Request'] = 'CancelTransfer';
        $buttons['Reject Transfer'] = 'RejectTransfer';
    }

    return $buttons;
}

function epp_OnHoldDomain(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);

        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }
        
        $statuses = $info['status'] ?? [];
        if (!is_array($statuses)) {
            $statuses = [$statuses];
        }

        $existing_status = 'ok';

        foreach ($statuses as $st) {
            $st = (string)$st;
            if ($st === '') {
                continue;
            }

            if ($st === 'clientHold') {
                $existing_status = 'clientHold';
                break;
            }

            if ($st === 'serverHold') {
                $existing_status = 'serverHold';
                break;
            }
        }

        if ($existing_status == 'ok') {
            $domainUpdateStatus = $epp->domainUpdateStatus([
                'domainname' => $domain,
                'command'    => 'add',
                'status'     => 'clientHold',
            ]);

            if (!empty($domainUpdateStatus['error'])) {
                throw new \Exception((string)$domainUpdateStatus['error']);
            }
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_UnHoldDomain(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);

        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }
        
        $statuses = $info['status'] ?? [];
        if (!is_array($statuses)) {
            $statuses = [$statuses];
        }

        $existing_status = 'ok';

        foreach ($statuses as $st) {
            $st = (string)$st;
            if ($st === '') {
                continue;
            }

            if ($st === 'clientHold') {
                $existing_status = 'clientHold';
                break;
            }

            if ($st === 'serverHold') {
                $existing_status = 'serverHold';
                break;
            }
        }

        if ($existing_status == 'clientHold') {
            $domainUpdateStatus = $epp->domainUpdateStatus([
                'domainname' => $domain,
                'command'    => 'rem',
                'status'     => 'clientHold',
            ]);

            if (!empty($domainUpdateStatus['error'])) {
                throw new \Exception((string)$domainUpdateStatus['error']);
            }
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_ApproveTransfer($params) {
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $domainTransfer = $epp->domainTransfer([
            'domainname' => $domain,
            'op'         => 'approve',
        ]);

        if (isset($domainTransfer['error'])) {
            throw new \Exception($domainTransfer['error']);
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_CancelTransfer($params) {
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $domainTransfer = $epp->domainTransfer([
            'domainname' => $domain,
            'op'         => 'cancel',
        ]);

        if (isset($domainTransfer['error'])) {
            throw new \Exception($domainTransfer['error']);
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_RejectTransfer($params) {
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $domainTransfer = $epp->domainTransfer([
            'domainname' => $domain,
            'op'         => 'reject',
        ]);

        if (isset($domainTransfer['error'])) {
            throw new \Exception($domainTransfer['error']);
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_TransferSync(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $domainTransfer = $epp->domainTransfer([
            'domainname' => $domain,
            'op'         => 'query',
        ]);

        if (isset($domainTransfer['error'])) {
            throw new \Exception($domainTransfer['error']);
        }

        $trStatus = $domainTransfer['trStatus'];
        $expDate = $domainTransfer['exDate'];
        if (!empty($params['gtld'])) {
            Capsule::table('namingo_domain')->where('name', $params['domain'])->update(['trstatus' => $trStatus]);
        } else {
            Capsule::table('tbldomains')->where('id', $params['domainid'])->update(['trstatus' => $trStatus]);
        }

        switch ($trStatus) {
            case 'pending':
                $return['completed'] = false;
            break;
            case 'clientApproved':
            case 'serverApproved':
                $return['completed'] = true;
                $return['expirydate'] = date('Y-m-d', is_numeric($expDate) ? $expDate : strtotime($expDate));
            break;
            case 'clientRejected':
            case 'clientCancelled':
            case 'serverCancelled':
                $return['failed'] = true;
                $return['reason'] = $trStatus;
            break;
            default:
                $return = array(
                    'error' => sprintf('invalid transfer status: %s', $trStatus)
                );
            break;
        }

        return $return;
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_Sync(array $params = [])
{
    $return = [];
    try {
        $epp = epp_client($params);
        $domain = $params['sld'] . '.' . ltrim($params['tld'], '.');

        $info = $epp->domainInfo([
            'domainname' => $domain,
        ]);

        if (isset($info['error'])) {
            throw new \Exception($info['error']);
        }
        
        $expDate = (string)($info['exDate'] ?? '');
        $timestamp = $expDate !== '' ? strtotime(substr($expDate, 0, 19)) : null;
        $roid = (string)($info['roid'] ?? '');

        if ($timestamp === false) {
            return array(
                'error' => 'Empty expDate date for domain: ' . $params['domain']
            );
        }

        $expDate = preg_replace("/^(\d+\-\d+\-\d+)\D.*$/", "$1", $expDate);

        if (!empty($params['gtld'])) {
            $formattedExpDate = date('Y-m-d H:i:s.000', $timestamp);

            Capsule::table('namingo_domain')
                ->where('name', $params['domain'])
                ->update([
                    'exdate' => $formattedExpDate,
                    'registry_domain_id' => $roid
                ]);
        }

        $isExpired = $timestamp !== null && $timestamp < time();

        return [
            'expirydate' => $expDate,
            $isExpired ? 'expired' : 'active' => true,
        ];
    } catch (\Throwable $e) {
        return ['error' => $e->getMessage()];
    } finally {
        epp_client_logout($epp);
    }
}

function epp_modulelog($send, $responsedata, $action)
{
    $from = $to = [];
    $from[] = "/<clID>[^<]*<\/clID>/i";
    $to[] = '<clID>[REDACTED]</clID>';
    $from[] = "/<pw>[^<]*<\/pw>/i";
    $to[]   = "<pw>[REDACTED]</pw>";
    $from[] = "/<authInfo>.*?<\/authInfo>/is";
    $to[]   = "<authInfo>[REDACTED]</authInfo>";
    $from[] = "/<domain:authInfo>.*?<\/domain:authInfo>/is";
    $to[]   = "<domain:authInfo>[REDACTED]</domain:authInfo>";
    $sendforlog = preg_replace($from, $to, $send);
    logModuleCall('epp',$action,$sendforlog,$responsedata);
}

function epp_create_table()
{
    if (!Capsule::schema()->hasTable('epp_domain_status')) {
        try {
            Capsule::schema()->create('epp_domain_status',
            function (Blueprint $table)
            {
                $table->increments('id');
                $table->integer('domain_id');
                $table->enum('status', array(
                    'clientDeleteProhibited',
                    'clientHold',
                    'clientRenewProhibited',
                    'clientTransferProhibited',
                    'clientUpdateProhibited',
                    'inactive',
                    'ok',
                    'pendingCreate',
                    'pendingDelete',
                    'pendingRenew',
                    'pendingTransfer',
                    'pendingUpdate',
                    'serverDeleteProhibited',
                    'serverHold',
                    'serverRenewProhibited',
                    'serverTransferProhibited',
                    'serverUpdateProhibited'
                ))->default('ok');
                $table->unique(array(
                    'domain_id',
                    'status'
                ));
                $table->foreign('domain_id')->references('id')->on('tbldomains')->onDelete('cascade');
            });
        }

        catch (\Throwable $e) {
            echo "Unable to create table 'epp_domain_status': {$e->getMessage() }";
        }
    }
}

function epp_create_column()
{
    if (!Capsule::schema()->hasColumn('tbldomains', 'trstatus')) {
        try {
            Capsule::schema()->table('tbldomains',
            function (Blueprint $table)
            {
                $table->enum('trstatus', array(
                    'clientApproved',
                    'clientCancelled',
                    'clientRejected',
                    'pending',
                    'serverApproved',
                    'serverCancelled'
                ))->nullable()->after('status');
            });
        }

        catch (\Throwable $e) {
            echo "Unable to alter table 'tbldomains' add column 'trstatus': {$e->getMessage() }";
        }
    }
}

function epp_insertContacts($params, $contacts) {
    $contactIds = [];

    for ($i = 1; $i <= 4; $i++) {
        $contactId = Capsule::table('namingo_contact')->insertGetId([
            'identifier' => $contacts[$i],
            'voice' => $params['fullphonenumber'],
            'email' => $params['email'],
            'name' => $params['firstname'] . ' ' . $params['lastname'],
            'org' => $params['companyname'],
            'street1' => $params['address1'],
            'street2' => $params['address2'],
            'street3' => $params['address3'],
            'city' => $params['city'],
            'sp' => $params['state'],
            'pc' => $params['postcode'],
            'cc' => $params['country'],        
            'clid' => 1,
            'crdate' => date('Y-m-d H:i:s.u')
        ]);

        $contactIds[] = $contactId;
    }

    return $contactIds;
}

function epp_insertDomain($params, $contactIds) {
    $crdate = date('Y-m-d H:i:s.u');
    $exdate = date('Y-m-d H:i:s.u', strtotime("+{$params['regperiod']} years"));

    $domainId = Capsule::table('namingo_domain')->insertGetId([
        'name' => $params['sld'] . '.' . ltrim($params['tld'], '.'),
        'registry_domain_id' => '',
        'clid' => 1,
        'crid' => 1,
        'crdate' => $crdate,
        'exdate' => $exdate,
        'registrant' => $contactIds[0] ?? null,
        'admin' => $contactIds[1] ?? null,
        'tech' => $contactIds[2] ?? null,
        'billing' => $contactIds[3] ?? null,
        'ns1' => $params['ns1'] ?? null,
        'ns2' => $params['ns2'] ?? null,
        'ns3' => $params['ns3'] ?? null,
        'ns4' => $params['ns4'] ?? null,
        'ns5' => $params['ns5'] ?? null
    ]);

    return $domainId;
}

function epp_getNamingoDomainId($whmcsDomainId) {
    $result = Capsule::selectOne("
        SELECT namingo_domain.id
        FROM namingo_domain
        JOIN tbldomains ON namingo_domain.name = tbldomains.domain
        WHERE tbldomains.id = ?
        LIMIT 1
    ", [$whmcsDomainId]);

    return $result ? $result->id : null;
}

function epp_getWhmcsDomainIdFromNamingo($namingoDomainName) {
    $namingoDomainName = strtolower($namingoDomainName);

    return Capsule::table('tbldomains')
        ->where('domain', $namingoDomainName)
        ->value('id');
}

function epp_random_contact_id(int $len = 10): string {
    $alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    $out = '';
    for ($i = 0; $i < $len; $i++) {
        $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return strtoupper($out);
}

function epp_random_auth_pw(int $len = 16): string {
    $result = '';
    $uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    $numbers = "1234567890";
    $specialSymbols = "!=+-";
    $minLength = 16;
    $maxLength = 16;
    $length = mt_rand($minLength, $maxLength);

    // Include at least one character from each set
    $result .= $uppercaseChars[mt_rand(0, strlen($uppercaseChars) - 1)];
    $result .= $lowercaseChars[mt_rand(0, strlen($lowercaseChars) - 1)];
    $result .= $numbers[mt_rand(0, strlen($numbers) - 1)];
    $result .= $specialSymbols[mt_rand(0, strlen($specialSymbols) - 1)];

    // Append random characters to reach the desired length
    while (strlen($result) < $length) {
        $chars = $uppercaseChars . $lowercaseChars . $numbers . $specialSymbols;
        $result .= $chars[mt_rand(0, strlen($chars) - 1)];
    }

    return $result;
}

function epp_client(array $params)
{
    $profile = $params['registry_profile'] ?? 'generic';

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

    $moduleDir = __DIR__;

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
    if ($profile === 'generic') {
        $raw = $params['login_extensions'] ?? '';
        $info['loginExtensions'] = trim($raw) !== ''
            ? array_values(array_filter(array_map('trim', preg_split('/[,\s]+/', $raw))))
            : [
                'urn:ietf:params:xml:ns:secDNS-1.1',
                'urn:ietf:params:xml:ns:rgp-1.0',
            ];
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