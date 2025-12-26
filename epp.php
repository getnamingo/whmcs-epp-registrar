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

use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\Schema\Blueprint;
use WHMCS\Carbon;
use WHMCS\Domain\Registrar\Domain;
use WHMCS\Domains\DomainLookup\ResultsList;
use WHMCS\Domains\DomainLookup\SearchResult;

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
        _epp_create_table();
        _epp_create_column();
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

        'set_authinfo_on_info' => [
            'FriendlyName' => 'Set AuthInfo on Request',
            'Type'         => 'yesno',
            'Default'      => '',
            'Description'  => 'Enable if the registry does not return the transfer code on domain info and requires setting it manually first.',
        ],

    ];
}

function _epp_startEppClient(array $params = [])
{
    $s = new epp_epp_client($params);
    $s->login($params['clid'], $params['pw'], $params['registrarprefix']);
    return $s;
}

function epp_RegisterDomain(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <check>
      <domain:check
        xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
        xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:check>
    </check>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->chkData;
        $reason = (string)$r->cd[0]->reason;
        if (!$reason) {
            $reason = 'Domain is not available';
        }

        if (0 == (int)$r->cd[0]->name->attributes()->avail) {
            throw new exception($r->cd[0]->name . ' ' . $reason);
        }

        if (empty($params['gtld']) && empty($params['min_data_set'])) {
            $contacts = array();
            foreach(array(
                'registrant',
                'admin',
                'tech',
                'billing'
            ) as $i => $contactType) {
                // contact:create
                $from = $to = [];

                $from[] = '/{{ id }}/';
                $to[] = strtoupper($s->generateRandomString());
                $from[] = '/{{ name }}/';
                $to[] = htmlspecialchars($params['firstname'] . ' ' . $params['lastname']);
                $from[] = '/{{ org }}/';
                $to[] = htmlspecialchars($params['companyname']);
                $from[] = '/{{ street1 }}/';
                $to[] = htmlspecialchars($params['address1']);
                $from[] = '/{{ street2 }}/';
                $to[] = htmlspecialchars($params['address2']);
                $from[] = '/{{ street3 }}/';
                $street3 = (isset($params['address3']) ? $params['address3'] : '');
                $to[] = htmlspecialchars($street3);
                $from[] = '/{{ city }}/';
                $to[] = htmlspecialchars($params['city']);
                $from[] = '/{{ state }}/';
                $to[] = htmlspecialchars($params['state']);
                $from[] = '/{{ postcode }}/';
                $to[] = htmlspecialchars($params['postcode']);
                $from[] = '/{{ country }}/';
                $to[] = htmlspecialchars($params['country']);
                $from[] = '/{{ phonenumber }}/';
                $to[] = htmlspecialchars($params['fullphonenumber']);
                $from[] = '/{{ email }}/';
                $to[] = htmlspecialchars($params['email']);
                $from[] = '/{{ authInfo }}/';
                $to[] = htmlspecialchars($s->generateObjectPW());
                $from[] = '/{{ clTRID }}/';
                $clTRID = str_replace('.', '', round(microtime(1), 3));
                $to[] = htmlspecialchars($params['registrarprefix'] . '-contact-create-' . $clTRID);
                $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
                $to[] = '';
                $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <create>
          <contact:create
           xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
            <contact:id>{{ id }}</contact:id>
            <contact:postalInfo type="int">
              <contact:name>{{ name }}</contact:name>
              <contact:org>{{ org }}</contact:org>
              <contact:addr>
                <contact:street>{{ street1 }}</contact:street>
                <contact:street>{{ street2 }}</contact:street>
                <contact:street>{{ street3 }}</contact:street>
                <contact:city>{{ city }}</contact:city>
                <contact:sp>{{ state }}</contact:sp>
                <contact:pc>{{ postcode }}</contact:pc>
                <contact:cc>{{ country }}</contact:cc>
              </contact:addr>
            </contact:postalInfo>
            <contact:voice>{{ phonenumber }}</contact:voice>
            <contact:fax></contact:fax>
            <contact:email>{{ email }}</contact:email>
            <contact:authInfo>
              <contact:pw>{{ authInfo }}</contact:pw>
            </contact:authInfo>
          </contact:create>
        </create>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
                $r = $s->write($xml, __FUNCTION__);
                $r = $r->response->resData->children('urn:ietf:params:xml:ns:contact-1.0')->creData;
                $contacts[$i + 1] = $r->id;
            }
        }

        foreach(array(
            'ns1',
            'ns2',
            'ns3',
            'ns4',
            'ns5'
        ) as $ns) {
            if (empty($params["{$ns}"])) {
                continue;
            }

        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params["{$ns}"]);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <check>
      <host:check
        xmlns:host="urn:ietf:params:xml:ns:host-1.0"
        xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
        <host:name>{{ name }}</host:name>
      </host:check>
    </check>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->chkData;

        if (0 == (int)$r->cd[0]->name->attributes()->avail) {
            continue;
        }

        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params["{$ns}"]);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-create-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <create>
      <host:create
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
      </host:create>
    </create>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
}

        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ period }}/';
        $to[] = htmlspecialchars($params['regperiod']);
        $from[] = '/{{ ns1 }}/';
        $to[] = htmlspecialchars($params['ns1']);
        $from[] = '/{{ ns2 }}/';
        $to[] = htmlspecialchars($params['ns2']);
        $from[] = '/{{ ns3 }}/';
        $to[] = htmlspecialchars($params['ns3']);
        $from[] = '/{{ ns4 }}/';
        $to[] = htmlspecialchars($params['ns4']);
        $from[] = '/{{ ns5 }}/';
        $to[] = htmlspecialchars($params['ns5']);      
        if (empty($params['gtld']) && empty($params['min_data_set'])) {        
            $from[] = '/{{ cID_1 }}/';
            $to[] = htmlspecialchars($contacts[1]);
            $from[] = '/{{ cID_2 }}/';
            $to[] = htmlspecialchars($contacts[2]);
            $from[] = '/{{ cID_3 }}/';
            $to[] = htmlspecialchars($contacts[3]);
            $from[] = '/{{ cID_4 }}/';
            $to[] = htmlspecialchars($contacts[4]);
        }
        $from[] = '/{{ authInfo }}/';
        $to[] = htmlspecialchars($s->generateObjectPW());
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-create-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';
        if (empty($params['gtld']) && empty($params['min_data_set'])) {
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <create>
          <domain:create
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
            <domain:name>{{ name }}</domain:name>
            <domain:period unit="y">{{ period }}</domain:period>
            <domain:ns>
              <domain:hostObj>{{ ns1 }}</domain:hostObj>
              <domain:hostObj>{{ ns2 }}</domain:hostObj>
              <domain:hostObj>{{ ns3 }}</domain:hostObj>
              <domain:hostObj>{{ ns4 }}</domain:hostObj>
              <domain:hostObj>{{ ns5 }}</domain:hostObj>
            </domain:ns>
            <domain:registrant>{{ cID_1 }}</domain:registrant>
            <domain:contact type="admin">{{ cID_2 }}</domain:contact>
            <domain:contact type="tech">{{ cID_3 }}</domain:contact>
            <domain:contact type="billing">{{ cID_4 }}</domain:contact>
            <domain:authInfo>
              <domain:pw>{{ authInfo }}</domain:pw>
            </domain:authInfo>
          </domain:create>
        </create>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
        } else {
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <create>
          <domain:create
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
            <domain:name>{{ name }}</domain:name>
            <domain:period unit="y">{{ period }}</domain:period>
            <domain:ns>
              <domain:hostObj>{{ ns1 }}</domain:hostObj>
              <domain:hostObj>{{ ns2 }}</domain:hostObj>
              <domain:hostObj>{{ ns3 }}</domain:hostObj>
              <domain:hostObj>{{ ns4 }}</domain:hostObj>
              <domain:hostObj>{{ ns5 }}</domain:hostObj>
            </domain:ns>
            <domain:authInfo>
              <domain:pw>{{ authInfo }}</domain:pw>
            </domain:authInfo>
          </domain:create>
        </create>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
        }
        $r = $s->write($xml, __FUNCTION__);

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
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_RenewDomain(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $expDate = (string)$r->exDate;
        $expDate = preg_replace("/^(\d+\-\d+\-\d+)\D.*$/", "$1", $expDate);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ regperiod }}/';
        $to[] = htmlspecialchars($params['regperiod']);
        $from[] = '/{{ expDate }}/';
        $to[] = htmlspecialchars($expDate);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-renew-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <renew>
      <domain:renew
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
        <domain:curExpDate>{{ expDate }}</domain:curExpDate>
        <domain:period unit="y">{{ regperiod }}</domain:period>
      </domain:renew>
    </renew>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_TransferDomain(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ years }}/';
        $to[] = htmlspecialchars($params['regperiod']);
        $from[] = '/{{ authInfo_pw }}/';
        $to[] = htmlspecialchars($params['transfersecret']);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-transfer-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <transfer op="request">
      <domain:transfer
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
        <domain:period unit="y">{{ years }}</domain:period>
        <domain:authInfo>
          <domain:pw>{{ authInfo_pw }}</domain:pw>
        </domain:authInfo>
      </domain:transfer>
    </transfer>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->trnData;
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_GetNameservers(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $i = 0;
        foreach($r->ns->hostObj as $ns) {
            $i++;
            $return["ns{$i}"] = (string)$ns;
        }

        $status = [];
        $domainId = $params['domainid'];
        if (!empty($params['gtld'])) {
            $domainId = epp_getWhmcsDomainIdFromNamingo($params['sld'] . '.' . ltrim($params['tld'], '.'));
        }
        Capsule::table('epp_domain_status')->where('domain_id', $domainId)->delete();

        foreach ($r->status as $e) {
            $st = (string)$e->attributes()->s;

            if ($st === 'pendingDelete') {
                Capsule::table('tbldomains')->where('id', $domainId)->update(['status' => 'Cancelled']);
            }

            Capsule::table('epp_domain_status')->insert([
                'domain_id' => $domainId,
                'status'    => $st,
            ]);
        }
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_SaveNameservers(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $add = $rem = array();
        $i = 0;
        foreach($r->ns->hostObj as $ns) {
            $i++;
            $ns = (string)$ns;
            if (!$ns) {
                continue;
            }

            $rem["ns{$i}"] = $ns;
        }

        foreach($params as $k => $v) {
            if (!$v) {
                continue;
            }

            if (!preg_match("/^ns\d$/i", $k)) {
                continue;
            }

            if ($k0 = array_search($v, $rem)) {
                unset($rem[$k0]);
            }
            else {
                $add[$k] = $v;
            }
        }

        if (!empty($add) || !empty($rem)) {
            // Ensure new nameserver hosts exist
            foreach ($add as $k => $nsName) {
                $nsName = trim((string)$nsName);
                if ($nsName === '') {
                    continue;
                }

                // host:check
                $from = $to = [];

                $from[] = '/{{ name }}/';
                $to[]   = htmlspecialchars($nsName);

                $from[] = '/{{ clTRID }}/';
                $clTRID = str_replace('.', '', round(microtime(1), 3));
                $to[]   = htmlspecialchars($params['registrarprefix'] . '-host-check-' . $clTRID);

                $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <check>
      <host:check
        xmlns:host="urn:ietf:params:xml:ns:host-1.0"
        xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
        <host:name>{{ name }}</host:name>
      </host:check>
    </check>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');

                $r = $s->write($xml, __FUNCTION__);
                $chk = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->chkData;

                // If host exists already, avail="0" (so nothing to do)
                if (0 == (int)$chk->cd[0]->name->attributes()->avail) {
                    continue;
                }

                // host:create
                $from = $to = [];

                $from[] = '/{{ name }}/';
                $to[]   = htmlspecialchars($nsName);

                $from[] = '/{{ clTRID }}/';
                $clTRID = str_replace('.', '', round(microtime(1), 3));
                $to[]   = htmlspecialchars($params['registrarprefix'] . '-host-create-' . $clTRID);

                $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <create>
      <host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
      </host:create>
    </create>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');

                $s->write($xml, __FUNCTION__);
            }

            $from = $to = [];

            $text = '';
            foreach($add as $k => $v) {
                $text.= '<domain:hostObj>' . $v . '</domain:hostObj>' . "\n";
            }

            $from[] = '/{{ add }}/';
            $to[] = (empty($text) ? '' : "<domain:add><domain:ns>\n{$text}</domain:ns></domain:add>\n");
            $text = '';
            foreach($rem as $k => $v) {
                $text.= '<domain:hostObj>' . $v . '</domain:hostObj>' . "\n";
            }

            $from[] = '/{{ rem }}/';
            $to[] = (empty($text) ? '' : "<domain:rem><domain:ns>\n{$text}</domain:ns></domain:rem>\n");
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
        {{ add }}
        {{ rem }}
      </domain:update>
    </update>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_CheckAvailability(array $params = [])
{
    try {
        $s = _epp_startEppClient($params);

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

            $from = $to = [];
            $from[] = '/{{ name }}/';
            $to[]   = htmlspecialchars($fqdn);

            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(true), 3));
            $to[]   = htmlspecialchars($params['registrarprefix'] . '-domain-check-' . $clTRID);

            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <check>
      <domain:check
        xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
        xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:check>
    </check>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');

            $r = $s->write($xml, __FUNCTION__);

            $chkData = $r->response->resData
                ->children('urn:ietf:params:xml:ns:domain-1.0')
                ->chkData;

            $avail  = (int) ($chkData->cd[0]->name->attributes()->avail ?? 0);
            $reason = (string) ($chkData->cd[0]->reason ?? '');

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

    } catch (\Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

function epp_GetRegistrarLock(array $params = [])
{
    $return = 'unlocked';
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        foreach($r->status as $e) {
            $attr = $e->attributes();
            if (preg_match("/clientTransferProhibited/i", $attr['s'])) {
                $return = 'locked';
            }
        }
    }

    catch (\Throwable $e) {
        $return = 'locked';
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_SaveRegistrarLock(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $status = array();
        foreach($r->status as $e) {
            $st = (string)$e->attributes()->s;
            if (!preg_match("/^client.+Prohibited$/i", $st)) {
                continue;
            }

            $status[$st] = true;
        }

        $rem = $add = array();
        foreach(array(
            'clientDeleteProhibited',
            'clientTransferProhibited'
        ) as $st) {
            if ($params["lockenabled"] == 'locked') {
                if (!isset($status[$st])) {
                    $add[] = $st;
                }
            }
            else {
                if (isset($status[$st])) {
                    $rem[] = $st;
                }
            }
        }

        if (!empty($add) || !empty($rem)) {
            $text = '';
            foreach($add as $st) {
                $text.= '<domain:status s="' . $st . '" lang="en"></domain:status>' . "\n";
            }

            $from[] = '/{{ add }}/';
            $to[] = (empty($text) ? '' : "<domain:add>\n{$text}</domain:add>\n");
            $text = '';
            foreach($rem as $st) {
                $text.= '<domain:status s="' . $st . '" lang="en"></domain:status>' . "\n";
            }

            $from[] = '/{{ rem }}/';
            $to[] = (empty($text) ? '' : "<domain:rem>\n{$text}</domain:rem>\n");
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
        {{ rem }}
        {{ add }}
      </domain:update>
    </update>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_GetContactDetails(array $params = [])
{
    if (!empty($params['min_data_set'])) {
        return [];
    }

    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $dcontact = array();
        $dcontact['registrant'] = (string)$r->registrant;
        foreach($r->contact as $e) {
            $type = (string)$e->attributes()->type;
            $dcontact[$type] = (string)$e;
        }

        $contact = array();
        foreach($dcontact as $id) {
            if (isset($contact[$id])) {
                continue;
            }

            $from = $to = [];

            $from[] = '/{{ id }}/';
            $to[] = htmlspecialchars($id);
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-contact-info-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <contact:info
       xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
        <contact:id>{{ id }}</contact:id>
      </contact:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:contact-1.0')->infData[0];
            $contact[$id] = array();
            $c = & $contact[$id];
            foreach($r->postalInfo as $e) {
                $c["Name"] = (string)$e->name;
                $c["Organization"] = (string)$e->org;
                for ($i = 0; $i <= 2; $i++) {
                    $c["Street " . ($i + 1) ] = (string)$e->addr->street[$i];
                }

                if (empty($c["Street 3"])) {
                    unset($c["street3"]);
                }

                $c["City"] = (string)$e->addr->city;
                $c["State or Province"] = (string)$e->addr->sp;
                $c["Postal Code"] = (string)$e->addr->pc;
                $c["Country Code"] = (string)$e->addr->cc;
                break;
            }

            $c["Phone"] = (string)$r->voice;
            $c["Fax"] = (string)$r->fax;
            $c["Email"] = (string)$r->email;
        }

        foreach($dcontact as $type => $id) {
            if ($type == 'registrant') {
                $type = 'Registrant';
            }
            elseif ($type == 'admin') {
                $type = 'Administrator';
            }
            elseif ($type == 'tech') {
                $type = 'Technical';
            }
            elseif ($type == 'billing') {
                $type = 'Billing';
            }
            else {
                continue;
            }

            $return[$type] = $contact[$id];
        }
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_SaveContactDetails(array $params = [])
{
    if (!empty($params['min_data_set'])) {
        return ['success' => true];
    }

    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $dcontact = array();
        $dcontact['registrant'] = (string)$r->registrant;
        foreach($r->contact as $e) {
            $type = (string)$e->attributes()->type;
            $dcontact[$type] = (string)$e;
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

            $from = $to = [];


            $from[] = '/{{ id }}/';
            $to[] = htmlspecialchars($id);

            $from[] = '/{{ name }}/';
            $name = ($a['Name'] ? $a['Name'] : $a['Full Name']);
            $to[] = htmlspecialchars($name);

            $from[] = '/{{ org }}/';
            $org = ($a['Organization'] ? $a['Organization'] : $a['Organisation Name']);
            $to[] = htmlspecialchars($org);

            $from[] = '/{{ street1 }}/';
            $street1 = ($a['Street 1'] ? $a['Street 1'] : $a['Address 1']);
            $to[] = htmlspecialchars($street1);

            $from[] = '/{{ street2 }}/';
            $street2 = ($a['Street 2'] ? $a['Street 2'] : $a['Address 2']);
            $to[] = htmlspecialchars($street2);

            $from[] = '/{{ street3 }}/';
            $street3 = ($a['Street 3'] ? $a['Street 3'] : $a['Address 3']);
            $to[] = htmlspecialchars($street3);

            $from[] = '/{{ city }}/';
            $to[] = htmlspecialchars($a['City']);

            $from[] = '/{{ sp }}/';
            $sp = ($a['State or Province'] ? $a['State or Province'] : $a['State']);
            $to[] = htmlspecialchars($sp);

            $from[] = '/{{ pc }}/';
            $pc = ($a['Postal Code'] ? $a['Postal Code'] : $a['Postcode']);
            $to[] = htmlspecialchars($pc);

            $from[] = '/{{ cc }}/';
            $cc = ($a['Country Code'] ? $a['Country Code'] : $a['Country']);
            $to[] = htmlspecialchars($cc);

            $from[] = '/{{ voice }}/';
            $to[] = htmlspecialchars($a['Phone']);

            $from[] = '/{{ fax }}/';
            $to[] = htmlspecialchars($a['Fax']);

            $from[] = '/{{ email }}/';
            $to[] = htmlspecialchars($a['Email']);

            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-contact-chg-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
        <contact:id>{{ id }}</contact:id>
        <contact:chg>
          <contact:postalInfo type="int">
            <contact:name>{{ name }}</contact:name>
            <contact:org>{{ org }}</contact:org>
            <contact:addr>
              <contact:street>{{ street1 }}</contact:street>
              <contact:street>{{ street2 }}</contact:street>
              <contact:street>{{ street3 }}</contact:street>
              <contact:city>{{ city }}</contact:city>
              <contact:sp>{{ sp }}</contact:sp>
              <contact:pc>{{ pc }}</contact:pc>
              <contact:cc>{{ cc }}</contact:cc>
            </contact:addr>
          </contact:postalInfo>
          <contact:voice>{{ voice }}</contact:voice>
          <contact:fax>{{ fax }}</contact:fax>
          <contact:email>{{ email }}</contact:email>
        </contact:chg>
      </contact:update>
    </update>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_IDProtectToggle(array $params = [])
{
    if (!empty($params['min_data_set'])) {
        return ['success' => true];
    }

    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $dcontact = array();
        $dcontact['registrant'] = (string)$r->registrant;
        foreach($r->contact as $e) {
            $type = (string)$e->attributes()->type;
            $dcontact[$type] = (string)$e;
        }

        $contact = array();
        foreach($dcontact as $id) {
            if (isset($contact[$id])) {
                continue;
            }

            $from = $to = [];

            $from[] = '/{{ id }}/';
            $to[] = htmlspecialchars($id);

            $from[] = '/{{ flag }}/';
            $to[] = ($params['protectenable'] ? 1 : 0);

            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1) , 3));
            $to[] = htmlspecialchars($params['RegistrarPrefix'] . '-contact-update-' . $clTRID);

            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
        <contact:id>{{ id }}</contact:id>
        <contact:chg>
          <contact:disclose flag="{{ flag }}">
            <contact:name type="int"/>
            <contact:addr type="int"/>
            <contact:voice/>
            <contact:fax/>
            <contact:email/>
          </contact:disclose>
        </contact:chg>
      </contact:update>
    </update>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['RegistrarPrefix']);
    }

    return $return;
}

function epp_GetEPPCode(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];
        
        if (!empty($params['set_authinfo_on_info'])) {
            $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            $symbols = '!@-';

            $authInfo = $symbols[random_int(0, strlen($symbols) - 1)];
            $charLen = strlen($characters);

            for ($i = 1; $i < 16; $i++) {
                $authInfo .= $characters[random_int(0, $charLen - 1)];
            }

            $eppcode = str_shuffle($authInfo);

            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['domainname']);
            $from[] = '/{{ authInfo }}/';
            $to[] = $eppcode;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
     <command>
       <update>
         <domain:update
          xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
          xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
           <domain:name>{{ name }}</domain:name>
           <domain:chg>
             <domain:authInfo>
               <domain:pw>{{ authInfo }}</domain:pw>
             </domain:authInfo>
           </domain:chg>
         </domain:update>
       </update>
       <clTRID>{{ clTRID }}</clTRID>
     </command>
    </epp>');
            $r = $s->write($xml, __FUNCTION__);
        } else {
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <info>
          <domain:info
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
           xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name hosts="all">{{ name }}</domain:name>
          </domain:info>
        </info>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
            $r = $s->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
            $eppcode = (string)$r->authInfo->pw;
        }

        if (!empty($s)) {
            $s->logout($params['registrarprefix']);
        }
        return array('eppcode' => $eppcode);
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_RegisterNameserver(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['nameserver']);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <check>
      <host:check
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
      </host:check>
    </check>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->chkData;
        if (0 == (int)$r->cd[0]->name->attributes()->avail) {
            throw new exception($r->cd[0]->name . " " . $r->cd[0]->reason);
        }

        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['nameserver']);
        $from[] = '/{{ ip }}/';
        $to[] = htmlspecialchars($params['ipaddress']);
        $from[] = '/{{ v }}/';
        $to[] = (preg_match('/:/', $params['ipaddress']) ? 'v6' : 'v4');
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-create-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <create>
      <host:create
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
        <host:addr ip="{{ v }}">{{ ip }}</host:addr>
      </host:create>
    </create>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_ModifyNameserver(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['nameserver']);
        $from[] = '/{{ ip1 }}/';
        $to[] = htmlspecialchars($params['currentipaddress']);
        $from[] = '/{{ v1 }}/';
        $to[] = (preg_match('/:/', $params['currentipaddress']) ? 'v6' : 'v4');
        $from[] = '/{{ ip2 }}/';
        $to[] = htmlspecialchars($params['newipaddress']);
        $from[] = '/{{ v2 }}/';
        $to[] = (preg_match('/:/', $params['newipaddress']) ? 'v6' : 'v4');
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-update-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <host:update
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
        <host:add>
          <host:addr ip="{{ v2 }}">{{ ip2 }}</host:addr>
        </host:add>
        <host:rem>
          <host:addr ip="{{ v1 }}">{{ ip1 }}</host:addr>
        </host:rem>
      </host:update>
    </update>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_DeleteNameserver(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['nameserver']);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-delete-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <delete>
      <host:delete
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
      </host:delete>
    </delete>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_RequestDelete(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-delete-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <delete>
      <domain:delete
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
      </domain:delete>
    </delete>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_manageDNSSECDSRecords(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);

        if (isset($_POST['command']) && ($_POST['command'] === 'secDNSadd')) {
            $keyTag = $_POST['keyTag'];
            $alg = $_POST['alg'];
            $digestType = $_POST['digestType'];
            $digest = $_POST['digest'];

            $from = $to = [];

            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));

            $from[] = '/{{ keyTag }}/';
            $to[] = htmlspecialchars($keyTag);

            $from[] = '/{{ alg }}/';
            $to[] = htmlspecialchars($alg);

            $from[] = '/{{ digestType }}/';
            $to[] = htmlspecialchars($digestType);

            $from[] = '/{{ digest }}/';
            $to[] = htmlspecialchars($digest);

            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:update>
    </update>
    <extension>
      <secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
        <secDNS:add>
          <secDNS:dsData>
            <secDNS:keyTag>{{ keyTag }}</secDNS:keyTag>
            <secDNS:alg>{{ alg }}</secDNS:alg>
            <secDNS:digestType>{{ digestType }}</secDNS:digestType>
            <secDNS:digest>{{ digest }}</secDNS:digest>
          </secDNS:dsData>
        </secDNS:add>
      </secDNS:update>
    </extension>    
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }

        if (isset($_POST['command']) && ($_POST['command'] === 'secDNSrem')) {
            $keyTag = $_POST['keyTag'];
            $alg = $_POST['alg'];
            $digestType = $_POST['digestType'];
            $digest = $_POST['digest'];

            $from = $to = [];

            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));

            $from[] = '/{{ keyTag }}/';
            $to[] = htmlspecialchars($keyTag);

            $from[] = '/{{ alg }}/';
            $to[] = htmlspecialchars($alg);

            $from[] = '/{{ digestType }}/';
            $to[] = htmlspecialchars($digestType);

            $from[] = '/{{ digest }}/';
            $to[] = htmlspecialchars($digest);

            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:update>
    </update>
    <extension>
      <secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
        <secDNS:rem>
          <secDNS:dsData>
            <secDNS:keyTag>{{ keyTag }}</secDNS:keyTag>
            <secDNS:alg>{{ alg }}</secDNS:alg>
            <secDNS:digestType>{{ digestType }}</secDNS:digestType>
            <secDNS:digest>{{ digest }}</secDNS:digest>
          </secDNS:dsData>
        </secDNS:rem>
      </secDNS:update>
    </extension>    
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }

        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);

        $secDNSdsData = array();
        if ($r->response->extension && $r->response->extension->children('urn:ietf:params:xml:ns:secDNS-1.1')->infData) {
            $DSRecords = 'YES';
            $i = 0;
            $r = $r->response->extension->children('urn:ietf:params:xml:ns:secDNS-1.1')->infData;
            foreach($r->dsData as $dsData) {
                $i++;
                $secDNSdsData[$i]["domainid"] = (int)$params['domainid'];
                $secDNSdsData[$i]["keyTag"] = (string)$dsData->keyTag;
                $secDNSdsData[$i]["alg"] = (int)$dsData->alg;
                $secDNSdsData[$i]["digestType"] = (int)$dsData->digestType;
                $secDNSdsData[$i]["digest"] = (string)$dsData->digest;
            }
        }
        else {
            $DSRecords = "You don't have any DS records";
        }

        $return = array(
            'templatefile' => 'manageDNSSECDSRecords',
            'requirelogin' => true,
            'vars' => array(
                'DSRecords' => $DSRecords,
                'DSRecordslist' => $secDNSdsData
            )
        );
    }

    catch (\Throwable $e) {
        return [
            'templatefile' => 'manageDNSSECDSRecords',
            'requirelogin' => true,
            'vars' => [
                'error' => $e->getMessage(),
            ],
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
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
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $status = array();
        $existing_status = 'ok';
        foreach($r->status as $e) {
            $st = (string)$e->attributes()->s;
            if ($st == 'clientHold') {
                $existing_status = 'clientHold';
                break;
            }

            if ($st == 'serverHold') {
                $existing_status = 'serverHold';
                break;
            }
        }

        if ($existing_status == 'ok') {
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
        <domain:add>
          <domain:status s="clientHold" lang="en">clientHold</domain:status>
        </domain:add>
      </domain:update>
    </update>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_UnHoldDomain(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $status = array();
        $existing_status = 'ok';
        foreach($r->status as $e) {
            $st = (string)$e->attributes()->s;
            if ($st == 'clientHold') {
                $existing_status = 'clientHold';
                break;
            }
        }

        if ($existing_status == 'clientHold') {
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
        <domain:rem>
          <domain:status s="clientHold" lang="en">clientHold</domain:status>
        </domain:rem>
      </domain:update>
    </update>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_ApproveTransfer($params) {
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-transfer-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <transfer op="approve">
      <domain:transfer
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
      </domain:transfer>
    </transfer>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->trnData;
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_CancelTransfer($params) {
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-transfer-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <transfer op="cancel">
      <domain:transfer
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
      </domain:transfer>
    </transfer>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->trnData;
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_RejectTransfer($params) {
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-transfer-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <transfer op="reject">
      <domain:transfer
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
      </domain:transfer>
    </transfer>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->trnData;
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_TransferSync(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-transfer-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <transfer op="query">
      <domain:transfer
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:transfer>
    </transfer>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->trnData;
        $trStatus = (string)$r->trStatus;
        $expDate = (string)$r->exDate;
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
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function epp_Sync(array $params = [])
{
    $return = [];
    try {
        $s = _epp_startEppClient($params);
        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $expDate = (string)$r->exDate;
        $roid = (string)$r->roid;
        $timestamp = strtotime($expDate);

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

        if ($timestamp < time()) {
            return array(
                'expirydate'    =>  $expDate,
                'expired'       =>  true
            );            
        }
        else {
            return array(
                'expirydate'    =>  $expDate,
                'active'        =>  true
            );
        }
    }

    catch (\Throwable $e) {
        return [
            'error' => $e->getMessage(),
        ];
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

class epp_epp_client

{
    var $socket;
    var $isLogined = false;
    var $params;
    function __construct($params)
    {
        $this->params = $params;
        $verify_peer = false;
        if ($params['verify_peer'] == 'on') {
            $verify_peer = true;
        }
        $ssl = array(
            'verify_peer' => $verify_peer,
            'cafile' => $params['cafile'],
            'local_cert' => $params['local_cert'],
            'local_pk' => $params['local_pk'],
            'passphrase' => $params['passphrase']
        );
        $host = $params['host'];
        $port = $params['port'];

        if ($host) {
            $this->connect($host, $port, $ssl);
        }
    }

    function connect($host, $port = 700, $ssl, $timeout = 30)
    {
        if ($host != $this->params['host']) {
            throw new exception("Unknown EPP server '$host'");
        }
        
        $tls_version = '1.2';
        if (!empty($this->params['tls_version'])) {
            $tls_version = '1.3';
        }

        $opts = array(
            'ssl' => array(
                'verify_peer' => $ssl['verify_peer'],
                'verify_peer_name' => false,
                'verify_host' => false,
                'cafile' => __DIR__ . '/' . $ssl['cafile'],
                'local_cert' => __DIR__ . '/' . $ssl['local_cert'],
                'local_pk' => __DIR__ . '/' . $ssl['local_pk'],
                'passphrase' => $ssl['passphrase'],
                'allow_self_signed' => true
            )
        );
        $context = stream_context_create($opts);
        $this->socket = stream_socket_client("tlsv{$tls_version}://{$host}:{$port}", $errno, $errmsg, $timeout, STREAM_CLIENT_CONNECT, $context);


        if (!$this->socket) {
            throw new exception("Cannot connect to server '{$host}': {$errmsg}");
        }

        return $this->read();
    }

    function login($login, $pwd, $prefix)
    {
        $from = $to = [];

        $from[] = '/{{ clID }}/';
        $to[] = htmlspecialchars($login);
        $from[] = '/{{ pw }}/';
        $to[] = $pwd;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($prefix . '-login-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <login>
      <clID>{{ clID }}</clID>
      <pw><![CDATA[{{ pw }}]]></pw>
      <options>
        <version>1.0</version>
        <lang>en</lang>
      </options>
      <svcs>
        <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
        <svcExtension>
          <extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI>
        </svcExtension>
      </svcs>
    </login>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $this->write($xml, __FUNCTION__);
        $this->isLogined = true;
        return true;
    }

    function logout($prefix)
    {
        if (!$this->isLogined) {
            return true;
        }

        $from = $to = [];

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($prefix . '-logout-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <logout/>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $this->write($xml, __FUNCTION__);
        $this->isLogined = false;
        return true;
    }

    function read()
    {
        $hdr = stream_get_contents($this->socket, 4);
        if ($hdr === false) {
            throw new exception('Connection appears to have closed.');
        }
        if (strlen($hdr) < 4) {
            throw new exception('Unable to connect to EPP server.');
        }
        $unpacked = unpack('N', $hdr);
        $xml = fread($this->socket, ($unpacked[1] - 4));
        return $xml;
    }

    function write($xml, $action = 'Unknown')
    {
        if (fwrite($this->socket, pack('N', (strlen($xml) + 4)) . $xml) === false) {
            throw new exception('Error writing to the connection.');
        }
        $r = simplexml_load_string($this->read());
        _epp_modulelog($xml, $r, $action);
        if (isset($r->response) && $r->response->result->attributes()->code >= 2000) {
            throw new exception($r->response->result->msg);
        }
        return $r;
    }

    function disconnect()
    {
        $result = fclose($this->socket);
        if (!$result) {
            throw new exception('Error closing the connection.');
        }
        $this->socket = null;
        return $result;
    }

    function generateObjectPW($objType = 'none')
    {
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
    
    function generateRandomString() 
    {
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $randomString = '';
        for ($i = 0; $i < 16; $i++) {
            $randomString .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $randomString;
    }

}

function _epp_modulelog($send, $responsedata, $action)
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

function _epp_create_table()
{
    //    Capsule::schema()->table('tbldomains', function (Blueprint $table) {
    //        $table->increments('id')->unsigned()->change();
    //    });

    if (!Capsule::schema()->hasTable('epp_domain_status')) {
        try {
            Capsule::schema()->create('epp_domain_status',
            function (Blueprint $table)
            {
                /** @var \Illuminate\Database\Schema\Blueprint $table */
                $table->increments('id');
                $table->integer('domain_id');

                // $table->integer('domain_id')->unsigned();

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

function _epp_create_column()
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
        // Insert into namingo_contact table
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

        // Save the last insert ID
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