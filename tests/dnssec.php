<?php
/** Run with php tests/dnssec.php; no WHMCS installation or registry needed. */
define('WHMCS', true);
require dirname(__DIR__) . '/epp.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function rejected(array $record): void
{
    try {
        epp_readDnssecDsRecord($record);
    } catch (InvalidArgumentException $e) {
        return;
    }
    throw new RuntimeException('Invalid DS record was accepted');
}

// Exercise the bundled EPP serializer while replacing only the network boundary.
class DnssecTestEpp extends \Pinga\Tembo\Registries\GenericEpp
{
    public string $request = '';

    public function __construct()
    {
        parent::__construct();
        $this->isLoggedIn = true;
        $this->prefix = 'test';
    }

    public function writeRequest($xml)
    {
        $this->request = $xml;
        return simplexml_load_string('<epp><response><result code="1000"><msg>OK</msg></result></response></epp>');
    }
}

$epp = new DnssecTestEpp();
foreach ([8, 13, 14, 15, 16, 17, 18] as $algorithm) {
    foreach ([2 => 64, 4 => 96, 6 => 64] as $digestType => $length) {
        foreach ([0, 65535] as $keyTag) {
            $input = ['keyTag' => (string) $keyTag, 'alg' => (string) $algorithm,
                'digestType' => (string) $digestType, 'digest' => chunk_split(str_repeat('ab', $length / 2), 16, " \n")];
            $record = epp_readDnssecDsRecord($input);
            check($record === ['keyTag' => $keyTag, 'alg' => $algorithm,
                'digestType' => $digestType, 'digest' => str_repeat('AB', $length / 2)], 'DS normalization failed');
            foreach (['add', 'rem'] as $command) {
                $result = $epp->domainUpdateDNSSEC([
                    'domainname' => 'example.test', 'command' => $command,
                    'keyTag_1' => $record['keyTag'], 'alg_1' => $record['alg'],
                    'digestType_1' => $record['digestType'], 'digest_1' => $record['digest'],
                ]);
                check(($result['code'] ?? null) === 1000, 'EPP serialization failed');
                $xml = simplexml_load_string($epp->request);
                $xml->registerXPathNamespace('s', 'urn:ietf:params:xml:ns:secDNS-1.1');
                $ds = $xml->xpath('//s:' . $command . '/s:dsData')[0]->children('urn:ietf:params:xml:ns:secDNS-1.1');
                check((int) $ds->keyTag === $keyTag && (int) $ds->alg === $algorithm
                    && (int) $ds->digestType === $digestType && (string) $ds->digest === $record['digest'], 'DS values changed on the wire');
            }
            foreach ([$length - 2, $length + 2] as $badLength) {
                rejected(array_replace($input, ['digest' => str_repeat('A', $badLength)]));
            }
        }
    }
}

$valid = ['keyTag' => '0', 'alg' => '18', 'digestType' => '6', 'digest' => str_repeat('A', 64)];
foreach (['keyTag' => [-1, 65536, '1x', '', null, true, [], '1.5'],
    'alg' => [0, 256, '18x', []], 'digestType' => [0, 256, '6x', []],
    'digest' => ['', str_repeat('G', 64), str_repeat('A', 63), null, []]] as $field => $values) {
    foreach ($values as $value) {
        rejected(array_replace($valid, [$field => $value]));
    }
}
foreach (array_keys($valid) as $field) {
    $missing = $valid;
    unset($missing[$field]);
    rejected($missing);
}
// Preserve handling of registry-specific/legacy values, including removal.
check(epp_readDnssecDsRecord(array_replace($valid, ['alg' => 5, 'digestType' => 1, 'digest' => str_repeat('A', 40)]))['alg'] === 5, 'Legacy DS rejected');
check(epp_readDnssecDsRecord(array_replace($valid, ['alg' => 253, 'digestType' => 3]))['alg'] === 253, 'Registry-specific DS rejected');
// Private digest types must remain removable even outside common digest lengths.
foreach ([253, 254] as $digestType) {
    foreach ([2, 32, 130, 256] as $length) {
        $record = epp_readDnssecDsRecord(array_replace($valid, [
            'digestType' => $digestType, 'digest' => str_repeat('ab', $length / 2),
        ]));
        $result = $epp->domainUpdateDNSSEC([
            'domainname' => 'example.test', 'command' => 'rem',
            'keyTag_1' => $record['keyTag'], 'alg_1' => $record['alg'],
            'digestType_1' => $record['digestType'], 'digest_1' => $record['digest'],
        ]);
        check(($result['code'] ?? null) === 1000, 'Private digest removal failed');
        $xml = simplexml_load_string($epp->request);
        $xml->registerXPathNamespace('s', 'urn:ietf:params:xml:ns:secDNS-1.1');
        $ds = $xml->xpath('//s:rem/s:dsData')[0]->children('urn:ietf:params:xml:ns:secDNS-1.1');
        check((int) $ds->digestType === $digestType && (string) $ds->digest === str_repeat('AB', $length / 2), 'Private digest changed on removal');
    }
    foreach (['', ' ', 'A', 'ABC', 'GG', 'AABBZZ'] as $digest) {
        rejected(array_replace($valid, ['digestType' => $digestType, 'digest' => $digest]));
    }
}
echo "DNSSEC validation and EPP add/remove serialization checks passed.\n";
