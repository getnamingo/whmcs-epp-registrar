# WHMCS EPP Registrar

[![StandWithUkraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

A generic WHMCS registrar module for connecting to any domain registry that uses the EPP protocol.

This module is designed to work with both gTLD and ccTLD registries and provides a flexible foundation for EPP-based domain management in WHMCS.

## Compatibility

This module is supposed to work with:

- Any Generic RFC EPP registry.

- Caucasus Online - .ge

- CentralNic - all

- CoCCA - all

- CORE/Knipp - all

- GoDaddy Registry - all

- Google Nomulus - all

- HKIRC - .hk

- Identity Digital - all

- RoTLD - .ro

- RyCE - all

- SIDN - all

- ZADNA - .za

- ZDNS - .all

## Installation

1. Download and install [WHMCS](https://whmcs.com/)

2. Place the repository as **epp** directory in `[WHMCS]/modules/registrars`, place your key.pem and cert.pem files in the same epp directory.

3. Activate from Configuration -> Apps & Integrations -> (search for _epp_) -> Activate

4. Configure from Configuration -> System Settings -> Domain Registrars

5. Add a new TLD using Configuration -> System Settings -> Domain Pricing

6. Create a **whois.json** file in `[WHMCS]/resources/domains` and add the following:

```
[
    {
        "extensions": ".yourtld",
        "uri": "socket://your.whois.url",
        "available": "NOT FOUND"
    }
]
```

You should be good to go now.

## Troubleshooting

### Fixing "Oops!" Issues in WHMCS

If you experience "Oops!" or blank page errors in WHMCS after activating the EPP module, it might be caused by incorrect file permissions or ownership. Follow these steps to fix it:

```bash
chown -R www-data:www-data /var/www/html/whmcs/modules/registrars/epp
chmod -R 755 /var/www/html/whmcs/modules/registrars/epp
```

Replace `/var/www/html/whmcs` with the path to your WHMCS installation, if different.

### Generating an SSL Certificate and Key

If you do not have an SSL certificate and private key for secure communication with the registry, you can generate one using OpenSSL.

```bash
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 365
```

**Note:** For production environments, it's recommended to use a certificate signed by a trusted Certificate Authority (CA) instead of a self-signed certificate.

## Need More Help?

If the steps above don’t resolve your issue, refer to the WHMCS logs (`/path/to/whmcs/logs`) or enable `Display Errors` in the WHMCS Admin under `Utilities > System > General Settings > Other` to identify the specific problem.