# WHMCS EPP Registrar

[![StandWithUkraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

A generic WHMCS registrar module for connecting to any domain registry that uses the EPP protocol.

This module is designed to work with both gTLD and ccTLD registries and provides a flexible foundation for EPP-based domain management in WHMCS.

## Registry Support

| Registry | TLDs | Profile | Needs |
|----------|----------|----------|----------|
| Generic RFC EPP | any | | |
| AFNIC | .fr/others | FR | |
| CARNET | .hr | HR | |
| CentralNic | all | | Set AuthInfo on Request |
| CoCCA | all | | Set AuthInfo on Request |
| CORE/Knipp | all | | |
| Domicilium | .im | | |
| DRS.UA | all | | | |
| EURid | .eu | EU | |
| GoDaddy Registry | all | | |
| Google Nomulus | all | | |
| Hostmaster | .ua | UA | |
| Identity Digital | all | | |
| IIS | .se, .nu | SE | |
| IT.COM | all | | |
| Namingo | all | | |
| NASK | .pl | PL | |
| NIC Chile | .cl | | |
| NIC Mexico | .mx | MX | |
| NIC.LV | .lv | LV | |
| .PT | .pt | PT | |
| Regtons | all | | |
| RoTLD | .ro | | |
| RyCE | all | | |
| SIDN | all | | |
| SWITCH | .ch, .li | SWITCH | Set AuthInfo on Request |
| Tucows Registry | all | | |
| Verisign | all | VRSN | |
| ZADNA | .za | | |
| ZDNS | all | | |

### In Progress

| Registry | TLDs | Profile | Status |
|----------|----------|----------|----------|
| Caucasus Online | .ge | | |
| DENIC | .de | DE | |
| DOMREG | .lt | LT | |
| FORTH-ICS | .gr, .ελ | GR | |
| FRED | .cz/any | FRED | |
| NORID | .no | NO | |

### Paid Registry Support

| Registry | TLDs | Profile | Status |
|----------|----------|----------|----------|
| HKIRC | .hk | HK | |
| Internet.ee | .ee | EE | |
| Registro.it | .it | IT | |
| Traficom | .fr | FI | |

## Installation

1. Use our **[Module Customizer Tool](https://namingo.org/whmcs-module/)** to generate a fine-tuned EPP registrar module specifically for your registry.

2. Place the **generated registrar module directory** (as produced by the Module Customizer Tool) into  
   `[WHMCS_path]/modules/registrars/`.  
   Then place your `key.pem` and `cert.pem` files inside that same generated module directory.

3. Ensure correct file permissions:
```bash
chown -R www-data:www-data [WHMCS_path]/modules/registrars/[MODULE]
chmod -R 755 [WHMCS_path]/modules/registrars/[MODULE]
```

4. Activate from Configuration -> Apps & Integrations -> (search for _[MODULE]_) -> Activate

5. Configure from Configuration -> System Settings -> Domain Registrars

6. Add a new TLD using Configuration -> System Settings -> Domain Pricing

7. Create a **whois.json** file in `[WHMCS]/resources/domains` and add the following:

```
[
    {
        "extensions": ".yourtld",
        "uri": "socket://your.whois.url",
        "available": "NOT FOUND"
    }
]
```

## Troubleshooting

### Running Multiple Instances of the WHMCS EPP Registrar Module

WHMCS **does not support running multiple instances of the same registrar module** at the same time.

This limitation exists because WHMCS identifies registrar modules by:
- the **module folder name**, and
- the **global PHP function names** defined by the module.

If you try to use the same EPP registrar module for multiple registries (for example: `.eu`, `.ua`, a test registry, and a production registry), you will encounter issues such as:
- function redeclaration errors,
- module settings overwriting each other,
- unpredictable behavior when provisioning or managing domains.

The supported solution is to **duplicate the module and rename its functions** so that each registry has its own uniquely named module.

Each module instance:
- has its **own configuration**
- talks to **one specific registry**
- avoids function name collisions

To simplify this process, we provide a **WHMCS Module Customizer Tool** that automatically:

- duplicates the module,
- renames all required functions,
- adjusts internal references,
- prepares the module for a specific registry.

You can use the tool here:  
👉 **https://namingo.org/whmcs-module/**

This is the safest way to run **multiple EPP registries in parallel** within a single WHMCS installation.

### EPP Server Access

If you're unsure whether your system can access the EPP server, you can test the connection using OpenSSL. Try one or both of the following commands:

1. Basic Connectivity Test:

```bash
openssl s_client -showcerts -connect epp.example.com:700
```

2. Test with Client Certificates:

```bash
openssl s_client -connect epp.example.com:700 -CAfile cacert.pem -cert cert.pem -key key.pem
```

Replace `epp.example.com` with your EPP server's hostname and adjust the paths to your certificate files (`cacert.pem`, `cert.pem`, and `key.pem`) as needed. These tests can help identify issues with SSL/TLS configurations or network connectivity.

### Generating an SSL Certificate and Key

If you do not have an SSL certificate and private key for secure communication with the registry, you can generate one using OpenSSL.

```bash
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 365
```

**Note:** For production environments, it's recommended to use a certificate signed by a trusted Certificate Authority (CA) instead of a self-signed certificate.

#### EPP-over-HTTPS Issues

If you experience login or other issues with EPP-over-HTTPS registries such as `.eu`, `.fi`, `.hr`, `.it`, or `.lv`, it might be caused by a corrupted or outdated cookie file. Follow these steps to fix it:

```bash
rm -f /tmp/eppcookie.txt
```

After deleting the cookie file, try logging in again. This will force the creation of a new cookie file and may resolve the issue.

### Need More Help?

If the steps above don’t resolve your issue, refer to the WHMCS logs or enable `Display Errors` in the WHMCS Admin under `Utilities > System > General Settings > Other` to identify the specific problem.

## Support

Your feedback and inquiries are invaluable to Namingo's evolutionary journey. If you need support, have questions, or want to contribute your thoughts:

- **Email**: Feel free to reach out directly at [help@namingo.org](mailto:help@namingo.org).

- **Discord**: Or chat with us on our [Discord](https://discord.gg/97R9VCrWgc) channel.
  
- **GitHub Issues**: For bug reports or feature requests, please use the [Issues](https://github.com/getnamingo/whmcs-epp-registrar/issues) section of our GitHub repository.

We appreciate your involvement and patience as Namingo continues to grow and adapt.

## 💖 Support This Project

If you find WHMCS EPP Registrar useful, consider donating:

- [Donate via Stripe](https://donate.stripe.com/7sI2aI4jV3Offn28ww)
- BTC: `bc1q9jhxjlnzv0x4wzxfp8xzc6w289ewggtds54uqa`
- ETH: `0x330c1b148368EE4B8756B176f1766d52132f0Ea8`

## Licensing

WHMCS EPP Registrar is licensed under the MIT License.