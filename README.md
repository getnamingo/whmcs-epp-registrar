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
| Caucasus Online | .ge | GE | |
| CentralNic | all | | Set AuthInfo on Request / Min Data Set and gTLD Enabled (for gTLD) |
| CoCCA | all | | Set AuthInfo on Request / Min Data Set and gTLD Enabled (for gTLD) |
| CORE/Knipp | all | | Min Data Set and gTLD Enabled (for gTLD) |
| Domicilium | .im | | |
| DRS.UA | all | | | |
| EURid | .eu | EU | |
| GoDaddy Registry | all | | Min Data Set and gTLD Enabled (for gTLD) |
| Google Nomulus | all | | Min Data Set and gTLD Enabled (for gTLD) |
| Hello Registry | all | | Min Data Set and gTLD Enabled (for gTLD) |
| Hostmaster | .ua | UA | |
| Identity Digital | all | | Min Data Set and gTLD Enabled (for gTLD) |
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
| Tucows Registry | all | | Min Data Set and gTLD Enabled (for gTLD) |
| Verisign | all | VRSN | Min Data Set and gTLD Enabled (for gTLD) |
| ZADNA | .za | | |
| ZDNS | all | | |

### In Progress

| Registry | TLDs | Profile | Status |
|----------|----------|----------|----------|
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

**Minimum requirement:** WHMCS v9.0.8 installed.

1. The recommended way to install is with the automated installer:

```bash
bash <(wget -qO- https://namingo.org/install-whmcs-epp.sh) namingo
```

Replace `namingo` with the registry name. Run without parameters to see all supported registries:

```bash
bash <(wget -qO- https://namingo.org/install-whmcs-epp.sh)
```

The installer automatically detects WHMCS under `/var/www`. You may also specify the path explicitly:

```bash
bash <(wget -qO- https://namingo.org/install-whmcs-epp.sh) namingo /var/www/whmcs
```

2. During installation, the script can optionally generate a **self-signed EPP client certificate for testing**. It will print the full certificate and private key paths after installation, which you can use directly in the module settings. For production, replace them with the certificate and private key issued or approved by your registry.

3. Activate from **Configuration -> Apps & Integrations -> (search for _[MODULE]_) -> Activate**, then configure it under **Configuration -> System Settings -> Domain Registrars**. Enter your registry connection details, including the EPP host, port, login credentials, and the full filesystem paths to your client TLS certificate (`cert.pem`) and private key (`key.pem`).

4. Add a new TLD using **Configuration -> System Settings -> Domain Pricing**, assign it to the activated registrar module, and configure the pricing as needed.

5. If your module includes **additional domain fields**, copy the contents of `additionalfields.php` into `[WHMCS_path]/resources/domains/additionalfields.php`. If the file already exists, **merge the contents carefully** (do not overwrite the existing file).

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

## Upgrade

Upgrade to the latest release with:

```bash
bash <(wget -qO- https://namingo.org/install-whmcs-epp.sh) namingo /var/www/whmcs
```

## Troubleshooting

1. **Multiple EPP modules conflict**
   - WHMCS does not allow multiple registrar modules that share the same internal function names.
   - If you are connecting to more than one registry, you must generate each module using the Module Customizer Tool to ensure unique module names.
   - Do not manually duplicate or rename module files, as this may cause function collisions or unexpected behavior.
   
2. **Network access / allowlisting**
   - Ensure the server’s outbound IP(s) are allowlisted by the registry EPP endpoint (both **IPv4** and **IPv6**, if applicable).

3. **IPv6 considerations**
   - Confirm both sides support IPv6 if you intend to use it.
   - If you encounter IPv6-related connection issues, temporarily **disable IPv6** on the client side and retry.
   
4. **EPP server access**
   - If you are unsure whether your server can reach the EPP endpoint, test the connection using OpenSSL:

   Basic test:
   ```bash
   openssl s_client -connect epp.example.com:700
   ```

   Test with client certificate:
   ```bash
   openssl s_client -connect epp.example.com:700 -CAfile cacert.pem -cert cert.pem -key key.pem
   ```
   
   Replace the hostname and certificate paths as needed. These tests help diagnose network or TLS issues.
   
5. **Generating a client TLS certificate (testing only)**
   - If you do not yet have a client certificate for EPP access, you can generate a temporary self-signed pair:

   ```bash
   openssl genrsa -out key.pem 2048
   openssl req -new -x509 -key key.pem -out cert.pem -days 365
   ```
   
   For production, use a certificate issued or approved by the registry (not a self-signed certificate).

6. **Registrar prefix**
   - Ensure the module is configured with the correct **registrar prefix** for your registry connection.

7. **Transfer AuthInfo not returned by registry**
   - Some registries (e.g. **CentralNic**, **CoCCA**) may not return the transfer AuthInfo code via standard `domain:info`.
   - If your module does not display the transfer code, enable the option **“Set AuthInfo on Request”** in the module configuration. This forces the module to set/generate AuthInfo when requested, so it can be displayed/managed consistently.

### Need More Help?

If the steps above don’t resolve your issue, refer to the WHMCS logs or enable `Display Errors` in the WHMCS Admin under `Utilities > System > General Settings > Other` to identify the specific problem.

## Support

Your feedback and inquiries are invaluable to Namingo's evolutionary journey. If you need support, have questions, or want to contribute your thoughts:

- **Email**: Feel free to reach out directly at [help@namingo.org](mailto:help@namingo.org).

- **Discord**: Or chat with us on our [Discord](https://discord.gg/97R9VCrWgc) channel.
  
- **GitHub Issues**: For bug reports or feature requests, please use the [Issues](https://github.com/getnamingo/whmcs-epp-registrar/issues) section of our GitHub repository.

We appreciate your involvement and patience as Namingo continues to grow and adapt.

## Support This Project

If you find WHMCS EPP Registrar useful, consider donating:

- [Donate via Stripe](https://donate.stripe.com/7sI2aI4jV3Offn28ww)
- BTC: `bc1q9jhxjlnzv0x4wzxfp8xzc6w289ewggtds54uqa`
- ETH: `0x330c1b148368EE4B8756B176f1766d52132f0Ea8`

## Licensing

WHMCS EPP Registrar is licensed under the MIT License.