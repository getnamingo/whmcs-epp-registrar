<?php

/*
 * Namingo EPP Registrar module for WHMCS
 *
 * Copyright (c) 2023-2026 Taras Kondratyuk
 * Copyright (c) 2025-2026 Namingo contributors
 * Copyright (c) 2026 Terbora Ltd.
 *
 * Based on Generic EPP with DNSsec Registrar Module for WHMCS written in 2019 by Lilian Rudenco (info@xpanel.com)
 * Work of Lilian Rudenco is under http://opensource.org/licenses/afl-3.0.php Academic Free License (AFL 3.0)
 * https://github.com/xpanel/Generic-EPP-with-DNSsec-Registrar-Module-for-WHMCS
 *
 * Licensed under the MIT License.
 * See the LICENSE file distributed with this software for the full license text.
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * Installation: Place this file in /resources/domains/additionalfields.php
 */

// -------------------------------------------------
// .SE — Sweden
// -------------------------------------------------

$additionaldomainfields[".se"][] = [
    "Name"     => "NIN",
    "LangVar"  => "nin",
    "Type"     => "text",
    "Size"     => "30",
    "Required" => true,
];

$additionaldomainfields[".se"][] = [
    "Name"     => "VAT",
    "LangVar"  => "vat_number",
    "Type"     => "text",
    "Size"     => "30",
    "Required" => false,
];

$additionaldomainfields[".nu"][] = [
    "Name"     => "NIN",
    "LangVar"  => "nin",
    "Type"     => "text",
    "Size"     => "30",
    "Required" => true,
];

$additionaldomainfields[".nu"][] = [
    "Name"     => "VAT",
    "LangVar"  => "vat_number",
    "Type"     => "text",
    "Size"     => "30",
    "Required" => false,
];

// -------------------------------------------------
// .HR — Croatia
// -------------------------------------------------

$additionaldomainfields[".hr"][] = [
    "Name"     => "NIN",
    "LangVar"  => "nin",
    "Type"     => "text",
    "Size"     => "20",
    "Required" => true,
];

$additionaldomainfields[".hr"][] = [
    "Name"     => "NIN Type",
    "LangVar"  => "nin_type",
    "Type"     => "dropdown",
    "Options"  => "personal|Personal,company|Company",
    "Default"  => "personal",
    "Required" => true,
];

// -------------------------------------------------
// .PT — Poland
// -------------------------------------------------

$additionaldomainfields[".pt"][] = [
    "Name"     => "VAT",
    "LangVar"  => "vat_number",
    "Type"     => "text",
    "Size"     => "30",
    "Required" => false,
];

// -------------------------------------------------
// .LV — Latvia
// -------------------------------------------------

$additionaldomainfields[".lv"][] = [
    "Name"     => "NIN",
    "LangVar"  => "nin",
    "Type"     => "text",
    "Size"     => "30",
    "Required" => true,
];

$additionaldomainfields[".lv"][] = [
    "Name"     => "VAT",
    "LangVar"  => "vat_number",
    "Type"     => "text",
    "Size"     => "30",
    "Required" => false,
];

// -------------------------------------------------
// .GE — Georgia
// -------------------------------------------------

$additionaldomainfields[".ge"][] = [
    "Name"     => "NIN",
    "LangVar"  => "nin",
    "Type"     => "text",
    "Size"     => "20",
    "Required" => true,
];

// -------------------------------------------------
// .RO — Romania
// -------------------------------------------------

$additionaldomainfields[".ro"][] = [
    "Name"     => "Registrant Type",
    "Type"     => "dropdown",
    "Options"  => "p|Private Person,ap|Authorized Person,nc|Non-commercial Organization,c|Commercial Company,gi|Government Institution,pi|Public Institution,o|Other Legal Entity",
    "Default"  => "p",
    "Required" => true,
];

$additionaldomainfields[".ro"][] = [
    "Name"        => "CNPFiscalCode",
    "Type"        => "text",
    "Size"        => "30",
    "Description" => "CNP for individuals or fiscal code for legal entities. Required for Romanian registrants.",
    "Required"    => false,
];

$additionaldomainfields[".ro"][] = [
    "Name"        => "Registration Number",
    "Type"        => "text",
    "Size"        => "30",
    "Description" => "Company registration number. Required for Romanian companies.",
    "Required"    => false,
];