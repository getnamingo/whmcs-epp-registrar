<?php
/**
 * Namingo EPP Registrar module for WHMCS (https://www.whmcs.com/)
 * Additional Domain Fields
 *
 * Installation: Place this file in /resources/domains/additionalfields.php
 *
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