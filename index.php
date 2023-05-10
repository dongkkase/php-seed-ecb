<?php
require_once("SeedECB.class.php");

$seed = new SeedECB('1234567812345678'); // Key

$enc = $seed->encrypt('test');
echo $enc; // k1K+z79CYi45WGuevLq+cA==

$dec = $seed->decrypt($enc);
echo $dec; // test
