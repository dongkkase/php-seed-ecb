<?php
require_once("SeedECB.class.php");

$seed = new SeedECB('1234567812345678');

$enc = $seed->encrypt('test');
echo $enc;

$dec = $seed->decrypt($enc);
echo $dec;
