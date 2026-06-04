<?php
ini_set('display_errors', '1');

$pdo = new PDO('sqlite::memory:');
$pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);

$payload = unserialize($_REQUEST['payload']);
echo shell_exec("convert " . $_GET['image']);
