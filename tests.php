<?php

// tests.php - unit tests for class.aesCrypt.php.

namespace aescrypt_tests;

use Exception, ErrorException, Throwable;
use AESCrypt;

error_reporting(E_ALL);
ini_set("ignore_repeated_errors", 1);

require_once 'class.aesCrypt.php';

const TEST_DATA = __DIR__ . "/test-data";

$test_cases = array(
    "encrypt file" => function() {
        $crypt = create_crypt_instance();
        $input_data = file_get_contents(TEST_DATA . "/text.txt");
        $expected = file_get_contents(TEST_DATA . "/text.txt.aes");

        $ciphertext = $crypt->encrypt($input_data);

        if ($ciphertext !== $expected) {
            throw new Exception("Incorrect ciphertext produced");
        }
    },
    "decrypt file" => function() {
        $crypt = create_crypt_instance();
        $input_data = file_get_contents(TEST_DATA . "/text.txt.aes");
        $expected = file_get_contents(TEST_DATA . "/text.txt");

        $plaintext = $crypt->decrypt($input_data);

        if ($plaintext !== $expected) {
            throw new Exception("Incorrect plaintext produced");
        }
    },
    "roundtrip" => function() {
        $crypt = create_crypt_instance();
        $input_data = "my test message";

        $ciphertext = $crypt->encrypt($input_data);
        $plaintext = $crypt->decrypt($ciphertext);

        if ($plaintext !== $input_data) {
            throw new Exception("Expected '$input_data' but got '$plaintext'");
        }
    },
);

function create_crypt_instance() {
    $passphrase = "ThisIsMySecretPassphrase";
    $date = "2024-04-01";
    $time = "11:22:33";

    $crypt = new class($passphrase) extends AESCrypt {
        function randomBytes($length) {
            return str_repeat("a", $length);
        }
    };

    $crypt->setExtText(array(
        $crypt::CREATED_DATE => $date,
        $crypt::CREATED_TIME => $time,
        $crypt::CREATED_BY => "test",
    ));

    return $crypt;
}

function run_tests() {
    global $test_cases;

    echo "AESCRYPT-PHP UNIT TESTS\n";
    echo "-----------------------\n";

    $failed = 0;
    foreach ($test_cases as $name => $func) {
        echo "\nTEST CASE: $name\n";
        try {
            $func();
            echo "OK\n";
        }
        catch (Throwable $ex) {
            echo "$ex\n";
            $failed++;
        }
    }

    if ($failed === 0) {
        echo "\nOK. All tests passed successfully.\n";
        exit(0);
    }
    else {
        echo "\nFAILED! $failed test cases failed.\n";
        exit(1);
    }
}

function regenerate_test_data() {
    $files = array("text.txt");
    $crypt = create_crypt_instance();

    foreach ($files as $filename) {
        $plaintext = file_get_contents(TEST_DATA . "/$filename");
        $output = "{$filename}.aes";
        echo "Generating file: $output\n";
        $ciphertext = $crypt->encrypt($plaintext);
        file_put_contents(TEST_DATA . "/$output", $ciphertext);
    }
}

header("Content-Type: text/plain; charset=utf-8");

set_error_handler(function($errno, $errstr, $errfile, $errline) {
    if ($errno === E_DEPRECATED) {
        return false;
    }
    else {
        throw new ErrorException($errstr, $errno, 0, $errfile, $errline);
    }
});

if (isset($argc) && $argc > 1 && $argv[1] === "--regenerate-test-data") {
    regenerate_test_data();
}
else if (isset($argc) && $argc > 1) {
    echo "Usage: php tests.php [--regenerate-test-data]\n";
    exit(1);
}
else {
    run_tests();
}
