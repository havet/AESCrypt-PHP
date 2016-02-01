<?php
	
// example.php

// EXAMPLE

// Version: 0.1

// Example of how to use clas.aesCrypt.php
// ---------------------------------------
 
//      Copyright (c) 2012-2013 Per Tunedal, Stockholm, Sweden
//       Author: Per Tunedal <info@tunedal.nu>

//       This program is free software: you can redistribute it and/or modify
//       it under the terms of the GNU General Public License as published by
//       the Free Software Foundation, either version 3 of the License, or
//       (at your option) any later version.

//       This program is distributed in the hope that it will be useful,
//       but WITHOUT ANY WARRANTY; without even the implied warranty of
//       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//       GNU General Public License for more details.

//       You should have received a copy of the GNU General Public License
//       along with this program.  If not, see <http://www.gnu.org/licenses/>.
 
	echo nl2br("Starts AES-file encryption" . "\n");
	echo nl2br("==========================" . "\n");

	require 'class.aesCrypt.php'; // class
	
	$passphrase = 'ThisIsMySecretPassphrase';
	  
	// Initializing the class
	$crypt = new AESCrypt($passphrase);
	
	// Setting date and time
	$date = date("Y-m-d");
	echo nl2br ("Date: " . $date . "\n");
	
	$time = date("H:i:s");
	echo nl2br ("Time: " . $time . "\n");
	
	// Adding date and time to the header
	// of the encrypted file
	$crypt->setExtText(array(
		$crypt::CREATED_DATE=>$date,
		$crypt::CREATED_TIME=>$time
			)
		);
	
	// File to encrypt
	//$file = 'path/to/my/file/file.txt';
	$file = 'readme.txt';
	
	echo nl2br ("Encryption of the file: " . $file . "\n");
	
	// read content
	$data=file_get_contents($file);
	
	// encrypt and write to a new file  (existing file is overwritten)
	file_put_contents($file . '.aes', $crypt->encrypt( $data) );


	echo nl2br("AES-file encryption finished" . "\n");
	echo nl2br("============================" . "\n");

	echo nl2br("AES-file decryption starts" . "\n");
	echo nl2br("============================" . "\n");

	echo nl2br ("Decryption of: " . $file . '.aes' . "\n");
	
	// read content
	$data=file_get_contents($file . '.aes');
	
	// decrypt and write to a new file (existing file is overwritten)
	file_put_contents($file . '.aes' . '.decrypted', $crypt->decrypt( $data) );

	echo nl2br("AES-file decryption finished" . "\n");
	echo nl2br("============================" . "\n");

?>