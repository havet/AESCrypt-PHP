AES-Crypt-PHP
=============

Yet an other PHP implementation of the open source AES crypt file format:
.aes

Use the library to encrypt/decrypt files at your site with PHP. The files 
will be encrypted with AES in CBC mode to a password of your choice. The password 
is hashed to create a 256-bit key for the encryption.

Usage: Please see example.php

The project is a fork of IgoAtM:s code,
 originally published at:

https://forums.packetizer.com/viewtopic.php?f=72&t=403

With his kind consent have I licensed this fork under the GPL v.3 license.

The encrypted .aes files can be decrypted at almost any platform:
https://www.aescrypt.com/
https://www.aescrypt.com/download/

The file specification is described here:
https://www.aescrypt.com/aes_file_format.html

This library supports version 2 of the file format.


