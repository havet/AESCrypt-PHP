<?php

/*
 * Class to encrypt to .aes files and to decrypt .aes files.
 
 * Use the library to encrypt/decrypt files at your site with PHP. The files 
 * will be encrypted with 128-bit AES in CBC mode to a password of your choice.

 * This class provides methods to encrypt and decrypt files using
 * http://www.aescrypt.com/aes_file_format.html aescrypt file format
 * version 1 or 2.
 
 * A clone of AESCrypt encryption/decryption in php
 * allows compatibility between this native php
 * version and the existing AESCrypt applications
 * for Linux OSx and Win
 
 * Coded for compatibility not efficiency 
 * The coding style deliberately attempts to ape the format and 
 * layout of the AESCrypt.c and AESCrypt.java open source versions 
 * this allows for parallel development if AESCrypt format changes 
 
 *  Copyright (C) 2013 IgoAtM
 *  Copyright (C) 2016 Per Tunedal (PT)

*/
 
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

// This is a fork of IgoAtM:s code,
// originally published at:
// https://forums.packetizer.com/viewtopic.php?f=72&t=403
// The original author has given me his kind consent to publish it 
// under the GPL license.

// Per Tunedal

// Changes:
// Removal of padding after decryption PT
// Removal of test PT

class AESCrypt{
// copy of java declerations
    const DIGEST_ALG = "sha256"; // hash compatible with c.aes and java-"SHA-256"
    const CRYPT_ALG = MCRYPT_RIJNDAEL_128;//MCRYPT_RIJNDAEL_256;// java-"AES";
#    const CRYPT_TRANS = "AES/CBC/NoPadding";// java-"AES/CBC/NoPadding"
#    const DEFAULT_MAC = "0x010x230x450x670x890xab0xcd0xef";
    const KEY_SIZE = 32; // Note requirements of key size to allow AES compatibility
    const BLOCK_SIZE = 16; // final data must be padded to a whole block size
    const SHA_SIZE = 32;
    //const PAD_BLOCK = 0; // padding characters: not used
// valid extension type vectors
    const CREATED_BY = 0;
    const CREATED_DATE = 1;
    const CREATED_TIME = 2;

    protected $password; //
    protected $passfile;
    protected $exttext = array(
      self::CREATED_BY => '"AES-Crypt-PHP" ver 0.5.0'
    );

    protected $etype = array( 
      self::CREATED_BY => 'CREATED_BY',
      self::CREATED_DATE => 'CREATED_DATE',
      self::CREATED_TIME => 'CREATED_TIME' 
    );

    protected $hmac; // Mac
    protected $random; // SecureRandom
    protected $digest; // MessageDigest
    protected $oIV; // IvParameterSpec
    protected $oAESKey; // SecretKeySpec
    protected $iIV; // IvParameterSpec
    protected $iAESKey; // SecretKeySpec
    protected $mode = 'cbc';//MCRYPT_MODE_CBC;//'cbc'


    function __construct($password){
      if( isset($password) ){
        if( is_file( $password ))
          $this->passfile = $password;
        else
          $this->setPassword($password);
      }
    }
    
    
// 
/*  
 *  Generate a type 2 AESCrypt style header file a clone of aescrypt.c (the java version has a limited empty entry insertion) 
 * 
 *  Note to retain compatibility between native PHP RIJNDAEL and AES used in c.aes and java versions
 *  must use block size of 16 byte blocks equivalent to 128 bit hence MCRYPT_RIJNDAEL_128
 * 
 * Current standard aesCrypt extension tags
 * CREATED_BY       This is a developer-defined text string that identifies the software product, 
 *                            manufacturer, or other useful information (such as software version).
 * CREATED_DATE  This indicates the date that the file was created. The format of the date string is YYYY-MM-DD.
 * CREATED_TIME   This indicates the time that the file was created. The format of the date string 
*                             is in 24-hour format like HH:MM:SS (e.g, 21:15:04). The time zone is UTC.
*/
  protected function _makeheader(){
    $etype = array( 
      0 => 'CREATED_BY',
      1 => 'CREATED_DATE',
      2 => 'CREATED_TIME' );
    $mode= 2;// emulation aes mode 0|1|2 Note: not $this->mode
    $header = '';
    // Generate the AES header for this file
    $header .= 'AES'; // bang/MIME
    $header .= chr($mode); // Version 0|1|2 Octet  - 0x02 (Version)
    $header .= chr(0); // File size modulo 16 in least significant bit positions (reserved mode 0 last block padd size)
// add type 2 extensions
    if( 2 == $mode ){
      foreach( $this->exttext as $k => $v){
// Note: Using $k type number. To give text of $type[$k] . cho(0) . $v as full extension
// maybe need to try to persuade AESCrypt to use option of type numbers (hex) here so can offer translation
// of extensions define via decrypting/encrypting engine  
// means real length must be less than 256 - (strlen($type[$k])+1+strlen($v) )
        $elen = strlen($etype[$k] )+1+strlen($v);
        if( 256 >  $elen ){// 255 is maximum total extension size
          $header .= chr(0).chr($elen); // in net-byte-order (big-endian)
          $header .= $etype[$k] . chr(0) . $v;
        }else{
          trigger_error( "extension string too long [".$etype[$k]." $v] length[".(strlen($etype[$k])+1+strlen($v))."]" ,E_USER_WARNING);
        }
      }
    }
// free access small extension area 128 byte block for any data that can be altered without rebuilding file
    $header .= chr(0);
    $header .= chr(128); 
    $header .= str_repeat(chr(0),128);
    $header .= chr(0).chr(0); // no further extensions marker
    return $header;
  }

/*
 *  Should not be needed in the php ver as random generation
 *  is catered for with mt_rand. 
 *  differences in source code method will not break compatibility
 *  if the requirement is just for random numbers as long as the
 *  result range is emulated
 *  SHA256 digest over given byte array and random bytes.
 *  bytes.length * num  random bytes are added to the digest.
 * 
 *  The generated hash is saved back to the original byte array.
 *  Maximum array size is SHA_SIZE bytes. ( 32 )
 */
  protected function _digestRandomBytes( &$bytes, $num) {
    $digest='';
    if(strlen($bytes) > self::SHA_SIZE )
      trigger_error("bad byte size encryption will likley fail", E_USER_ERROR);
    for ($i = 0; $i < $num; $i++){
      for($j = 0; $j < strlen($bytes); $j++)
        $bytes[$j] = $this->randomBytes(1);
        $digest = $this->hash($bytes);
    }
    $bytes = substr($digest, 0, strlen($bytes));
  }

/*
 * Generates the random AES key used to crypt file contents.
 * @return AES key of KEY_SIZE bytes. (32)
 *  by generating a 32 byte key retains compatibility with AES and php MCRYPT_RIJNDAEL_128
*/
  protected function _generateInnerAESKey() {
    return $this->randomBytes(self::KEY_SIZE);
  }

/*
 *  Generates a pseudo-random IV 
 *  replacement for native java code not using MAC may alter to include time
 *  CBC mode requires this initialization vector.  The size of the IV (initialization
 * vector) is always equal to the block-size for AES this is fixed to 128 bit or 16 byte
 * Not key-size which defines the encryption depth
 * -- from java based on time and this computer's MAC. and c --
 * using php default mcrypt_create_iv
 * 
 * This IV is used to crypt IV 2 and AES key 2 in the file.
 * @return IV.
*/ 
  protected function _generateOuterIV() {
    return $this->randomBytes(self::BLOCK_SIZE);
  }
    
/*
 * Generates an oAESKey starting with oIV and applying the supplied user password.
 * This AES key is used to crypt iIV  and iAESKey.
 * @return AES key of KEY_SIZE ( 32 byte - 256 bit )
 *  tests as -- compliant with block sized key length c.aes and Java 
 */
  protected function _generateOuterAESKey( $iv, $password){
    $aesKey = $iv . str_repeat(chr(0), (32-strlen($iv) ));
    for ( $i = 0; $i < 8192; $i++) {//
      $aesKey = $this->hash($aesKey . $password);
   }
    return $aesKey;
  }
    
/*
 * Generates the random IV used to crypt file contents.
 * standard random character string generator this can be
 * expounded upon if desired 
 * @return IV 2. of BLOCK_SIZE bytes (16)
*/
  protected function _generateInnerIV(){
    return $this->randomBytes(self::BLOCK_SIZE);
  }

/*
 * Generates a string of the specified length containing random bytes.
 *
 * Override this method if you need a different random number generator;
 * the default implementation calls PHP's built-in cryptographically secure
 * random_bytes function.
 */
  protected function randomBytes($length) {
    return random_bytes($length);
  }

/*
 * Computes a hash of the provided binary string.
 * Returns a binary string.
 */
  protected function hash($data) {
    return hash(self::DIGEST_ALG, $data, $binary = true);
  }

/*
 * Computes a HMAC for the provided data and key.
 * Parameters and return value are binary strings.
 */
  protected function hmac($data, $key) {
    return hash_hmac(self::DIGEST_ALG, $data, $key, $binary = true);
  }

/*
 *  Not used 
 *  adds padding type PAD_BLOCK 
 *  padd to native block size (default)
 *  for AES this will always be 128bit 16byte blocks
 *  or to defined $blocksize

  protected function _addpadding($string, $blocksize = self::BLOCK_SIZE){
    $len = strlen($string);
    $pad = $blocksize - ($len % $blocksize);
    $string .= str_repeat(chr(self::PAD_BLOCK), $pad);
    return $string;
  }
*/

/*
 * Set the user entered password
 * converts format to single byte UTF-16LE if UTF-8
 * Note: uses little-endian for conversion from UTF-8 as required value resides in lsb of word
*/
  public function setPassword($password){
    $this->password = mb_convert_encoding($password, "UTF-16LE", "UTF-8");// tested to match aescrypt format for passwd
  }
  
/*
 * Builds extension text array after checking for valid inputs
 * requires an array of extension values
 * int key = valid extension type
 * str value = "the extension user added text"
 * total size of the expounded key+value+1 must be less 
 * than 255 single byte characters
 * if all above satisfied will enter into AES header on next
 * encrypt until cleared 
 * Note keys are unique so will overwrite data to existing
 * key values
*/
  public function setExtText($ext){
    if(!isset($ext) || !is_array($ext)){
      trigger_error( "WARN: ext invalid format. ext must an array", E_USER_WARNING);
      return false;
    }
    foreach( $ext as $k => $v ){
      if(!empty($this->etype[$k]) && 256 > strlen($this->etype[$k] )+1+strlen($v) ){
        $this->exttext[$k] = $v;
      }else{
        if(empty($this->etype[$k])){
          trigger_error("WARN: Not a valid extension type [$k]", E_USER_WARNING);
        }else{
          trigger_error("WARN: extension is too big", E_USER_WARNING);
        }
        return false;
      }
    }
  }
    
/*
 * The $data is encrypted and returned in encrypted form.
 * 
*/
  public function encrypt( $data ){
    if( empty($this->password) )
      return false;
    if(empty($data))
      return false;
    $out='';
// generate a valid version 2 aesCrypt header
    $out .= $this->_makeheader();
// generate the outer IV (oIV)used for password and inner IV hashing
    $oIV = $this->_generateOuterIV(); // CRYPT_ALG
// generate the outer Key (oAESKey) using supplied password hashing with oIV
    $oAESKey =$this->_generateOuterAESKey( $oIV, $this->password );
// generate the encrypted inner IV (iIV) and Key (iAESKey) used for textstring data encryption
    $iIV = $this->_generateInnerIV();
    $iAESKey = $this->_generateInnerAESKey(); // CRYPT_ALG
// Output oIV
    $out .=$oIV;
// encrypt and write out iIV and iAESKey 
    $ivnkey = mcrypt_encrypt( self::CRYPT_ALG, $oAESKey,  $iIV.$iAESKey, MCRYPT_MODE_CBC, $oIV );
    $out .= $ivnkey;
// generate HMAC for iIV and iAESKey1
    $hmac = $this->hmac($ivnkey, $oAESKey);
    $out .= $hmac;
// hash the textstring data using the inner IV and Key
    $ctext = mcrypt_encrypt( self::CRYPT_ALG, $iAESKey,   $data, MCRYPT_MODE_CBC, $iIV );
    $out .= $ctext;
// mark the last whole block size (deduct padding to full length)
    $out .= chr(strlen($data)%16);
	//echo nl2br("last block length: " . strlen($data)%16 . "\n");
	//echo nl2br("last block length: " . chr(strlen($data)%16) . "\n");
// generate the HMAC for the textstring data
    $cmac = $this->hmac($ctext, $iAESKey);
    $out .= $cmac;
    return $out;
  }

 /*
 * AESCrypt decrypt 
 * The $data is decrypted and returned in un-encrypted form.
 * fails return false
 * 
 * version can be either 1 or 2
 * 
 * 
 * 
*/
  public function decrypt($data) {
// check data exists and has file bang/MIME
    if(!isset($data) || 'AES' !== substr($data,0,3) ){
      trigger_error("decrypt called with none AES headed file", E_USER_ERROR);
      return false;
    }
// The AES Version code byte 0 | 1 | 2  
    $mode=ord(substr($data,3,1));
    if(3 < $mode ){
      trigger_error("AES mode [$mode] unsupported", E_USER_ERROR);
      return false;
    }
// If mode = 0 or 1 then? Problem is generating mode 0 and 1 files
// for testing. For now assume mode is 2
    $ptr=4;
// For now skip past all header extensions 
// may decide to act on if flagged for situations like say extract all after date
// or only process if user name is or or ...? or
    if( 2 == $mode ){
      if(138 > strlen($data) ){
        trigger_error("file is too short [".strlen($data)."] for a AES mode 2 file", E_USER_ERROR);
        return false;
      }
      while($ptr < strlen($data) ){
        $ptr++;
        $len = ord($data[$ptr])+ord($data[$ptr+1]);
#        $ext = substr($data,$ptr+2,$len); // extension string available if required
        $ptr = $ptr + ord($data[$ptr+1])+1;
        if(0 == $len){// found our 0000 end of ext marker
          break;
        }
        else{ // if response is required to ext this is where they would go ? 
          true;//echo "\nuse it or loose it [$ext]\n";
        }
      }
    }
// ptr+1 = 16 Octets - Initialisation Vector (IV) used for encrypting the IV and symmetric key 
// that is actually used to decrypt the bulk of the plaintext file.
    $ptr++;
    $oIV=substr($data, $ptr, 16);// the oIV from the cipher
    $oAESKey = $this->_generateOuterAESKey( $oIV, $this->password);// use the cipher oIV and password to generate oAESKey
    $ptr = $ptr+16;
// 48 Octets - Encrypted IV and 256-bit AES key used to encrypt the bulk of the file
// comprising 16 octets - initialisation vector 32 octets - encryption key
    $iIV = substr($data, $ptr, 16);// cipher iIV
    $ptr = $ptr+16;
    $iAESKey = substr($data, $ptr, 32);// cipher iAESKey
    $ptr = $ptr+32;
// decrypt the cipher iIV IAESKey with the cipher oIV Using the user input password generated oAESKey
    $ivnkey = mcrypt_decrypt( self::CRYPT_ALG, $oAESKey,  $iIV.$iAESKey, MCRYPT_MODE_CBC, $oIV );
//32 Octets - HMAC
    $ohmac = substr($data, $ptr, 32); // data HMAC cipher (iIV iAESKey) HMAC must match
    $xhmac = $this->hmac($iIV.$iAESKey, $oAESKey);// HMAC generated using oAESKey made using user password
    if($ohmac != $xhmac){
      trigger_error("HMAC mismatch the password is incorrect or the message is corrupt",E_USER_WARNING);
      return false;
    }
    $ptr = $ptr+32;// for version 2 files ptr should now be at start of ciphertext 
// recover hashed iIV and iAESKey
    $iIV = substr($ivnkey,0,16);
    $iAESKey = substr($ivnkey,16,32);
// last block offset
    $lbo = ord(substr($data,strlen($data)-33, 1));
// main encrypted ciphertext ends 33 bytes less than the length of data 
// 1 byte last block offset and 32 byte inner HMAC
    $buffer = substr($data, $ptr, -33);
// ciphertext HMAC
    $xhmac = substr($data,strlen($data)-32, 32);
// generate the HMAC for the textstring data
    $cmac = $this->hmac($buffer, $iAESKey);
    if($cmac != $xhmac){
      trigger_error("HMAC the message is corrupt",E_USER_WARNING);
      return false;
    }
    $ctext = mcrypt_decrypt( self::CRYPT_ALG, $iAESKey, $buffer, MCRYPT_MODE_CBC, $iIV );
	
	// Remove padding (PT)
	// -------------------
	
	// Modulus of original data is retrieved from file
    $ptr = -1+strlen($data)-32;

	$lastblocklen = substr($data, $ptr, 1);
	$lastLength = unpack("C", $lastblocklen);
	//print_r($lastLength);
	$lastLength = $lastLength[1];
	//echo nl2br("lastLength: " . $lastLength . "\n");
	
	// Length of padding
	$paddLength = 16 - $lastLength;
	//echo nl2br("paddLength: " . $paddLength . "\n");
	
	// Padding is removed
	$ctext = substr($ctext, 0, (strlen($ctext) - $paddLength));

    return $ctext;
  }
  }
?>