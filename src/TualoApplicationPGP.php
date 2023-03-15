<?php
namespace Tualo\Office\TualoPGP;
use phpseclib3\Crypt\RSA;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\Common\PrivateKey;

class TualoApplicationPGP {
    public static function keyGen($keySize,$userID=''){
        $private = RSA::createKey($keySize); // $rsa->createKey($keySize);
        $public = $private->getPublicKey();
        return [
            'private'   => (string) $private,
            'public'    => (string) $public
        ];
    }

    public static function encrypt($keyData,$content){
        $key = RSA::load($keyData);
        if ($key instanceof PublicKey){
            $public = $key;
        }else{
            $public = $key->getPublicKey();
        }
        return $public->encrypt($content);
    }

    public static function decrypt($keyData,$content){
        $private = RSA::load($keyData);
        if ($private instanceof PrivateKey){
            return $private->decrypt($content);
        }else{
            
        }
        return null;
    }

    static function header(string $marker) {
        return '-----BEGIN ' . strtoupper((string)$marker) . '-----';
    }
    static function footer(string $marker) {
        return '-----END ' . strtoupper((string)$marker) . '-----';
    }

    static function enarmor(string $data, string $marker = 'MESSAGE', array $headers = array()) {
        $text = self::header($marker) . "\n";
        foreach ($headers as $key => $value) {
            $text .= $key . ': ' . (string)$value . "\n";
        }
        $text .= "\n" . base64_encode($data);
        $text .= "\n".'=' . base64_encode(substr(pack('N', self::crc24($data)), 1)) . "\n";
        $text .= self::footer($marker) . "\n";
        return $text;
    }


    static function crc24(string $data) {
        $crc = 0x00b704ce;
        for ($i = 0; $i < strlen($data); $i++) {
            $crc ^= (ord($data[$i]) & 255) << 16;
            for ($j = 0; $j < 8; $j++) {
                $crc <<= 1;
                if ($crc & 0x01000000) {
                    $crc ^= 0x01864cfb;
                }
            }
        }
        return $crc & 0x00ffffff;
    }
 
    static function unarmor(string $text, string $header = 'MESSAGE') {
        $header = self::header($header);
        $text = str_replace(array("\r\n", "\r"), array("\n", ''), $text);
        if (($pos1 = strpos($text, $header)) !== FALSE &&
            ($pos1 = strpos($text, "\n\n", $pos1 += strlen($header))) !== FALSE &&
            ($pos2 = strpos($text, "\n=", $pos1 += 2)) !== FALSE) {
            return base64_decode($text = substr($text, $pos1, $pos2 - $pos1));
        }
    }

    public static function fingerprint($keyData){
        $private = RSA::load($keyData);
        $fp = [];
        if ($private instanceof PrivateKey){
            $fp[] = $private->getPublicKey()->getFingerprint();
        }
        return $fp;
    }



}
