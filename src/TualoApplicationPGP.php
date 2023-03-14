<?php
namespace Tualo\Office\TualoPGP;
use phpseclib3\Crypt\RSA;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\Common\PrivateKey;

class TualoApplicationPGP {
    public static function keyGen($keySize,$userID){
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
        $public->encrypt($content);
    }

    public static function decrypt($keyData,$content){
        $private = RSA::load($keyData);
        if ($private instanceof PrivateKey){
            return $private->decrypt($content);
        }else{
            
        }
        return null;
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
