<?php
namespace Tualo\Office\TualoPGP;

class TualoApplicationPGP {
    public static function keyGen($keySize,$userID){

        $rsa = new \phpseclib\Crypt\RSA();
        $k = $rsa->createKey($keySize);
        $rsa->loadKey($k['privatekey']);
        
        $nkey = new \OpenPGP_SecretKeyPacket(
            array(
                'n' => $rsa->modulus->toBytes(),
                'e' => $rsa->publicExponent->toBytes(),
                'd' => $rsa->exponent->toBytes(),
                'p' => $rsa->primes[2]->toBytes(),
                'q' => $rsa->primes[1]->toBytes(),
                'u' => $rsa->coefficients[2]->toBytes()
            )
        );
        $uid = new \OpenPGP_UserIDPacket($userID);
        $wkey = new \OpenPGP_Crypt_RSA($nkey);
        $m = $wkey->sign_key_userid(array($nkey, $uid));
        $pubm = clone($m);
        $pubm[0] = new \OpenPGP_PublicKeyPacket($pubm[0]);
        
    
        $o = [];
        // Serialize private key
        $o['private'] =  $m;
        $o['public'] =  $pubm;
        return $o;
    }

    public static function encrypt($keyData,$content){

        $key = \OpenPGP_Message::parse(\OpenPGP::unarmor($keyData, 'PGP PUBLIC KEY BLOCK'));
        $data = new \OpenPGP_LiteralDataPacket( $content , array('format' => 'u', 'filename' => 'stuff.txt') );
        $encrypted = \OpenPGP_Crypt_Symmetric::encrypt($key, new \OpenPGP_Message(array($data)));
        $enc_message=\OpenPGP::enarmor($encrypted->to_bytes(),'PGP MESSAGE');
        
        
        return $enc_message;
    }
    public static function fingerprint($keyData){
        $key = \OpenPGP_Message::parse( \OpenPGP::unarmor($keyData, 'PGP PRIVATE KEY BLOCK') );
        if (is_null($key)){
            $key = \OpenPGP_Message::parse($keyData);
        }

        $fp = [];
        foreach($key as $p) {
            if(!($p instanceof \OpenPGP_SecretKeyPacket)) continue;
            if (method_exists($p,"fingerprint")){
                $fp[] = $p->fingerprint();
            }
        }
        return $fp;
    }

    public static function decrypt($keyData,$content){
        $keyEncrypted = \OpenPGP_Message::parse(\OpenPGP::unarmor($keyData, 'PGP PRIVATE KEY BLOCK'));
        foreach($keyEncrypted as $p) {
            if(!($p instanceof \OpenPGP_SecretKeyPacket)) continue;
            $key = $p;//\OpenPGP_Crypt_Symmetric::decryptSecretKey("", $p);
            $msg = \OpenPGP_Message::parse(\OpenPGP::unarmor($content, 'PGP MESSAGE'));
            $decryptor = new \OpenPGP_Crypt_RSA($key);
            $decrypted = $decryptor->decrypt($msg);
            if (is_null($decrypted)) return "";
            return  $decrypted->offsetGet(0)->data;
        }
    }
}
