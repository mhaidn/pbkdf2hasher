<?php

namespace MarkHofstetter\Pbkdf2Hasher\Facades;

use Illuminate\Support\Facades\Facade;
use Illuminate\Contracts\Hashing\HashManager;

class Pbkdf2Hasher extends Facade
{
    protected $algo = 'sha512';
    protected $iterations = '100001';
    protected $length = 0;

    # fixed at the moment
    protected $hashing_method = 'pbkdf2'; 

    public function __construct(array $options = [])
    {}



    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'pbkdf2hasher';
    }

    /**
     * NOTE: Declaring info function from Laravel AbstractHasher since HashManager will call
     * it to determine if rehashing is required.
     *
     * @param $hashedValue
     * @return array
     */
    public function info($hashedValue)
    {
        preg_match('/(.+?)\:(.+?)\:(.+?)\$(.+?)\$(.*)/', $hashedValue, $matches);

        if (! $matches) {
            return [];
        }

        return [
            'algoName' => $matches[1],
            'algo' => $matches[2],
            'iterations' => $matches[3],
            'salt' => $matches[4],
            'hash' => $matches[5],
        ];
    }


    /**
     * create hash value + algo info 
     * to be compatible with https://werkzeug.palletsprojects.com/en/0.15.x/utils/#module-werkzeug.security
    */
    public function make($value, array $options = [])
    {
        $this->algo = $options['algo'] ?? $this->algo;
        $this->iterations = $options['iterations'] ?? $this->iterations;
        $this->length = $options['length'] ?? $this->length;
        $this->salt = $options['salt'] ??  $salt = bin2hex(openssl_random_pseudo_bytes(8));

        $hash = hash_pbkdf2($this->algo, $value, $this->salt, $this->iterations, $this->length);

        return sprintf("%s:%s:%s$%s$%s", $this->hashing_method, $this->algo, $this->iterations, $this->salt, $hash);
    }


    public function check($value, $hashedValue, array $options = [])
    {
        if (strlen($hashedValue) === 0 || strlen($value) === 0) {
            return false;
        }

        $hashInfo = $this->info($hashedValue);
        if (! empty($hashInfo)) {
            $options = array_merge($options, $hashInfo);
        } else {
            return false;
        }

        return ($this->make($value, $options) === $hashedValue);
    }


    public function needsRehash($hashedValue, array $options = [])
    {
        return false;
    }

}
