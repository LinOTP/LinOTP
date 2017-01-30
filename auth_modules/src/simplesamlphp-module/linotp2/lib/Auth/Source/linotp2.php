<?php

/*
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2017 KeyIdentity GmbH
 *
 *   This file is part of LinOTP authentication modules.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.

 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.keyidentity.com
 *
 */


/**
 * LinOTP2 authentication source.
 *
 * This class is based on Radius.php
 *
 */
class sspmod_linotp2_Auth_Source_linotp2 extends sspmod_core_Auth_UserPassBase {

	/**
	 * The URL of the LinOTP server
	 */
	private $linotpserver;

	/**
	 * If the sslcert should be checked
	 */
	private $sslverifyhost;

	/**
	 * If the sslcert should be checked
	 */
	private $sslverifypeer;
	
	/**
	 * The realm of the user
	 */
	private $realm;
	
	/**
	 * The attribute map. It is an array
	 */
	 
	private $attributemap = array();
	
	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);

		if (array_key_exists('linotpserver', $config)) {
            $this->linotpserver = $config['linotpserver'];
        }
        if (array_key_exists('realm', $config)) {
            $this->realm = $config['realm'];
        }
        if (array_key_exists('sslverifyhost', $config)) {
            $this->sslverifyhost = $config['sslverifyhost'];
        }
        if (array_key_exists('sslverifypeer', $config)) {
            $this->sslverifypeer = $config['sslverifypeer'];
        }
        if (array_key_exists('attributemap', $config)) {
			$this->attributemap = $config['attributemap'];
		}
		
	}


	/**
	 * Attempt to log in using the given username and password.
	 *
	 * @param string $username  The username the user wrote.
	 * @param string $password  The password the user wrote.
	 * @return array  Associative array with the users attributes.
	 */
	protected function login($username, $password) {
		assert('is_string($username)');
		assert('is_string($password)');

        $ch = curl_init();
        
        $escPassword = urlencode($password);
        $escUsername = urlencode($username);

		$url = $this->linotpserver . '/validate/samlcheck?user='.$escUsername
			.'&pass=' . $escPassword . '&realm=' . $this->realm;
		
		//throw new Exception("url: ". $url);
		SimpleSAML_Logger::debug("LinOTP2 URL:" . $url);
	
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, TRUE);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        if ($this->sslverifyhost) {
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);
		} else {
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	    }
	    if ($this->sslverifypeer) {
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
		} else {
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		}
	    
	    $response = curl_exec($ch);     
        $header_size = curl_getinfo($ch,CURLINFO_HEADER_SIZE);
        $body = json_decode(substr( $response, $header_size ));
       
        $status=True;
        $value=True;
    
		try {
			$status = $body->result->status;
			$value = $body->result->value->auth;
		} catch (Exception $e) {
			throw new SimpleSAML_Error_BadRequest("We were not able to read the response from the LinOTP server:" . $e);
		}
		
    	if ( False==$status ) {
			/* We got a valid JSON respnse, but the STATUS is false */
			throw new SimpleSAML_Error_BadRequest("Valid JSON response, but some internal error occured in LinOTP server.");
				
		} else {
			/* The STATUS is true, so we need to check the value */
			if ( False==$value ) {
				throw new SimpleSAML_Error_Error("WRONGUSERPASS");
			}
		}
		/* status and value are true
		 * We can go on and fill attributes
		 */

		/* If we get this far, we have a valid login. */
		$attributes = array();
		$arr = array( "username", "surname", "email", "givenname", "mobile", "phone");
		reset($arr);
		foreach ( $arr as $key) {
			if (array_key_exists($key, $this->attributemap)) {
				$attributes[$this->attributemap[$key]] = array( $body->result->value->attributes->$key );
			} else {
				$attributes[$key] = array( $body->result->value->attributes->$key );
			}	
		}
		return $attributes;
	}

}


?>
