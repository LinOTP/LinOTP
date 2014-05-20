<?php
/*
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
 *    Support: www.lsexperts.de
 */

class LinOTP {
	private $server, $verify_peer, $verify_host;
	
	public function __construct( $server = "localhost",  $verify_peer=0, $verify_host=0) {
		$this->server=$server;
		# can be 0 or 2
		#$verify_host = 0;
		#$verify_peer = 0;
		$this->verify_peer=$verify_peer;
		$this->verify_host=$verify_host;
	}


	public function linotp_auth($user="", $pass="", $realm="") {
		$ret=false;
		try {
			$server = $this->server;
			$REQUEST="https://$server/validate/check?pass=$pass&user=$user";
			if(""!=$realm) 
				$REQUEST="$REQUEST&realm=$realm";
#				print "\n\n\n$REQUEST\n\n\n";

			
			if(!function_exists("curl_init"))
				die("cURL extension is not installed");

			$ch=curl_init($REQUEST);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verify_peer);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->verify_host);
			$r=curl_exec($ch);
			curl_close($ch);
			
		
			$jObject = json_decode($r);
			if (true == $jObject->{'result'}->{'status'} )
				if (true == $jObject->{'result'}->{'value'} )
					$ret=true;
		} catch (Exception $e) {
			print "Error in receiving response from LinOTP server: $e";
		}	
		return $ret;
	}
}
?>

