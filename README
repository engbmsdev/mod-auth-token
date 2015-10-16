#What is mod_auth_token ?
mod_auth_token is a famous apache module that allow you to generate URIS for a determined time window, you can also limit them by IP. This is very useful to handle file downloads, generated URIS can't be hot-linked (after it expires), also it allows you to protect very large files that can't be piped trough a script languages due to memory limitation.

#Who is using mod_auth_token
Various commercial and video sharing sites are running mod_auth_token module, if you want to be listed here, please fille an issue.

#Updates version 1.0.6
New version 1.0.6 is available and has good performance, it has been tested on a heavily loaded site for several months now (www.citiesxl.com From MonteCristo Games). This release introduce a new configuration item (AuthTokenLimitByIp) which limit the access to the ressource only for the ip who generated the link. This release is backward compatible and it should be safe to use on production. The reason that is in beta is the lack of feedback from users.
As always, if you need a feature or found a bug, don't hesitate to fill an issue .

#How it works ?
A secret string is shared between the token generator and the Apache server. The token is an hex-encoded MD5 hash of the secret string, relative file path and the timestamp. It is encoded onto the URI as:

	uri-prefix/token/timestamp-in-hex/rel-path

For example :

	/downloads/dee0ed6174a894113d5e8f6c98f0e92b/43eaf9c5/file_to_protect.txt

Apache will verify this token and allow (or not) the access to the resource.

#Install
Please read INSTALL file in tgz.
If link are broken before installing, rebuild them by typing

	rm -f configure
	autoreconf -fi
	automake -f
	./configure
	make

You can also grab the latest source code to get the latest patches.

#Example
##Apache Configuration
First we need to configure the apache server.

	<Location /downloads/>
		AuthTokenSecret       "secret string"
		AuthTokenPrefix       /downloads/
		AuthTokenTimeout      60
		AuthTokenLimitByIp    off
	</Location>

By such configuration, we tell Apache that accesses on /downloads/ is protected by :

* A timeout of the links set to 60 seconds
* The Ip address of the client who generated the token (so people can't share links, this setting is optional) 

#URI generation

##PHP
Now you have to generate URIs on dynamically in such way (here is an example for PHP):

	<?php
		// Settings to generate the URI
		$secret = "secret string";             // Same as AuthTokenSecret
		$protectedPath = "/downloads/";        // Same as AuthTokenPrefix
		$ipLimitation = false;                 // Same as AuthTokenLimitByIp
		$hexTime = dechex(time());             // Time in Hexadecimal
		//$hexTime = dechex(time()+120);         // Link available after 2 minutes      
		$fileName = "/file_to_protect.txt";    // The file to access
		// Let's generate the token depending if we set AuthTokenLimitByIp
		if ($ipLimitation) {
			$token = md5($secret . $fileName . $hexTime . $_SERVER['REMOTE_ADDR']);
		}
		else {
			$token = md5($secret . $fileName. $hexTime);
		}
		// We build the url
		$url = $protectedPath . $token. "/" . $hexTime . $fileName;
		echo $url;
	?>

##Python
Sample python code contributed by Ales Teska

	#!/usr/bin/env python
	import os, time, hashlib
	
	secret = "secret string"                                # Same as AuthTokenSecret
	protectedPath = "/downloads/"                           # Same as AuthTokenPrefix
	ipLimitation = False                                    # Same as AuthTokenLimitByIp
	hexTime = "{0:x}".format(int(time.time()))              # Time in Hexadecimal      
	fileName = "/file_to_protect.txt"                       # The file to access
	
	# Let's generate the token depending if we set AuthTokenLimitByIp
	if ipLimitation:
	  token = hashlib.md5(''.join([secret, fileName, hexTime, os.environ["REMOTE_ADDR"]])).hexdigest()
	else:
	  token = hashlib.md5(''.join([secret, fileName, hexTime])).hexdigest()
	
	# We build the url
	url = ''.join([protectedPath, token, "/", hexTime, fileName])
	print url

##Perl
Please note that a perl module made by Assaf Gordon exists to generate URIs: you can check it here : http://search.cpan.org/~agordon/Authen-ModAuthToken-0.03/
Sample perl code contributed by aanbar

	#!/usr/bin/perl
	use strict;
	use warnings;
	
	print protectedPath('SecretWord', '/downloads/', 1, 'file.zip' );
	
	sub protectedPath {
	        use Digest::MD5 qw/md5_hex/;
	        my ( $secret, $protectedPath, $ipLimitation, $fileName ) = @_;
	        my $hexTime = sprintf("%x", time() );
	        my $token = md5_hex($secret . $fileName. $hexTime);
	        $token = md5_hex($secret . $fileName . $hexTime . $ENV{'REMOTE_ADDR'}) if $ipLimitation;
	        return $protectedPath . $token. '/' . $hexTime . '/' . $fileName;
	}

Of course, you can implement this in any language that you want. Don't hesitate to post here implementations in other languages, they will appear in this page.

##Java
Sample Java code contributed by kanchangxin

	String secret="secret string";                    // Same as AuthTokenSecret
	String protectedPath="/vod/";                   // Same as AuthTokenPrefix
	//boolean ipLimitation=false;                     // Same as AuthTokenLimitByIp
	long time= (new Date()).getTime();                // Time in decimal
	time=time/1000;                                   // timestamp of java is longer than PHP 
	String hexTime =Long.toHexString(time);            // hexTime  in Hexadecimal  
	String token =getMD5( (secret+ filePathName + hexTime).getBytes());
	return protectedPath +token+"/"+hexTime+ filePathName;
	
	
	public String getMD5(byte[] source) {
	        String s = null;
	        char hexDigits[] = { 
	        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',   'e', 'f' };
	        try {
	                java.security.MessageDigest md = java.security.MessageDigest
	                                .getInstance("MD5");
	                md.update(source);
	                byte tmp[] = md.digest();
	                char str[] = new char[16 * 2];
	                int k = 0; 
	                for (int i = 0; i < 16; i++) { 
	                        byte byte0 = tmp[i]; 
	                        str[k++] = hexDigits[byte0 >>> 4 & 0xf]; 
	                        str[k++] = hexDigits[byte0 & 0xf];
	                }
	                s = new String(str); 
	        } catch (Exception e) {
	                e.printStackTrace();
	        }
	        return s;
	}


#More documentation
Ajbapps has made a guide here to setup apache with mod_auth_token for Streaming.

#License
mod_auth_token is released under the Apache 2.0 License

#Credits
mod_auth_token is an apache module written by Mikael Johansson and by David Alves.
Inspired from mod_secdownload in LIGHTTPD. 
