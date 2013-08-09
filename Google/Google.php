<?php

class Google 
{
	protected $client_id;
	protected $client_secret;
	protected $redirect_uri;
	protected $code;
	protected $domain;

	
    /**
     * Add information from: https://code.google.com/apis/console/
     *
     * @param $client_id The Client ID.
     * @param $client_secret The Client secret.
     * @param $redirect_uri The Redirect Url.
     * @param $code The callback code.
     */

	public function __construct( $client_id, $client_secret, $domain )
	{
		if( !$client_id || !$client_secret || !$domain )
		{
			throw new Exception( 'Invalid credentials.' );
		}
		else
		{
			$this->client_id 	 = $client_id;
			$this->client_secret = $client_secret;
			$this->domain 		 = $domain;
			$this->redirect_uri  = get_bloginfo('url');
			$this->code   		 = isset( $_GET['code'] ) ? $_GET['code'] : null;

			$this->handle();
		}
	} 


	/**
     * Handles incoming authentication requests.
     *
     * @param Request $request The request object.
     */

	public function handle()
	{
		try 
	    {
			// Chek for the code callback, the nonce and not logged in
			if( $this->code && wp_verify_nonce( $_GET['state'], 'state' ) && !is_user_logged_in() )
			{
				$response = wp_remote_request( 'https://accounts.google.com/o/oauth2/token', array(
			        'method'    => 'POST',
			        'timeout'   => 60,
			        'sslverify' => true,
			        'body' =>  array(
			           	'code' 	   		=> $this->code,
			            'client_id' 	=> $this->client_id,
			            'client_secret' => $this->client_secret,
			            'redirect_uri' 	=> $this->redirect_uri,
			            'grant_type'    => 'authorization_code'
			        )
			    ));

			    $token = json_decode( $response['body'] )->access_token;

			    if( !empty( $token ) )
			    {
			    	$user = $this->userInfo( $token );

			    	$this->findUser( $user );
			    }
			    else
			    {
			    	throw new Exception( 'Invalid token.' );
			    }
			}
		}

		catch( Exception $e ) 
		{
		    echo 'Caught exception: ',  $e->getMessage();
		}
	}


	public function userInfo( $token )
	{
		$response = wp_remote_request( 'https://www.googleapis.com/oauth2/v1/userinfo?access_token=' . $token );
		
		$data = json_decode( $response['body'] );

		return (object) array(
			'ID' 	 	 	 => $data->id,
			'email' 		 => $data->email,
			'verified_email' => $data->verified_email,
			'name' 			 => $data->name,
			'given_name' 	 => $data->given_name,
			'family_name' 	 => $data->family_name,
			'hd' 			 => $data->hd,
		);
	}


	public function loginLogout( $loginText = false, $logoutText = false )
	{
		if( !is_user_logged_in() )
		{
			$url = sprintf( 
		        'https://accounts.google.com/o/oauth2/auth?client_id=%s&response_type=%s&scope=%s&redirect_uri=%s&state=%s',
				$this->client_id,
				urlencode( 'code' ),
				urlencode( 'profile email openid' ),
				urlencode( $this->redirect_uri ),
				wp_create_nonce( 'state' )
		    );

		    $link = '<a href="'. $url .'">'.( !empty( $loginText ) ? $loginText : __( 'Login with Google Account' ) ).'</a>';
		}
		else
		{
			$link = '<a href="'. wp_logout_url() .'">'.( !empty( $logoutText ) ? $logoutText : __( 'Logout' ) ).'</a>';
		}

		return $link;
	}


	public function findUser( $user )
    {
    	try 
	    {
	    	if( strstr( $user->email, $this->domain ) !== FALSE )
	    	{
		        $userID = (int) current( get_users( array(
		            'meta_key' 	 => 'uid',
		            'meta_value' => $user->ID,
		            'fields' 	 => 'ID'
		        )));

		        if( !$userID )
		        {
		        	$userData = array(
						'ID' 			=> '',
						'user_login'	=> $user->email,
						'user_email'	=> $user->email,
						'display_name'	=> $user->name,
						'role'			=> 'author',
					);

		        	$userID = (int) wp_insert_user( $userData );

		        	if( $userID > 0 )
		        	{
		        		update_user_meta( $userID, 'uid', $user->ID );	
		        	}
		        	else
		        	{
		        		throw new Exception( 'Could not add uid to user.' );
		        	}
		        }

		        wp_set_auth_cookie( $userID, true );
		        wp_redirect( home_url() ); 

		        exit;
		    }
		    else
		    {
		    	throw new Exception( 'Only ' . $this->domain . ' are allowed to login!' );
		    }
		}
	  
		catch( Exception $e ) 
		{
		    echo 'Caught exception: ',  $e->getMessage();
		}
	}
}