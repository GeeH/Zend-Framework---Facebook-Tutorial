<?php
class Application_Model_Facebook
{
    /**
     * The encrypted Facebook sigs POSTed through signed_request
     * @var string
     */
    private $_fbSigs;
    /**
     * Has the user authenticated successfully?
     * @var bool
     */
    public $isAuthed = false;
     /**
     * Has the user actually installed (allowed) the app?
     * @var bool
     */
    public $hasInstalled = false;
    /**
     * Facebook passed data
     * @var array
     */
    public $fbData;
    /**
     * Facebook Application ID
     */
    const FACEBOOK_APP_ID = '107263386015999';
    /**
     * Facebook Secret String
     */
    const FACEBOOK_SECRET = 'e68e873a1bd976e7c56567c9a0b5e93c';
    /**
     * Facebook allow URL
     */
    const FACEBOOK_ALLOW_URL = 'https://www.facebook.com/dialog/oauth';
    /**
     * Facebook Graph Entry Point
     */
    const FACEBOOK_GRAPH_URL = 'https://graph.facebook.com/';
    /**
     * Facebook FQL Entry Point
     */
    const FACEBOOK_FQL_URL = 'https://api.facebook.com/method/fql.query';

    public function __construct($signed_request)
    {
        // Check the signed request is what we would have expected
        if(!is_string($signed_request) || empty($signed_request))
        {
            throw new Application_Model_FacebookException('Invalid signed_request');
        }
        // Set the private variable to the passed string
        $this->_fbSigs = $signed_request;
        // Parse the sigs
        $this->_parseSignedRequest();
    }
    
    /**
     * Returns information about the currently logged in user
     * @return array
     */
    public function getUserInfo()
    {
        $url = self::FACEBOOK_GRAPH_URL.'me';
        return $this->_getFromGraph($url);
    }

    /**
     * Returns a list of a user's Facebook friends
     * @param bool $justUsingApp Only return friends who are using this app?
     * @return array
     */
    public function getUserFriends($justUsingApp = false)
    {
        if(!$justUsingApp)
        {
            $url = self::FACEBOOK_GRAPH_URL.'me/friends';
            return $this->_getFromGraph($url);
        }
        else
        {
            $fql = "SELECT uid FROM user WHERE has_added_app=1 and uid IN (SELECT uid2 FROM friend WHERE uid1 = {$this->fbData['user_id']})";
            return $this->_doFQLQuery($fql);
        }
    }

    private function _parseSignedRequest()
    {
        // If the Facbook Sigs are not valid, set authed param and return false
        if (!is_string($this->_fbSigs) || empty($this->_fbSigs))
        {
            $this->isAuthed = false;
            return false;
        }
        // Split the sigs into 2 parts
        list($encoded_sig, $payload) = explode('.', $this->_fbSigs, 2);

        // decode the data
        $sig = $this->_base64UrlDecode($encoded_sig);
        $data = json_decode($this->_base64UrlDecode($payload), true);

        // Check if the encryption is valid
        if (strtoupper($data['algorithm']) !== 'HMAC-SHA256')
        {
            $this->isAuthed = false;
            return false;
        }

        // Check the sigs are valid
        $expected_sig = hash_hmac('sha256', $payload, self::FACEBOOK_SECRET, $raw = true);
        if ($sig !== $expected_sig)
        {
            $this->isAuthed = false;
            return false;
        }

        // Sigs are valid, set the variables
        $this->isAuthed = true;
        $this->fbData = $data;

        // If an oAuth token is sent, we know that the user has allowed the app
        if (isset($this->fbData['oauth_token']) && is_string($this->fbData['oauth_token']) && !empty($this->fbData['oauth_token']))
        {
            $this->hasInstalled = true;
        }
        
        return true;
    }

    /**
     * base64 url decoder
     * @param string $input
     * @return string
     */
    private function _base64UrlDecode($input)
    {
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Handles requests to the Facebook Graph API
     * @param string $url The URL to query
     * @param array $args An array of arguement to pass
     * @return object
     */
    protected function _getFromGraph($url, array $args=array())
    {
        // Check if the user is authed
        if (!$this->isAuthed)
        {
            throw new Application_Model_FacebookException('User is not authenticated');
        }
        // Create an instance of the Http Client
        $http = new Zend_Http_Client($url);
        // Add the access token we were passed in the encoded sigs to the request
        $args['access_token']=$this->fbData['oauth_token'];
        // Set the get parameters to the arguments we need
        $http->setParameterGet($args);
        try {
            // do the request
            $request = $http->request();
          
            // if the status isn't 200 (OK)
            if($request->getStatus() != 200)
            {
                throw new Application_Model_FacebookException('Error requesting data.. Status: '.$request->getStatus());
            }
            else
            {
                // Return the decoded object as an array
                return Zend_Json::decode($request->getBody(), Zend_Json::TYPE_ARRAY);
            }
        }
        catch (Exception $e)
        {
            throw new Application_Model_FacebookException('Error from Facebook API: '.$e->getMessage());
        }
    }

    /**
     * Gets data from the Facebook FQL API
     * @param string $fql
     */
    protected function _doFQLQuery($fql)
    {
        // Check if the user is authed
        if (!$this->isAuthed)
        {
            throw new Application_Model_FacebookException('User is not authenticated');
        }
        $url = self::FACEBOOK_FQL_URL;
        $args = array(
            'query' => $fql,
            'format' => 'json'
        );
        
        return $this->_getFromGraph($url, $args);
    }

}