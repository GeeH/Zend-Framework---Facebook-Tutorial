<?php
class IndexController extends Zend_Controller_Action
{
    
    public function init()
    {
        /* Initialize action controller here */
    }

    public function indexAction()
    {
        // Grab the signed request and setup the Facebook model
        $signed_request = $this->_getParam('signed_request', null);
        if(empty($signed_request))
        {
            throw new Exception('Security Error');
        }
        $FB = new Application_Model_Facebook($signed_request);

        // if the user has not installed,
        // redirect to the allow URL
        if (!$FB->hasInstalled)
        {
            $this->view->redirect_url =
                Application_Model_Facebook::FACEBOOK_ALLOW_URL
                .'?client_id='.Application_Model_Facebook::FACEBOOK_APP_ID
                .'&redirect_uri='.$_SERVER['HTTP_REFERER'];
            $this->_helper->viewRenderer->setScriptAction('redirect');
        }

        // set some view variables...
        $userInfo = $FB->getUserInfo();
        Zend_Debug::dump($userInfo);
    }

}

