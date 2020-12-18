<?php namespace App\Controllers;

use App\Libraries\SiteGuard;

class General_settings extends BaseController {
	public function index() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("general_settings");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'General Settings',
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel
							);
		
		
		######################
		if($this->request->getPost('update_settings') !== NULL) {
			$validation = \Config\Services::validation();
			helper('text');

			if(!$siteGuard->privilege("general_settings.update")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("general_settings?edit=fail&msg={$msg}"));
			}
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
				
				$validation->setRule('site_name', 'Site Name', 'trim|required');
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to(base_url('general_settings'));
				} else {
					$miscModel = new \App\Models\MiscFunction();
					$siteGuard_settings_array = $miscModel->get_function("general_settings");
					if($siteGuard_settings_array->value) {
						$settings = unserialize($siteGuard_settings_array->value);
						if(!is_array($settings)) {
							$settings = array();
						}
					} else {
						$settings = array();
					}
					
					$settings['site_name'] = escape_value($this->request->getPost('site_name', FILTER_SANITIZE_STRING));
					$settings['public_index'] = escape_value(urlencode($this->request->getPost('public_index', FILTER_SANITIZE_URL)));
					$settings['social_login'] = escape_value($this->request->getPost('social_login', FILTER_SANITIZE_STRING));
					$settings['2fa'] = escape_value($this->request->getPost('2fa', FILTER_SANITIZE_STRING));
					$settings['disable_after'] = escape_value($this->request->getPost('disable_after', FILTER_SANITIZE_STRING));
					$settings['attempts'] = str_replace('-' , '' , escape_value($this->request->getPost('attempts', FILTER_SANITIZE_STRING)));
					$settings['registration'] = escape_value($this->request->getPost('registration', FILTER_SANITIZE_STRING));
					$settings['registration_group'] = escape_value($this->request->getPost('registration_group', FILTER_SANITIZE_STRING));
					$settings['registration_activate'] = escape_value($this->request->getPost('registration_activate', FILTER_SANITIZE_STRING));
					$settings['smtp'] = escape_value($this->request->getPost('smtp', FILTER_SANITIZE_STRING));
					$settings['smtphost'] = escape_value(urlencode($this->request->getPost('smtphost', FILTER_SANITIZE_URL)));
					$settings['smtpport'] = escape_value($this->request->getPost('smtpport', FILTER_SANITIZE_STRING));
					$settings['smtpsecure'] = escape_value($this->request->getPost('smtpsecure', FILTER_SANITIZE_STRING));
					$settings['smtpusername'] = escape_value($this->request->getPost('smtpusername', FILTER_SANITIZE_STRING));
					$settings['smtppassword'] = escape_value($this->request->getPost('smtppassword', FILTER_SANITIZE_STRING));
					$settings['api'] = escape_value($this->request->getPost('api', FILTER_SANITIZE_STRING));
					$settings['api_key'] = escape_value($this->request->getPost('api_key', FILTER_SANITIZE_STRING));
					$settings['api_salt'] = escape_value($this->request->getPost('api_salt', FILTER_SANITIZE_STRING));
					$settings['salt'] = random_string('alnum', 10);
					$settings['footer'] = escape_value($this->request->getPost('footer', FILTER_SANITIZE_STRING));
					
					if(isset($_FILES['logo']) ) {
						$files = '';
						$f = 0;
						$images = array();
						$num_pics = 1;
						$target = $_FILES['logo'];
						$crop_arr = $this->request->getPost('cropped');
						$crop = json_decode($crop_arr , true);
						for ($f ; $f < $num_pics ; $f++) :
							$file = "file";
							$string = $$file . "{$f}";
							$$string = new \App\Models\SiteGuardFile();	
							if(!empty($_FILES['logo']['name'][$f])) {
								$$string->attach_file($_FILES['logo'], $f);
								if ($fileid= $$string->save_file($crop)) {
									$images[$f] = $fileid;
								} else {
									$upl_msg = "Cannot upload profile picture, please try again";
									$upl_msg .= join("<br />" , $$string->errors);
									$upload_problems = 1;
								}
							}
						endfor;
						
						if(!empty($images)) {
							$final_string = implode("," , $images);
							$settings['logo'] = $final_string;
						}
					}
					
					if($this->request->getPost('reset-logo') !== NULL && $this->request->getPost('reset-logo') == '1' ) {
						$settings['logo'] = '';
					}
					
					$data = array('value' => serialize($settings));
					
					if($miscModel->update($siteGuard_settings_array->id, $data)) {
						$logModel = new \App\Models\SiteGuardLog();
						$logModel->log_action($current_user->id , "Update Settings" , "Updated script general settings");
						$msg = siteGuard_msg('submit-success');
						if(isset($upload_problems) && $upload_problems == '1' ) {
							$msg .= '<br>'.$upl_msg;
						}
						return redirect()->to(base_url("general_settings?edit=success&msg={$msg}"));
					} else {
						$msg = siteGuard_msg('submit-fail');
						return redirect()->to(base_url("general_settings?edit=fail&msg={$msg}"));
					}

					
				}
				
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("general_settings?edit=fail&msg={$msg}"));	
			}
		}	
		######################
		
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('settings/general_settings', $data);
		echo view('pages/footer', $data, ['cache' => 60]);	
	}
	
	
}
