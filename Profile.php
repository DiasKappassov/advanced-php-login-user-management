<?php namespace App\Controllers;

use App\Libraries\SiteGuard;
use App\Libraries\Authenticator;
use App\Libraries\PasswordHash;

class Profile extends BaseController {
	public function view($user_id = null) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("profile");
		
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if(isset($user_id) && $userModel->exists('id',$user_id)) {
			$user = $userModel->get_specific_id($user_id);
		} else {
			$user = $current_user;
		}
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'View Profile',
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel,
								'user' => $user
							);
		
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('profile/view', $data);
		echo view('pages/footer', $data, ['cache' => 60]);
		
	}
	
	public function update($user_id,$hash) {
		
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		if(!$siteGuard->privilege("profile.update")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("profile?edit=fail&msg={$msg}"));
		}
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("profile?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$userModel->exists('id',$user_id)) {
			return redirect()->to(base_url("profile"));
			exit();
		}
		
		if(isset($user_id) && $userModel->exists('id',$user_id) && $current_user->prvlg_group == "1" ) {
			$user = $userModel->get_specific_id($user_id);
		} else {
			$user = $current_user;
		}
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => "Update Profile ({$user->name})",
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel,
								'user' => $user
							);
		
		if($this->request->getPost('update_profile') !== NULL) {
			$validation =  \Config\Services::validation();
			helper('text');
			
			if(!$siteGuard->privilege("profile.update")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("profile/update/{$user_id}/{$hash}?edit=fail&msg={$msg}"));
			}
			
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
		        
				$validation->setRule('name', 'Name', 'trim|required');
				$validation->setRule('username', 'Username', "trim|required|min_length[4]|max_length[30]|is_unique[users.username, id,{$user_id}]");
				if($user->hybridauth_provider_uid == '') {
					$validation->setRule('old_password', 'Password', 'trim|required|min_length[4]');
				}
				$validation->setRule('email', 'Email', "trim|required|valid_email|is_unique[users.email, id,{$user_id}]");
				
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to(base_url("profile/update/{$user_id}/{$hash}"));
				} else {
					####################
					$db_fields = Array('name','mobile', 'address' , 'about' );
					
					foreach($db_fields as $field) {
						if($this->request->getPost($field) !== NULL) {
							$$field = escape_value($this->request->getPost($field, FILTER_SANITIZE_STRING));
							$user->$field = $$field;
						}
					}
					
					if($user->hybridauth_provider_uid == '') {
					$password = escape_value($this->request->getPost('password', FILTER_SANITIZE_STRING));
					if(isset($_POST['old_password']) && $_POST['old_password'] != '' ) {
						$old_password = escape_value($_POST['old_password']);
						$current_password = $user->password;
						$phpass = new PasswordHash(8, true);
						
						if(!$phpass->CheckPassword($old_password, $current_password)) {
							$msg = "Invalid Password. Please try again";
							return redirect()->to(base_url("profile/update/{$user_id}/{$hash}?edit=fail&msg={$msg}&id={$user_id}"));
						}
						
						} else {
							$msg = "Please enter your current password to continue editing your profile";
							return redirect()->to(base_url("profile/update/{$user_id}/{$hash}?edit=fail&msg={$msg}&id={$user_id}"));
						}
					
						if($siteGuard->privilege('profile.change_password')) {
							$current_password = $user->password;
							if($password !='' && $password != $current_password ) {
							$phpass = new PasswordHash(8, true);
							$hashedpassword = $phpass->HashPassword($password);		
							$user->password = $hashedpassword;
							}
						}
					}
					
					if($siteGuard->privilege('profile.change_email') ) {
						$email = escape_value($this->request->getPost('email', FILTER_SANITIZE_EMAIL));
						
						$current_email = $user->email;
						$email_exists = $userModel->exists_except("email", $email , $user_id);
						
						if($email_exists) {
							$msg = siteGuard_msg('email-exists');
							return redirect()->to(base_url("profile?edit=fail&msg={$msg}"));
						}
						
						if($email != '' && $email != $current_email) {
							$user->email = $email;
						}
					}
					
					if($siteGuard->privilege('profile.change_username') ) {
						$username = escape_value($this->request->getPost('username', FILTER_SANITIZE_STRING));
						
						$current_username = $user->username;
						$username_exists = $userModel->exists_except("username", $username , $user_id);
						
						if($username_exists) {
							$msg = siteGuard_msg('username-exists');
							return redirect()->to(base_url("profile/?edit=fail&msg={$msg}"));
						}
					
						if($username != '' && $username != $current_username) {
							$user->username = $username;
						}
					}
					
					$upl_msg = '';
					$upload_problems = 0;
					if($_FILES['avatar'] !== NULL) {
						$files = '';
							$f = 0;
							$images = array();
							$num_pics = 1;
							$target = $_FILES['avatar'];
							$crop_arr = $this->request->getPost('cropped');
							$crop = json_decode($crop_arr , true);
							for ($f ; $f < $num_pics ; $f++) :
								$file = "file";
								$string = $$file . "{$f}";
								$$string = new \App\Models\SiteGuardFile();	
									if(!empty($_FILES['avatar']['name'][$f])) {
										$$string->attach_file($_FILES['avatar'], $f);
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
								$user->avatar = $final_string;
							}
					}
					if($this->request->getPost('tfa_status') !== NULL && $this->request->getPost('tfa_status') == '1' ) {
						$user->tfa = 1;
						$user->tfa_secret = escape_value($this->request->getPost('tfa_secret', FILTER_SANITIZE_STRING));
						if($user->tfa_codes == '') {
							$codes = array();
							for($i = 1 ; $i <= 5 ; $i++) {
								$codes[] = random_string('numeric', 6);
							}
							$user->tfa_codes = implode(',',$codes);
						}
					} else {
						$user->tfa = 0;
						$user->tfa_secret = "";
						$user->tfa_codes = "";
					}
					
					if($this->request->getPost('disabled') !== NULL  && $this->request->getPost('disabled') == '1' && $user_id != "1" ) {
						$user->disabled = 1;
					} else {
						$user->disabled = 0;
					}
					
					if($userModel->update($user_id, $user)) {
						$group = $groupModel->get_specific_id($user->prvlg_group);
						$log = new \App\Models\SiteGuardLog();
						$log->log_action($current_user->id , "Update User" , "Update user object ({$user->name}), id #({$user->id}), Access level ({$group->name}) - access level id #({$group->id})" );
						$msg = siteGuard_msg('update-success');
						if(isset($upload_problems) && $upload_problems == '1' ) { $msg .= $upl_msg; }
						return redirect()->to(base_url("profile/?edit=success&msg={$msg}"));
					 } else {
						 $msg = siteGuard_msg('update-fail');
						return redirect()->to(base_url("profile/update/{$user_id}/{$hash}?edit=fail&msg={$msg}"));
					 }
					
					####################
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("profile?edit=fail&msg={$msg}"));	
			}
		
	}
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('profile/update', $data);
		echo view('pages/footer', $data, ['cache' => 60]);
	
	}
	
	public function close($user_id,$hash) {
		
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		if(!$siteGuard->privilege("profile.update")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("profile?edit=fail&msg={$msg}"));
		}
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("profile?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$userModel->exists('id',$user_id)) {
			return redirect()->to(base_url("profile"));
			exit();
		}
		
		if(isset($user_id) && $userModel->exists('id',$user_id) && $current_user->prvlg_group == "1" ) {
			$user = $userModel->get_specific_id($user_id);
		} else {
			$user = $current_user;
		}
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => "Update Profile ({$user->name})",
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel,
								'user' => $user
							);
		
		if($this->request->getPost('close_profile') !== NULL) {
			$validation =  \Config\Services::validation();
			helper('text');
			
			if(!$siteGuard->privilege("profile.update")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("profile/update/{$user_id}/{$hash}?edit=fail&msg={$msg}"));
			}
			
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
		        
				$validation->setRule('old_password', 'Password', 'trim|required|min_length[4]');
				
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to(base_url("profile/close/{$user_id}/{$hash}"));
				} else {
					####################
					if($this->request->getPost('old_password') !== NULL) {
					$old_password = escape_value($this->request->getPost('old_password',FILTER_SANITIZE_STRING));
						$current_password = $user->password;
						$phpass = new PasswordHash(8, true);
						
						if(!$phpass->CheckPassword($old_password, $current_password)) {	
							$msg = "Invalid Password. Please try again";
							return redirect()->to(base_url("profile/close/{$user_id}/{$hash}/?edit=fail&msg={$msg}"));
						}
					} else {
						$msg = "Please enter your current password to close your account";
						return redirect()->to(base_url("profile/close/{$user_id}/{$hash}/?edit=fail&msg={$msg}"));
					}
					$user->closed = 1;
					$user->last_seen = 0;
					if($userModel->update($user_id, $user)) {
						$group = $groupModel->get_specific_id($user->prvlg_group);
						$log = new \App\Models\SiteGuardLog();
						$onlineModel = new \App\Models\Online();
						$log->log_action($current_user->id , "Close Account" , "Close account ({$user->name}), id #({$user->id}), Access level ({$group->name}) - access level id #({$group->id})" );
						
						$online = $onlineModel->get_everything(" user_id = '{$user->id}' ");
						if($online) {
							foreach($online as $onl) {
								$onlineModel->delete($onl->id);
							}
						}
						$_SESSION = array();
						if (isset($_COOKIE[session_name()])) {
							setcookie(session_name() , '' , time()-42000 , '/');		
						}
						session_destroy();
						return redirect()->to(base_url("login/?edit=success&msg=Farewell, {$user->name}!"));
						
					 } else {
						 $msg = siteGuard_msg('submit-fail');
						return redirect()->to(base_url("profile/update/{$user_id}/{$hash}?edit=fail&msg={$msg}"));
					 }
					
					####################
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("profile?edit=fail&msg={$msg}"));	
			}
		
	}
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('profile/close', $data);
		echo view('pages/footer', $data, ['cache' => 60]);
	
	}
	
}
