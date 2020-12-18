<?php namespace App\Controllers;

use App\Libraries\SiteGuard;

class Users extends BaseController {
	public function index() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("users");
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Manage Users',
								'current_user' => $current_user,
								'userModel' => new \App\Models\User(),
								'groupModel' => new \App\Models\Group()
							);
		
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('users/view', $data);
		echo view('pages/footer', $data, ['cache' => 60]);
		
	}
	
	public function create() {
		
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		if(!$siteGuard->privilege("users.create")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
		}
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Create New User',
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel
							);
		
		if($this->request->getPost('add_user') !== NULL) {
			
			$validation =  \Config\Services::validation();
			
			if(!$siteGuard->privilege("users.create")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			}
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
		        
				$validation->setRule('name', 'Name', 'trim|required');
				$validation->setRule('username', 'Username', 'trim|required|min_length[4]|max_length[30]|is_unique[users.username]');
				$validation->setRule('password', 'Password', 'trim|required|min_length[4]');
				$validation->setRule('email', 'Email', 'trim|required|valid_email|is_unique[users.email]');
				
				
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to(base_url('users/create'));
				} else {
					####################
					$db_fields = Array('name','mobile', 'address' , 'about' , 'prvlg_group' , 'username' , 'email', 'api_key');
					
					$new_user = new \App\Entities\User();
					
					foreach($db_fields as $field) {
						if($this->request->getPost($field) !== NULL) {
							$$field = escape_value($this->request->getPost($field, FILTER_SANITIZE_STRING));
							$new_user->$field = $$field;
						}
					}
					
					$new_user->registered = now_db();
					
					$email_exists = $userModel->exists("email", $new_user->email);
					if($email_exists) {
						$msg = siteGuard_msg('email-exists');
						return redirect()->to(base_url("users/create?edit=fail&msg={$msg}"));
					}
					
					$username_exists = $userModel->exists("username", $new_user->username);
					if($username_exists) {
						$msg = siteGuard_msg('username-exists');
						return redirect()->to(base_url("users/create?edit=fail&msg={$msg}"));
					}
					
					
					$phpass = new \App\Libraries\PasswordHash(8, true);
					$new_user->password = $phpass->HashPassword($this->request->getPost('password',FILTER_SANITIZE_STRING));
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
								$new_user->avatar = $final_string;
							}
					}
					
					####################
					  $query = $userModel->save($new_user);
					 if($query) {
						$group = $groupModel->get_specific_id($new_user->prvlg_group, true);
						$log = new \App\Models\SiteGuardLog();
						$log->log_action($current_user->id , "Add New User" , "Add new user object ({$new_user->name}), id #({$userModel->getInsertID()}), Access level ({$group->name}) - access level id #({$group->id})" );
						$msg = siteGuard_msg('submit-success');
						return redirect()->to(base_url("users?edit=success&msg={$msg}"));
					 } else {
						 $msg = siteGuard_msg('submit-fail');
						 return redirect()->to(base_url("users/create?edit=fail&msg={$msg}"));
					 }
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("users?edit=fail&msg={$msg}"));	
			}
		} else {
			echo view('pages/header', $data, ['cache' => 60]);
			echo view('pages/navbar', $data, ['cache' => 60]);
			echo view('users/create', $data);
			echo view('pages/footer', $data, ['cache' => 60]);
		}
		
		
	}
	public function delete($user_id,$hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("users");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$userModel->exists('id',$user_id)) {
			$msg = siteGuard_msg('user-not_found');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj = $userModel->get_specific_id($user_id);
		if(!$siteGuard->privilege("users.delete")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if($user_id == "1" || $this_obj->prvlg_group == '1' && $current_user->prvlg_group != '1' ) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj->deleted = '1';
		if($userModel->update($user_id, $this_obj)) {
			$msg = siteGuard_msg('delete-success');
			$group = $groupModel->get_specific_id($this_obj->prvlg_group);
			$log = new \App\Models\SiteGuardLog();
			$log->log_action($current_user->id , "Delete User" , "Delete User object ({$this_obj->name}) - id #({$this_obj->id}), Access level ({$group->name}) - access level id #({$group->id})");
			return redirect()->to(base_url("users?edit=success&msg={$msg}"));
		} else {
			$msg = siteGuard_msg('delete-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
	}
	public function ban($user_id,$hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("users");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$userModel->exists('id',$user_id)) {
			$msg = siteGuard_msg('user-not_found');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj = $userModel->get_specific_id($user_id);
		if(!$siteGuard->privilege("users.update")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if($user_id == "1" || $this_obj->prvlg_group == '1' && $current_user->prvlg_group != '1' ) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj->disabled = '1';
		if($userModel->update($user_id, $this_obj)) {
			$msg = siteGuard_msg('ban-success');
			$group = $groupModel->get_specific_id($this_obj->prvlg_group);
			$log = new \App\Models\SiteGuardLog();
			$log->log_action($current_user->id , "Ban User" , "Ban User object ({$this_obj->name}) - id #({$this_obj->id}), Access level ({$group->name}) - access level id #({$group->id})");
			return redirect()->to(base_url("users?edit=success&msg={$msg}"));
		} else {
			$msg = siteGuard_msg('delete-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
	}
	public function unban($user_id,$hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("users");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$userModel->exists('id',$user_id)) {
			$msg = siteGuard_msg('user-not_found');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj = $userModel->get_specific_id($user_id);
		if(!$siteGuard->privilege("users.update")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if($user_id == "1" || $this_obj->prvlg_group == '1' && $current_user->prvlg_group != '1' ) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj->disabled = '0';
		if($userModel->update($user_id, $this_obj)) {
			$msg = siteGuard_msg('activation-success');
			$group = $groupModel->get_specific_id($this_obj->prvlg_group);
			$log = new \App\Models\SiteGuardLog();
			$log->log_action($current_user->id , "Unban User" , "Unban User object ({$this_obj->name}) - id #({$this_obj->id}), Access level ({$group->name}) - access level id #({$group->id})");
			return redirect()->to(base_url("users?edit=success&msg={$msg}"));
		} else {
			$msg = siteGuard_msg('update-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
	}
	public function impersonate($user_id,$hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("users");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$userModel->exists('id',$user_id)) {
			$msg = siteGuard_msg('user-not_found');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$siteGuard->privilege("users.impersonate")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if($user_id == "1" || $current_user->prvlg_group != '1' || !$siteGuard->privilege("users.impersonate")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj = $userModel->get_specific_id($user_id);
		$group = $groupModel->get_specific_id($this_obj->prvlg_group);
		$log = new \App\Models\SiteGuardLog();
		$log->log_action($current_user->id , "Impersonate User" , "Impersonate User object ({$this_obj->name}) - id #({$this_obj->id}), Access level ({$group->name}) - access level id #({$group->id})");
		$siteGuard->clear_user();
		$siteGuard->impersonate($this_obj);
		return redirect()->to(base_url("index"));
	}
	public function activate($user_id,$hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("users");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$userModel->exists('id',$user_id)) {
			$msg = siteGuard_msg('user-not_found');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj = $userModel->get_specific_id($user_id);
		if(!$siteGuard->privilege("users.update")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if($user_id == "1" || $this_obj->prvlg_group == '1' && $current_user->prvlg_group != '1' ) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj->pending = '0';
		if($userModel->update($user_id, $this_obj)) {
			# MAILER #
			$msg = "Your account on {$siteGuard->settings['site_name']} (".base_url() . ") has been activated successfully.";
			$title = 'Account activated';
			$link = array('text' => "Login" , "link" => base_url() );
			$siteGuard->send_mail_to($this_obj->email , $this_obj->name , $msg , $title, $link);
			$msg = siteGuard_msg('activation-success');
			$group = $groupModel->get_specific_id($this_obj->prvlg_group);
			$log = new \App\Models\SiteGuardLog();
			$log->log_action($current_user->id , "Activate User" , "Activate User object ({$this_obj->name}) - id #({$this_obj->id}), Access level ({$group->name}) - access level id #({$group->id})");
			return redirect()->to(base_url("users?edit=success&msg={$msg}"));
		} else {
			$msg = siteGuard_msg('delete-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
	}
	
	public function restore($user_id,$hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("users");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$userModel->exists('id',$user_id)) {
			$msg = siteGuard_msg('user-not_found');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj = $userModel->get_specific_id($user_id);
		if(!$siteGuard->privilege("users.update")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if($user_id == "1" || $this_obj->prvlg_group == '1' && $current_user->prvlg_group != '1' ) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj->closed = '0';
		if($userModel->update($user_id, $this_obj)) {
			# MAILER #
			$msg = "Your account on {$siteGuard->settings['site_name']} (".base_url() . ") has been activated successfully.";
			$title = 'Account activated';
			$link = array('text' => "Login" , "link" => base_url() );
			$siteGuard->send_mail_to($this_obj->email , $this_obj->name , $msg , $title, $link);
			
			$msg = siteGuard_msg('activation-success');
			$group = $groupModel->get_specific_id($this_obj->prvlg_group);
			$log = new \App\Models\SiteGuardLog();
			$log->log_action($current_user->id , "Restore User Account" , "Restore User account ({$this_obj->name}) - id #({$this_obj->id}), Access level ({$group->name}) - access level id #({$group->id})");
			return redirect()->to(base_url("users?edit=success&msg={$msg}"));
		} else {
			$msg = siteGuard_msg('delete-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
	}
	public function update($user_id, $hash) {
		
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		if(!$siteGuard->privilege("users.update")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
		}
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$userModel->exists('id',$user_id)) {
			$msg = $siteGuard_msg['user-not_found'];
			return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj = $userModel->get_specific_id($user_id);
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Update User',
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel,
								'this_obj' => $this_obj
							);
		
		if($this->request->getPost('update_user') !== NULL) {
			
			$validation =  \Config\Services::validation();
			
			if(!$siteGuard->privilege("users.update")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
			}
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
		        
				$validation->setRule('name', 'Name', 'trim|required');
				$validation->setRule('username', 'Username', 'trim|required|min_length[4]|max_length[30]|is_unique[users.username,id,'.$user_id.']');
				$validation->setRule('email', 'Email', 'trim|required|valid_email|is_unique[users.email,id,'.$user_id.']');
				
				
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to(base_url("users/update/{$user_id}/{$siteGuard->csrf}"));
				} else {
					####################
					$db_fields = Array('name','mobile', 'address' , 'about' , 'prvlg_group', 'api_key');
					helper('text');
					$edited_user = $userModel->get_specific_id($user_id);
					
					foreach($db_fields as $field) {
						if($this->request->getPost($field) !== NULL) {
							$$field = escape_value($this->request->getPost($field, FILTER_SANITIZE_STRING));
							$edited_user->$field = $$field;
						}
					}
					
					
					$password = escape_value($this->request->getPost('password', FILTER_SANITIZE_STRING));
				
					if($current_user->prvlg_group == "1" && $siteGuard->privilege('profile.change_email') ) {
						$email = escape_value($this->request->getPost('email', FILTER_SANITIZE_STRING));
						
						$current_email = $this_obj->email;
						$email_exists = $userModel->exists_except("email", $email , $user_id);
						
						if($email_exists) {
							$msg = $siteGuard_msg['email-exists'];
							return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
						}
						
						if($email != '' && $email != $current_email) {
							$edited_user->email = $email;
						}
					}
					
					if($current_user->prvlg_group == "1" && $siteGuard->privilege('profile.change_username') ) {
						$username = escape_value($this->request->getPost('username', FILTER_SANITIZE_STRING));
						
						$current_username = $this_obj->username;
						$username_exists = $userModel->exists_except("username", $username , $user_id);
						
						if($username_exists) {
							$msg = $siteGuard_msg['username-exists'];
							return redirect()->to(base_url("users?edit=fail&msg={$msg}"));
						}
					
						if($username != '' && $username != $current_username) {
							$edited_user->username = $username;
						}
					}
					
					if($current_user->prvlg_group == "1" && $siteGuard->privilege('profile.change_password') ) {
						$current_password = $this_obj->password;
						if($password !='' && $password != $current_password ) {
						$phpass = new \App\Libraries\PasswordHash(8, true);
						$hashedpassword = $phpass->HashPassword($password);
						
						$edited_user->password = $hashedpassword;
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
								$edited_user->avatar = $final_string;
							}
					}
					if($this->request->getPost('tfa_status') !== NULL && $this->request->getPost('tfa_status') == '1' ) {
					$edited_user->tfa = 1;
					$edited_user->tfa_secret = escape_value($this->request->getPost('tfa_secret', FILTER_SANITIZE_STRING));
					if($edited_user->tfa_codes == '') {
						$codes = array();
						for($i = 1 ; $i <= 5 ; $i++) {
							$codes[] = random_string('numeric', 6);
						}
						$edited_user->tfa_codes = implode(',',$codes);
					}
				} else {
					$edited_user->tfa = 0;
					$edited_user->tfa_secret = "";
					$edited_user->tfa_codes = "";
				}
				
				
				if($this->request->getPost('closed') !== NULL  && $this->request->getPost('closed') == '1' && $user_id != "1" ) {
					$edited_user->closed = 1;
				} else {
					$edited_user->closed = 0;
				}
				
				if($this->request->getPost('disabled') !== NULL  && $this->request->getPost('disabled') == '1' && $user_id != "1" ) {
					$edited_user->disabled = 1;
				} else {
					$edited_user->disabled = 0;
				}
					####################
					
					 $query = $userModel->update($user_id, $edited_user);
					 if($query) {
						$group= $groupModel->get_specific_id($edited_user->prvlg_group);
						$log = new \App\Models\SiteGuardLog();
						$log->log_action($current_user->id , "Update User" , "Update user object ({$this_obj->name}), id #({$this_obj->id}), Access level ({$group->name}) - access level id #({$group->id})" );
						$msg = siteGuard_msg('update-success');
						return redirect()->to(base_url("users?edit=success&msg={$msg}"));
					 } else {
						 $msg = siteGuard_msg('update-fail');
						 return redirect()->to(base_url("userscreate?edit=fail&msg={$msg}"));
					 }
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("users?edit=fail&msg={$msg}"));	
			}
		} else {
			echo view('pages/header', $data, ['cache' => 60]);
			echo view('pages/navbar', $data, ['cache' => 60]);
			echo view('users/update', $data);
			echo view('pages/footer', $data, ['cache' => 60]);
		}
		
		
	}
	
}
