<?php namespace App\Controllers;

use App\Libraries\SiteGuard;
use App\Libraries\Authenticator;
use App\Libraries\PasswordHash;

class Login extends BaseController {
	public function index() {
		$siteGuard = new Siteguard();
		$siteGuard->get_user("check_logged_in");
		
		helper('form');
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		$onlineModel = new \App\Models\Online();
		
		$data = array(  'siteGuard' => $siteGuard,
								'captcha_info' => $siteGuard->config['captcha'],
								'two_factor_step' => false,
								'username' => '',
								'password' => '',
								'remember' => ''
							);
		
		####################
		
		if($this->request->getPost('enterlogin') !== NULL) {
			
			$validation =  \Config\Services::validation();
				
				$validation->setRule('username', 'Username', 'trim|required');
				$validation->setRule('password', 'Password', 'trim|required');
		
		
		if ($this->request->getPost(csrf_token()) == $siteGuard->csrf ) {
			
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to("login");
				} else {
					
		$username = trim(escape_value($this->request->getPost("username",FILTER_SANITIZE_STRING)));
		$password = trim(escape_value($this->request->getPost("password",FILTER_SANITIZE_STRING)));
		if(isset($_POST['remember-me']) && $_POST['remember-me'] == '1') {
			$remember = true;
			$data['remember'] = true;
		}
		
		$data['username'] = $username;
		$data['password'] = $password;
		
		
		if(isset($_POST['next']) && $_POST['next'] != '' ) {
			$n = escape_value($_POST['next']);	
			$next = urldecode($n);
		}
		if (strlen($password) > 72) {
			return redirect()->to('login');
			die();
		}
		
		$log = new \App\Models\SiteGuardLog();
		
		$found_user =$userModel->hash_authenticate($username);
		
		if ($found_user) {
			
			//check if disabled ...
			if ($found_user->disabled == "1") {
				$msg = "Account banned! please contact system administration";
				return redirect()->to("login?edit=fail&msg={$msg}");
			}
			//check if closed ...
			if ($found_user->closed == "1") {
				$msg = "This account is closed, please contact system administration if you want to restore your account.";
				return redirect()->to("login?edit=fail&msg={$msg}");
			}
			//check if not activated ...
			if ($found_user->pending == "1") {
				if(isset($siteGuard->settings['registration_activate']) && $siteGuard->settings['registration_activate'] == 'self_activation') {
					$msg = "Account pending activation, please enter your email address to resend activation email";
					return redirect()->to("login?type=activation-link&edit=fail&msg={$msg}");
				} else {
					$msg = "Account pending admin approval. we will notify you on your email upon approval";
					return redirect()->to("login?edit=fail&msg={$msg}");
				}
			}
			//check max. sessions ...
			$group = $groupModel->get_specific_id($found_user->prvlg_group);
			if($group->max_connections) {
				$cur_connections = $onlineModel->count_everything(" user_id = '{$found_user->id}' ");
				if ($cur_connections > $group->max_connections) {
					$msg = "This account has reached the maximum number of simultaneous sessions.";
					return redirect()->to("login?edit=fail&msg={$msg}");
				}
			}
			
			//check for throttling ...
			if($found_user->throttle_from != '' && time() < $found_user->throttle_from + $found_user->throttle_time) {
				$then = ($found_user->throttle_from + $found_user->throttle_time) - time();
				$msg = "Account Locked ! Please try again after " . secondsToTime($then);
				return redirect()->to("login?edit=fail&msg={$msg}");
			}
			
			
				//check password ...
				$saltedhash = $found_user->password;
				$phpass = new PasswordHash(8, true);
				
				if ($phpass->CheckPassword($password, $saltedhash)) {
					//Check for 2 factor authentication
					if($found_user->tfa && isset($siteGuard->settings['2fa']) && $siteGuard->settings['2fa']  == 'on' ) {
						$data['two_factor_step'] = true;
						if(isset($_POST['otp']) && $_POST['otp'] != '' ) {
							$ga = new Authenticator();
							$otp = escape_value($this->request->getPost('otp'));
							$backup_pass = false;
							$checkResult = $ga->verify($found_user->tfa_secret, $otp);
							if($found_user->tfa_codes) {
								$backup_codes = explode(',' , $found_user->tfa_codes);
								if (in_array($otp, $backup_codes)) {
									$backup_pass = true;
									$key = array_search($otp, $backup_codes);
									unset($backup_codes[$key]);
									$sent_data = array("tfa_codes" => implode(',' , $backup_codes));
									$userModel->update($found_user->id, $sent_data);
								}
							}
							if($checkResult || $backup_pass == true) {
								$siteGuard->login($found_user);
								if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {$userModel->clear_invalid_login($found_user->id);}
								$log->log_action($found_user->id , "Login" , "Login to system");
								if(isset($_POST['remember-me']) && $_POST['remember-me'] == '1') {
									$params = session_get_cookie_params();
									setcookie(session_name(), $_COOKIE[session_name()], time() + 60*60*24*30, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
								}
								if(isset($_POST['next']) && $_POST['next'] != '' ) {
									$n = escape_value($_POST['next']);	
									$next = urldecode($n);
									return redirect()->to($next);
								} else {
									if(isset($siteGuard->settings['public_index']) && $siteGuard->settings['public_index']  != '') { $index = urldecode($siteGuard->settings['public_index']); } else { $index = 'index'; }
									return redirect()->to($index);
								}
							} else {
								$error_message = "OTP Code is invalid! please try again.";
								if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {									
									$userModel->invalid_login($found_user->id, $siteGuard->settings['attempts']);
									
									$attempts = str_replace('-','',$siteGuard->settings['attempts']) - $found_user->invalid_logins;
									if($attempts < 0) {
										$attempts = 0;
									}
									$error_message .= " you have ({$attempts}) attempts left";
								}
								return redirect()->to("login?edit=fail&msg={$error_message}");
							}
						}
					} else {
					
						$siteGuard->login($found_user);
						
						if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {$userModel->clear_invalid_login($found_user->id);}
						$log->log_action($found_user->id , "Login" , "Login to system");
						
						if(isset($_POST['remember-me']) && $_POST['remember-me'] == '1') {
							$params = session_get_cookie_params();
							setcookie(session_name(), $_COOKIE[session_name()], time() + 60*60*24*30, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
						}
						if(isset($_POST['next']) && $_POST['next'] != '' ) {
							$n = escape_value($_POST['next']);	
							$next = urldecode($n);
							return redirect()->to($next);
						} else {
							if(isset($siteGuard->settings['public_index']) && $siteGuard->settings['public_index']  != '') { $index = urldecode($siteGuard->settings['public_index']); } else { $index = 'index'; }
							return redirect()->to($index);
						}
						
					}
				} else {
					$error_message = "Invalid Password, Please try again.";
					if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {
						$userModel->invalid_login($found_user->id,$siteGuard->settings['attempts']);
						$attempts = str_replace('-','',$siteGuard->settings['attempts']) - $found_user->invalid_logins;
						if($attempts < 0) {
							$attempts = 0;
						}
						$error_message .= " you have ({$attempts}) attempts left";
					}
					
					return redirect()->to("login?edit=fail&msg={$error_message}");
				}
				
			
			
		} else {
			$error_message = "User not found , Please try again";
			return redirect()->to("login?edit=fail&msg={$error_message}");
		}
		
		
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to("login?edit=fail&msg={$msg}");
			}
			
		}
		####################
		if($this->request->getPost('forgot_pass') !== NULL) {
			
			$validation =  \Config\Services::validation();
			$validation->setRule('forgot-email', 'Email', 'trim|required|valid_email');
			
		
		if ($this->request->getPost(csrf_token()) == $siteGuard->csrf ) {
			
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to("login");
				} else {
						
						$email = trim(escape_value($this->request->getPost("forgot-email",FILTER_SANITIZE_EMAIL)));
						
						$user = $userModel->get_everything("email = '{$email}' AND deleted = 0", 'id DESC' , 1);
						
						if($user) {
							$user = $user[0];			
							
							if ($user->disabled == "1") {
								$msg = "Account banned! please contact system admins.";
								return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
							}
							
							if($user->reset_hash) {
								$then = $user->reset_hash;
								if(is_numeric($then) && (time() - $then) > 3600 || !is_numeric($then) ) {		//expired link..
									$reset_data = array( "reset_hash" => '');
									$userModel->update($user->id, $reset_data);
								}
								
								if(is_numeric($then) && (time() - $then) < 300 ) {		//very early to re-generate! < 5 mins.
									$deficit = 300 - (time() - $then);
									$msg = "Reset link already generated and sent to this email, Please try again after " . secondsToTime($deficit);
									return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
								}
							}
							
							$reset_hash = time();
							$reset_data = array( "reset_hash" => $reset_hash);
							$userModel->update($user->id, $reset_data);
							
							$reset_link = base_url() . "/login/?reset_hash=" . rawurlencode(mjencode($reset_hash.'|'.$user->username, $siteGuard->settings['salt']));
							
							##########
							## MAILER ##
							##########
							$msg = "You've requested to reset your password on {$siteGuard->settings['site_name']} (". base_url() . ")<br>";
							$msg .= "Please click this link to issue a temporary password for you:<br>";
							$msg .= "<pre>{$reset_link}</pre>";
							$msg .= "<br>This link will expire in 1 hour, If it wasn't you please ignore this mail";
							
							$title = 'Password Reset Request';
							
							$link = array('text' => "Reset Password" , "link" => $reset_link);
							$siteGuard->send_mail_to($user->email , $user->name , $msg , $title, $link);
							
							$msg = "Password reset request initiated. please check your email for instructions.";
							return redirect()->to(base_url("login/?edit=success&msg={$msg}"));
							
						} else {
							$msg = "Account not found on database! please contact system administration";
							return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
						}
					}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
			}
		}
		####################
		if($this->request->getGet('reset_hash') !== NULL) {
				$get_reset = escape_value($this->request->getGet('reset_hash'));
				$reset_hash= mjdecode($get_reset, $siteGuard->settings['salt']);
				$data = explode('|', $reset_hash);
				$then = $data[0];
				
				if(is_numeric($then) && (time() - $then) > 3600 || !is_numeric($then) ) {
					$msg = "This link is expired! Please generate another link to continue";
					return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
				}
				
				$found_user = $userModel->get_everything(" reset_hash='{$then}' AND username = '{$data[1]}' AND deleted = 0" ," id DESC", 1);

				if($found_user) {
					$found_user = $found_user[0];
					helper('text');
					
					$password = random_string('alnum', 10);
					$phpass = new PasswordHash(8, true);
					$hashedpassword = $phpass->HashPassword($password);
					
					$reset_data = array("password" => $hashedpassword, "reset_hash" => "");
					
					if($userModel->update($found_user->id, $reset_data)) {
						##########
						## MAILER ##
						##########
						$msg = "You've requested to reset your password on {$siteGuard->settings['site_name']} (". base_url() . ")<br>";
						$msg .= "Here's a temporary password generated for your account, please login and reset your password to ensure safety of your information<br>";
						$msg .= "Your new password is:<br><pre>{$password}</pre>";
						$title = 'Password Reset';
						$link = array('text' => "Login" , "link" => base_url());
						$siteGuard->send_mail_to($found_user->email , $found_user->name , $msg , $title, $link);
						
						$group = $groupModel->get_specific_id($found_user->prvlg_group);
						$logModel = new \App\Models\SiteGuardLog();
						
						$logModel->log_action($found_user->id , "Password Reset" , "New temporary password created for ({$found_user->username}), id #({$found_user->id}), and sent to ({$found_user->email}) Access level ({$group->name}) - access level id #({$group->id})" );
						
						$msg = "New temporary password sent to your email";
						return redirect()->to(base_url("login/?edit=success&msg={$msg}"));
					}
				} else {
					$msg = "This link is invalid! Please generate another link to continue";
					return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
				}
				
		}
		####################
		if($this->request->getPost('register-account') !== NULL) {
			
			$validation =  \Config\Services::validation();
			$validation->setRule('name', 'Name', 'trim|required');
			$validation->setRule('reg-username', 'Username', 'trim|required|min_length[4]|max_length[30]|is_unique[users.username]');
			$validation->setRule('reg-email', 'Email', 'trim|required|valid_email|is_unique[users.email]');
			$validation->setRule('reg-password', 'Password', 'trim|required|min_length[6]');
			
				
		if ($this->request->getPost(csrf_token()) == $siteGuard->csrf ) {
			
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to("login/?type=register");
				} else {	
					if(isset($_POST['g-recaptcha-response'])) {
					  $captcha=$_POST['g-recaptcha-response'];

					if(!$captcha){
						$msg = "Captcha Error! Please try again.";
						return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
					}
					$response=json_decode(file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$siteGuard->config['captcha']['secret']}&response=".$captcha."&remoteip=".$_SERVER['REMOTE_ADDR']), true);
					
					if($response['success'] == false){
						$msg = "Captcha Error! Please try again";
						return redirect()->to(base_url("login/?type=register&edit=fail&msg={$msg}"));
					} else {
							$name = escape_value($this->request->getPost('name', FILTER_SANITIZE_STRING));
							$email = escape_value($this->request->getPost('reg-email', FILTER_SANITIZE_EMAIL));
							$username = escape_value(trim(str_replace(' ','',$this->request->getPost('reg-username',FILTER_SANITIZE_STRING))));
							$password = escape_value($this->request->getPost('reg-password',FILTER_SANITIZE_STRING));
							
							$terms = escape_value($_POST['terms']);
							
							if(!$terms) {
								$msg= "You must accept Terms and Conditions before registering new account with us";
								return redirect()->to(base_url("login/?type=register&edit=fail&msg={$msg}"));
							}
							
				
					$email_exists = $userModel->exists("email", $email);
					if($email_exists) {
						$msg = siteGuard_msg('email-exists');
						return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
					}
					$username_exists = $userModel->exists("username", $username);
					if($username_exists) {
						$msg = siteGuard_msg('username-exists');
						return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
					}
					
					$phpass = new PasswordHash(8, true);
					$hashedpassword = $phpass->HashPassword($password);	
					
					$new_user = new \App\Entities\User();
					$new_user->name= $name;
					$new_user->email= $email;
					$new_user->username= $username;
					$new_user->password= $hashedpassword;
					$new_user->prvlg_group= $siteGuard->settings['registration_group'];
					$new_user->registered= strftime("%Y-%m-%d %H:%M:%S");
					$new_user->pending= 1;
															
					if($userModel->save($new_user)) {
						
						$group = $groupModel->get_specific_id($new_user->prvlg_group);
						$logModel = new \App\Models\SiteGuardLog();
						
					$logModel->log_action($userModel->getInsertID() , "Account Registration" , "Register new account ({$new_user->name} - {$new_user->email}), id #({$userModel->getInsertID()}), Access level ({$group->name}) - access level id #({$group->id})" );
					
					$ip = getRealIpAddr();
					##########
					## MAILER ##
					##########
					$admin = $userModel->get_specific_id(1);
					$msg = "New user registration on: {$siteGuard->settings['site_name']} (". base_url() . ")";
					
					$msg .= "<br><br>New User Details<br><br><ul>";
					$msg .= "<li><b>Name: </b> {$name}</li>";
					$msg .= "<li><b>Email: </b> {$email}</li>";
					$msg .= "<li><b>Username: </b> {$username}</li>";
					$msg .= "<li><b>Access Level: </b> {$group->name}</li>";
					$msg .= "<li><b>User IP: </b> {$ip}</li>";
					$msg .="</ul><br>Please login to activate user's profile.";
					
					$title = 'New Registration';
					$activate_link = base_url(). '/users?user_id=' . $userModel->getInsertID();
					$link = array('text' => "Activate Account" , "link" => $activate_link);
					$siteGuard->send_mail_to($admin->email , $admin->name , $msg , $title, $link);
					
					if(isset($siteGuard->settings['registration_activate']) && $siteGuard->settings['registration_activate'] == 'self_activation' ) {
						
						$activation_hash =  time();
						$reset_data = array( "reset_hash" => $activation_hash);
						$userModel->update($new_user->id, $reset_data);
						
						$activation_link = base_url() . "/login?activate=" . rawurlencode(mjencode($activation_hash.'|'.$new_user->username, $siteGuard->settings['salt']));
			
						##########
						## MAILER ##
						##########
						$name = explode(' ', $new_user->name);
						$msg = "Welcome {$name[0]} !<br><br>Your account on {$siteGuard->settings['site_name']} (". base_url() . ") was created successfully<br>";
						$msg .= "Please click this link to confirm your email and activate your account:<br>";
						$msg .= "<pre>{$activation_link}</pre>";
						$title = 'Activate your account';
						$link = array('text' => "Activate Account" , "link" => $activation_link);
						$siteGuard->send_mail_to($new_user->email , $new_user->name , $msg , $title, $link);
						
						$msg = "Account created successfully! We have sent you an email with an activation link. Please click on the link to activate your account.";
					} else {
						$msg = "Account created successfully! Please wait for admin approval.";
					}
						
						return redirect()->to(base_url("login/?edit=success&msg={$msg}"));
					} else {
						$msg = "Account creation failed! Please try registering again";
						return redirect()->to(base_url("login/?type=register&edit=fail&msg={$msg}"));
					}
								
							
					}
					
					} else {
						$msg = "Captcha Error! Please try again";
						return redirect()->to(base_url("login/?type=register&edit=fail&msg={$msg}"));
					}
					
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("login/?type=register&edit=fail&msg={$msg}"));
			}
		}
		####################
		if( isset( $_GET["provider"] ) && $siteGuard->settings['social_login'] == 'on' ){
			$provider_name = escape_value($this->request->getGet("provider", FILTER_SANITIZE_STRING));
			helper('text');
					
			try {
				include_once(FCPATH . 'SiteGuard/includes/hybridauth/autoload.php');
				$config = [
					'callback' => base_url(). '/login/?provider=' . $provider_name,
					'providers' => [
						'Google'   => ['enabled' => true, 'keys' => [ 'id'  => "{$siteGuard->config['google']['id']}", 'secret' => "{$siteGuard->config['google']['secret']}"]], 
						'Facebook' => ['enabled' => true, 'keys' => [ "id" => "{$siteGuard->config['facebook']['id']}", "secret" => "{$siteGuard->config['facebook']['secret']}"] , "trustForwarded" => false, "scope"   => ['email'], "display" => "popup" ]
					]
				];
				
				$hybridauth = new \Hybridauth\Hybridauth($config);
				// try to authenticate with the selected provider
				$adapter = $hybridauth->authenticate( $provider_name );
				// then grab the user profile
				$user_profile = $adapter->getUserProfile();
			}
		 
			// something went wrong?
			catch( Exception $e ) {
				
				switch( $e->getCode() ){
				  case 0 : $msg= "Unspecified error."; break;
				  case 1 : $msg= "Hybriauth configuration error."; break;
				  case 2 : $msg= "Provider not properly configured."; break;
				  case 3 : $msg= "Unknown or disabled provider."; break;
				  case 4 : $msg= "Missing provider application credentials."; break;
				  case 5 : $msg= "Authentification failed. "
							  . "The user has canceled the authentication or the provider refused the connection.";
						   break;
				  case 6 : $msg= "User profile request failed. Most likely the user is not connected "
							  . "to the provider and he should authenticate again.";
						   if(isset($adapter)) { $adapter->logout(); }
						   break;
				  case 7 : $msg= "User not connected to the provider.";
						   if(isset($adapter)) { $adapter->logout(); }
						   break;
				  case 8 : $msg= "Provider does not support this feature."; break;
				}
				return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
				exit();
			}

			// check if the current user already have authenticated using this provider before
			$user_exist = $userModel->get_for_hybridauth( $provider_name, $user_profile->identifier );
			
			// if the used didn't authenticate using the selected provider before
			// we create a new entry on database.users for him
			if( ! $user_exist ) {
				$email_exists = $userModel->exists("email", $user_profile->email );
				
				if($email_exists) {
					$msg = siteGuard_msg('email-exists');
					return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
				}
				
				$password = random_string("alnum", 10);
				$phpass = new PasswordHash(8, true);
				$hashedpassword = $phpass->HashPassword($password);
				
				//get avatar ..
				$ch = curl_init($user_profile->photoURL);
				$filename = uniqid().'.jpg';
				file_put_contents(FCPATH.'SiteGuard/upl_files/'.$filename, file_get_contents($user_profile->photoURL));
				
				$avatar_data = array("filename" => $filename,
												"type" => 'image/jpg');
				
				$file = new \App\Models\SiteGuardFile();
				$file->create($avatar_data);
				$avatar_id = $file->getInsertID();
				
				$username = $user_profile->firstName . '.' . $user_profile->lastName;
				
				$new_user = new \App\Entities\User();
				$new_user->email= $user_profile->email;
				$new_user->password= $hashedpassword;
				$new_user->prvlg_group= $siteGuard->settings['registration_group'];
				$new_user->name= $user_profile->firstName . ' ' .$user_profile->lastName;
				$new_user->username= $username;
				$new_user->hybridauth_provider_name= $provider_name;
				$new_user->hybridauth_provider_uid= $user_profile->identifier;
				$new_user->registered= strftime("%Y-%m-%d %H:%M:%S");
				$new_user->avatar= $avatar_id;
				
				$userModel->save($new_user);
				$user_exist = $userModel->get_specific_id($userModel->getInsertID());
			}
		 
			// set the user as connected and redirect him
			$siteGuard->login($user_exist);
			$log = new \App\Models\SiteGuardLog();
			
			$this->SiteGuardLog->log_action($user_exist->id , "Login" , "Login to system via ({$provider_name}) social login");
			
			$params = session_get_cookie_params();
			setcookie(session_name(), $_COOKIE[session_name()], time() + 60*60*24*30, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
			
			if(isset($siteGuard->settings['public_index']) && $siteGuard->settings['public_index']  != '') { $index = urldecode($siteGuard->settings['public_index']); } else { $index = base_url('index'); }
			redirect_to($index);
		}
		####################
		if($this->request->getPost('activation_link') !== NULL) {
			$validation =  \Config\Services::validation();
			$validation->setRule('activation-email', 'Email', 'trim|required|valid_email');
			
		
		if ($this->request->getPost(csrf_token()) == $siteGuard->csrf ) {
			
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to("login");
				} else {
						
						$email = trim(escape_value($this->request->getPost("activation-email",FILTER_SANITIZE_EMAIL)));
						
						$user = $userModel->get_everything("email = '{$email}' AND deleted = 0", 'id DESC' , 1);
						
						if($user) {
							$user = $user[0];			
							
							if ($user->disabled == "1") {
								$msg = "Account banned! please contact system admins.";
								return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
							}
							
							if ($user->pending == "0") {
								$msg = "Your account is already activated, please login using your credentials.";
								return redirect()->to(base_url("login/?edit=success&msg={$msg}"));
							}
							
							if($user->reset_hash) {
								$then = $user->reset_hash;
								if(is_numeric($then) && (time() - $then) > 3600 || !is_numeric($then) ) {		//expired link..
									$reset_data = array( "reset_hash" => '');
									$userModel->update($user->id, $reset_data);
								}
								
								if(is_numeric($then) && (time() - $then) < 300 ) {		//very early to re-generate! < 5 mins.
									$deficit = 300 - (time() - $then);
									$msg = "Reset link already generated and sent to this email, Please try again after " . secondsToTime($deficit);
									return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
								}
							}
							
							$reset_hash = time();
							$reset_data = array( "reset_hash" => $reset_hash);
							$userModel->update($user->id, $reset_data);
							
							$activation_link = base_url() . "/login/?activate=" . rawurlencode(mjencode($reset_hash.'|'.$user->username, $siteGuard->settings['salt']));
							
							##########
							## MAILER ##
							##########
							$name = explode(' ', $user->name);
							$msg = "Welcome {$name[0]} !<br><br>Your account on {$siteGuard->settings['site_name']} (". base_url() . ") was created successfully<br>";
							$msg .= "Please click this link to confirm your email and activate your account:<br>";
							$msg .= "<pre>{$activation_link}</pre>";
							$title = 'Activate your account';
							$link = array('text' => "Activate Account" , "link" => $activation_link);
							$siteGuard->send_mail_to($user->email , $user->name , $msg , $title, $link);
							
							$msg = "We have sent you an email with an activation link. Please click on the link to activate your account.";
							return redirect()->to(base_url("login/?edit=success&msg={$msg}"));
							
						} else {
							$msg = "Account not found on database! please contact system administration";
							return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
						}
					}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
			}
		}
		####################
		if($this->request->getGet('activate') !== NULL) {
			
			$get_reset = escape_value($this->request->getGet('activate'));
			$reset_hash= mjdecode($get_reset, $siteGuard->settings['salt']);
			$data = explode('|', $reset_hash);
			$then = $data[0];
			
			$found_user = $userModel->get_everything(" reset_hash='{$then}' AND username = '{$data[1]}' AND deleted = 0" ," id DESC", 1);
			
			if($found_user) {
				$found_user = $found_user[0];
				if ($found_user->pending == "0") {
					$msg = "Your account is already activated, please login using your credentials.";
					return redirect()->to(base_url("login?edit=success&msg={$msg}"));
				}
				$reset_data = array("pending" => 0, "reset_hash" => "");
				
				if($userModel->update($found_user->id, $reset_data)) {
					
					$group = $groupModel->get_specific_id($found_user->prvlg_group);
					$logModel = new \App\Models\SiteGuardLog();
					
					$logModel->log_action($found_user->id , "Account Self Activation" , "User account activated ({$found_user->username}), id #({$found_user->id}) , Access level ({$group->name}) - access level id #({$group->id})" );
					
					$msg = "Account activated successfully, please login to continue.";
					return redirect()->to(base_url("login/?edit=success&msg={$msg}"));
				}
			} else {
				$msg = "This link is invalid! Please generate another link to continue";
				return redirect()->to(base_url("login/?edit=fail&msg={$msg}"));
			}
			
		}
		####################
		
		
		return view('login', $data);
		
	}
	
	public function logout() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		
			if ($siteGuard->is_logged_in() == true ) {
				$userModel = new \App\Models\User();
				$current_user->last_seen = 0;
				$userModel->save($current_user);
				
				$onlineModel = new \App\Models\Online();
				
				$online = $onlineModel->get_everything(" user_id = '{$current_user->id}' ");
				if($online) {
					foreach($online as $onl) {
						$onlineModel->delete($onl->id);
					}
				}
			}
				// 2. destroy session vars ..
				$_SESSION = array();	
				// 3. destroy session cookie ..
				if (isset($_COOKIE[session_name()])) {
				setcookie(session_name() , '' , time()-42000 , '/');		
				}
				// 4. destroy the session ..
				session_destroy();
				return redirect()->to("login?edit=success&msg=Logged out successfully");
	}

}
