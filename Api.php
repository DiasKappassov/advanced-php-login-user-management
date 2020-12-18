<?php namespace App\Controllers;

use App\Libraries\SiteGuard;
use App\Libraries\Authenticator;
use Firebase\JWT\JWT;

class Api extends BaseController {
	
	
	public function prepare_user_jwt() {
			
		$siteGuard = new SiteGuard();
		
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		$onlineModel = new \App\Models\Online();
		$logModel = new \App\Models\SiteGuardLog();
		
		header("Access-Control-Allow-Origin: *");
		header("Access-Control-Allow-Methods: GET, POST");
		header('Content-type: application/json');
		header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

		$result = array('code'=> 100, 'status' => 'waiting' , 'response' => '', 'link' => strtolower("http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"));
		
		$request = \Config\Services::request(); 
		$segments = $request->uri->getSegments();
		
		if(isset($segments[2])) {
			$action = $segments[2];
		} else {
			$action = null;
		}
		if(isset($segments[3])) {
			$id = $segments[3];
		}else {
			$id = null;
		}
		if(isset($segments[4])) {
			$extra = $segments[4];
		}else {
			$extra = null;
		}
		
		if(isset($siteGuard->settings['api']) && $siteGuard->settings['api'] == 'on' ) {
			
			if(!isset($_POST['api_key'])) {
				$result['code'] = 401;
				$result['status'] = 'error';
				$result['response'] = 'Invalid User API key';
				echo json_encode($result);
				die();
			}	
			$sent_api_key = mjdecode($_POST['api_key'], $siteGuard->settings['api_salt']);
			
				if(is_numeric($action)) {
						if(!$userModel->exists('id',$action)) {
							$result['code'] = 404;
							$result['status'] = 'error';
							$result['response'] = "User not found!";
							echo json_encode($result);
							die();
						} else {
							$user = $userModel->get_specific_id($action);
							if($sent_api_key != $user->api_key) {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = "Invalid User API Key";
								echo json_encode($result);
								die();
							}
							
							$jwt = $siteGuard->encode_jwt($_POST['api_key']);
							$result['code'] = 200;
							$result['status'] = 'success';
							$result['response'] = $jwt;
							echo json_encode($result);
							die();
						}
				} else {
					$result['code'] = 400;
					$result['status'] = 'error';
					$result['response'] = 'Please specify valid User ID';
					echo json_encode($result);
					die();
				}
		
			} elseif(!isset($siteGuard->settings['api']) || isset($siteGuard->settings['api']) && $siteGuard->settings['api'] == 'off') {
				$result['code'] = 403;
				$result['status'] = 'error';
				$result['response'] = 'API Server is disabled';
			}
		}
			
	public function prepare_public_jwt() {
		
		$siteGuard = new SiteGuard();
		
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		$onlineModel = new \App\Models\Online();
		$logModel = new \App\Models\SiteGuardLog();
		
		header("Access-Control-Allow-Origin: *");
		header("Access-Control-Allow-Methods: GET, POST");
		header('Content-type: application/json');
		header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

		$result = array('code'=> 100, 'status' => 'waiting' , 'response' => '', 'link' => strtolower("http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"));
		
		$request = \Config\Services::request(); 
		$segments = $request->uri->getSegments();
		
		if(isset($segments[2])) {
			$action = $segments[2];
		} else {
			$action = null;
		}
		if(isset($segments[3])) {
			$id = $segments[3];
		}else {
			$id = null;
		}
		if(isset($segments[4])) {
			$extra = $segments[4];
		}else {
			$extra = null;
		}
		
		if(isset($siteGuard->settings['api']) && $siteGuard->settings['api'] == 'on' ) {
			if(!isset($_POST['api_key'])) {
				$result['code'] = 401;
				$result['status'] = 'error';
				$result['response'] = 'Invalid Public API key';
				echo json_encode($result);
				die();
			}	
			
			$sent_api_key = mjdecode($_POST['api_key'], $siteGuard->settings['api_salt']);
			
				if($sent_api_key != $siteGuard->settings['api_key']) {
					$result['code'] = 403;
					$result['status'] = 'error';
					$result['response'] = "Invalid Public API Key";
					echo json_encode($result);
					die();
				}
				
				$jwt = $siteGuard->encode_jwt($_POST['api_key']);
				$result['code'] = 200;
				$result['status'] = 'success';
				$result['response'] = $jwt;
				echo json_encode($result);
				die();
		} elseif(!isset($siteGuard->settings['api']) || isset($siteGuard->settings['api']) && $siteGuard->settings['api'] == 'off') {
			$result['code'] = 403;
			$result['status'] = 'error';
			$result['response'] = 'API Server is disabled';
		}
	}
	
	public function user() {
		
		$siteGuard = new SiteGuard();
		
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		$onlineModel = new \App\Models\Online();
		$logModel = new \App\Models\SiteGuardLog();
		
		header("Access-Control-Allow-Origin: *");
		header("Access-Control-Allow-Methods: GET, POST");
		header('Content-type: application/json');
		header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

		$result = array('code'=> 100, 'status' => 'waiting' , 'response' => '', 'link' => strtolower("http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"));
		
		$request = \Config\Services::request(); 
		$segments = $request->uri->getSegments();
		
		if(isset($segments[2])) {
			$action = $segments[2];
		} else {
			$action = null;
		}
		if(isset($segments[3])) {
			$id = $segments[3];
		}else {
			$id = null;
		}
		if(isset($segments[4])) {
			$extra = $segments[4];
		}else {
			$extra = null;
		}
		
		if(isset($siteGuard->settings['api']) && $siteGuard->settings['api'] == 'on' ) {
		
			######################
			if($action == 'update') {
				helper('text');
				if(is_numeric($id)) {
					
					if(!$userModel->exists('id',$id)) {
						$result['code'] = 404;
						$result['status'] = 'error';
						$result['response'] = "User not found!";
					} else {
						$user = $userModel->get_specific_id($id);
						/* Check JWT Validity */
							$jwt = getBearerToken();
							if($jwt) {
								$info = json_decode($siteGuard->decode_jwt($jwt),true); 
								if(is_array($info)) {
									if($info['type'] == 'success') {
										$sent_api_key = mjdecode($info['api_key'], $siteGuard->settings['api_salt']);
										if($sent_api_key != $user->api_key) {
											$result['code'] = 403;
											$result['status'] = 'error';
											$result['response'] = "Invalid User API Key";
											echo json_encode($result);
											die();
										}
									} else {
										$result['code'] = 401;
										$result['status'] = 'error';
										$result['response'] = $info['api_key'];
										echo json_encode($result);
										die();
									}
								} else {
									$result['code'] = 401;
									$result['status'] = 'error';
									$result['response'] = "Invalid Authorization Bearer.";
									echo json_encode($result);
									die();
								}
							} else {
								$result['code'] = 401;
								$result['status'] = 'error';
								$result['response'] = "Missing Authorization Bearer.";
								echo json_encode($result);
								die();
							}
							/***************/
						$qr_link= '';
						$sent_data = array();
					if(isset($_POST['password']) && $_POST['password'] != '' ) {
						$password = escape_value($_POST['password']);
						$saltedhash = $user->password;
						$phpass = new \App\Libraries\PasswordHash(8, true);
						if ($phpass->CheckPassword($password, $saltedhash)) {
							if(isset($_POST['name']) && $_POST['name'] != '' ) {
								$name = escape_value($_POST['name']);
								$sent_data['name'] = $name;
							}if(isset($_POST['phone']) && $_POST['phone'] != '' ) {
								$phone = escape_value($_POST['phone']);
								$sent_data['mobile'] = $phone;
							}if(isset($_POST['address']) && $_POST['address'] != '' ) {
								$address = escape_value($_POST['address']);
								$sent_data['address'] = $address;
							}if(isset($_POST['email']) && $_POST['email'] != '' ) {
								$email = escape_value($_POST['email']);
								$sent_data['email'] = $email;
							}if(isset($_POST['banned']) && $_POST['banned'] == '1' && $id != '1' ) {
								if($_POST['banned'] == '1') {
									$sent_data['disabled'] = 1;
								} elseif($_POST['banned'] == '0') {
									$sent_data['disabled'] = 0;
								}
							}if(isset($_POST['tfa']) && $_POST['tfa'] != '' ) {
								if($_POST['tfa'] == '1') {
									$tfa = new Authenticator();
									$sent_data['tfa'] = 1;
									if($user->tfa_secret == '') {
										$tfa_secret =$tfa->createSecret();
									} else {
										$tfa_secret =$user->tfa_secret;
									}
									$sent_data['tfa_secret'] = $tfa_secret;
									if($user->tfa_codes == '') {
										$codes = array();
										for($i = 1 ; $i <= 5 ; $i++) {
											$codes[] = random_string('numeric', 6);
										}
										$sent_data['tfa_codes'] = implode(',',$codes);
									}
									if(isset($siteGuard->settings['site_name']) && $siteGuard->settings['site_name'] != '' ) { $site_name = $siteGuard->settings['site_name']; } else { $site_name = "SiteGuard"; }
									$qr_link = ''.$tfa->GetQR("{$site_name} ({$user->username})", $tfa_secret);
								} elseif($_POST['tfa'] == '0') {
									$sent_data['tfa'] = 0;
									$sent_data['tfa_secret'] = "";
									$sent_data['tfa_codes'] = "";
								}
							}
							if($userModel->update($user->id, $sent_data)) {
								$logModel->log_action($user->id , "Update User" , "Update user info via API Call" );
								$result['code'] = 200;
								$result['status'] = 'success';
								if($qr_link) {
									$result['response'] = $qr_link;
								} else {
									$result['response'] = 'Data updated successfully.';
								}
							} else {
								$result['code'] = 200;
								$result['status'] = 'error';
								$result['response'] = 'No changes detected in user data';
							}
						} else {
							$result['code'] = 400;
							$result['status'] = 'error';
							$result['response'] = 'Wrong password.';
						}
							
						} else {
							$result['code'] = 400;
							$result['status'] = 'error';
							$result['response'] = 'Please enter user password.';
						}
					}
				} else {
					$result['code'] = 400;
					$result['status'] = 'error';
					$result['response'] = 'Please specify valid User ID';
				}

			} elseif($action == 'find') {
				/* Check JWT Validity */
				$jwt = getBearerToken();
				if($jwt) {
					$info = json_decode($siteGuard->decode_jwt($jwt),true); 
					if(is_array($info)) {
						if($info['type'] == 'success') {
							$sent_api_key = mjdecode($info['api_key'], $siteGuard->settings['api_salt']);
							if($sent_api_key != $siteGuard->settings['api_key']) {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = "Invalid Public API Key";
								echo json_encode($result);
								die();
							}
						} else {
							$result['code'] = 401;
							$result['status'] = 'error';
							$result['response'] = $info['api_key'];
							echo json_encode($result);
							die();
						}
					} else {
						$result['code'] = 401;
						$result['status'] = 'error';
						$result['response'] = "Invalid Authorization Bearer.";
						echo json_encode($result);
						die();
					}
				} else {
					$result['code'] = 401;
					$result['status'] = 'error';
					$result['response'] = "Missing Authorization Bearer.";
					echo json_encode($result);
					die();
				}
				/***************/
				if($id != '') {
					$query = " AND (name LIKE '%{$id}%' OR username LIKE '%{$id}%' OR email LIKE '%{$id}%' OR mobile LIKE '%{$id}%' )";
					$users = $userModel->get_everything( "deleted = 0 {$query}" , "name ASC" );
					$return_arr = array();
					if($users) {
						foreach($users as $user) {
							$group = $groupModel->get_specific_id($user->prvlg_group);
							
							$user_arr = array();
							$user_arr['name'] = $user->name;
							$user_arr['email'] = $user->email;
							$user_arr['username'] = $user->username;
							$user_arr['phone'] = $user->mobile;
							$user_arr['address'] = $user->address;
							$user_arr['about'] = $user->about;
							$user_arr['registeration_date'] = $user->registered;
							$user_arr['access_level'] = $group->name;
							$user_arr['avatar'] = $userModel->get_avatar($user->id);
							if($extra != '' && array_key_exists($extra, $user_arr)) {
								$temp = $user_arr[$extra];
								$user_arr = array();
								$user_arr[$extra] = $temp;
							}
							
							$return_arr[] = $user_arr;
						}
						$result['code'] = 200;
						$result['status'] = 'success';
						$result['response'] = $return_arr;
					} else {
						$result['code'] = 404;
						$result['status'] = 'error';
						$result['response'] = 'No users found matching search criteria';
					}
				} else {
					$result['code'] = 400;
					$result['status'] = 'error';
					$result['response'] = 'Please enter search keyword.';
				}
			} elseif($action == 'get') {
				/* Check JWT Validity */
				$jwt = getBearerToken();
				if($jwt) {
					$info = json_decode($siteGuard->decode_jwt($jwt),true); 
					if(is_array($info)) {
						if($info['type'] == 'success') {
							$sent_api_key = mjdecode($info['api_key'], $siteGuard->settings['api_salt']);
							if($sent_api_key != $siteGuard->settings['api_key']) {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = "Invalid Public API Key";
								echo json_encode($result);
								die();
							}
						} else {
							$result['code'] = 401;
							$result['status'] = 'error';
							$result['response'] = $info['api_key'];
							echo json_encode($result);
							die();
						}
					} else {
						$result['code'] = 401;
						$result['status'] = 'error';
						$result['response'] = "Invalid Authorization Bearer.";
						echo json_encode($result);
						die();
					}
				} else {
					$result['code'] = 401;
					$result['status'] = 'error';
					$result['response'] = "Missing Authorization Bearer.";
					echo json_encode($result);
					die();
				}
				/***************/
				if($id == 'all') {
					//get all users
					$users = $userModel->get_everything( " deleted = 0 ", "name ASC " );
					$return_arr = array();
					foreach($users as $user) {
						$group = $groupModel->get_specific_id($user->prvlg_group);
						
						$user_arr = array();
						$user_arr['name'] = $user->name;
						$user_arr['email'] = $user->email;
						$user_arr['username'] = $user->username;
						$user_arr['phone'] = $user->mobile;
						$user_arr['address'] = $user->address;
						$user_arr['about'] = $user->about;
						$user_arr['registeration_date'] = $user->registered;
						$user_arr['access_level'] = $group->name;
						$user_arr['avatar'] = $userModel->get_avatar($user->id);
						if($extra != '' && array_key_exists($extra, $user_arr)) {
							$temp = $user_arr[$extra];
							$user_arr = array();
							$user_arr[$extra] = $temp;
						}
						
						$return_arr[] = $user_arr;
					}
					$result['code'] = 200;
					$result['status'] = 'success';
					$result['response'] = $return_arr;
					
				} elseif($id == 'banned') {
					//get all users
					$users = $userModel->get_everything( " disabled = 1 AND deleted = 0 ", "name ASC" );
					$return_arr = array();
					foreach($users as $user) {
						$group = $groupModel->get_specific_id($user->prvlg_group);
						
						$user_arr = array();
						$user_arr['name'] = $user->name;
						$user_arr['email'] = $user->email;
						$user_arr['username'] = $user->username;
						$user_arr['phone'] = $user->mobile;
						$user_arr['address'] = $user->address;
						$user_arr['about'] = $user->about;
						$user_arr['registeration_date'] = $user->registered;
						$user_arr['access_level'] = $group->name;
						$user_arr['avatar'] = $userModel->get_avatar($user->id);
						if($extra != '' && array_key_exists($extra, $user_arr)) {
							$temp = $user_arr[$extra];
							$user_arr = array();
							$user_arr[$extra] = $temp;
						}
						
						$return_arr[] = $user_arr;
					}
					$result['code'] = 200;
					$result['status'] = 'success';
					$result['response'] = $return_arr;
					
				} elseif($id == 'pending') {
					//get all users
					$users = $userModel->get_everything( "pending = 1 AND deleted = 0","name ASC " );
					$return_arr = array();
					foreach($users as $user) {
						$group = $groupModel->get_specific_id($user->prvlg_group);
						
						$user_arr = array();
						$user_arr['name'] = $user->name;
						$user_arr['email'] = $user->email;
						$user_arr['username'] = $user->username;
						$user_arr['phone'] = $user->mobile;
						$user_arr['address'] = $user->address;
						$user_arr['about'] = $user->about;
						$user_arr['registeration_date'] = $user->registered;
						$user_arr['access_level'] = $group->name;
						$user_arr['avatar'] = $userModel->get_avatar($user->id);
						if($extra != '' && array_key_exists($extra, $user_arr)) {
							$temp = $user_arr[$extra];
							$user_arr = array();
							$user_arr[$extra] = $temp;
						}
						
						$return_arr[] = $user_arr;
					}
					$result['code'] = 200;
					$result['status'] = 'success';
					$result['response'] = $return_arr;
					
				} elseif($id == 'active') {
					//get active users
					$time_check = time() - 300;
					$users = $onlineModel->get_everything("time > '{$time_check}'");
					$return_arr = array();
					foreach($users as $online_user) {
						$user = $userModel->get_specific_id($online_user->user_id);
						$group = $groupModel->get_specific_id($user->prvlg_group);
						
						$user_arr = array();
						$user_arr['name'] = $user->name;
						$user_arr['email'] = $user->email;
						$user_arr['username'] = $user->username;
						$user_arr['phone'] = $user->mobile;
						$user_arr['address'] = $user->address;
						$user_arr['about'] = $user->about;
						$user_arr['registeration_date'] = $user->registered;
						$user_arr['access_level'] = $group->name;
						$user_arr['avatar'] = $userModel->get_avatar($user->id);
						$user_arr['ip'] = $online_user->ip;
						$user_arr['currently_viewing'] = $online_user->current_page;
						$details = json_decode(file_get_contents("https://ipinfo.io/{$online_user->ip}/json"));
						if($details) {
							$countries = json_decode(file_get_contents("http://country.io/names.json"), true);
							if(isset($details->country)) {
								$user_arr['country'] = $countries[$details->country];
								$user_arr['city'] = $details->city;
							}
						}
						if($extra != '' && array_key_exists($extra, $user_arr)) {
							$temp = $user_arr[$extra];
							$user_arr = array();
							$user_arr[$extra] = $temp;
						}
						$return_arr[] = $user_arr;
					}
					$result['code'] = 200;
					$result['status'] = 'success';
					$result['response'] = $return_arr;
					
				} elseif(is_numeric($id)) {
					
					if(!$userModel->exists('id',$id)) {
						$result['code'] = 404;
						$result['status'] = 'error';
						$result['response'] = "User not found!";
					} else {
					
					$user = $userModel->get_specific_id($id);
					$return_arr = array();
					
						$group = $groupModel->get_specific_id($user->prvlg_group);
						
						$user_arr = array();
						$user_arr['name'] = $user->name;
						$user_arr['email'] = $user->email;
						$user_arr['username'] = $user->username;
						$user_arr['phone'] = $user->mobile;
						$user_arr['address'] = $user->address;
						$user_arr['about'] = $user->about;
						$user_arr['registeration_date'] = $user->registered;
						$user_arr['access_level'] = $group->name;
						$user_arr['avatar'] = $userModel->get_avatar($user->id);
						if($extra != '' && array_key_exists($extra, $user_arr)) {
							$temp = $user_arr[$extra];
							$user_arr = array();
							$user_arr[$extra] = $temp;
						}
						$return_arr[] = $user_arr;
					
					$result['code'] = 200;
					$result['status'] = 'success';
					$result['response'] = $return_arr;
					
					}
				} else {
					$result['code'] = 400;
					$result['status'] = 'error';
					$result['response'] = 'Please specify valid User ID';
				}
			} elseif($action == 'privilege') {
				/* Check JWT Validity */
				$jwt = getBearerToken();
				if($jwt) {
					$info = json_decode($siteGuard->decode_jwt($jwt),true); 
					if(is_array($info)) {
						if($info['type'] == 'success') {
							$sent_api_key = mjdecode($info['api_key'], $siteGuard->settings['api_salt']);
							if($sent_api_key != $siteGuard->settings['api_key']) {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = "Invalid Public API Key";
								echo json_encode($result);
								die();
							}
						} else {
							$result['code'] = 401;
							$result['status'] = 'error';
							$result['response'] = $info['api_key'];
							echo json_encode($result);
							die();
						}
					} else {
						$result['code'] = 401;
						$result['status'] = 'error';
						$result['response'] = "Invalid Authorization Bearer.";
						echo json_encode($result);
						die();
					}
				} else {
					$result['code'] = 401;
					$result['status'] = 'error';
					$result['response'] = "Missing Authorization Bearer.";
					echo json_encode($result);
					die();
				}
				/***************/
					if($id != "" && is_numeric($id)) {
						
						if(!$userModel->exists('id',$id)) {
							$result['code'] = 404;
							$result['status'] = 'error';
							$result['response'] = "User not found!";
						} else {
							if($extra == '') {
								$result['code'] = 400;
								$result['status'] = 'error';
								$result['response'] = 'Please specify valid Privilege';
							} else {
								$user = $userModel->get_specific_id($id);
								$result['code'] = 200;
								$result['status'] = 'success';
								if($siteGuard->group_privilege($extra , $user->prvlg_group)) {
									$result['response'] = 'true';
								} else {
									$result['response'] = 'false';
								}
							}
						}
					} else {
						$result['code'] = 400;
						$result['status'] = 'error';
						$result['response'] = 'Please specify valid User ID';
					}
			} elseif($action == 'page') {
				/* Check JWT Validity */
				$jwt = getBearerToken();
				if($jwt) {
					$info = json_decode($siteGuard->decode_jwt($jwt),true); 
					if(is_array($info)) {
						if($info['type'] == 'success') {
							$sent_api_key = mjdecode($info['api_key'], $siteGuard->settings['api_salt']);
							if($sent_api_key != $siteGuard->settings['api_key']) {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = "Invalid Public API Key";
								echo json_encode($result);
								die();
							}
						} else {
							$result['code'] = 401;
							$result['status'] = 'error';
							$result['response'] = $info['api_key'];
							echo json_encode($result);
							die();
						}
					} else {
						$result['code'] = 401;
						$result['status'] = 'error';
						$result['response'] = "Invalid Authorization Bearer.";
						echo json_encode($result);
						die();
					}
				} else {
					$result['code'] = 401;
					$result['status'] = 'error';
					$result['response'] = "Missing Authorization Bearer.";
					echo json_encode($result);
					die();
				}
				/***************/
					if($id != "" && is_numeric($id)) {
						
						if(!$userModel->exists('id', $id)) {
							$result['code'] = 404;
							$result['status'] = 'error';
							$result['response'] = "User not found!";
						} else {
							if($extra == '') {
								$result['code'] = 400;
								$result['status'] = 'error';
								$result['response'] = 'Please specify valid Page Name';
							} else {
								$user = $userModel->get_specific_id($id);
								$result['code'] = 200;
								$result['status'] = 'success';
								if($siteGuard->group_privilege($extra.'.read' , $user->prvlg_group)) {
									$result['response'] = 'true';
								} else {
									$result['response'] = 'false';
								}
							}
						}
					} else {
						$result['code'] = 400;
						$result['status'] = 'error';
						$result['response'] = 'Please specify valid User ID';
					}
			} else {
				$result['code'] = 400;
				$result['status'] = 'error';
				$result['response'] = 'Please specify valid function for (User) Model';
			}
			######################
		
		
		} elseif(!isset($siteGuard->settings['api']) || isset($siteGuard->settings['api']) && $siteGuard->settings['api'] == 'off') {
			$result['code'] = 403;
			$result['status'] = 'error';
			$result['response'] = 'API Server is disabled';
		}
		echo json_encode($result);
		
	}
	
	public function auth() {
		
		$siteGuard = new SiteGuard();
		
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		$onlineModel = new \App\Models\Online();
		$logModel = new \App\Models\SiteGuardLog();
		
		
		header('Content-type: application/json');
		$result = array('code'=> 100, 'status' => 'waiting' , 'response' => '', 'link' => strtolower("http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"));
		
		$request = \Config\Services::request(); 
		$segments = $request->uri->getSegments();
		
		if(isset($segments[2])) {
			$action = $segments[2];
		} else {
			$action = null;
		}
		if(isset($segments[3])) {
			$id = $segments[3];
		}else {
			$id = null;
		}
		if(isset($segments[4])) {
			$extra = $segments[4];
		}else {
			$extra = null;
		}
		
		if(isset($siteGuard->settings['api']) && $siteGuard->settings['api'] == 'on' ) {
		
			
			######################
			if($action == 'reset-password') {
				if(is_numeric($id)) {
					if(!$userModel->exists('id',$id)) {
						$result['code'] = 404;
						$result['status'] = 'error';
						$result['response'] = "User not found!";
					} else {
						$user = $userModel->get_specific_id($id);
							/* Check JWT Validity */
							$jwt = getBearerToken();
							if($jwt) {
								$info = json_decode($siteGuard->decode_jwt($jwt),true); 
								if(is_array($info)) {
									if($info['type'] == 'success') {
										$sent_api_key = mjdecode($info['api_key'], $siteGuard->settings['api_salt']);
										if($sent_api_key != $user->api_key) {
											$result['code'] = 403;
											$result['status'] = 'error';
											$result['response'] = "Invalid User API Key";
											echo json_encode($result);
											die();
										}
									} else {
										$result['code'] = 401;
										$result['status'] = 'error';
										$result['response'] = $info['api_key'];
										echo json_encode($result);
										die();
									}
								} else {
									$result['code'] = 401;
									$result['status'] = 'error';
									$result['response'] = "Invalid Authorization Bearer.";
									echo json_encode($result);
									die();
								}
							} else {
								$result['code'] = 401;
								$result['status'] = 'error';
								$result['response'] = "Missing Authorization Bearer.";
								echo json_encode($result);
								die();
							}
							/***************/
						if ($user->disabled == "1") {
							$result['code'] = 403;
							$result['status'] = 'error';
							$result['response'] = 'Account banned! please contact system administration.';
						} elseif($user->closed == "1") {
							$result['code'] = 403;
							$result['status'] = 'error';
							$result['response'] = 'Account closed! please contact system administration.';
						} elseif($user->pending == "1") {
							$result['code'] = 403;
							$result['status'] = 'error';
							$result['response'] = 'Account pending admin approval.';
						} elseif($user->throttle_from != '' && time() < $user->throttle_from + $user->throttle_time) {
							$then = ($user->throttle_from + $user->throttle_time) - time();
							$result['code'] = 403;
							$result['status'] = 'error';
							$result['response'] = "Account Locked ! Please try again after " . secondsToTime($then);
						} else {
								
							if(isset($_POST['current_password']) && $_POST['current_password'] != '' && isset($_POST['new_password']) && $_POST['new_password'] != '' && isset($_POST['confirm_new_password']) && $_POST['confirm_new_password'] != '') {
								$current_password = escape_value($_POST['current_password']);
								$new_password = escape_value($_POST['new_password']);
								$confirm_new_password = escape_value($_POST['confirm_new_password']);
								if($new_password != $confirm_new_password) {
									$result['code'] = 400;
									$result['status'] = 'error';
									$result['response'] = 'passwords does not match.';
								} else {
									
									if($user->tfa && isset($siteGuard->settings['2fa']) && $siteGuard->settings['2fa']  == 'on' ) {
										
										if(!isset($_POST['otp'])) {
											$error_message = "OTP Code is invalid! please try again.";
											if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {
												$userModel->invalid_login($siteGuard->settings['attempts'], $user->id);
												$attempts = str_replace('-','',$siteGuard->settings['attempts']) - $user->invalid_logins;
												if($attempts < 0) {
													$attempts = 0;
												}
												$error_message .= " you have ({$attempts}) attempts left";
											}
											$result['code'] = 403;
											$result['status'] = 'error';
											$result['response'] = $error_message;
										} else {
											$ga = new Authenticator();
											$otp = escape_value($_POST['otp']);
											$backup_pass = false;
											$checkResult = $ga->verify($user->tfa_secret, $otp);
											if($user->tfa_codes) {
												$backup_codes = explode(',' , $user->tfa_codes);
												if (in_array($otp, $backup_codes)) {
													$backup_pass = true;
													$key = array_search($otp, $backup_codes);
													unset($backup_codes[$key]);
													$sent_data2 = array("tfa_codes" => implode(',' , $backup_codes));
													$userModel->update($user->id, $sent_data2);
												}
											}
											if($checkResult || $backup_pass == true) {
												$phpass = new \App\Libraries\PasswordHash(8, true);
												if($phpass->CheckPassword($current_password, $user->password)) {
													$hashedpassword = $phpass->HashPassword($new_password);
													$sent_data = array("password" => $hashedpassword);
													if($userModel->update($user->id, $sent_data)) {
														$logModel->log_action($user->id , "Change Password" , "Change password via API Call");
														if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {$userModel->clear_invalid_login($user->id);}
														$result['code'] = 200;
														$result['status'] = 'success';
														$result['response'] = 'password changed successfully.';
													} else {
														$result['code'] = 400;
														$result['status'] = 'error';
														$result['response'] = 'No changes detected in user data.';
													}
												} else {
													$result['code'] = 400;
													$result['status'] = 'error';
													$result['response'] = 'Wrong password.';
												}
											} else {
												$error_message = "OTP Code is invalid! please try again.";
												if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {
													$userModel->invalid_login($siteGuard->settings['attempts'], $user->id);
													$attempts = str_replace('-','',$siteGuard->settings['attempts']) - $user->invalid_logins;
													if($attempts < 0) {
														$attempts = 0;
													}
													$error_message .= " you have ({$attempts}) attempts left";
												}
												$result['code'] = 403;
												$result['status'] = 'error';
												$result['response'] = $error_message;
											}
											
										}
									
										
										
									} else {
									
										$phpass = new \App\Libraries\PasswordHash(8, true);
										if($phpass->CheckPassword($current_password, $user->password)) {
											$hashedpassword = $phpass->HashPassword($new_password);
											$sent_data = array("password" => $hashedpassword);
											if($userModel->update($user->id, $sent_data)) {
												$logModel->log_action($user->id , "Change Password" , "Change password via API Call");
												$result['code'] = 200;
												$result['status'] = 'success';
												$result['response'] = 'password changed successfully.';
											} else {
												$result['code'] = 400;
												$result['status'] = 'error';
												$result['response'] = 'No changes detected in user data.';
											}
										} else {
											$result['code'] = 400;
											$result['status'] = 'error';
											$result['response'] = 'Wrong password.';
										}
									}
								}
								
							} else {
								$result['code'] = 400;
								$result['status'] = 'error';
								$result['response'] = 'Please enter all required fields.';
							}
						}
					}
				} else {
					$result['code'] = 400;
					$result['status'] = 'error';
					$result['response'] = 'Please specify valid User ID';
				}
				
			} elseif($action == 'logout') {
				/* Check JWT Validity */
				$jwt = getBearerToken();
				if($jwt) {
					$info = json_decode($siteGuard->decode_jwt($jwt),true); 
					if(is_array($info)) {
						if($info['type'] == 'success') {
							$sent_api_key = mjdecode($info['api_key'], $siteGuard->settings['api_salt']);
							if($sent_api_key != $siteGuard->settings['api_key']) {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = "Invalid Public API Key";
								echo json_encode($result);
								die();
							}
						} else {
							$result['code'] = 401;
							$result['status'] = 'error';
							$result['response'] = $info['api_key'];
							echo json_encode($result);
							die();
						}
					} else {
						$result['code'] = 401;
						$result['status'] = 'error';
						$result['response'] = "Invalid Authorization Bearer.";
						echo json_encode($result);
						die();
					}
				} else {
					$result['code'] = 401;
					$result['status'] = 'error';
					$result['response'] = "Missing Authorization Bearer.";
					echo json_encode($result);
					die();
				}
				/***************/
				
				if ($siteGuard->is_logged_in() == true ) {
						$current_user = $userModel->get_specific_id($siteGuard->get_admin_id());
						$sent_data = array('last_seen' => '0');
						$userModel->update($current_user->id, $sent_data);
						$online = $onlineModel->get_everything("user_id = '{$current_user->id}'");
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
						$result['code'] = 200;
						$result['status'] = 'success';
						$result['response'] = 'true';
					} else {
						$result['code'] = 400;
						$result['status'] = 'error';
						$result['response'] = 'Please login first!';
					}
				
			} elseif($action == 'login') {
				/* Check JWT Validity */
				$jwt = getBearerToken();
				if($jwt) {
					$info = json_decode($siteGuard->decode_jwt($jwt),true); 
					if(is_array($info)) {
						if($info['type'] == 'success') {
							$sent_api_key = mjdecode($info['api_key'], $siteGuard->settings['api_salt']);
							if($sent_api_key != $siteGuard->settings['api_key']) {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = "Invalid Public API Key";
								echo json_encode($result);
								die();
							}
						} else {
							$result['code'] = 401;
							$result['status'] = 'error';
							$result['response'] = $info['api_key'];
							echo json_encode($result);
							die();
						}
					} else {
						$result['code'] = 401;
						$result['status'] = 'error';
						$result['response'] = "Invalid Authorization Bearer.";
						echo json_encode($result);
						die();
					}
				} else {
					$result['code'] = 401;
					$result['status'] = 'error';
					$result['response'] = "Missing Authorization Bearer.";
					echo json_encode($result);
					die();
				}
				/***************/
				if ($siteGuard->is_logged_in() == true ) {
					$result['code'] = 400;
					$result['status'] = 'error';
					$result['response'] = 'Please logout first!';
				} else {
					
					if(isset($_POST['username']) && $_POST['username'] != '' && isset($_POST['password']) && $_POST['password'] != '' ) {
						$username = trim(escape_value($_POST["username"]));
						$password = trim(escape_value($_POST["password"]));
						$found_user =$userModel->hash_authenticate($username);
						if ($found_user) {
							if ($found_user->disabled == "1") {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = 'Account banned! please contact system administration.';
							} elseif($found_user->pending == "1") {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = 'Account pending admin approval.';
							} elseif($found_user->throttle_from != '' && time() < $found_user->throttle_from + $found_user->throttle_time) {
								$then = ($found_user->throttle_from + $found_user->throttle_time) - time();
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = "Account Locked ! Please try again after " . secondsToTime($then);
							} else  {
								$group = $groupModel->get_specific_id($found_user->prvlg_group);
								if($group->max_connections) {
									$cur_connections = $onlineModel->count_everything(" AND user_id = '{$found_user->id}' ");
									if ($cur_connections > $group->max_connections) {
										$result['code'] = 403;
										$result['status'] = 'error';
										$result['response'] = 'This account has reached the maximum number of simultaneous sessions.';
										echo json_encode($result);
										die();
									}
								}
								
								$saltedhash = $found_user->password;
								$phpass = new \App\Libraries\PasswordHash(8, true);
								if ($phpass->CheckPassword($password, $saltedhash)) {
									if($found_user->tfa && isset($siteGuard->settings['2fa']) && $siteGuard->settings['2fa']  == 'on' ) {
										
										if(!isset($_POST['otp'])) {
											$error_message = "OTP Code is invalid! please try again.";
											if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {
												$userModel->invalid_login($siteGuard->settings['attempts'], $found_user->id);
												$attempts = str_replace('-','',$siteGuard->settings['attempts']) - $found_user->invalid_logins;
												if($attempts < 0) {
													$attempts = 0;
												}
												$error_message .= " you have ({$attempts}) attempts left";
											}
											$result['code'] = 403;
											$result['status'] = 'error';
											$result['response'] = $error_message;
										} else {
											$ga = new Authenticator();
											$otp = escape_value($_POST['otp']);
											$backup_pass = false;
											$checkResult = $ga->verify($found_user->tfa_secret, $otp);
											if($found_user->tfa_codes) {
												$backup_codes = explode(',' , $found_user->tfa_codes);
												if (in_array($otp, $backup_codes)) {
													$backup_pass = true;
													$key = array_search($otp, $backup_codes);
													unset($backup_codes[$key]);
													$sent_data2 = array("tfa_codes" => implode(',' , $backup_codes));
													$userModel->update($found_user->id, $sent_data2); 
												}
											}
											if($checkResult || $backup_pass == true) {
												$siteGuard->login($found_user);
												if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {$userModel->clear_invalid_login($found_user->id);}
												$logModel->log_action($found_user->id , "Login" , "Login to system via API Call");
												$result['code'] = 200;
												$result['status'] = 'success';
												$result['response'] = 'Logged in successfully.';
											} else {
												$error_message = "OTP Code is invalid! please try again.";
												if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {
													$userModel->invalid_login($siteGuard->settings['attempts'], $found_user->id);
													$attempts = str_replace('-','',$siteGuard->settings['attempts']) - $found_user->invalid_logins;
													if($attempts < 0) {
														$attempts = 0;
													}
													$error_message .= " you have ({$attempts}) attempts left";
												}
												$result['code'] = 403;
												$result['status'] = 'error';
												$result['response'] = $error_message;
											}
											
										}
									} else {
										$siteGuard->login($found_user);
										if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {$userModel->clear_invalid_login($found_user->id);}
										$logModel->log_action($found_user->id , "Login" , "Login to system via API Call");
										$result['code'] = 200;
										$result['status'] = 'success';
										$result['response'] = 'Logged in successfully.';
									}
								} else {
									$result['code'] = 403;
									$result['status'] = 'error';
									$error_message = "Wrong password! please try again.";
									if(isset($siteGuard->settings['disable_after']) && $siteGuard->settings['disable_after'] == "on" ) {
										$userModel->invalid_login($siteGuard->settings['attempts'], $found_user->id);
										$attempts = str_replace('-','',$siteGuard->settings['attempts']) - $found_user->invalid_logins;
										$error_message .= " you have ({$attempts}) attempts left";
									}
									$result['response'] = $error_message;
								}
							}
							
						} else {
							$result['code'] = 404;
							$result['status'] = 'error';
							$result['response'] = 'User not found!';
						}
						
					} else {
						$result['code'] = 400;
						$result['status'] = 'error';
						$result['response'] = 'Please enter valid username/password';
					}
				}
			} elseif($action == 'register') {
				/* Check JWT Validity */
				$jwt = getBearerToken();
				if($jwt) {
					$info = json_decode($siteGuard->decode_jwt($jwt),true); 
					if(is_array($info)) {
						if($info['type'] == 'success') {
							$sent_api_key = mjdecode($info['api_key'], $siteGuard->settings['api_salt']);
							if($sent_api_key != $siteGuard->settings['api_key']) {
								$result['code'] = 403;
								$result['status'] = 'error';
								$result['response'] = "Invalid Public API Key";
								echo json_encode($result);
								die();
							}
						} else {
							$result['code'] = 401;
							$result['status'] = 'error';
							$result['response'] = $info['api_key'];
							echo json_encode($result);
							die();
						}
					} else {
						$result['code'] = 401;
						$result['status'] = 'error';
						$result['response'] = "Invalid Authorization Bearer.";
						echo json_encode($result);
						die();
					}
				} else {
					$result['code'] = 401;
					$result['status'] = 'error';
					$result['response'] = "Missing Authorization Bearer.";
					echo json_encode($result);
					die();
				}
				/***************/
				
				if(isset($_POST['g-recaptcha-response'])) {
					$captcha=$_POST['g-recaptcha-response'];
					$response=json_decode(file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$captcha_info['secret']}&response=".$captcha."&remoteip=".$_SERVER['REMOTE_ADDR']), true);
				
					if($response['success'] == true) {
						if(isset($_POST['name']) && $_POST['name'] != '' && isset($_POST['email']) && $_POST['email'] != '' && isset($_POST['username']) && $_POST['username'] != '' && isset($_POST['password']) && $_POST['password'] != '' && isset($_POST['confirm_password']) && $_POST['confirm_password'] != '' ) {
							$name = escape_value($_POST['name']);
							$email = escape_value($_POST['email']);
							$username = escape_value(trim(str_replace(' ','',$_POST['username'])));
							$password = escape_value($_POST['password']);
							$confirm_password = escape_value($_POST['confirm_password']);
							if($password != $confirm_password) {
								$result['code'] = 400;
								$result['status'] = 'error';
								$result['response'] = 'Confirm password does not match';
							} else {
								$email_exists = $userModel->exists("email", $email);
								if($email_exists) {
									$result['code'] = 400;
									$result['status'] = 'error';
									$result['response'] = "Email already exists in database! please try again";
								} else {
									$username_exists = $userModel->exists("username", $username);
									if($username_exists) {
										$result['code'] = 400;
										$result['status'] = 'error';
										$result['response'] = "Username already exists in database! please try again";
									} else {
										$sent_data = array();
										$sent_data['name'] = $name;
										$sent_data['email'] = $email;
										$sent_data['username'] = $username;
										$phpass = new \App\Libraries\PasswordHash(8, true);
										$hashedpassword = $phpass->HashPassword($password);
										$sent_data['prvlg_group'] = $siteGuard->settings['registration_group'];
										$sent_data['password'] = $hashedpassword;
										$sent_data['registered'] = strftime("%Y-%m-%d %H:%M:%S");
										$sent_data['pending'] = 1;
										if($userModel->save($sent_data)) {
											$user_id = $userModel->getInsertID();
											$result['code'] = 200;
											$result['status'] = 'success';
											$logModel->log_action($user_id , "Register" , "Register account via API Call");
											$result['response'] = "Account created successfully! please wait admin approval.";
										} else {
											$result['code'] = 400;
											$result['status'] = 'error';
											$result['response'] = "Account creation failed! Please try registering again";
										}
									}
								}
							}
						} else {
							$result['code'] = 400;
							$result['status'] = 'error';
							$result['response'] = 'Please enter all required fields';
						}
						
					} else {
						$result['code'] = 403;
						$result['status'] = 'error';
						$result['response'] = 'Google re-captcha error';
					}
				
				} else {
					$result['code'] = 403;
					$result['status'] = 'error';
					$result['response'] = 'Google re-captcha error';
				}
			}else {
				$result['code'] = 400;
				$result['status'] = 'error';
				$result['response'] = 'Please specify valid function for (Auth) Model';
			}
			######################
		
		
		} elseif(!isset($siteGuard->settings['api']) || isset($siteGuard->settings['api']) && $siteGuard->settings['api'] == 'off') {
			$result['code'] = 403;
			$result['status'] = 'error';
			$result['response'] = 'API Server is disabled';
		}
		echo json_encode($result);
		
	}
}
