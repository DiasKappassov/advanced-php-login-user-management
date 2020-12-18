<?php namespace App\Controllers;

use App\Libraries\SiteGuard;

class Privileges extends BaseController {
	public function index() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("privileges");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		$miscModel = new \App\Models\MiscFunction();
		$privileges = $miscModel->get_function('privileges');
		$navigation = $miscModel->get_function('navigation');
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'General Settings',
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel,
								'privileges' => $privileges,
								'navigation' => $navigation
							);
				
		######################
		if($this->request->getPost('update_privileges') !== NULL) {
			helper('text');

			if(!$siteGuard->privilege("privileges.update")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("privileges?edit=fail&msg={$msg}"));
			}
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
				
				if(isset($_POST['display_name'])) { $display_name = $this->request->getPost('display_name'); } else { $display_name = array(); }
				if(isset($_POST['database_name'])) { $db_name = $this->request->getPost('database_name'); } else { $db_name = array(); }
				
				$total_m = array();
				if(!empty($display_name)) {
					for($c = 0 ; $c < count($display_name) ; $c++ ) {
						if(isset($display_name[$c]) && $display_name[$c] != '' && isset($db_name[$c]) && $db_name[$c] != ''  ) {
							$total_m[$display_name[$c]] = url_title($db_name[$c],'_', TRUE);
						}
					}
				}
				
				if(!empty($total_m)) { 
					$sent_data = array("value" => serialize($total_m));
				} else { 
					$sent_data = array("value" => '');
				}
				
				if($miscModel->update($privileges->id, $sent_data)) {
					$logModel = new \App\Models\SiteGuardLog();
					$logModel->log_action($current_user->id , "Update Privileges List" , "Updated available privileges list");
					$msg = siteGuard_msg('submit-success');
					return redirect()->to(base_url("privileges?edit=success&msg={$msg}"));
				} else {
					$msg = siteGuard_msg('submit-fail');
					return redirect()->to(base_url("privileges?edit=fail&msg={$msg}"));
				}	
				
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("privileges?edit=fail&msg={$msg}"));
			}
		}
		######################
		if($this->request->getPost('update_pages') !== NULL) {
			helper('text');
			
			if(!$siteGuard->privilege("privileges.update") || !$siteGuard->only_for('1') ) {
				$msg = $siteGuard_msg['restricted_privilege'];
				return redirect()->to(base_url("privileges?edit=fail&msg={$msg}"));
			}
			
			$result = array();
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
				
				$pages_arr = $this->request->getPost('data');
				$new_pages = array();
				foreach($pages_arr[0] as $d ) {
					if($d['type'] == 'section' && isset($d['children']) ) {
						foreach($d['children'][0] as $dc) {
							if($dc['type'] == 'page' && isset($dc['create_page']) && $dc['create_page'] == 'yes' ) {
								$new_pages[] = url_title(escape_value($dc['name']),'_', TRUE);
							}
						}
					}
					if($d['type'] == 'page' && isset($d['create_page']) && $d['create_page'] == 'yes' ) {
						$new_pages[] = url_title(escape_value($d['name']),'_', TRUE);
					}
				}
				
				/*Creating New Pages */
				if(!empty($new_pages)) {
					foreach($new_pages as $page) {
						$page_title = str_replace('_' , ' ' , $page);
						$page_title = str_replace('-' , ' ' , $page_title);
						$page_title = ucwords($page_title);
						
						$controller = ucwords($page);
						
						/*1. create Controller*/
						$new_file = file_get_contents(FCPATH.'/SiteGuard/includes/blankController.php');
						$new_file = str_replace('[PAGE]', $page, $new_file);
						$new_file = str_replace('[TITLE]', $page_title, $new_file);
						$new_file = str_replace('[CONTROLLER]', $controller, $new_file);
						
						if (!file_exists(APPPATH.'/Controllers/'.$controller . ".php")) {
							$myfile = fopen(APPPATH.'/Controllers/'.$controller . ".php", "w");
							fwrite($myfile, $new_file);
							fclose($myfile);
						}
						
						/*2. create View*/
						$new_file = file_get_contents(FCPATH.'/SiteGuard/includes/blankView.php');
						$new_file = str_replace('[PAGE]', $page, $new_file);
						$new_file = str_replace('[TITLE]', $page_title, $new_file);
						
						if (!file_exists(APPPATH.'/Views/'.$page . ".php")) {
							$myfile = fopen(APPPATH.'/Views/'.$page . ".php", "w");
							fwrite($myfile, $new_file);
							fclose($myfile);
						}
					}
				}
				/*------------------------*/
				
				$sent_data = array("value" => base64_encode(serialize($pages_arr[0])));
				if($miscModel->update($navigation->id, $sent_data)) {
					$logModel = new \App\Models\SiteGuardLog();					
					$logModel->log_action($current_user->id , "Update Pages List" , "Updated sections & pages list");
					$result['title'] = 'Success!';
					$result['type'] = 'success';
					$result['message'] = siteGuard_msg('submit-success');
					header('Content-Type: application/json');
					echo json_encode($result);
					exit();
				} else {
					$result['title'] = 'Error!';
					$result['type'] = 'error';
					$result['message'] = siteGuard_msg('submit-fail');
					header('Content-Type: application/json');
					echo json_encode($result);
					exit();
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("privileges?edit=fail&msg={$msg}"));
			}
		} 
		
		
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('settings/privileges', $data);
		echo view('pages/footer', $data, ['cache' => 60]);	
	}
	
	
}
