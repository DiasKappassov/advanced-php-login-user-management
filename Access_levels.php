<?php namespace App\Controllers;

use App\Libraries\SiteGuard;

class Access_levels extends BaseController {
	public function index() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("access_levels");
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Manage Access Levels',
								'current_user' => $current_user,
								'userModel' => new \App\Models\User(),
								'groupModel' => new \App\Models\Group()
							);
		
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('access_levels/view', $data);
		echo view('pages/footer', $data, ['cache' => 60]);
		
	}
	
	public function create() {
		
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		if(!$siteGuard->privilege("access_levels.create")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
		}
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		$miscModel = new \App\Models\MiscFunction();
		$privileges = $miscModel->get_function("privileges");
		$navigation = $miscModel->get_function("navigation");
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Create New Access Level',
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel,
								'privileges' => $privileges,
								'navigation' => $navigation
							);
		
		if($this->request->getPost('add_group') !== NULL) {
			
			$validation =  \Config\Services::validation();
			
			if(!$siteGuard->privilege("access_levels.create")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
			}
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
		        
				$validation->setRule('name', 'Name', 'trim|required');
				
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to(base_url('access_levels/create'));
				} else {
					####################
					$new_item = new \App\Entities\Group();
					
					$privileges_raw= $this->request->getPost('privileges');
					$name= escape_value($this->request->getPost('name', FILTER_SANITIZE_STRING));
					$privileges_danger = implode("-,-" , $privileges_raw);
					$privileges =escape_value($privileges_danger);
					
					$default_index = escape_value(urlencode($this->request->getPost('default_index', FILTER_SANITIZE_URL)));
					$max_connections = escape_value($this->request->getPost('max_connections', FILTER_SANITIZE_STRING));
					
					if($max_connections <= 0 || !is_numeric($max_connections) ) {
						$max_connections = '';
					}
					
					$new_item->name = $name;
					$new_item->privileges = '-index.read-,-'.$privileges.'-';
					
					$new_item->max_connections = $max_connections;
					$new_item->default_index = $default_index;
					
					####################
					 $query = $groupModel->save($new_item);
					 if($query) {
						$log = new \App\Models\SiteGuardLog();
						$log->log_action($current_user->id , "Add Group object" , "Add new Group object to application ({$name}), id #({$groupModel->getInsertID()})" );
						$msg = siteGuard_msg('submit-success');
						return redirect()->to(base_url("access_levels?edit=success&msg={$msg}"));
					 } else {
						 $msg = siteGuard_msg('submit-fail');
						 return redirect()->to(base_url("access_levels/create?edit=fail&msg={$msg}"));
					 }
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));	
			}
		} else {
			echo view('pages/header', $data, ['cache' => 60]);
			echo view('pages/navbar', $data, ['cache' => 60]);
			echo view('access_levels/create', $data);
			echo view('pages/footer', $data, ['cache' => 60]);
		}
		
		
	}
	
	public function update($group_id, $hash) {
		
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		if(!$siteGuard->privilege("access_levels.update")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
		}
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		$miscModel = new \App\Models\MiscFunction();
		$privileges = $miscModel->get_function("privileges");
		$navigation = $miscModel->get_function("navigation");
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$groupModel->exists('id',$group_id)) {
			return redirect()->to(base_url("access_levels"));
			exit();
		}
		$this_obj = $groupModel->get_specific_id($group_id);
		$data = array(  'siteGuard' => $siteGuard,
								'title' => "Update Group ({$this_obj->name})",
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel,
								'privileges' => $privileges,
								'navigation' => $navigation,
								'this_obj' => $this_obj
							);
		
		if($this->request->getPost('update_group') !== NULL) {
			
			$validation =  \Config\Services::validation();
			
			if(!$siteGuard->privilege("access_levels.update")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
			}
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
		        
				$validation->setRule('name', 'Name', 'trim|required');
				
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to(base_url("access_levels/update/{$group_id}/{$siteGuard->csrf}"));
				} else {
					####################
					$edit_item = $groupModel->get_specific_id($group_id);
					
					$privileges_raw= $this->request->getPost('privileges');
					$name= escape_value($this->request->getPost('name', FILTER_SANITIZE_STRING));
					$privileges_danger = implode("-,-" , $privileges_raw);
					$privileges =escape_value($privileges_danger);
					$default_index = escape_value(urlencode($this->request->getPost('default_index', FILTER_SANITIZE_URL)));
					$max_connections = escape_value($this->request->getPost('max_connections', FILTER_SANITIZE_STRING));
					
					if($max_connections <= 0 || !is_numeric($max_connections) ) {
						$max_connections = '';
					}
					$edit_item->name = $name;
					$edit_item->privileges = '-index.read-,-'.$privileges.'-';
					
					$edit_item->max_connections = $max_connections;
					$edit_item->default_index = $default_index;
					####################
					 $query = $groupModel->update($group_id, $edit_item);
					 if($query) {
						$log = new \App\Models\SiteGuardLog();
						$log->log_action($current_user->id , "Update Group Object" , "Update access level ({$groupModel->name}), id #({$groupModel->id})" );
						$msg = siteGuard_msg('update-success');
						return redirect()->to(base_url("access_levels?edit=success&msg={$msg}"));
					 } else {
						 $msg = siteGuard_msg('update-fail');
						 return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
					 }
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));	
			}
		} else {
			echo view('pages/header', $data, ['cache' => 60]);
			echo view('pages/navbar', $data, ['cache' => 60]);
			echo view('access_levels/update', $data);
			echo view('pages/footer', $data, ['cache' => 60]);
		}
		
		
	}
	
	public function delete($group_id,$hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("access_levels");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$groupModel->exists('id',$group_id)) {
			return redirect()->to(base_url("access_levels"));
			exit();
		}
		$this_obj = $groupModel->get_specific_id($group_id);
		if(!$siteGuard->privilege("access_levels.delete")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
			exit();
		}
		if($group_id <= "2") {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj->deleted = '1';
		if($groupModel->update($group_id, $this_obj)) {
			$msg = siteGuard_msg('delete-success');
			$log = new \App\Models\SiteGuardLog();
			$log->log_action($current_user->id ,"Delete Group object" , "Delete Group object named ({$this_obj->name}) - id #({$this_obj->id})");
			return redirect()->to(base_url("access_levels?edit=success&msg={$msg}"));
		} else {
			$msg = siteGuard_msg('delete-fail');
			return redirect()->to(base_url("access_levels?edit=fail&msg={$msg}"));
			exit();
		}
	}
	
}
