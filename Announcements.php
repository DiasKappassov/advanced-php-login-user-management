<?php namespace App\Controllers;

use App\Libraries\SiteGuard;

class Announcements extends BaseController {
	public function index() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("announcements");
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Manage Announcements',
								'current_user' => $current_user,
								'userModel' => new \App\Models\User(),
								'groupModel' => new \App\Models\Group(),
								'annModel' => new \App\Models\Announcement()
							);
		#####################
		if($this->request->getPost('upl_img') !== NULL) {
			$result = array();
			if ($_FILES['img']['name']) {
				if (!$_FILES['img']['error']) {
					
					$files = '';
					$img_id = 0;
					$f = 0;
					$target = $_FILES['img'];
					$upload_problems = 0;
					
						$file = "file";
						$string = $$file . "{$f}";
						$$string = new \App\Models\SiteGuardFile();
							if(!empty($_FILES['img']['name'])) {
								$$string->ajax_attach_file($_FILES['img']);
								if ($img_id = $$string->save_file()) {
									$fileModel = new \App\Models\SiteGuardFile();
									
									$result['title'] = 'Upload Success!';
									$result['type'] = 'success';
									$result['message'] = base_url()."/".$fileModel->image_path($img_id);
									header('Content-type: application/json');
									echo json_encode($result);
									die();
									
								} else {
									
									$result['title'] = 'Upload Failed!';
									$result['type'] = 'error';
									$result['message'] = join(" " , $$string->errors);
									header('Content-type: application/json');
									echo json_encode($result);
									die();
								}
							}
				} else {
					$result['title'] = 'Upload Failed!';
					$result['type'] = 'error';
					$result['message'] = $_FILES['img']['error'];
					header('Content-type: application/json');
					echo json_encode($result);
					die();
				}
			}
		}
		#####################
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('announcements/view', $data);
		echo view('pages/footer', $data, ['cache' => 60]);
		
	}
	
	public function create() {
		
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		if(!$siteGuard->privilege("announcements.create")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));
		}
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		$annModel = new \App\Models\Announcement();
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Create New Announcement',
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel
							);
		
		if($this->request->getPost('add_announcement') !== NULL) {
			
			$validation =  \Config\Services::validation();
			
			if(!$siteGuard->privilege("announcements.create")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));
			}
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
		        
				$validation->setRule('name', 'Name', 'trim|required');
				$validation->setRule('message', 'Message', 'trim|required');
				
				if($_POST['visible_to'] == '') {
					$msg = "Please choose who can see this announcement.";
					return redirect()->to(base_url('announcements/create?edit=fail&msg='.$msg));
				}
				
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to(base_url('announcements/create'));
				} else {
					####################
					$entry = new \App\Entities\Announcement();
					
					$entry->name = escape_value($this->request->getPost('name', FILTER_SANITIZE_STRING));
					$entry->user_id = $current_user->id;
					$entry->type = escape_value($this->request->getPost('type', FILTER_SANITIZE_STRING));
					$entry->expire_after = escape_value($this->request->getPost('expire_after', FILTER_SANITIZE_STRING));
					$entry->visible_to = implode(",", $this->request->getPost('visible_to', FILTER_SANITIZE_STRING));
					$entry->message = escape_only(urlencode($this->request->getPost('message')));
					$entry->created_at = now_db();
					####################
					  $query = $annModel->save($entry);
					 if($query) {
						$groups_arr = explode("," , $entry->visible_to);
						$visibility = array();
						if(!empty($groups_arr)) {
							foreach($groups_arr as $group) {
								$group_id = str_replace('-' , '', $group);
								$group = $groupModel->get_specific_id($group_id);
								$visibility[] = $group->name;
						}} $visibility = implode(', ' , $visibility);
						$log = new \App\Models\SiteGuardLog();
						$log->log_action($current_user->id , "Add New Announcement" , "Add new announcement ({$entry->name}), id #({$annModel->getInsertID()}), visible to {$visibility}" );
						$msg = siteGuard_msg('submit-success');
						return redirect()->to(base_url("announcements?edit=success&msg={$msg}"));
					 } else {
						 $msg = siteGuard_msg('submit-fail');
						 return redirect()->to(base_url("announcements/create?edit=fail&msg={$msg}"));
					 }
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));	
			}
		} else {
			echo view('pages/header', $data, ['cache' => 60]);
			echo view('pages/navbar', $data, ['cache' => 60]);
			echo view('announcements/create', $data);
			echo view('pages/footer', $data, ['cache' => 60]);
		}
		
		
	}
	public function delete($ann_id,$hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("announcements");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		$annModel = new \App\Models\Announcement();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$annModel->exists('id',$ann_id)) {
			return redirect()->to(base_url("announcements"));
			exit();
		}
		$this_obj = $annModel->get_specific_id($ann_id);
		if(!$siteGuard->privilege("announcements.delete")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));
			exit();
		}
		
		if($annModel->delete($ann_id)) {
			$msg = siteGuard_msg('delete-success');
			$log = new \App\Models\SiteGuardLog();
			$log->log_action($current_user->id , "Delete Announcement" , "Delete announcement ({$this_obj->name}) - id #({$this_obj->id})");
			return redirect()->to(base_url("announcements?edit=success&msg={$msg}"));
		} else {
			$msg = siteGuard_msg('delete-fail');
			return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));
			exit();
		}
	}
	
	public function update($ann_id, $hash) {
		
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		if(!$siteGuard->privilege("announcements.update")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));
		}
		
		$siteGuard->page_access("announcements");
		$userModel = new \App\Models\User();
		$groupModel = new \App\Models\Group();
		$annModel = new \App\Models\Announcement();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$annModel->exists('id',$ann_id)) {
			$msg = $siteGuard_msg['user-not_found'];
			return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));
			exit();
		}
		$this_obj = $annModel->get_specific_id($ann_id);
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Update User',
								'current_user' => $current_user,
								'userModel' => $userModel,
								'groupModel' => $groupModel,
								'annModel' => $annModel,
								'this_obj' => $this_obj
							);
		
		if($this->request->getPost('update_announcement') !== NULL) {
			
			$validation =  \Config\Services::validation();
			
			if(!$siteGuard->privilege("announcements.update")) {
				$msg = siteGuard_msg('restricted_privilege');
				return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));
			}
			if ($this->request->getPost(csrf_token(),FILTER_SANITIZE_STRING) == $siteGuard->csrf ) {
		        
				$validation->setRule('name', 'Name', 'trim|required');
				$validation->setRule('message', 'Message', 'trim|required');
				
				if($_POST['visible_to'] == '') {
					$msg = "Please choose who can see this announcement.";
					return redirect()->to(base_url("announcements/update/{$ann_id}/{$siteGuard->csrf}?edit=fail&msg={$msg}"));
				}
				
				if ($validation->withRequest($this->request)->run() == FALSE) {
					$siteGuard->session->setFlashdata('errors', $validation->getErrors());
					return redirect()->to(base_url("announcements/update/{$ann_id}/{$siteGuard->csrf}"));
				} else {
					####################
					$entry = $annModel->get_specific_id($ann_id);
					
					$entry->name = escape_value($this->request->getPost('name', FILTER_SANITIZE_STRING));
					$entry->user_id = $current_user->id;
					$entry->type = escape_value($this->request->getPost('type', FILTER_SANITIZE_STRING));
					$entry->expire_after = escape_value($this->request->getPost('expire_after', FILTER_SANITIZE_STRING));
					$entry->visible_to = implode(",", $this->request->getPost('visible_to', FILTER_SANITIZE_STRING));
					$entry->message = escape_only(urlencode($this->request->getPost('message')));
					
					####################
					
					 $query = $annModel->update($ann_id, $entry);
					 if($query) {
						$groups_arr = explode("," , $entry->visible_to);
						$visibility = array();
						if(!empty($groups_arr)) {
							foreach($groups_arr as $group) {
								$group_id = str_replace('-' , '', $group);
								$group = $groupModel->get_specific_id($group_id);
								$visibility[] = $group->name;
						}} $visibility = implode(', ' , $visibility);
						$log = new \App\Models\SiteGuardLog();
						$log->log_action($current_user->id , "Update Announcement" , "Update announcement ({$entry->name}), id #({$entry->id}), visible to {$visibility}");
						$msg = siteGuard_msg('update-success');
						return redirect()->to(base_url("announcements?edit=success&msg={$msg}"));
					 } else {
						 $msg = siteGuard_msg('update-fail');
						 return redirect()->to(base_url("announcementscreate?edit=fail&msg={$msg}"));
					 }
				}
			} else {
				$msg = siteGuard_msg('timestamp-fail');
				return redirect()->to(base_url("announcements?edit=fail&msg={$msg}"));	
			}
		} else {
			echo view('pages/header', $data, ['cache' => 60]);
			echo view('pages/navbar', $data, ['cache' => 60]);
			echo view('announcements/update', $data);
			echo view('pages/footer', $data, ['cache' => 60]);
		}
		
		
	}
	
}
