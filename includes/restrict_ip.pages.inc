<?php

/**
 * Page callback function for admin/config/people/restrict_ip
 */
function restrict_ip_settings($form, &$form_state)
{
	form_load_include($form_state, 'inc', 'restrict_ip', 'includes/restrict_ip.pages');

	$form['restrict_ip_address_description'] = array
	(
		'#markup' => t('Enter the list of allowed IP addresses below'),
		'#prefix' => '<h2>',
		'#suffix' => '</h2><p><strong style="color:red">' . t("Warning: If you enable IP restriction, and don't enter your current IP address into the list, you will immediately be locked out of the system upon save, and will not be able to access the system until you are in a location with an allowed IP address. Alternatively you can allow Restrict IP to be bypassed by role, and set at least one of your roles to be bypassed on the !permissions page.", array('!permissions' => user_access('administer permissions') ? l(t('permissions'), 'admin/people/permissions') : t('permissions'))) . '</strong></p><p><strong>' . t('Your current IP address is: !ip_address', array('!ip_address' => '<em>' . ip_address() . '</em>')) . '</strong></p>',
	);

	$form['restrict_ip_enable'] = array
	(
		'#type' => 'checkbox',
		'#title' => t('Enable Restricted IPs'),
		'#description' => t('IP addresses will only be enabled when this option is selected'),
		'#default_value' => variable_get('restrict_ip_enable', 0),
	);

	$form['restrict_ip_address_list'] = array
	(
		'#title' => t('Allowed IP Address List'),
		'#description' => t('Enter the list of IP Addresses that are allowed to access the site. Enter one IP address per line, in IPv4 or IPv6 format. You may also enter a range of IPv4 addresses in the format AAA.BBB.CCC.XXX - AAA.BBB.CCC.YYY'),
		'#type' => 'textarea',
		'#default_value' => variable_get('restrict_ip_address_list', ''),
	);

	$form['restrict_ip_mail_address'] = array
	(
		'#title' => t('Email Address'),
		'#type' => 'textfield',
		'#description' => t('If you would like to include a contact email address in the error message that is shown to users that do not have an allowed IP address, enter the email address here.'),
		'#default_value' => trim(variable_get('restrict_ip_mail_address', '')),
	);

	if(module_exists('dblog'))
	{
		$form['restrict_ip_watchdog'] = array
		(
			'#title' => t('Log access attempts to watchdog'),
			'#type' => 'checkbox',
			'#default_value' => variable_get('restrict_ip_watchdog', FALSE),
			'#description' => t('When this box is checked, attempts to access the site will be logged to the Drupal log (Recent log entries)'),
		);
	}

	$form['restrict_ip_allow_role_bypass'] = array
	(
		'#title' => t('Allow restrict IP to be bypassed by role'),
		'#type' => 'checkbox',
		'#default_value' => variable_get('restrict_ip_allow_role_bypass', FALSE),
		'#description' => t('When this box is checked, the permission "Bypass IP Restriction" will become available on the site !permissions page', array('!permissions' => user_access('administer permissions') ? l(t('permissions'), 'admin/people/permissions') : t('permissions'))),
	);

	$form['restrict_ip_bypass_action'] = array
	(
		'#title' => t('Access denied action'),
		'#type' => 'radios',
		'#default_value' => variable_get('restrict_ip_bypass_action', 'provide_link_login_page'),
		'#description' => t('Action to be performed when access is permitted by role, but the user is not logged in.'),
		'#options' => array
		(
			'provide_link_login_page' => 'Provide a link to the login page',
			'redirect_login_page' => 'Redirect to the login page',
		),
		'#states' => array
		(
			'visible' => array
			(
				'#edit-restrict-ip-allow-role-bypass' => array('checked' => TRUE),
			),
		),
	);

	$form['restrict_ip_white_black_list'] = array
	(
		'#type' => 'radios',
		'#options' => array
		(
			t('Check IP addresses on all paths'),
			t('Check IP addresses on all paths except the following'),
			t('Check IP addresses only on the following paths'),
		),
		'#default_value' => variable_get('restrict_ip_white_black_list', 0),
	);

	$form['restrict_ip_page_whitelist'] = array
	(
		'#title' => t('Whitelisted pages'),
		'#description' => t('Enter a list of paths that will be allowed regardless of IP address. For example, to not check IP addresses on this page, you would enter <em>admin/config/people/restrict_ip</em>. All paths not included here will be checked. Do not include domain names. Wildcards in paths do not work.'),
		'#type' => 'textarea',
		'#default_value' => variable_get('restrict_ip_page_whitelist', ''),
		'#states' => array
		(
			'visible' => array
			(
				':input[name="restrict_ip_white_black_list"]' => array('value' => 1),
			),
		),
	);

	$form['restrict_ip_page_blacklist'] = array
	(
		'#title' => t('Blacklisted pages'),
		'#description' => t('Enter a list of paths on which IP addresses will be checked. For example, to check IP addresses on this page, you would enter <em>admin/config/people/restrict_ip</em>. All paths not included here will not be checked. Do not include domain names. Wildcards in paths do not work.'),
		'#type' => 'textarea',
		'#default_value' => variable_get('restrict_ip_page_blacklist'),
		'#states' => array
		(
			'visible' => array
			(
				':input[name="restrict_ip_white_black_list"]' => array('value' => 2),
			),
		),
	);

	return system_settings_form($form);
}

/**
 * Validation function for restrict_ip_settings()
 *
 * This function determines whether or not the values entered
 * in whitelisted IPs list are valid IP addresses
 */
function restrict_ip_settings_validate($form, &$form_state)
{
	$ip_addresses = restrict_ip_sanitize_ip_list($form_state['values']['restrict_ip_address_list']);
	if(count($ip_addresses))
	{
		foreach($ip_addresses as $ip_address)
		{
			$ip_address = trim($ip_address);
			if($ip_address != '::1')
			{
				// Check if IP address is a valid singular IP address (ie - not a range)
				if(!preg_match('~^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$~', $ip_address) && !preg_match('~^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$~', $ip_address))
				{
					// IP address is not a single IP address, so we need to check if it's a range of addresses
					$pieces = explode('-', $ip_address);
					// We only need to continue checking this IP address
					// if it is a range of addresses
					if(count($pieces) == 2)
					{
						$start_ip = trim($pieces[0]);
						if(!preg_match('~^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$~', $start_ip))
						{
							form_set_error('restrict_ip_address_list', t('@ip_address is not a valid IP address.', array('@ip_address' => $start_ip)));
						}
						else
						{
							$start_pieces = explode('.', $start_ip);
							$start_final_chunk = (int) array_pop($start_pieces);
							$end_ip = trim($pieces[1]);
							$end_valid = TRUE;
							if(preg_match('~^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$~', $end_ip))
							{
								$end_valid = TRUE;
								$end_pieces = explode('.', $end_ip);
								for($i = 0; $i < 3; $i++)
								{
									if((int) $start_pieces[$i] != (int) $end_pieces[$i])
									{
										$end_valid = FALSE;
									}
								}
								if($end_valid)
								{
									$end_final_chunk = (int) array_pop($end_pieces);
									if($start_final_chunk > $end_final_chunk)
									{
										$end_valid = FALSE;
									}
								}
							}
							elseif(!is_numeric($end_ip))
							{
								$end_valid = FALSE;
							}
							else
							{
								if($end_ip > 255)
								{
									$end_valid = FALSE;
								}
								else
								{
									$start_final_chunk = array_pop($start_pieces);
									if($start_final_chunk > $end_ip)
									{
										$end_valid = FALSE;
									}
								}
							}

							if(!$end_valid)
							{
								form_set_error('restrict_ip_address_list', t('@range is not a valid IP address range.', array('@range' => $ip_address)));
							}
						}
					}
					else
					{
						form_set_error('restrict_ip_address_list', t('!ip_address is not a valid IP address or range of addresses.', array('!ip_address' => $ip_address)));
					}
				}
			}
		}
	}
}

/**
 * Callback path for restrict_ip/access_denied
 *
 * Redirects user to the front page if they have been
 * whitelisted. Otherwise shows an access denied error.
 */
function restrict_ip_access_denied_page()
{
	if(!isset($_SESSION['restrict_ip']) || !$_SESSION['restrict_ip'])
	{
		drupal_goto('<front>');
	}

	$page['access_denied'] = array
	(
		'#markup' => t('The page you are trying to access cannot be accessed from your IP address.'),
		'#prefix' => '<p>',
		'#suffix' => '</p>',
	);

	$contact_mail = trim(variable_get('restrict_ip_mail_address', ''));
	if(strlen($contact_mail))
	{
		$contact_mail = str_replace('@', '[at]', $contact_mail);
		$page['contact_us'] = array
		(
			'#markup' => t('If you feel this is in error, please contact an administrator at !email.', array('!email' => '<span id="restrict_ip_contact_mail">' . $contact_mail . '</span>')),
			'#prefix' => '<p>',
			'#suffix' => '</p>',
		);		
	}

	if(variable_get('restrict_ip_allow_role_bypass', FALSE))
	{
		if(user_is_logged_in())
		{
			$page['logout_link'] = array
			(
				'#markup' => l(t('Logout'), 'user/logout'),
				'#prefix' => '<p>',
				'#suffix' => '</p>',
			);
		}
		elseif(variable_get('restrict_ip_bypass_action', 'provide_link_login_page') === 'provide_link_login_page')
		{
			$page['login_link'] = array
			(
				'#markup' => l(t('Sign in'), 'user/login'),
				'#prefix' => '<p>',
				'#suffix' => '</p>',
			);
		}
	}

	$page['#attached']['js'][] = array
	(
		'type' => 'file',
		'data' => drupal_get_path('module', 'restrict_ip') . '/js/restrict_ip.js',
	);

	drupal_alter('restrict_ip_access_denied_page', $page);

	return $page;
}
