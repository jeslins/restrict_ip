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
		'#suffix' => '</h2><p><strong style="color:red">' . t("Warning: If you don't enter your current IP address into the list, you will immediately be locked out of the system upon save, and will not be able to access the system until you are in a location with an allowed IP address. Alternatively you can allow Restrict IP to be bypassed by role, and set at least one of your roles to be bypassed on the !permissions page.", array('!permissions' => user_access('administer permissions') ? l(t('permissions'), 'admin/people/permissions') : t('permissions'))) . '</strong></p><p><strong>' . t('Your current IP address is: !ip_address', array('!ip_address' => '<em>' . ip_address() . '</em>')) . '</strong></p>',
	);

	$form['restrict_ip_address_list'] = array
	(
		'#title' => t('Allowed IP Address List'),
		'#description' => t('Enter the list of IP Addresses that are allowed to access the site. If this field is left empty, all IP addresses will be able to access the site. Enter one IP address per line. You may also enter a range of IP addresses in the format AAA.BBB.CCC.XXX - AAA.BBB.CCC.YYY'),
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

	$form['restrict_ip_allow_role_bypass'] = array
	(
		'#title' => t('Allow restrict IP to be bypassed by role'),
		'#type' => 'checkbox',
		'#default_value' => variable_get('restrict_ip_allow_role_bypass', FALSE),
		'#description' => t('When this box is checked, the permission "Bypass IP Restriction" will become available on the site !permissions page', array('!permissions' => user_access('administer permissions') ? l(t('permissions'), 'admin/people/permissions') : t('permissions'))),
	);

	$form['restrict_ip_login_link_denied_page'] = array
	(
		'#title' => t('Provide a link to the login page'),
		'#type' => 'checkbox',
		'#default_value' => variable_get('restrict_ip_login_link_denied_page', FALSE),
		'#description' => t('When this box is checked, a link to the login page will be provided to users who have been blocked by IP, so that they can sign in. If their role allows it, they will then be given access to the site.'),
		'#states' => array
		(
			'visible' => array
			(
				'#edit-restrict-ip-allow-role-bypass' => array('checked' => TRUE),
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
	$ip_addresses = $form_state['values']['restrict_ip_address_list'];
	if(strlen(trim($ip_addresses)))
	{
		$ip_addresses = explode(PHP_EOL, trim($form_state['values']['restrict_ip_address_list']));
		foreach($ip_addresses as $ip_address)
		{
			if($ip_address != '::1')
			{
				if(!preg_match('~^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$~', trim($ip_address)))
				{
					$pieces = explode('-', $ip_address);
					if(count($pieces) !== 2)
					{
						form_set_error('restrict_ip_address_list', t('!ip_address is not a valid IP address.', array('!ip_address' => $ip_address)));
					}
					else
					{
						$ip1 = trim($pieces[0]);
						$ip2 = trim($pieces[1]);
						$both_valid = TRUE;	
						if(!preg_match('~^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$~', $ip1))
						{
							form_set_error('restrict_ip_address_list', t('!ip_address is not a valid IP address.', array('!ip_address' => $ip1)));
							$both_valid = FALSE;
						}
						if(!preg_match('~^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$~', $ip2))
						{
							form_set_error('restrict_ip_address_list', t('!ip_address is not a valid IP address.', array('!ip_address' => $ip2)));
							$both_valid = FALSE;
						}
						if($both_valid)
						{
							$first_parts_equal = TRUE;
							$last_part_ok = TRUE;
							$ip1_pieces = explode('.', $ip1);
							$ip2_pieces = explode('.', $ip2);
							for($i = 0; $i < 3; $i++)
							{
								if($ip1_pieces[$i] != $ip2_pieces[$i])
								{
									$first_parts_equal = FALSE;
									break;
								}
							}
							if($first_parts_equal)
							{
								if($ip2_pieces[3] <= $ip1_pieces[3])
								{
									$last_part_ok = FALSE;
								}
							}
							if(!$first_parts_equal || !$last_part_ok)
							{
								form_set_error('restrict_ip_address_list', t('@ip_address is not a valid range of IP addresses.', array('@ip_address' => $ip_address)));
							}
						}
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
	if(!ip_restricted())
	{
		drupal_goto('<front>');
	}

	$page['access_denied'] = array
	(
		'#markup' => t('This site cannot be accessed from your IP address.'),
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
		elseif(variable_get('restrict_ip_login_link_denied_page', FALSE))
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
