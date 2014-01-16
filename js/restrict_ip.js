/*globals jQuery, Drupal, location*/
/*jslint plusplus: true, sloppy: true, white: true */

(function($)
{
	// We do not use Drupal.behaviors, as the Drupal object
	// is not available due to drupal.js having been removed
	$(document).ready(function()
	{
		var mailDiv, contactMail;
		mailDiv = $("#restrict_ip_contact_mail");
		contactMail = mailDiv.text().replace("[at]", "@");
		mailDiv.html("<a href=\"mailto:" + contactMail + "\">" + contactMail + "</a>");
	});
}(jQuery));
