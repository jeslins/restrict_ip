/**
 * @file
 * Adds JS functionality to the access denied page of the Restrict IP module.
 */

/*globals jQuery, document*/
/*jslint white: true */

(function ($, document) {

  "use strict";

  // We do not use Drupal.behaviors, as the Drupal object is not available due
  // to drupal.js having been removed.
  $(document).ready(function () {
    var mailDiv, contactMail;
    mailDiv = $("#restrict_ip_contact_mail");
    contactMail = mailDiv.text().replace("[at]", "@");
    mailDiv.html("<a href=\"mailto:" + contactMail + "\">" + contactMail + "</a>");
  });
}(jQuery, document));
