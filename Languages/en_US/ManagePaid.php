<?php

// Version: 3.0 Alpha 2; ManagePaid

// Some payment gateways need language specific information.
$txt['lang_paypal'] = 'US';

// Symbols.
$txt['usd_symbol'] = '$%1.2f';
$txt['eur_symbol'] = '&euro;%1.2f';
$txt['gbp_symbol'] = '&pound;%1.2f';
$txt['cad_symbol'] = 'C$%1.2f';
$txt['aud_symbol'] = 'A$%1.2f';

$txt['usd'] = 'USD ($)';
$txt['eur'] = 'EUR (&euro;)';
$txt['gbp'] = 'GBP (&pound;)';
$txt['cad'] = 'CAD (C$)';
$txt['aud'] = 'AUD (A$)';
$txt['other'] = 'Other';

$txt['paid_username'] = 'Username';

$txt['paid_subscriptions_desc'] = 'From this section you can add, remove and edit paid subscription methods to your forum.';
$txt['paid_subs_settings'] = 'Settings';
$txt['paid_subs_settings_desc'] = 'From here you can edit the payment methods available to your users.';
$txt['paid_subs_view'] = 'View Subscriptions';
$txt['paid_subs_view_desc'] = 'From this section you can view all the subscriptions you have available.';

// Setting type strings.
$txt['paid_enabled'] = 'Enable Paid Subscriptions';
$txt['paid_enabled_desc'] = 'This must be checked for the paid subscriptions to be used on the forum.';
$txt['paid_email'] = 'Send Notification emails';
$txt['paid_email_desc'] = 'Inform the admin when a subscription automatically changes.';
$txt['paid_email_to'] = 'Email for Correspondence';
$txt['paid_email_to_desc'] = 'Comma-separated list of addresses to email to send notifications to.';
$txt['paidsubs_test'] = 'Enable test mode';
$txt['paidsubs_test_desc'] = 'This puts the paid subscriptions into &quot;test&quot; mode, which will, wherever possible, use sandbox payment methods in PayPal, Authorize.net etc. Do not enable unless you know what you are doing!';
$txt['paidsubs_test_confirm'] = 'Are you sure you want to enable test mode?';
$txt['paid_email_no'] = 'Do not send any notifications';
$txt['paid_email_error'] = 'Inform when subscription fails';
$txt['paid_email_all'] = 'Inform on all automatic subscription changes';
$txt['paid_currency'] = 'Select Currency';
$txt['paid_currency_code'] = 'Currency Code';
$txt['paid_currency_code_desc'] = 'Code used by payment merchants';
$txt['paid_currency_symbol'] = 'Symbol used by payment method';
$txt['paid_currency_symbol_desc'] = 'Use "%1.2f" to specify where the number goes. For example $%1.2f, %1.2f EUR etc';
$txt['paid_settings_save'] = 'Save';

$txt['paypal_email'] = 'PayPal email address';
$txt['paypal_email_desc'] = 'Leave blank if you do not wish to use PayPal.';
$txt['paypal_additional_emails'] = 'Primary PayPal email address';
$txt['paypal_additional_emails_desc'] = 'If different (for business account)';
$txt['paypal_sandbox_email'] = 'PayPal sandbox email address';
$txt['paypal_sandbox_email_desc'] = 'Can be left blank if test mode is disabled or not using PayPal.';

// argument(s): Config::$boardurl
$txt['paid_note'] = '<strong class="alert">Note:</strong><br>
SMF currently supports <strong>PayPal</strong> as the installed payment method.
<ul class="bbc_list">
	<li>It is not necessary to enable IPN in your PayPal account; but if you do, the forum will receive payment notifications for all payments made to your account, and this will generate Paid Subscriptions errors for payments that are not subscription related.</li>
	<li>You must have a business or premier account to use recurring payments.</li>
	<li>You must provide your primary PayPal email address for validation purposes.</li>
</ul>
<br>
If you install a different payment gateway, you may need to set up a return URL for payment notification. For all payment types, this return URL should be set as:
<br><br>
<ul class="bbc_list">
	<li><strong>{boardurl}/subscriptions.php</strong></li>
</ul>
<br>
You can normally find it in your customer panels, usually under the term &quot;Return URL&quot; or &quot;Callback URL&quot;.';

// View subscription strings.
$txt['paid_name'] = 'Name';
$txt['paid_status'] = 'Status';
$txt['paid_cost'] = 'Cost';
$txt['paid_duration'] = 'Duration';
$txt['paid_active'] = 'Active';
$txt['paid_pending'] = 'Pending Payment';
$txt['paid_finished'] = 'Finished';
$txt['paid_total'] = 'Total';
$txt['paid_is_active'] = 'Activated';
$txt['paid_none_yet'] = 'You have not set up any subscriptions yet.';
$txt['paid_payments_pending'] = 'Payments Pending';
$txt['paid_order'] = 'Order';

$txt['yes'] = 'Yes';
$txt['no'] = 'No';

// Add/Edit/Delete subscription.
$txt['paid_add_subscription'] = 'Add Subscription';
$txt['paid_edit_subscription'] = 'Edit Subscription';
$txt['paid_delete_subscription'] = 'Delete Subscription';
$txt['paid_add_subscription_name'] = 'Add Subscription "{name}"';
$txt['paid_edit_subscription_name'] = 'Edit Subscription "{name}"';
$txt['paid_delete_subscription_name'] = 'Delete Subscription "{name}"';
$txt['paid_add_subscription_name_for_member'] = 'Add Subscription "{name}" for {member}';
$txt['paid_edit_subscription_name_for_member'] = 'Edit Subscription "{name}" for {member}';
$txt['paid_delete_subscription_name_for_member'] = 'Delete Subscription "{name}" for {member}';

$txt['paid_mod_name'] = 'Subscription Name';
$txt['paid_mod_desc'] = 'Description';
$txt['paid_mod_reminder'] = 'Send Reminder email';
$txt['paid_mod_reminder_desc'] = 'Days before subscription is due to expire to send reminder.';
$txt['paid_mod_email'] = 'Email to Send upon Completion';
$txt['paid_mod_email_desc'] = 'Where {NAME} is members name; {FORUM} is community name. Email subject should be on first line. Blank for no email notification.';
$txt['paid_mod_cost_usd'] = 'Cost (USD)';
$txt['paid_mod_cost_eur'] = 'Cost (EUR)';
$txt['paid_mod_cost_gbp'] = 'Cost (GBP)';
$txt['paid_mod_cost_cad'] = 'Cost (CAD)';
$txt['paid_mod_cost_aud'] = 'Cost (AUD)';
$txt['paid_mod_cost_blank'] = 'Leave this blank to not offer this currency.';
$txt['paid_mod_span'] = 'Length of Subscription';
$txt['paid_mod_span_days'] = 'Days';
$txt['paid_mod_span_weeks'] = 'Weeks';
$txt['paid_mod_span_months'] = 'Months';
$txt['paid_mod_span_years'] = 'Years';
$txt['paid_mod_active'] = 'Active';
$txt['paid_mod_active_desc'] = 'A subscription must be active for new members to join.';
$txt['paid_mod_prim_group'] = 'Primary Group upon Subscription';
$txt['paid_mod_prim_group_desc'] = 'Primary group to put the user into when they subscribe.';
$txt['paid_mod_add_groups'] = 'Additional Groups upon Subscription';
$txt['paid_mod_add_groups_desc'] = 'Additional groups to add the user to after subscription.';
$txt['paid_mod_no_group'] = 'Do not Change';
$txt['paid_mod_edit_note'] = 'Note that as this group has existing subscribers the group settings cannot be changed!';
$txt['paid_mod_delete_warning'] = '<strong>WARNING</strong><br><br>If you delete this subscription all users currently subscribed will lose any access rights granted by the subscription. Unless you are sure you want to do this it is recommended that you simply deactivate a subscription rather than delete it.<br>';
$txt['paid_mod_repeatable'] = 'Allow user to auto-renew this subscription';
$txt['paid_mod_fixed_price'] = 'Subscription for fixed price and period';
$txt['paid_mod_flexible_price'] = 'Subscription price varies on duration ordered';
$txt['paid_mod_price_breakdown'] = 'Flexible Price Breakdown';
$txt['paid_mod_price_breakdown_desc'] = 'Define here how much the subscription should cost dependent on the period they subscribe for. For example, it could cost 12USD to subscribe for a month, but only 100USD for a year. If you do not want to define a price for a particular period of time leave it blank.';
$txt['flexible'] = 'Flexible';

$txt['paid_per_day'] = 'Price per Day';
$txt['paid_per_week'] = 'Price per Week';
$txt['paid_per_month'] = 'Price per Month';
$txt['paid_per_year'] = 'Price per Year';
$txt['day'] = 'Day';
$txt['week'] = 'Week';
$txt['month'] = 'Month';
$txt['year'] = 'Year';

// View subscribed users.
$txt['viewing_users_subscribed'] = 'Viewing Users';
$txt['view_users_subscribed'] = 'Viewing users subscribed to: &quot;{name}&quot;';
$txt['no_subscribers'] = 'There are currently no subscribers to this subscription.';
$txt['add_subscriber'] = 'Add new Subscriber';
$txt['edit_subscriber'] = 'Edit Subscriber';
$txt['delete_selected'] = 'Delete Selected';
$txt['complete_selected'] = 'Complete selected';

// @todo These strings are used in conjunction with JavaScript. Use numeric entities.
$txt['delete_are_sure'] = 'Are you sure you want to delete all records of the selected subscriptions?';
$txt['complete_are_sure'] = 'Are you sure you want to complete the selected subscriptions?';

$txt['start_date'] = 'Start Date';
$txt['end_date'] = 'End Date';
$txt['start_date_and_time'] = 'Start Date and Time';
$txt['end_date_and_time'] = 'End Date and Time';
$txt['edit'] = 'EDIT';
$txt['one_username'] = 'Please enter one username only.';
$txt['minute'] = 'Minute';
$txt['error_member_not_found'] = 'The member entered could not be found';
$txt['member_already_subscribed'] = 'This member is already subscribed to this subscription. Please edit their existing subscription.';
$txt['search_sub'] = 'Find User';

// Make payment.
$txt['paid_confirm_payment'] = 'Confirm Payment';
$txt['paid_confirm_desc'] = 'To continue through to payment please check the details below and hit &quot;Order&quot;';
$txt['paypal'] = 'PayPal';
$txt['paid_confirm_paypal'] = 'To pay using <a href="https://www.paypal.com">PayPal</a> please click the button below. You will be directed to the PayPal site for payment.';
$txt['paid_paypal_order'] = 'Order with PayPal';
$txt['paid_done'] = 'Payment Complete';
$txt['paid_done_desc'] = 'Thank you for your payment. Once the transaction has been verified the subscription will be activated.';
$txt['paid_sub_return'] = 'Return to Subscriptions';
$txt['paid_current_desc'] = 'Below is a list of all your current and previous subscriptions. To extend an existing subscription simply select it from the list above.';
$txt['paid_admin_add'] = 'Add This Subscription';

$txt['paid_not_set_currency'] = 'You have not setup your currency yet. Please do so from the <a href="{url}">Settings</a> section before continuing.';
$txt['paid_no_cost_value'] = 'You must enter a cost and subscription length.';
$txt['paid_invalid_duration'] = 'You must enter a valid duration for this subscription.';
$txt['paid_invalid_duration_D'] = 'If putting in a subscription length measured in days, you can only use 1 to 90 days. If you want a subscription that long, you should use weeks, months or years.';
$txt['paid_invalid_duration_W'] = 'If putting in a subscription length measured in weeks, you can only use 1 to 52 weeks. If you want a subscription that long, you should use months or years.';
$txt['paid_invalid_duration_M'] = 'If putting in a subscription length measured in months, you can only use 1 to 24 months. If you want a subscription that long, you should use years.';
$txt['paid_invalid_duration_Y'] = 'If putting in a subscription length measured in years, you can only use 1 to 5 years.';
$txt['paid_all_freq_blank'] = 'You must enter a cost for at least one of the four durations.';

// Some error strings.
$txt['paid_no_data'] = 'No valid data was sent to the script.';

$txt['paypal_could_not_connect'] = 'Could not connect to PayPal server';
$txt['paid_sub_not_active'] = 'That subscription is not taking any new users.';
$txt['paid_disabled'] = 'Paid subscriptions are currently disabled.';
$txt['paid_unknown_transaction_type'] = 'Unknown Paid Subscriptions transaction type.';
$txt['paid_empty_member'] = 'Paid subscription handler could not recover member ID';
$txt['paid_could_not_find_member'] = 'Paid subscription handler could not find member with ID: {0, number, integer}';
$txt['paid_count_not_find_subscription'] = 'Paid subscription handler could not find subscription for member ID: {0, number, integer}, subscription ID: {1, number, integer}';
$txt['paid_count_not_find_subscription_log'] = 'Paid subscription handler could not find subscription log entry for member ID: {0, number, integer}, subscription ID: {1, number, integer}';
$txt['paid_count_not_find_outstanding_payment'] = 'Could not find outstanding payment entry for member ID: {0, number, integer}, subscription ID: {1, number, integer} so ignoring';
$txt['paid_admin_not_setup_gateway'] = 'Sorry, the admin has not yet finished setting up paid subscriptions. Please check back later.';
$txt['paid_make_recurring'] = 'Make this a recurring payment';

$txt['subscriptions'] = 'Subscriptions';
$txt['subscription'] = 'Subscription';
$txt['paid_subs_desc'] = 'Below is a list of all the subscriptions which are available on this forum.';
$txt['paid_subs_none'] = 'There are currently no paid subscriptions available.';

$txt['paid_current'] = 'Existing Subscriptions';
$txt['pending_payments'] = 'Pending Payments';
$txt['pending_payments_desc'] = 'This member has attempted to make the following payments for this subscription but the confirmation has not been received by the forum. If you are sure the payment has been received click &quot;accept&quot; to action to subscription. Alternatively you can click &quot;Remove&quot; to remove all reference to the payment.';
$txt['pending_payments_value'] = 'Value';
$txt['pending_payments_accept'] = 'Accept';
$txt['pending_payments_remove'] = 'Remove';

?>