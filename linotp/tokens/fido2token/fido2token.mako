# -*- coding: utf-8
<%doc>
 * copyright notice goes here
</%doc>

%if c.scope == 'config.title' :
  ${_("FIDO2 Token")}
%endif

%if c.scope == 'config' :
<script type="text/javascript">
  function fido2_get_config_val() {
    var id_map = {};
    id_map['FIDO2ChallengeValidityTime'] = 'fido2config_challenge_timeout';
    return id_map;
  }
  function fido2_get_config_params() {
    var url_params = {};
    url_params['FIDO2ChallengeValidityTime'] = $('#fido2config_challenge_timeout').val();
    return url_params;
  }
</script>
<form class="cmxform" id="form_fido2token_config" action="">
  <fieldset>
    <legend>${_("FIDO2 Token Settings")}</legend>
    <table>
      <tr>
        <td>
	  <label for="fido2config_challenge_timeout">
	    ${_("Challenge expiration time (sec)")}
	  </label>
	</td>
	<td>
	  <input type="number" name="fido2config_challenge_timeout"
	    id="fido2config_challenge_timeout"
	    class="required text ui-widget-content ui-corner-all"
	    min="0">
	</td>
      </tr>
    </table>
  </fieldset>
</form>
%endif

%if c.scope == 'enroll.title' :
  ${_("FIDO2 Token")}
%endif

%if c.scope == 'enroll' :
<script type="text/javascript">

/**
 * Setup defaults before enrollment dialog is shown
 */

function fido2_enroll_setup_defaults(config, options) {
  fido2_clear_input_fields();

  // Hide/show PIN fields based on random PIN setting
  const should_hide_pin_rows = options['otp_pin_random'] > 0;
  $("[name='set_pin_rows']").toggle(!should_hide_pin_rows);
}

function fido2_get_enroll_params() {
  const params = {
    type: 'fido2',
    description: $('#enroll_fido2_desc').val()
  };

  const pin = $('#fido2_pin1').val();
  if (pin) {
    params.pin = pin;
  }

  const userData = add_user_data();
  jQuery.extend(params, userData);

  fido2_clear_input_fields();

  $(document).one('ajaxSuccess', function(event, xhr, settings) {
    if (settings.url && settings.url.indexOf('/admin/init') !== -1) {
      try {
        const response = JSON.parse(xhr.responseText);
	if (response.result && response.result.status && response.detail) {
	  const serial = response.detail.serial;
	  if (serial && response.detail.registerrequest) {
	    fido2_show_activation_ui(serial, response.detail.registerrequest, userData);
	  }
	}
      } catch (e) {
        console.error('[FIDO2] Error checking enrollment response: ', e);
      }
    }
  });

  return params;
}

function fido2_clear_input_fields() {
  $('#fido2_pin1').val('');
  $('#fido2_pin2').val('');
  $('#enroll_fido2_desc').val('webGUI_generated');
}

function fido2_show_activation_ui(serial, registerRequest, userData) {
  window._fido2_pending_register_request = registerRequest;
  window._fido2_pending_serial = serial;
  window._fido2_pending_user_data = userData || {};

  var $dlg = $('#dialog_token_enroll');

  // Hide enrollment chrome (user info, token type selector, form)
  $('#enroll_info_text_user, #enroll_info_text_nouser, #enroll_info_text_multiuser').hide();
  $('#form_enroll_token > fieldset > table').first().hide(); // token type selector row
  $('#token_enroll_fido2 .fido2_enroll_form').hide();
  $('#form_enroll_token > fieldset').css('border', 'none').css('padding', '0');

  // Show activation UI
  $('#fido2_activate_section').show();
  $('#fido2_activate_serial').text(serial);
  $('#fido2_activate_status').text('').hide();

  // Replace dialog title
  $dlg.dialog('option', 'title', '${_("Activate FIDO2 Token")}');

  // Replace dialog buttons
  $dlg.dialog('option', 'buttons', {
    '${_("Activate Now")}': {
      click: function() {
        fido2_admin_activate_now();
      },
      id: 'fido2_btn_activate',
      text: '${_("Activate Now")}'
    },
    '${_("Skip")}': {
      click: function() {
        fido2_close_and_reset();
      },
      id: 'fido2_btn_skip',
      text: '${_("Skip")}'
    }
  });
  $dlg.dialog_icons();
}


/**
 * Close the enrollment dialog and reset it to its original state.
 */

function fido2_close_and_reset() {
  var $dlg = $('#dialog_token_enroll');

  // Reset UI state - restore enrollment chrome
  $('#fido2_activate_section').hide();
  $('#token_enroll_fido2 .fido2_enroll_form').show();
  $('#form_enroll_token > fieldset > table').first().show();
  $('#form_enroll_token > fieldset').css('border', '').css('padding', '');
  get_enroll_infotext(); // restore user info text

  // Restore original dialog title and buttons
  $dlg.dialog('option', 'title', '${_("Enroll Token")}');
  $dlg.dialog('option', 'buttons', {
    'Enroll': {
      click: function() {
        try {
	  var result = token_enroll();
	  var typ = $('#tokentype').val();
	  if (typ !== 'fido2') {
	    $(this).dialog('close');
	  }
	} catch (e) {
	  if (e === "PinMatchError") {
	    alert_box({
	      'title': i18n.gettext('Failed to enroll token'),
	      'text': i18n.gettext('The entered PINs do not match!'),
	      'type': ERROR,
	      'is_escaped': true
	    });
	  } else {
	    alert_box({
	      'title': i18n.gettext('Failed to enroll token'),
	      'text': i18n.gettext('Error: ') + e,
	      'type': ERROR,
	      'is_escaped': true
	    });
	  }
	}
      },
      id: "button_enroll_enroll",
      text: "Enroll"
    },
    'Cancel': {
      click: function() {
        $(this).dialog('close');
      },
      id: "button_enroll_cancel",
      text: "Cancel"
    }
  });
  $dlg.dialog_icons();

  // Clean up state
  window._fido2_pending_register_request = null;
  window._fido2_pending_serial = null;
  window._fido2_pending_user_data = null;

  $dlg.dialog('close');
}

/**
 * Perform WebAuthn ceremony to activate the newly created token
 */
async function fido2_admin_activate_now() {
  const serial = window._fido2_pending_serial;
  const registerRequest = window._fido2_pending_register_request;

  if (!serial || !registerRequest) {
    return;
  }

  try {
    // Disable buttons and show progress
    var $dlg = $('#dialog_token_enroll');
    $dlg.parent().find('.ui-dialog-buttonpane button').prop('disabled', true);
    $('#fido2_activate_status')
      .text('${_("Please interact with your FIDO2 security key …")}')
      .css('color', '#336')
      .show();

    // Call WebAuthn API
    const publicKey = {
      rp: registerRequest.rp,
      user: {
        id: Base64URL.decode(registerRequest.user.id),
	name: registerRequest.user.name,
	displayName: registerRequest.user.displayName
      },
      challenge: Base64URL.decode(registerRequest.challenge),
      pubKeyCredParams: registerRequest.pubKeyCredParams,
      timeout: registerRequest.timeout || 60000,
      authenticatorSelection: registerRequest.authenticatorSelection || {},
      attestation: registerRequest.attestation || 'none'
    };

    if (registerRequest.excludeCredentials) {
      publicKey.excludeCredentials = registerRequest.excludeCredentials.map(cred => ({
        type: cred.type,
	id: Base64URL.decode(cred.id)
      }));
    }

    const credential = await navigator.credentials.create({ publicKey });

    // Submit attestation (phase 2)
    const attestationResponse = {
      id: credential.id,
      rawId: Base64URL.encode(credential.rawId),
      response: {
        clientDataJSON: Base64URL.encode(credential.response.clientDataJSON),
	attestationObject: Base64URL.encode(credential.response.attestationObject)
      },
      type: credential.type
    };

    // Include user/realm data to preserve token assignment
    const phase2Data = {
      serial: serial,
      type: 'fido2',
      attestationResponse: JSON.stringify(attestationResponse)
    };
    jQuery.extend(phase2Data, window._fido2_pending_user_data || {});

    const phase2Response = await $.ajax({
      url: '/admin/init',
      type: 'POST',
      data: phase2Data,
      dataType: 'json'
    });

    if (!phase2Response.result?.status) {
      throw new Error(phase2Response.result?.error?.message || 'Activation failed');
    }

    // Success - reset and close dialog, show success banner
    fido2_close_and_reset();
    alert_info_text({
      text: '${_("Token")} ' + escape(serial) + ' ${_("activated successfully!")}',
      is_escaped: true
    });
  } catch (error) {
    console.error('[FIDO2] Activation error: ', error);
    // Show error in the dialog and re-enable buttons
    $('#fido2_activate_status')
      .text('${_("Activation failed")}: ' + error.message)
      .css('color', '#c00')
      .show();
    var $dlg = $('#dialog_token_enroll');
    $dlg.parent().find('.ui-dialog-buttonpane button').prop('disabled', false);
  }
}

const Base64URL = {
  /**
   * Decode base64url string to ArrayBuffer
   */
  decode(base64url) {
    // Convert base64url to base64
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding
    const padding = (4 - (base64.length % 4)) % 4;
    base64 += "=".repeat(padding);

    // Decode to binary string
    const binary = atob(base64);

    // Convert to Uint8Array
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
  },

  /**
   * Encode ArrayBuffer to base64url string
   */
 encode(buffer) {
   const bytes = new Uint8Array(buffer);
   let binary = '';

   for (let i = 0; i < bytes.length; i++) {
     binary += String.fromCharCode(bytes[i]);
   }

   return btoa(binary)
     .replace(/\+/g, '-')
     .replace(/\//g, '_')
     .replace(/=+$/, '');
   }
};

</script>

<div class="fido2_enroll_form">
<hr>
<p><strong>${_("Create FIDO2/WebAuthn Token")}</strong></p>
<p>${_("This creates a FIDO2 token. After creation, you can activate it immediately with your security key, or leave it inactive for the assigned user to activate later via selfservice.")}</p>

<table>
  <tr>
    <td>
      <label for="enroll_fido2_desc" id="enroll_fido2_desc_label">
        ${_("Description")}
      </label>
    </td>
    <td>
      <input type="text" name="enroll_fido2_desc" id="enroll_fido2_desc"
         value="webGUI_generated" class="text">
    </td>
  </tr>
  <tr name="set_pin_rows" class="space" title='{$_("Protect your token with a static PIN")}'>
    <th colspan="2">${_("Token PIN:")}</th>
  </tr>
  <tr name="set_pin_rows">
    <td class="description">
      <label for="fido2_pin1" id="fido2_pin1_label">
        ${_("Enter PIN")}:
      </label>
    </td>
    <td>
      <input type="password" autocomplete="off" name="pin1" id="fido2_pin1"
        class="text ui-widget-content ui-corner-all">
    </td>
  </tr>
  <tr name="set_pin_rows">
    <td class="description">
      <label for="fido2_pin2" id="fido2_pin2_label">
        ${_("Confirm PIN")}:
      </label>
    </td>
    <td>
      <input type="password" autocomplete="off" name="pin2" id="fido2_pin2"
        class="text ui-widget-content ui-corner-all">
    </td>
  </tr>
</table>
</div>

<!-- Activation UI (hidden, shown in-place after enrollment -->
<div id="fido2_activate_section" style="display: none;">
  <p>
    <strong>${_("Token created:")} <span id="fido2_activate_serial" style="font-family: monospace;"></span></strong>
  </p>
  <p>
    ${_("The token is currently inactive. Would you like to activate it now by pairing a security key?")}
  </p>
  <p style="margin-top: 10px; padding: 8px; background-color: #fff8e1; border: 1px solid #ffe082; border-radius: 4px;">
    <strong>${_("Note:")}</strong> ${_("If you activate it here, the paired security key will be used for authentication. Choose 'Skip' to let the assigned user activate it with their own key later.")}
  </p>
  <p id="fido2_activate_status" style="display: none; margin-top: 10px; padding: 8px; font-weight: bold; border-radius: 4px;">
  </p>
</div>

%endif
