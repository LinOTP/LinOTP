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
