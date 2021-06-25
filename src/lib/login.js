import lodash_1 from "lodash"
import attempt_1 from "@lifeomic/attempt"
import Chance from 'chance';
import request from 'request-promise'
import { createHmac } from 'crypto';
import request_1 from "request"
import tough_cookie_1 from "tough-cookie"
import Bluebird from "bluebird"
import crypto from 'crypto'
import  {devices}  from "../devices/devices.models.js";
import { builds } from "../devices/devices.builds.js";

var cookieStore = new tough_cookie_1.MemoryCookieStore();
var cookieJar = request_1.jar(cookieStore);
var deviceString,deviceId,uuid,phoneId,adid,build,passwordEncryptionPubKey,passwordEncryptionKeyId;
export async function newLogin(username,password){
  generateDevice(username);
  await simulatePreLoginFlow();
  return await login(username,password)
}
function generateDevice(val) {
  const chance = new Chance(val);
  deviceString = chance.pickone(devices);
  const id = chance.string({
    pool: 'abcdef0123456789',
    length: 16,
  });
  deviceId = `android-${id}`;
  uuid = chance.guid();
  phoneId = chance.guid();
  adid = chance.guid();
  build = chance.pickone(builds);
}

async function simulatePreLoginFlow() {
  await executeRequestsFlow({
    requests:[
    ()=>readMsisdnHeader(),
    ()=>msisdnHeaderBootstrap('ig_select_app'),
    ()=>tokenResult(),
    ()=>contactPointPrefill('prefill').catch(() => undefined),
    ()=>preLoginSync(),
    ()=>syncLoginExperiments(),
    ()=>logAttribution(),
    ()=>getPrefillCandidates().catch(() => undefined)
    ]
  })
}
async function executeRequestsFlow({ requests, concurrency = 1, toShuffle = true, }) {
  if (toShuffle) {
      requests = lodash_1.shuffle(requests);
  }
  await Bluebird.map(requests, request => request(), { concurrency });
}
async function readMsisdnHeader(usage = 'default') {
   await send({
    method: 'POST',
    url: '/api/v1/accounts/read_msisdn_header/',
    headers: {
      'X-DEVICE-ID': uuid,
    },
    form: sign({
      mobile_subno_usage: "default",
      device_id: uuid,
    }),
  });
}
async function msisdnHeaderBootstrap(usage = 'default') {
   await send({
    method: 'POST',
    url: '/api/v1/accounts/msisdn_header_bootstrap/',
    form: sign({
      mobile_subno_usage: "default",
      device_id: uuid,
    }),
  });
}
async function tokenResult() {
  return await send({
      url: '/api/v1/zr/token/result/',
      qs: {
          device_id: deviceId,
          token_hash: '',
          custom_device_id: uuid,
          fetch_reason: 'token_expired',
      },
  });
}
async function contactPointPrefill(usage = 'default') {
  return await send({
      method: 'POST',
      url: '/api/v1/accounts/contact_point_prefill/',
      form: sign({
          phone_id: phoneId,
          _csrftoken: extractCookie('csrftoken'),
          usage,
      }),
  });
}
async function preLoginSync() {
  return await sync({
      id: uuid,
      configs: 'ig_fbns_blocked,ig_android_felix_release_players,ig_user_mismatch_soft_error,ig_android_carrier_signals_killswitch,ig_android_killswitch_perm_direct_ssim,fizz_ig_android,ig_mi_block_expired_events,ig_android_os_version_blocking_config',
  });
}
async function sync(data) {
  return await send({
      method: 'POST',
      url: '/api/v1/launcher/sync/',
      form: sign(data),
  });
}
async function syncLoginExperiments() {
  return await sync2(loginExperiments);
}
async function sync2(experiments) {
  let data;
  try {
      const uid = extractCookie('ds_user_id')
      if (uid === null) {
        throw "uid not found";
    }
      data = {
          _csrftoken: extractCookie('csrftoken'),
          id: uid,
          _uid: uid,
          _uuid: uuid,
      };
  }
  catch (_a) {
      data = {
          id: uuid,
      };
  }
  data = Object.assign(data, { experiments });
  return await send({
      method: 'POST',
      url: '/api/v1/qe/sync/',
      headers: {
          'X-DEVICE-ID': uuid,
      },
      form: sign(data),
  });
}
async function logAttribution() {
  return await send({
      method: 'POST',
      url: '/api/v1/attribution/log_attribution/',
      form: sign({
          adid: adid,
      }),
  });
}
async function getPrefillCandidates() {
  return await send({
      method: 'POST',
      url: '/api/v1/accounts/get_prefill_candidates/',
      form: sign({
          android_device_id: deviceId,
          usages: '["account_recovery_omnibox"]',
          device_id: uuid
      }),
  });
}

async function login(username,password){

  if (!passwordEncryptionPubKey) {
    await syncLoginExperiments();
}
const { encrypted, time } = encryptPassword(password);
const response = await Bluebird.try(() => send({
    method: 'POST',
    url: '/api/v1/accounts/login/',
    form: sign({
        username,
        enc_password: `#PWD_INSTAGRAM:4:${time}:${encrypted}`,
        guid: uuid,
        phone_id: phoneId,
        _csrftoken:  extractCookie('csrftoken'),
        device_id: deviceId,
        adid: adid,
        google_tokens: '[]',
        login_attempt_count: 0,
        country_codes: JSON.stringify([{ country_code: '1', source: 'default' }]),
        jazoest: createJazoest(phoneId),
    }),
})).catch(error => {});
return response.body;
}
async function send(userOptions, onlyCheckHttpStatus) {
  const options = lodash_1.defaultsDeep(userOptions, {
      baseUrl: 'https://i.instagram.com/',
      resolveWithFullResponse: true,
      proxy: undefined,
      simple: false,
      jar: cookieJar,
      strictSSL: false,
      gzip: true,
      headers: getDefaultHeaders(),
      method: 'GET',
  }, {});
  const response = await faultTolerantRequest(options);
  updateState(response);
  return response;
}

async function faultTolerantRequest(options) {
  try {
      return await attempt_1.retry(async () => request(options), {maxAttempts: 1});
  }
  catch (err) {
      console.log("error23"+err)
  }
}




//utils
function sign(payload){
  const json = typeof payload === 'object' ? JSON.stringify(payload) : payload;
  const signatures = signature(json);
  return {
    ig_sig_key_version: '4',
    signed_body: `${signatures}.${json}`,
  };
}
function signature(data) {
  return createHmac('sha256', '9193488027538fd3450b83b7d05286d4ca9599a0f7eeed90d8c85925698a05dc')
    .update(data)
    .digest('hex');
}

function updateState(response) {
  const { 'x-ig-set-www-claim': wwwClaim, 'ig-set-authorization': auth, 'ig-set-password-encryption-key-id': pwKeyId, 'ig-set-password-encryption-pub-key': pwPubKey, } = response.headers;
  if (typeof wwwClaim === 'string') {
     let igWWWClaim = wwwClaim;
  }
  if (typeof auth === 'string' && !auth.endsWith(':')) {
      let authorization = auth;
  }
  if (typeof pwKeyId === 'string') {
      passwordEncryptionKeyId = pwKeyId;
  }
  if (typeof pwPubKey === 'string') {
     passwordEncryptionPubKey = pwPubKey;
  }
}
function getDefaultHeaders() {
  var _a;
  return {
    'User-Agent': appUserAgent(),
    'X-Ads-Opt-Out': '0',
    'X-CM-Bandwidth-KBPS': '-1.000',
    'X-CM-Latency': '-1.000',
    'X-IG-App-Locale': 'en_US',
    'X-IG-Device-Locale': 'en_US',
    'X-Pigeon-Session-Id': '7a4555d0-6cc9-5623-9f2c-20ea1446aed3',
    'X-Pigeon-Rawclienttime': '1624525849.174',
    'X-IG-Connection-Speed': '2741kbps',
    'X-IG-Bandwidth-Speed-KBPS': '-1.000',
    'X-IG-Bandwidth-TotalBytes-B': '0',
    'X-IG-Bandwidth-TotalTime-MS': '0',
    'X-IG-EU-DC-ENABLED': undefined,
    'X-IG-Extended-CDN-Thumbnail-Cache-Busting-Value': '1000',
    'X-Bloks-Version-Id': '1b030ce63a06c25f3e4de6aaaf6802fe1e76401bc5ab6e5fb85ed6c2d333e0c7',
    'X-MID': 'YNRMFgABAAFVm7FrIhDjOBRZtRfI',
    'X-IG-WWW-Claim': '0',
    'X-Bloks-Is-Layout-RTL': 'false',
    'X-IG-Connection-Type': 'WIFI',
    'X-IG-Capabilities': '3brTvwE=',
    'X-IG-App-ID': '567067343352427',
    'X-IG-Device-ID': uuid,
    'X-IG-Android-ID': deviceId,
    'Accept-Language': 'en-US',
    'X-FB-HTTP-Engine': 'Liger',
    Authorization: undefined,
    Host: 'i.instagram.com',
    'Accept-Encoding': 'gzip',
    Connection: 'close'
  };
}

function extractCookie(key) {
  const cookies = cookieJar.getCookies('https://i.instagram.com');
  return lodash_1.find(cookies, { key }) || null;
}
var loginExperiments = 'ig_android_fci_onboarding_friend_search,ig_android_device_detection_info_upload,ig_android_account_linking_upsell_universe,ig_android_direct_main_tab_universe_v2,ig_android_allow_account_switch_once_media_upload_finish_universe,ig_android_sign_in_help_only_one_account_family_universe,ig_android_sms_retriever_backtest_universe,ig_android_direct_add_direct_to_android_native_photo_share_sheet,ig_android_spatial_account_switch_universe,ig_growth_android_profile_pic_prefill_with_fb_pic_2,ig_account_identity_logged_out_signals_global_holdout_universe,ig_android_prefill_main_account_username_on_login_screen_universe,ig_android_login_identifier_fuzzy_match,ig_android_mas_remove_close_friends_entrypoint,ig_android_shared_email_reg_universe,ig_android_video_render_codec_low_memory_gc,ig_android_custom_transitions_universe,ig_android_push_fcm,multiple_account_recovery_universe,ig_android_show_login_info_reminder_universe,ig_android_email_fuzzy_matching_universe,ig_android_one_tap_aymh_redesign_universe,ig_android_direct_send_like_from_notification,ig_android_suma_landing_page,ig_android_prefetch_debug_dialog,ig_android_smartlock_hints_universe,ig_android_black_out,ig_activation_global_discretionary_sms_holdout,ig_android_video_ffmpegutil_pts_fix,ig_android_multi_tap_login_new,ig_save_smartlock_universe,ig_android_caption_typeahead_fix_on_o_universe,ig_android_enable_keyboardlistener_redesign,ig_android_sign_in_password_visibility_universe,ig_android_nux_add_email_device,ig_android_direct_remove_view_mode_stickiness_universe,ig_android_hide_contacts_list_in_nux,ig_android_new_users_one_tap_holdout_universe,ig_android_ingestion_video_support_hevc_decoding,ig_android_mas_notification_badging_universe,ig_android_secondary_account_in_main_reg_flow_universe,ig_android_secondary_account_creation_universe,ig_android_account_recovery_auto_login,ig_android_pwd_encrytpion,ig_android_bottom_sheet_keyboard_leaks,ig_android_sim_info_upload,ig_android_mobile_http_flow_device_universe,ig_android_hide_fb_button_when_not_installed_universe,ig_android_account_linking_on_concurrent_user_session_infra_universe,ig_android_targeted_one_tap_upsell_universe,ig_android_gmail_oauth_in_reg,ig_android_account_linking_flow_shorten_universe,ig_android_vc_interop_use_test_igid_universe,ig_android_notification_unpack_universe,ig_android_registration_confirmation_code_universe,ig_android_device_based_country_verification,ig_android_log_suggested_users_cache_on_error,ig_android_reg_modularization_universe,ig_android_device_verification_separate_endpoint,ig_android_universe_noticiation_channels,ig_android_account_linking_universe,ig_android_hsite_prefill_new_carrier,ig_android_one_login_toast_universe,ig_android_retry_create_account_universe,ig_android_family_apps_user_values_provider_universe,ig_android_reg_nux_headers_cleanup_universe,ig_android_mas_ui_polish_universe,ig_android_device_info_foreground_reporting,ig_android_shortcuts_2019,ig_android_device_verification_fb_signup,ig_android_onetaplogin_optimization,ig_android_passwordless_account_password_creation_universe,ig_android_black_out_toggle_universe,ig_video_debug_overlay,ig_android_ask_for_permissions_on_reg,ig_assisted_login_universe,ig_android_security_intent_switchoff,ig_android_device_info_job_based_reporting,ig_android_add_account_button_in_profile_mas_universe,ig_android_add_dialog_when_delinking_from_child_account_universe,ig_android_passwordless_auth,ig_radio_button_universe_2,ig_android_direct_main_tab_account_switch,ig_android_recovery_one_tap_holdout_universe,ig_android_modularized_dynamic_nux_universe,ig_android_fb_account_linking_sampling_freq_universe,ig_android_fix_sms_read_lollipop,ig_android_access_flow_prefil'

function encryptPassword(password) {
  const randKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const rsaEncrypted = crypto.publicEncrypt({
      key: Buffer.from(passwordEncryptionPubKey, 'base64').toString(),
      padding: crypto.constants.RSA_PKCS1_PADDING,
  }, randKey);
  const cipher = crypto.createCipheriv('aes-256-gcm', randKey, iv);
  const time = Math.floor(Date.now() / 1000).toString();
  cipher.setAAD(Buffer.from(time));
  const aesEncrypted = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
  const sizeBuffer = Buffer.alloc(2, 0);
  sizeBuffer.writeInt16LE(rsaEncrypted.byteLength, 0);
  const authTag = cipher.getAuthTag();
  return {
      time,
      encrypted: Buffer.concat([
          Buffer.from([1, passwordEncryptionKeyId]),
          iv,
          sizeBuffer,
          rsaEncrypted, authTag, aesEncrypted
      ])
          .toString('base64'),
  };
}
function createJazoest(input) {
  const buf = Buffer.from(input, 'ascii');
  let sum = 0;
  for (let i = 0; i < buf.byteLength; i++) {
      sum += buf.readUInt8(i);
  }
  return `2${sum}`;
}
function appUserAgent() {
  return `Instagram 121.0.0.29.119 Android (${deviceString}; en_US; 185203708)`;
}