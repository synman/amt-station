/* The Advanced tab (design/wsman.html, note 2.13): the WS-MAN browser (amt_wsman_get, read-only) with Copy as JSON and Edit and Put, the script editor
   (amt_wsman_invoke, a write) with its client-side credential-name check, and the guarded templates for the actions that have no typed tool.
   A read happens when asked, never on a timer and never for a paused server. A write is a sheet from components.js (the call shown is the call sent, with
   confirmed: true; Unprovision is the hold because the one predicate there says so). A redacted field is stripped from a Put and the sheet says which; nothing
   from the host or the tool is set as markup. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var head = document.querySelector('.srvhead[data-server]'), page = document.getElementById('wsman-page');
  if (!head || !page) return;
  var key = head.getAttribute('data-server'), POLL_MS = 5000;
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;
  var isObj = function (v) { return v !== null && typeof v === 'object' && !Array.isArray(v); };

  // ---- the credential-name check, the same rule as amt_wsman.is_secret_field (console/tests pins the two to each other) ----
  var SECRET_FIELD = /password|passwd|passphrase|secret|credential|privatekey|sharedkey|apikey|masterkey|netadminpass|psk/i;
  var SECRET_WORDS = ['pwd', 'pass', 'token', 'hash', 'pps', 'pid'];
  var WORD = /[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+/g;
  var NOT_CREDENTIAL = ['UserPasswordBypass'];
  function isSecretName(name) {
    if (NOT_CREDENTIAL.indexOf(name) !== -1) return false;
    if (SECRET_FIELD.test(name)) return true;
    return (String(name).match(WORD) || []).some(function (w) { return SECRET_WORDS.indexOf(w.toLowerCase()) !== -1; });
  }
  function isBoolish(v) {
    if (typeof v === 'boolean') return true;
    if (typeof v === 'number') return v === 0 || v === 1;
    return typeof v === 'string' && ['true', 'false', '0', '1'].indexOf(v.trim().toLowerCase()) !== -1;
  }
  function isSecretField(name, value) { return NOT_CREDENTIAL.indexOf(name) !== -1 ? !isBoolish(value) : isSecretName(name); }
  var CLASS_NAME = /^(AMT|CIM|IPS)_[A-Za-z0-9_]{1,80}$/, SELECTOR_NAME = /^[A-Za-z0-9_.-]{1,64}$/, FIELD_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/, METHOD_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
  var PLACEHOLDER = /^<[^<>]+>$/;

  // ---- the Class list and each class's get keys (designer ruling 2026-10-21): every class amt-mcp's code names, with the selector names a get
  //      round-tripped with for every instance on a live host (console/tests/data/wsman_class_keys.json, pinned by a test). null: no instance there
  //      to prove a key. Free text stays: an unlisted class is still read. Picking a class never reads. ----
  var CLASS_KEYS = {
    AMT_AgentPresenceCapabilities: ["InstanceID"],
    AMT_AgentPresenceWatchdog: null,
    AMT_AgentPresenceWatchdogAction: null,
    AMT_AlarmClockService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    AMT_AuditLog: ["Name"],
    AMT_AuthorizationService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    AMT_BootSettingData: ["InstanceID"],
    AMT_EnvironmentDetectionSettingData: ["InstanceID"],
    AMT_EthernetPortSettings: ["InstanceID"],
    AMT_EventSubscriber: null,
    AMT_GeneralSettings: ["InstanceID"],
    AMT_IPHeadersFilter: null,
    AMT_ManagementPresenceRemoteSAP: null,
    AMT_MessageLog: ["CreationClassName", "Name"],
    AMT_PublicKeyCertificate: ["InstanceID"],
    AMT_RedirectionService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    AMT_RemoteAccessPolicyRule: null,
    AMT_SetupAndConfigurationService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    AMT_SystemDefensePolicy: null,
    AMT_SystemDefenseService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    AMT_TLSSettingData: ["InstanceID"],
    CIM_AssociatedPowerManagementService: null,
    CIM_BIOSElement: ["Name"],
    CIM_BootConfigSetting: ["InstanceID"],
    CIM_BootService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    CIM_BootSourceSetting: ["InstanceID"],
    CIM_Card: ["CreationClassName", "Tag"],
    CIM_Chassis: ["CreationClassName", "Tag"],
    CIM_ComputerSystem: ["CreationClassName", "Name"],
    CIM_FilterCollectionSubscription: null,
    CIM_IndicationFilter: null,
    CIM_KVMRedirectionSAP: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    CIM_MediaAccessDevice: ["CreationClassName", "DeviceID", "SystemCreationClassName", "SystemName"],
    CIM_MessageLog: null,
    CIM_PhysicalMedia: null,
    CIM_PhysicalMemory: ["CreationClassName", "Tag"],
    CIM_PowerManagementService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    CIM_Processor: ["CreationClassName", "DeviceID", "SystemCreationClassName", "SystemName"],
    CIM_SoftwareIdentity: ["InstanceID"],
    IPS_AlarmClockOccurrence: null,
    IPS_HostBasedSetupService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    IPS_KVMRedirectionSettingData: ["InstanceID"],
    IPS_OptInService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"],
    IPS_PowerManagementService: ["CreationClassName", "Name", "SystemCreationClassName", "SystemName"]
  };
  var NO_KEYS_HELP = 'JSON text values · empty = bare get (one-instance class)';

  // ---- the guarded templates: the actions with no typed tool. `checks` names the classes a live enumerate must find before the template is kept. ----
  var CIM_SYSTEM = { epr: { class: 'CIM_ComputerSystem', selectors: { Name: 'ManagedSystem' } } };
  var TEMPLATES = [
    { id: 'os-wake', title: 'OS wake from standby', op: 'invoke', cls: 'IPS_PowerManagementService', method: 'RequestOSPowerSavingStateChange',
      fields: { OSPowerSavingState: 2, ManagedElement: CIM_SYSTEM }, checks: ['IPS_PowerManagementService', 'CIM_ComputerSystem'], say: 'Asks the OS to leave power saving (state 2).' },
    { id: 'os-saving', title: 'OS power saving', op: 'invoke', cls: 'IPS_PowerManagementService', method: 'RequestOSPowerSavingStateChange',
      fields: { OSPowerSavingState: 3, ManagedElement: CIM_SYSTEM }, checks: ['IPS_PowerManagementService', 'CIM_ComputerSystem'], say: 'Asks the OS to enter power saving (state 3).' },
    { id: 'consent-request', title: 'Request a user-consent code', op: 'invoke', cls: 'IPS_OptInService', method: 'StartOptIn', fields: {}, checks: ['IPS_OptInService'],
      note: 'the host shows a 6-digit code', say: 'Starts a user-consent request: the host shows a 6-digit code.' },
    { id: 'consent-send', title: 'Send a consent code', op: 'invoke', cls: 'IPS_OptInService', method: 'SendOptInCode', fields: { OptInCode: '<code shown on the host>' }, checks: ['IPS_OptInService'],
      note: 'within 2 minutes of the request', say: 'Sends the consent code the host showed. A wrong code counts against the attempts AMT allows.' },
    { id: 'consent-cancel', title: 'Cancel a consent request', op: 'invoke', cls: 'IPS_OptInService', method: 'CancelOptIn', fields: {}, checks: ['IPS_OptInService'], say: 'Cancels the pending user-consent request.' },
    { id: 'watchdog-timeouts', title: 'Agent presence watchdog timeouts', op: 'put', cls: 'AMT_AgentPresenceWatchdog', selectors: { DeviceID: '<DeviceID>' },
      fields: { TimeoutLow: '<seconds>', TimeoutHigh: '<seconds>', StartupInterval: '<seconds>' }, checks: ['AMT_AgentPresenceWatchdog'],
      note: 'Get-merge-Put: read the full instance in the browser and use Edit and Put to keep every other field', say: 'Rewrites the watchdog\'s timeouts.' },
    { id: 'watchdog-action', title: 'Agent presence watchdog action', op: 'invoke', cls: 'AMT_AgentPresenceWatchdogAction', method: 'AddAction',
      fields: { ActionSd: '<ActionSd>', ActionEac: '<ActionEac>', ActionEvent: '<ActionEvent>', ActionEventOnTransition: '<ActionEventOnTransition>' }, checks: ['AMT_AgentPresenceWatchdogAction'],
      say: 'Adds an action to the agent presence watchdog.' },
    { id: 'defense-filter', title: 'System defense filter', op: 'create', cls: 'AMT_IPHeadersFilter',
      fields: { Name: '<Name>', FilterDirection: '<FilterDirection>', FilterProfile: '<FilterProfile>', FilterProfileData: '<FilterProfileData>', ActionDrop: '<ActionDrop>', ActionEventOnMatch: '<ActionEventOnMatch>' },
      checks: ['AMT_IPHeadersFilter'], note: 'then the policy below names its handle', say: 'Creates a system defense filter.' },
    { id: 'defense-policy', title: 'System defense policy', op: 'create', cls: 'AMT_SystemDefensePolicy',
      fields: { PolicyName: '<PolicyName>', PolicyPrecedence: '<PolicyPrecedence>', AntiSpoofingSupport: '<AntiSpoofingSupport>', FilterCreationHandles: '<filter handle>', TxDefaultDrop: '<TxDefaultDrop>',
        TxDefaultMatchEvent: '<TxDefaultMatchEvent>', RxDefaultDrop: '<RxDefaultDrop>', RxDefaultMatchEvent: '<RxDefaultMatchEvent>' },
      checks: ['AMT_SystemDefensePolicy'], say: 'Creates a system defense policy that names the filter handle.' },
    { id: 'subscription-delete', title: 'Delete an event subscription', op: 'delete', cls: 'AMT_EventSubscriber', selectors: { Index: '<Index>' }, checks: ['AMT_EventSubscriber'],
      note: 'adding one is WS-Eventing Subscribe, which amt_wsman_invoke does not offer', say: 'Deletes the event subscription. There is no undo.' },
    { id: 'wake-alarm', title: 'Wake alarm', op: 'create', cls: 'IPS_AlarmClockOccurrence',
      fields: { InstanceID: '<InstanceID>', StartTime: '<StartTime>', Interval: '<Interval>', DeleteOnCompletion: '<DeleteOnCompletion>' }, checks: ['IPS_AlarmClockOccurrence'],
      say: 'Creates a wake alarm occurrence.' },
    { id: 'unprovision', title: 'Unprovision AMT (factory reset)', op: 'invoke', cls: 'AMT_SetupAndConfigurationService', method: 'Unprovision', fields: { ProvisioningMode: 1 },
      checks: ['AMT_SetupAndConfigurationService'], note: 'drops all management', danger: true,
      say: 'AMT is factory-reset: every setting, user, certificate and this console\'s access to the server are gone. Re-provisioning is a hands-on MEBx step at the machine. There is no undo.' }
  ];
  var UNAVAILABLE = { id: 'platform-erase', title: 'Platform Erase at next boot', sub: 'not available: AMT ignores a bare Put of AMT_BootSettingData.PlatformErase; activation needs ChangeBootOrder then SetBootConfigRole(1), which this editor cannot chain and amt-mcp has no tool for' };

  var st = { op: 'get', busy: false, writing: false, paused: null, gone: false, view: null, loaded: null, edOp: 'invoke' };
  var gates = [];
  var browserGate = { read: null, copy: null, edit: null }, editorGate = { run: null };

  function pausedWhy() { return st.paused ? 'paused · ' + (st.paused.reason || 'refused') : null; }
  function mkGate(id, why) { var btn = $(id), g = { btn: btn, wrap: btn.parentNode, reason: null, why: why }; gates.push(g); return g; }
  function controls() {
    gates.forEach(function (g) { S.setReason(g, g.why()); });
    document.querySelectorAll('#ws-op [data-op]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-op') === st.op)); });
    document.querySelectorAll('#ed-op [data-op]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-op') === st.edOp)); });
    var enumerating = st.op === 'enumerate', sel = $('ws-selectors');
    sel.readOnly = enumerating; if (enumerating) sel.setAttribute('aria-disabled', 'true'); else sel.removeAttribute('aria-disabled');
    var keys = CLASS_KEYS[$('ws-class').value.trim()] || null;
    $('ws-selectors-help').textContent = enumerating ? 'not valid with enumerate: no selectors are sent'
      : keys ? 'keys: ' + keys.join(', ') + ' · empty = bare get (one-instance class) · or enumerate and pick' : NO_KEYS_HELP;
    var ph = {}; (keys || ['InstanceID']).forEach(function (k) { ph[k] = '…'; });
    sel.setAttribute('placeholder', JSON.stringify(ph));
    var m = $('ed-method'), inv = st.edOp === 'invoke';
    m.readOnly = !inv; if (!inv) m.setAttribute('aria-disabled', 'true'); else m.removeAttribute('aria-disabled');
  }
  function banner() {
    var box = $('ws-paused'), text = $('ws-paused-text');
    clear(text);
    box.hidden = !st.paused;
    if (st.paused) S.pausedNote('WS-MAN', key, st.paused).forEach(function (n) { text.appendChild(typeof n === 'string' ? document.createTextNode(n) : n); });
  }
  function parseObject(text, what) {                        // '' -> {ok, value: null}; a JSON object -> {ok, value}; else {why}
    if (text.trim() === '') return { ok: true, value: null };
    var v;
    try { v = JSON.parse(text); } catch (e) { return { why: what + ' is not valid JSON' }; }
    return isObj(v) ? { ok: true, value: v } : { why: what + ' must be a JSON object' };
  }
  function textValues(o) { return Object.keys(o).every(function (k) { return typeof o[k] === 'string'; }); }

  // ================= the browser =================
  function browserArgs() {
    var cls = $('ws-class').value.trim();
    if (!CLASS_NAME.test(cls)) return { why: cls ? 'class must be AMT_, CIM_ or IPS_ and a name' : 'enter a class' };
    var args = { device: key, class_name: cls, operation: st.op };
    if (st.op === 'get') {
      var sel = parseObject($('ws-selectors').value, 'selectors');
      if (sel.why) return { why: sel.why };
      if (sel.value) {
        if (!textValues(sel.value) || !Object.keys(sel.value).every(function (k) { return SELECTOR_NAME.test(k); })) return { why: 'selectors are names and text values' };
        args.selectors = sel.value;
      }
    }
    return { args: args };
  }
  function readWhy() { return pausedWhy() || (st.busy ? 'waiting for amt-mcp' : browserArgs().why || null); }

  function unreadable(s, args) {
    if (!isObj(s)) return 'no result object';
    var bad = [];
    if (s.class !== args.class_name) bad.push('class');
    if (s.operation !== args.operation) bad.push('operation');
    if (args.operation === 'get') { if (!isObj(s.instance)) bad.push('instance'); }
    else {
      if (!Array.isArray(s.instances)) bad.push('instances');
      if (typeof s.truncated !== 'boolean') bad.push('truncated');
      if (!Number.isInteger(s.count) || (Array.isArray(s.instances) && s.count !== s.instances.length)) bad.push('count');
    }
    return bad.length ? 'missing or wrong: ' + bad.join(', ') : null;
  }
  function read() {
    var a = browserArgs();
    if (st.busy || st.paused || st.gone || a.why) return Promise.resolve();
    st.busy = true; st.view = null;
    clear($('ws-state')); $('ws-cov').hidden = true;
    $('ws-state').appendChild(h('div', { class: 'progress', role: 'progressbar', 'aria-label': 'Reading ' + a.args.class_name }, [h('i', { 'data-motion': 'progress' })]));
    controls();
    return amtc.post('/api/call', { tool: 'amt_wsman_get', arguments: a.args }).catch(function () { return { status: 0, body: {} }; })
      .then(function (r) { st.busy = false; outcome(r, a.args); return loadEntry(); });
  }
  function outcome(r, args) {
    var slot = $('ws-state'), b = r.body || {}, what = 'read ' + args.class_name + ' (' + args.operation + ')';
    clear(slot);
    if (r.status !== 200) slot.appendChild(S.readFailure(what, r));
    else if (b.isError) slot.appendChild(S.readRefusal(what, b.text));
    else {
      var bad = unreadable(b.structured, args);
      if (bad) slot.appendChild(S.result('error', 'i-block', [S.stamp() + ' · ' + what + ' · amt-mcp returned a result this page cannot read (' + bad + '), so nothing is shown and no Put is offered']));
      else st.view = { s: b.structured, args: args, at: Date.now() / 1000 };
    }
    draw();
  }
  function fmt(v) { return v === null || v === undefined ? '(nil)' : v === '<redacted>' ? '[redacted]   (credential-named)' : String(v); }
  function treeLines(obj, ind) {
    var keys = Object.keys(obj), w = Math.max(14, keys.reduce(function (m, k) { return Math.max(m, k.length + 6); }, 0)), out = [];
    keys.forEach(function (k) {
      var v = obj[k];
      if (isObj(v)) { out.push(ind + k); treeLines(v, ind + '  ').forEach(function (l) { out.push(l); }); }
      else if (Array.isArray(v)) {
        if (!v.length) out.push(ind + (k + ' ').padEnd(w) + '(empty list)');
        v.forEach(function (x, i) {
          var name = k + ' [' + i + ']';
          if (isObj(x)) { out.push(ind + name); treeLines(x, ind + '  ').forEach(function (l) { out.push(l); }); }
          else out.push(ind + name.padEnd(w) + fmt(x));
        });
      } else out.push(ind + k.padEnd(w) + fmt(v));
    });
    return out;
  }
  function treeText(v) {
    var s = v.s, cls = v.args.class_name;
    if (v.args.operation === 'get') return [cls].concat(treeLines(s.instance, '  ')).join('\n');
    if (!s.instances.length) return cls + '\n  no instances reported';
    return s.instances.map(function (it, i) { return cls + ' [' + (i + 1) + ' of ' + s.instances.length + ']\n' + treeLines(isObj(it) ? it : { value: it }, '  ').join('\n'); }).join('\n\n');
  }
  // After an enumerate of a class with known keys: one chip per instance. A pick switches to get and fills Selectors with that instance's own key
  // values; it does not read.
  function instances(v) {
    var row = $('ws-instances');
    row.querySelectorAll('button').forEach(function (b) { b.remove(); });
    var keys = v && v.args.operation === 'enumerate' ? CLASS_KEYS[v.args.class_name] : null;
    var list = keys ? v.s.instances.filter(function (it) { return isObj(it) && keys.every(function (k) { return it[k] !== null && it[k] !== undefined && !isObj(it[k]); }); }) : [];
    row.hidden = !list.length;
    list.forEach(function (it) {
      var sel = {}; keys.forEach(function (k) { sel[k] = String(it[k]); });
      var shown = keys.filter(function (k) { return ['CreationClassName', 'SystemCreationClassName', 'SystemName'].indexOf(k) === -1; });
      var b = h('button', { type: 'button', class: 'chip small', 'data-instance': JSON.stringify(sel) }, [(shown.length ? shown : keys).map(function (k) { return sel[k]; }).join(' · ')]);
      b.addEventListener('click', function () {
        st.op = 'get'; $('ws-class').value = v.args.class_name; $('ws-selectors').value = JSON.stringify(sel); controls();
      });
      row.appendChild(b);
    });
  }
  function draw() {
    var v = st.view, tree = $('ws-tree'), box = $('ws-cov');
    box.hidden = true; $('ws-call').textContent = '';
    instances(v);
    tree.textContent = v ? treeText(v) : 'Nothing read yet. Choose a class and press Read.';
    if (v) {
      var s = v.s, text = $('ws-cov-text');
      clear(text);
      text.appendChild(h('strong', {}, ['Coverage:']));
      text.appendChild(document.createTextNode(' ' + (v.args.operation === 'get' ? 'One instance, as the device returned it.'
        : s.count + ' instance(s) read. ' + (s.truncated ? 'The list was cut at the item cap: more exist than were read.' : 'Nothing was truncated.'))));
      box.className = 'banner' + (v.args.operation === 'enumerate' && s.truncated ? ' live' : '');
      box.hidden = false;
      $('ws-call').textContent = amtc.fmtCall({ tool: 'amt_wsman_get', arguments: v.args }) + ' · read-only · redacted fields are marked as the tool returned them';
    }
    controls();
  }
  function copyJson() {
    var v = st.view; if (!v) return;
    var data = JSON.stringify(v.args.operation === 'get' ? v.s.instance : v.s.instances, null, 2), b = $('ws-copy'), label = b.lastChild;
    var done = function (ok) { label.textContent = ok ? 'Copied' : 'Could not copy'; setTimeout(function () { label.textContent = 'Copy as JSON'; }, 2000); };
    try { navigator.clipboard.writeText(data).then(function () { done(true); }, function () { done(false); }); } catch (e) { done(false); }
  }
  function strip(inst) {                                              // the instance without its credential-named or redacted fields, and their names
    var gone = [];
    function keep(v) { return Array.isArray(v) ? v.map(keep) : isObj(v) ? walk(v) : v; }       // an object inside a list is walked too
    function walk(o) {
      var into = {};
      Object.keys(o).forEach(function (k) {
        var v = o[k];
        if (isSecretField(k, v) || v === '<redacted>') { if (gone.indexOf(k) === -1) gone.push(k); return; }
        into[k] = keep(v);
      });
      return into;
    }
    return { fields: walk(inst), stripped: gone };
  }
  function editAndPut() {
    var v = st.view;
    if (!v || v.args.operation !== 'get') return;
    var cut = strip(v.s.instance), a = v.args;
    setEditor('put', a.class_name, '', a.selectors || null, cut.fields);
    st.loaded = { cls: a.class_name, selectors: JSON.stringify(a.selectors || null), stripped: cut.stripped };
    var note = $('ed-loaded-text');
    clear(note);
    note.appendChild(document.createTextNode('Loaded the full instance of ' + a.class_name + ' from the read for a Put.' + (cut.stripped.length
      ? ' Stripped from the Put because they were redacted in the read: ' + cut.stripped.join(', ') + '. AMT may reset such a field when the whole instance is replaced; prefer AMT settings for a class that carries one.'
      : ' No field was redacted.')));
    $('ed-loaded').hidden = false;
    $('ed-class').focus();
    controls();
  }
  function whyEdit() {
    var v = st.view;
    return !v ? 'read an instance first' : v.args.operation !== 'get' ? 'get one instance to edit it: enumerate carries no selectors for a Put' : null;
  }

  // ================= the editor =================
  function setEditor(op, cls, method, selectors, fields) {
    st.edOp = op;
    $('ed-class').value = cls; $('ed-method').value = op === 'invoke' ? method : '';
    $('ed-selectors').value = selectors ? JSON.stringify(selectors) : '';
    $('ed-fields').value = fields && Object.keys(fields).length ? JSON.stringify(fields, null, 2) : '';
    controls();
  }
  function walkNames(o, fn) {                                          // field names at any depth, an EPR's selector names included, as amt_wsman_write.refuse_secret_names walks them
    if (Array.isArray(o)) o.forEach(function (x) { walkNames(x, fn); });
    else if (isObj(o)) Object.keys(o).forEach(function (k) {
      if (k === 'epr' && isObj(o.epr) && Object.keys(o).length === 1) { walkNames(o.epr.selectors || {}, fn); return; }
      var bad = fn(k, o[k]);
      if (bad) throw bad;
      walkNames(o[k], fn);
    });
  }
  function hasPlaceholder(o) {
    if (typeof o === 'string') return PLACEHOLDER.test(o);
    if (Array.isArray(o)) return o.some(hasPlaceholder);
    return isObj(o) ? Object.keys(o).some(function (k) { return hasPlaceholder(o[k]); }) : false;
  }
  // The editor's call, or the refusal the tool would make (its own codes), judged here so that nothing known to be refused is sent.
  function validate() {
    var op = st.edOp, cls = $('ed-class').value.trim(), method = $('ed-method').value.trim();
    var sel = parseObject($('ed-selectors').value, 'selectors'), fields = parseObject($('ed-fields').value, 'fields');
    if (sel.why) return { why: sel.why };
    if (fields.why) return { why: fields.why };
    if (!CLASS_NAME.test(cls)) return { why: cls ? 'invalid_class_name:' + JSON.stringify(cls) : 'enter a class' };
    if (op === 'invoke' && !method) return { why: 'invoke_needs_method' };
    if (op === 'invoke' && !METHOD_NAME.test(method)) return { why: 'invalid_method_name:' + JSON.stringify(method) };
    if (op === 'delete' && (fields.value && Object.keys(fields.value).length || !sel.value || !Object.keys(sel.value).length)) return { why: 'delete_takes_selectors_only' };
    var f = fields.value || {}, s = sel.value || {};
    if (!textValues(s)) return { why: 'selectors must be text values' };
    var names = Object.keys(f);
    for (var i = 0; i < names.length; i++) {
      var v = f[names[i]];
      if (isObj(v) && !(Object.keys(v).length === 1 && isObj(v.epr) && Object.keys(v.epr).sort().join() === 'class,selectors')) return { why: 'unsupported_nested_field:' + names[i] };
      if (!FIELD_NAME.test(names[i])) return { why: 'invalid_field_name:' + JSON.stringify(names[i]) };
    }
    try {
      walkNames(f, function (k, val) { return isSecretField(k, val) ? 'secret_field_refused:' + k : null; });
      walkNames(s, function (k, val) { return isSecretField(k, val) ? 'secret_field_refused:' + k : null; });
    } catch (e) { if (typeof e === 'string') return { why: e }; throw e; }
    var bad = Object.keys(s).filter(function (k) { return !SELECTOR_NAME.test(k); })[0];
    if (bad !== undefined) return { why: 'invalid_selector_name:' + JSON.stringify(bad) };
    var args = { device: key, operation: op, class_name: cls };
    if (op === 'invoke') args.method = method;
    if (Object.keys(s).length) args.selectors = s;
    if (Object.keys(f).length) args.fields = f;
    return { args: args, placeholder: hasPlaceholder(f) || hasPlaceholder(s) };
  }
  function runWhy() {
    var v = validate();
    return pausedWhy() || (st.writing ? 'waiting for amt-mcp' : v.why ? v.why : v.placeholder ? 'replace the <placeholders> first' : null);
  }
  function what(args) { return args.operation + ' ' + args.class_name + (args.method ? '.' + args.method : ''); }
  function lead(t) { return h('strong', {}, [S.stamp() + ' · ' + t]); }
  function validateOnly() {
    var v = validate(), slot = $('ed-results'), row;
    if (v.why) row = S.result('error', 'i-block', [lead('validate'), ' · refused here: ' + v.why + ' · nothing sent']);
    else row = S.result(v.placeholder ? 'live' : 'ok', v.placeholder ? 'i-help' : 'i-check',
      [lead('validate ' + what(v.args)), ' · ' + (v.placeholder ? 'a <placeholder> is still in the call: replace it before Run' : 'no credential-named field and nothing the tool refuses on its shape') + ' · nothing sent']);
    addResult(row);
  }
  function addResult(node) {
    var slot = $('ed-results');
    slot.insertBefore(node, slot.firstChild);
    while (slot.children.length > 5) slot.removeChild(slot.lastChild);
  }
  function templateFor(args) {
    return TEMPLATES.filter(function (t) { return t.op === args.operation && t.cls === args.class_name && (t.method || undefined) === args.method; })[0] || null;
  }
  function runSpec() {
    var v = validate(), a = v.args, t = templateFor(a), cls = a.class_name, op = a.operation;
    var call = { tool: 'amt_wsman_invoke', arguments: a }, forced = amtc.destructiveCall(call);
    var loaded = op === 'put' && st.loaded && st.loaded.cls === cls && st.loaded.selectors === JSON.stringify(a.selectors || null) ? st.loaded : null;
    var say;
    if (op === 'invoke') say = (t ? t.say + ' ' : '') + 'Calls ' + cls + '.' + a.method + ' on the AMT host with the fields shown. A non-zero ReturnValue or a SOAP fault raises; a reply with no ReturnValue is reported as unknown and you read the instance to confirm. No safeguard other than this confirmation applies.';
    else if (op === 'put') say = 'The fields shown are written as the whole instance of ' + cls + '; a Put may reset any field you omit. ' + (loaded && loaded.stripped.length ? loaded.stripped.join(', ')
      + ' ' + (loaded.stripped.length > 1 ? 'were' : 'was') + ' redacted in the read and ' + (loaded.stripped.length > 1 ? 'are' : 'is') + ' stripped from this Put: AMT may reset ' + (loaded.stripped.length > 1 ? 'them' : 'it') + ' when the instance is replaced. ' : '')
      + 'A SOAP fault raises. This tool does not read the instance back: read it in the browser afterwards.';
    else if (op === 'create') say = (t ? t.say + ' ' : '') + 'Creates a new ' + cls + ' instance with the fields shown. A SOAP fault raises. No safeguard other than this confirmation applies.';
    else say = (t ? t.say + ' ' : '') + 'Deletes the ' + cls + ' instance the selectors pick. A SOAP fault raises. There is no undo.';
    var title = forced ? 'Unprovision AMT on ' + key : (op === 'invoke' ? 'Invoke ' + cls + '.' + a.method : op[0].toUpperCase() + op.slice(1) + ' ' + cls) + ' on ' + key + (loaded ? ' (Get-merge-Put)' : '');
    return { id: 'ws-run-sheet', title: title, verb: forced ? 'unprovision' : 'Run', nowLabel: forced ? 'Unprovision now' : undefined, consequence: say, call: call,
      onResult: function (r) { ran(a, r); } };
  }

  // ---- results (design 7.4): the tool's own words, in the editor's card ----
  var NOT_SENT = /secret_field_refused|unsupported_nested_field|invalid_field_name|invalid_class_name|invalid_method_name|invalid_selector_name|invoke_needs_method|method_only_valid_for_invoke|delete_takes_selectors_only|delete_requires_selectors|field_value_too_long|too_many_fields|too_many_list_items|unsupported_field_value_type|unknown_operation/;
  var SENT = /wsman_return_value(_missing)?:/;
  function failure(w, r) {
    var code = (r.body && r.body.error) || 'no answer';
    if (r.status === 502) return S.result('live', 'i-help', [lead(w), ' · amt-mcp did not answer (' + code + ') · it is not known whether the request was sent; read the instance in the browser to see']);
    return S.result('error', 'i-block', [lead(w), ' · refused: ' + code + ' · nothing sent']);
  }
  function refusal(w, text) {
    var tail = NOT_SENT.test(text) ? ' · nothing sent' : SENT.test(text) ? ' · the request was sent and AMT\'s ReturnValue says it did not succeed'
      : ' · the text does not say whether the host changed: read the instance in the browser to see';
    return S.result('error', 'i-block', [lead(w), ' · refused: ' + text + tail]);
  }
  function ran(args, r) {
    var b = r.body || {}, w = what(args), row;
    if (r.status !== 200) row = failure(w, r);
    else if (b.isError) row = refusal(w, b.text);
    else {
      var s = b.structured || {}, rv = isObj(s.result) ? s.result.ReturnValue : undefined;
      if (args.operation !== 'invoke') row = S.result('ok', 'i-check', [lead(w), ' · accepted by AMT (no fault); this tool does not read the instance back: read it in the browser to confirm']);
      else if (s.return_value === 'unknown' || rv === undefined) row = S.result('live', 'i-help', [lead(w), ' · reply with no ReturnValue · return_value unknown · read the instance to confirm' + (typeof s.note === 'string' ? ' · ' + s.note : '')]);
      else if (String(rv) === '0') row = S.result('ok', 'i-check', [lead(w), ' · ReturnValue 0']);
      else row = S.result('live', 'i-help', [lead(w), ' · sent; ReturnValue ' + rv + ' (not 0): AMT did not confirm it']);
    }
    addResult(row);
  }

  // ---- the template list ----
  function brief(o) {                                                // a field's name, with its value when it is a fixed one (a <placeholder> shows the name alone)
    return Object.keys(o).map(function (k) {
      var v = o[k];
      return isObj(v) && v.epr ? k + ': epr ' + v.epr.class : typeof v === 'string' && PLACEHOLDER.test(v) ? k : k + ': ' + v;
    }).join(', ');
  }
  function buildTemplates() {
    var list = $('ws-templates');
    TEMPLATES.forEach(function (t) {
      var sub = t.op + ' ' + t.cls + (t.method ? '.' + t.method : '') + (t.selectors ? ' · selectors {' + brief(t.selectors) + '}' : '')
        + (t.fields && Object.keys(t.fields).length ? ' · {' + brief(t.fields) + '}' : ' · no fields');
      var load = h('button', { type: 'button', class: 'btn text', 'aria-label': 'Load ' + t.title, 'data-load': t.id }, ['Load']);
      var li = h('li', { 'data-template': t.id, 'data-class': t.cls, 'data-check-classes': t.checks.join(' '), 'data-operation': t.op, 'data-method': t.method || null }, [icon(t.danger ? 'i-warning' : 'i-list'),
        h('span', { class: 'txt' }, [h('span', {}, [t.title]), h('span', { class: 'sub data' }, [sub])]), load]);
      load.addEventListener('click', function () { loadTemplate(t); });
      list.appendChild(li);
    });
    var btn = h('button', { type: 'button', class: 'btn text', 'aria-disabled': 'true', 'aria-label': 'Load ' + UNAVAILABLE.title }, ['Load']);
    list.appendChild(h('li', { id: UNAVAILABLE.id }, [icon('i-block'), h('span', { class: 'txt' }, [h('span', {}, [UNAVAILABLE.title]), h('span', { class: 'sub data' }, [UNAVAILABLE.sub])]),
      h('div', { class: 'btn-wrap' }, [btn, h('span', { class: 'reason' }, ['no tool yet'])])]));
  }
  function loadTemplate(t) {
    st.loaded = null;
    setEditor(t.op, t.cls, t.method || '', t.selectors || null, t.fields || null);
    var note = $('ed-loaded-text');
    clear(note);
    note.appendChild(document.createTextNode('Template: ' + t.title + '. Nothing runs until you confirm.' + (t.note ? ' ' + t.note[0].toUpperCase() + t.note.slice(1) + '.' : '')));
    $('ed-loaded').hidden = false;
    $('ed-class').scrollIntoView && $('ed-class').scrollIntoView({ block: 'nearest' });
    $('ed-class').focus();
    controls();
  }

  function loadEntry() {
    return S.get('/api/server/' + key).then(function (r) {
      if (r.status === 404) { st.gone = true; return; }
      if (r.status !== 200) return;
      var e = r.body.server;
      st.paused = e.state === 'paused' ? (e.paused || { reason: 'refused' }) : null;
      banner(); controls();
    });
  }

  amtc.wsman = { TEMPLATES: TEMPLATES, UNAVAILABLE: UNAVAILABLE, isSecretField: isSecretField, validate: validate, strip: strip };   // read by the tests that pin these to the tools

  // ---- wiring ----
  buildTemplates();
  browserGate.read = mkGate('ws-read', readWhy);
  browserGate.copy = mkGate('ws-copy', function () { return st.view ? null : 'read first'; });
  browserGate.edit = mkGate('ws-edit', whyEdit);
  editorGate.run = mkGate('ed-run', runWhy);
  document.querySelectorAll('#ws-op [data-op]').forEach(function (b) { b.addEventListener('click', function () { st.op = b.getAttribute('data-op'); controls(); }); });
  document.querySelectorAll('#ed-op [data-op]').forEach(function (b) {
    b.addEventListener('click', function () { st.edOp = b.getAttribute('data-op'); if (st.edOp !== 'invoke') $('ed-method').value = ''; controls(); });
  });
  ['ws-class', 'ws-selectors'].forEach(function (id) { $(id).addEventListener('input', controls); });
  Object.keys(CLASS_KEYS).forEach(function (c) { $('ws-classes').appendChild(h('option', { value: c })); });
  ['ed-class', 'ed-method', 'ed-selectors', 'ed-fields'].forEach(function (id) { $(id).addEventListener('input', controls); });
  ['ws-class', 'ws-selectors'].forEach(function (id) { $(id).addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.repeat && $('ws-read').getAttribute('aria-disabled') !== 'true') read(); }); });
  $('ws-read').addEventListener('click', function () { if ($('ws-read').getAttribute('aria-disabled') !== 'true') read(); });
  $('ws-copy').addEventListener('click', function () { if ($('ws-copy').getAttribute('aria-disabled') !== 'true') copyJson(); });
  $('ws-edit').addEventListener('click', function () { if ($('ws-edit').getAttribute('aria-disabled') !== 'true') editAndPut(); });
  $('ed-validate').addEventListener('click', validateOnly);
  amtc.bindWrite($('ed-run'), runSpec);
  document.addEventListener('tools-call', function (e) { if (/^ws-/.test(e.detail.sheet || '')) { st.writing = true; controls(); } });
  document.addEventListener('tools-result', function (e) { if (/^ws-/.test(e.detail.sheet || '')) { st.writing = false; controls(); } });
  setEditor('invoke', '', '', null, null);
  controls();
  amtc.ready.then(function () {
    loadEntry();
    setInterval(loadEntry, POLL_MS);                                // the cached state only: a pause or a resume shows; nothing is read
  });
}());
