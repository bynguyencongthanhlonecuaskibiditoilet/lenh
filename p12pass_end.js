document.getElementById('createZipBtn').addEventListener('click', function() {
const p12FileInput = document.getElementById('p12File');
const mobileprovisionFileInput = document.getElementById('mobileprovisionFile');
const oldPassword = document.getElementById('oldPassword').value;
const newPassword = document.getElementById('newPassword').value;
const confirmNewPassword = document.getElementById('confirmNewPassword').value;
const currentLang = document.documentElement.lang || 'vi';
function showStatus(messageKey, type = '', ...args) {
const statusDiv = document.getElementById('status');
let message = (translations[currentLang] && translations[currentLang][messageKey]) || messageKey;
if (args.length > 0) {
message = message.replace('%s', args[0]); }
statusDiv.textContent = message;
statusDiv.className = type;
} showStatus('', '');
if (!p12FileInput.files || p12FileInput.files.length === 0) {
showStatus('status_error_select_p12', 'error'); return;
} if (!oldPassword) {
showStatus('status_error_missing_old_pass', 'error'); return; }
if (newPassword && newPassword !== confirmNewPassword) {
showStatus('status_error_pass_mismatch', 'error'); return; }
const p12File = p12FileInput.files[0];
const reader = new FileReader();
reader.onload = function(event) {
(async () => { try {
showStatus('status_processing');
const p12ArrayBuffer = event.target.result;
const p12Der = forge.util.createBuffer(p12ArrayBuffer).getBytes();
const p12Asn1 = forge.asn1.fromDer(p12Der);
const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, oldPassword);
const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
const privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0].key;
const certs = certBags[forge.pki.oids.certBag].map(bag => bag.cert);
if (!privateKey || certs.length === 0) {
throw new Error("Could not find key or certificate in .p12 file."); }
const newP12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, certs, newPassword, { algorithm: '3des' });
const newP12Der = forge.asn1.toDer(newP12Asn1).getBytes();
showStatus('status_zip_creating');
const zip = new JSZip();
const newP12Bytes = new Uint8Array(newP12Der.length);
for (let i = 0; i < newP12Der.length; ++i) {
newP12Bytes[i] = newP12Der.charCodeAt(i); }
const originalP12Name = p12File.name.replace(/\.[^/.]+$/, "");
zip.file(`${originalP12Name}_new.p12`, newP12Bytes, { binary: true });
let readmeContent; if (newPassword) {
readmeContent = `New Password / Mật Khẩu Mới / 新密码: ${newPassword}`; } else {
readmeContent = (translations[currentLang] && translations[currentLang]['p12_readme_no_pass']) || 'This P12 file has no password.'; }
zip.file("Pass.txt", readmeContent);
if (mobileprovisionFileInput.files.length > 0) {
const mobileprovisionFile = mobileprovisionFileInput.files[0];
zip.file(mobileprovisionFile.name, mobileprovisionFile); }
const zipBlob = await zip.generateAsync({ type: "blob", compression: "DEFLATE", compressionOptions: { level: 9 } });
const link = document.createElement('a');
link.href = URL.createObjectURL(zipBlob);
link.download = 'NewPassCert.zip';
document.body.appendChild(link); link.click();
document.body.removeChild(link);
showStatus('status_success', 'success');
} catch (err) { console.error(err);
if (err.message && (err.message.includes('Invalid password') || err.message.includes('Unable to parse PKCS12') || err.message.includes('mac check failed'))) {
showStatus('status_error_wrong_pass', 'error'); } else {
showStatus('status_error_generic', 'error', err.message); } } })(); };
reader.onerror = function() {
showStatus('status_error_read_file', 'error'); };
reader.readAsArrayBuffer(p12File); });
