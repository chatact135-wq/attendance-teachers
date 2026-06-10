const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const preview = document.getElementById('preview');
const startCamera = document.getElementById('startCamera');
const capturePhoto = document.getElementById('capturePhoto');
const getLocation = document.getElementById('getLocation');
const signInBtn = document.getElementById('signInBtn');
const signOutBtn = document.getElementById('signOutBtn');
const actionInput = document.getElementById('actionInput');
const cameraStatus = document.getElementById('cameraStatus');
const locationStatus = document.getElementById('locationStatus');
const photoData = document.getElementById('photo_data');
const latInput = document.getElementById('latitude');
const lngInput = document.getElementById('longitude');
const accInput = document.getElementById('accuracy');
const deviceTime = document.getElementById('device_time');
const securityStatus = document.getElementById('securityStatus');

let securityBlocked = false;
let cameraReady = false;
let photoReady = false;
let locationReady = false;
let selectedAction = '';

function setAction(action) {
  selectedAction = action;
  actionInput.value = action;
}

function updateButtons(){
  deviceTime.value = 'SERVER_UAE_TIME_ONLY';
  const ready = photoReady && locationReady && !securityBlocked;
  if (signInBtn) signInBtn.disabled = !(ready && window.CAN_SIGN_IN);
  if (signOutBtn) signOutBtn.disabled = !(ready && window.CAN_SIGN_OUT);
}

async function checkSecurity(){
  if(!securityStatus){ return; }
  try{
    const res = await fetch('/security-status', {cache:'no-store'});
    const data = await res.json();
    if(data.blocked){
      securityBlocked = true;
      securityStatus.textContent = `Security: BLOCKED - ${data.reason}. Turn off VPN/proxy and use the normal local network.`;
      alert(`Blocked: ${data.reason}. Turn off VPN/proxy and try again.`);
    }else{
      securityBlocked = false;
      securityStatus.textContent = `Security: ${data.reason}${data.ip ? ' | IP: '+data.ip : ''}`;
    }
  }catch(e){
    securityBlocked = false;
    securityStatus.textContent = 'Security: IP/VPN check could not be completed now. Server will check again on submit.';
  }
  updateButtons();
}

startCamera.addEventListener('click', async ()=>{
  try{
    const stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:'user'}, audio:false});
    video.srcObject = stream;
    cameraReady = true;
    capturePhoto.disabled = false;
    cameraStatus.textContent = 'Camera: ready. Take a photo before submitting.';
  }catch(e){
    cameraStatus.textContent = 'Camera blocked or unavailable. Attendance cannot be submitted.';
  }
});

capturePhoto.addEventListener('click', ()=>{
  if(!cameraReady){ return; }
  canvas.width = video.videoWidth || 640;
  canvas.height = video.videoHeight || 480;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video,0,0,canvas.width,canvas.height);
  const data = canvas.toDataURL('image/jpeg',0.86);
  photoData.value = data;
  preview.src = data;
  preview.style.display = 'block';
  photoReady = true;
  cameraStatus.textContent = 'Camera: required photo captured.';
  checkSecurity();
  updateButtons();
});

getLocation.addEventListener('click', ()=>{
  if(!navigator.geolocation){
    locationStatus.textContent = 'Location is not supported on this device.';
    return;
  }
  locationStatus.textContent = 'Location: checking...';
  navigator.geolocation.getCurrentPosition((pos)=>{
    latInput.value = pos.coords.latitude;
    lngInput.value = pos.coords.longitude;
    accInput.value = pos.coords.accuracy;
    locationReady = true;
    locationStatus.textContent = `Location: ready (${pos.coords.latitude.toFixed(6)}, ${pos.coords.longitude.toFixed(6)}), accuracy ${Math.round(pos.coords.accuracy)} m`;
    checkSecurity();
    updateButtons();
  },(err)=>{
    locationStatus.textContent = 'Location blocked or unavailable. Attendance cannot be submitted.';
  },{enableHighAccuracy:true, timeout:15000, maximumAge:0});
});

if (signInBtn) {
  signInBtn.addEventListener('click', () => setAction('IN'));
}
if (signOutBtn) {
  signOutBtn.addEventListener('click', () => setAction('OUT'));
}

document.getElementById('attendanceForm').addEventListener('submit',(e)=>{
  if(!photoReady || !locationReady){
    e.preventDefault();
    alert('Camera photo and location are both required.');
    return;
  }
  if(securityBlocked){
    e.preventDefault();
    alert('Attendance blocked because VPN/proxy/datacenter IP was detected.');
    return;
  }
  if(!actionInput.value){
    e.preventDefault();
    alert('Please select Sign In or Sign Out.');
  }
});

checkSecurity();
updateButtons();
